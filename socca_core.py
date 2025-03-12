#!/usr/bin/env python3
"""
SOCca Core - Minimal CVE to Sentinel pipeline

This script:
1. Pulls CVEs from NVD API
2. Analyzes them with OpenAI
3. Sends them to Microsoft Sentinel

All in a single file with no unnecessary components.
"""

import json
import logging
import os
import sqlite3
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import openai

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/app/logs/socca.log')
    ]
)
logger = logging.getLogger('socca')

# Load environment variables
NVD_API_KEY = os.environ.get('NVD_API_KEY')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
OPENAI_MODEL = os.environ.get('OPENAI_MODEL', 'gpt-4o-mini')
SENTINEL_WORKSPACE_ID = os.environ.get('SENTINEL_WORKSPACE_ID')
SENTINEL_PRIMARY_KEY = os.environ.get('SENTINEL_PRIMARY_KEY')
SENTINEL_LOG_TYPE = os.environ.get('SENTINEL_LOG_TYPE', 'SOCcaCVE')
SENTINEL_API_VERSION = os.environ.get('SENTINEL_API_VERSION', '2016-04-01')
# Clean environment variables to handle comments
def get_clean_env_int(key, default):
    value = os.environ.get(key, str(default))
    # Extract just the number from the beginning of the string
    # This handles cases where comments are in the same line
    match = re.search(r'^\d+', value.strip())
    if match:
        return int(match.group(0))
    return default

POLLING_INTERVAL = get_clean_env_int('POLLING_INTERVAL', 60)
MAX_TOKEN_LIMIT = get_clean_env_int('MAX_TOKEN_LIMIT', 16000)

# File paths
DATA_DIR = '/app/data'
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = f'{DATA_DIR}/socca.db'
CACHE_DIR = f'{DATA_DIR}/cache'
os.makedirs(CACHE_DIR, exist_ok=True)

# Initialize OpenAI
openai.api_key = OPENAI_API_KEY

# Pre-compile regex patterns
MITRE_ATTACK_PATTERN = re.compile(r'T\d{4}')

# System prompt for OpenAI
SYSTEM_PROMPT = """You are a cybersecurity expert specialized in vulnerability assessment. Analyze the provided CVE and create a structured analysis with these fields:
{
  "cve_id": "[CVE ID]",
  "summary": "[1-2 sentence overview]",
  "affected": {"products": ["[product1]"], "vendors": ["[vendor1]"]},
  "vulnerability": {"type": "[vuln type]", "technical_details": "[detailed explanation]", "root_cause": "[cause]"},
  "severity": {"cvss_score": "[score]", "risk_rating": "[Critical/High/Medium/Low]", "impact_rationale": "[explanation]"},
  "attack_vector": {"prerequisites": ["[prereq1]"], "attack_complexity": "[Low/Medium/High]"},
  "detection": {
    "ioc": ["[indicator1]"],
    "detection_rules": [{"type": "Microsoft Sentinel KQL", "rule": "[KQL query]", "description": "[description]"}],
    "log_sources": ["[log source1]"]
  },
  "mitre_att_ck": {"tactics": ["[tactic1]"], "techniques": ["[technique1]"]},
  "remediation": {"immediate_actions": ["[action1]"], "permanent_fixes": ["[fix1]"]}
}

Your response must be valid JSON. Provide specific, actionable information in all fields."""

# Database Management
@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()

def initialize_database():
    """Initialize database tables and indexes"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # CVE data table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                reference_urls TEXT,
                published TEXT,
                cvss_data TEXT,
                metadata TEXT,
                processed_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # AI analysis results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis (
                cve_id TEXT PRIMARY KEY,
                report TEXT,
                processed_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Sentinel export tracking table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sentinel_exports (
                cve_id TEXT PRIMARY KEY,
                sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_published ON cves(published)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_date ON cves(processed_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sent_date ON sentinel_exports(sent_date)")
        
        conn.commit()
        logger.info("Database initialized")

# NVD API Functions
def create_request_session():
    """Create a request session with retry logic"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    
    # Add NVD API key if available
    if NVD_API_KEY:
        session.headers.update({"apiKey": NVD_API_KEY})
    
    return session

def fetch_cves(start_time, end_time):
    """Fetch CVEs from NVD API for a specified time period"""
    logger.info(f"Fetching CVEs from {start_time} to {end_time}")
    
    # Format timestamps for NVD API
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.999Z")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start_str,
        "pubEndDate": end_str,
        "resultsPerPage": 100
    }
    
    session = create_request_session()
    all_cves = []
    
    try:
        # Handle pagination
        total_results = None
        start_index = 0
        
        while True:
            if start_index > 0:
                params["startIndex"] = start_index
            
            response = session.get(url, params=params, timeout=30)
            
            if response.status_code != 200:
                logger.error(f"NVD API error: {response.status_code} - {response.text}")
                break
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            if total_results is None:
                total_results = data.get('totalResults', 0)
                logger.info(f"Found {total_results} CVEs")
            
            all_cves.extend(vulnerabilities)
            
            # Check if we need to fetch more pages
            if len(all_cves) >= total_results or len(vulnerabilities) == 0:
                break
                
            start_index += len(vulnerabilities)
            
            # Rate limiting to avoid hitting API limits
            time.sleep(1.0 if NVD_API_KEY else 6.0)
    
    except Exception as e:
        logger.error(f"Error fetching CVEs: {e}")
    
    logger.info(f"Successfully retrieved {len(all_cves)} CVEs")
    return all_cves

def process_cve(cve):
    """Extract relevant information from a CVE object"""
    cve_data = cve.get('cve', {})
    cve_id = cve_data.get('id')
    
    if not cve_id:
        logger.warning(f"Skipping CVE with no ID: {cve}")
        return None
    
    # Extract description
    descriptions = cve_data.get('descriptions', [])
    english_descriptions = [d for d in descriptions if d.get('lang') == 'en']
    description = english_descriptions[0].get('value') if english_descriptions else "No description available"
    
    # Extract references
    references = []
    for ref in cve_data.get('references', []):
        url = ref.get('url')
        if url:
            references.append(url)
    
    # Extract publish date
    published = cve_data.get('published')
    
    # Extract CVSS data
    metrics = cve_data.get('metrics', {})
    
    return {
        'cve_id': cve_id,
        'description': description,
        'reference_urls': json.dumps(references),
        'published': published,
        'cvss_data': json.dumps(metrics),
        'metadata': json.dumps(cve_data)
    }

def is_cve_processed(cve_id):
    """Check if a CVE has already been processed"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,))
        return cursor.fetchone() is not None

def save_cve(cve_data):
    """Save a CVE to the database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cves (cve_id, description, reference_urls, published, cvss_data, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            cve_data['cve_id'],
            cve_data['description'],
            cve_data['reference_urls'],
            cve_data['published'],
            cve_data['cvss_data'],
            cve_data['metadata']
        ))
        conn.commit()
    logger.debug(f"Saved CVE {cve_data['cve_id']} to database")

# OpenAI Functions
def truncate_text(text, max_tokens):
    """Simple token count estimation and truncation"""
    # Approximate token count (very rough estimate)
    tokens = len(text) / 4
    
    if tokens <= max_tokens:
        return text
    
    # If over limit, truncate
    ratio = max_tokens / tokens
    truncated_length = int(len(text) * ratio * 0.95)  # 5% safety margin
    return text[:truncated_length]

def analyze_cve_with_ai(cve_data):
    """Analyze a CVE using OpenAI API"""
    logger.info(f"Analyzing {cve_data['cve_id']} with OpenAI")
    
    # Prepare prompt content
    references = json.loads(cve_data['reference_urls'])
    ref_text = "\n".join([f"- {url}" for url in references[:5]])  # Limit to top 5 refs
    
    prompt = (
        f"CVE ID: {cve_data['cve_id']}\n"
        f"Description: {cve_data['description']}\n"
        f"Published: {cve_data['published']}\n"
        f"References:\n{ref_text}\n\n"
        f"CVSS Data: {cve_data['cvss_data']}\n\n"
        f"Provide a detailed analysis of this vulnerability."
    )
    
    # Truncate if too long
    prompt = truncate_text(prompt, MAX_TOKEN_LIMIT)
    
    # Call OpenAI API with retries
    max_retries = 3
    for attempt in range(max_retries):
        try:
            start_time = time.time()
            response = openai.ChatCompletion.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3  # Lower temperature for more focused output
            )
            elapsed = time.time() - start_time
            logger.info(f"OpenAI analysis completed in {elapsed:.2f}s")
            
            report = response['choices'][0]['message']['content']
            save_analysis(cve_data['cve_id'], report)
            return report
        except Exception as e:
            wait_time = 2 ** attempt
            if attempt < max_retries - 1:
                logger.warning(f"OpenAI API error: {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                logger.error(f"OpenAI API error after {max_retries} retries: {e}")
                return None

def save_analysis(cve_id, report):
    """Save CVE analysis to database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO analysis (cve_id, report)
            VALUES (?, ?)
        """, (cve_id, report))
        conn.commit()
    logger.debug(f"Saved analysis for {cve_id}")

def get_analysis(cve_id):
    """Get the AI analysis for a CVE"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT report FROM analysis WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        return row['report'] if row else None

# Microsoft Sentinel Functions
def is_cve_sent_to_sentinel(cve_id):
    """Check if a CVE has been sent to Sentinel"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM sentinel_exports WHERE cve_id = ?", (cve_id,))
        return cursor.fetchone() is not None

def mark_cve_sent_to_sentinel(cve_id):
    """Mark a CVE as sent to Sentinel"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO sentinel_exports (cve_id, sent_date)
            VALUES (?, CURRENT_TIMESTAMP)
        """, (cve_id,))
        conn.commit()
    logger.debug(f"Marked {cve_id} as sent to Sentinel")

def build_sentinel_signature(workspace_id, date, content_length, primary_key):
    """Build authentication signature for Sentinel Log Analytics API"""
    import base64
    import hashlib
    import hmac
    
    x_headers = f'x-ms-date:{date}'
    string_to_hash = f'POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs'
    bytes_to_hash = string_to_hash.encode('utf-8')
    decoded_key = base64.b64decode(primary_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode('utf-8')
    
    return f"SharedKey {workspace_id}:{encoded_hash}"

def prepare_cve_for_sentinel(cve_id):
    """Prepare a CVE record for Sentinel"""
    # Get CVE data
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.description, c.published, c.cvss_data, a.report
            FROM cves c
            LEFT JOIN analysis a ON c.cve_id = a.cve_id
            WHERE c.cve_id = ?
        """, (cve_id,))
        result = cursor.fetchone()
        
    if not result:
        logger.warning(f"No data found for {cve_id} in database")
        return None
    
    # Parse CVSS data
    cvss_data = {}
    cvss_score = 0.0
    severity = "Unknown"
    
    try:
        metrics = json.loads(result['cvss_data'])
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            severity = get_severity_from_cvss(cvss_score)
    except Exception as e:
        logger.warning(f"Error parsing CVSS data for {cve_id}: {e}")
    
    # Extract MITRE tactics from report
    mitre_tactics = ""
    if result['report']:
        try:
            tactics = set(MITRE_ATTACK_PATTERN.findall(result['report']))
            if tactics:
                mitre_tactics = ','.join(tactics)
        except Exception as e:
            logger.debug(f"Error extracting MITRE tactics: {e}")
    
    # Create the log entry
    sentinel_log = {
        "TimeGenerated": datetime.now().isoformat(),
        "CVE_ID": cve_id,
        "Description": result['description'],
        "PublishedDate": result['published'],
        "CVSS_Score": cvss_score,
        "Severity": severity,
        "ReferenceURL": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    }
    
    # Add report excerpt if available
    if result['report']:
        sentinel_log['ReportHighlights'] = result['report'][:1000]  # Limit to 1000 chars
    
    # Add MITRE tactics if available
    if mitre_tactics:
        sentinel_log['MitreAttackTactics'] = mitre_tactics
    
    return sentinel_log

def get_severity_from_cvss(score):
    """Convert CVSS score to severity string"""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"

def send_to_sentinel(cve_id):
    """Send a CVE to Microsoft Sentinel"""
    if not SENTINEL_WORKSPACE_ID or not SENTINEL_PRIMARY_KEY:
        logger.error("Microsoft Sentinel configuration missing")
        return False
    
    # Check if already sent
    if is_cve_sent_to_sentinel(cve_id):
        logger.debug(f"{cve_id} already sent to Sentinel")
        return True
    
    # Prepare the log data
    sentinel_log = prepare_cve_for_sentinel(cve_id)
    if not sentinel_log:
        logger.warning(f"Cannot prepare {cve_id} for Sentinel")
        return False
    
    # Create the request
    api_url = f"https://{SENTINEL_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version={SENTINEL_API_VERSION}"
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    
    # Convert log to JSON and create signature
    body = json.dumps([sentinel_log])
    content_length = len(body)
    signature = build_sentinel_signature(SENTINEL_WORKSPACE_ID, rfc1123date, content_length, SENTINEL_PRIMARY_KEY)
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': signature,
        'Log-Type': SENTINEL_LOG_TYPE,
        'x-ms-date': rfc1123date
    }
    
    # Send request with retries
    max_retries = 3
    for attempt in range(max_retries):
        try:
            start_time = time.time()
            response = requests.post(
                api_url,
                data=body,
                headers=headers,
                timeout=30
            )
            elapsed = time.time() - start_time
            
            if response.status_code in (200, 204):
                logger.info(f"✓ Successfully sent {cve_id} to Microsoft Sentinel in {elapsed:.2f}s")
                mark_cve_sent_to_sentinel(cve_id)
                return True
            elif response.status_code == 429:  # Rate limit
                wait_time = 2 ** attempt + 1
                logger.warning(f"Rate limited by Sentinel API. Retry {attempt+1}/{max_retries} in {wait_time}s")
                time.sleep(wait_time)
            else:
                logger.error(f"Sentinel API error: {response.status_code} - {response.text}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    return False
        except Exception as e:
            logger.error(f"Error sending to Sentinel: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                return False
    
    return False

def generate_alert_templates():
    """Generate Microsoft Sentinel alert templates"""
    logger.info("Generating Microsoft Sentinel alert templates")
    
    # Get CVEs with analysis from the last 24 hours
    with get_db_connection() as conn:
        cursor = conn.cursor()
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute("""
            SELECT c.cve_id, c.description, c.cvss_data, a.report
            FROM cves c
            JOIN analysis a ON c.cve_id = a.cve_id
            WHERE c.processed_date >= ?
        """, (yesterday,))
        cves = [dict(row) for row in cursor.fetchall()]
    
    if not cves:
        logger.info("No recent CVEs found for alert templates")
        return
    
    # Generate templates
    templates = {"sentinel_alerts": []}
    
    for cve in cves:
        try:
            # Get severity
            severity = "Medium"
            cvss_score = 0.0
            try:
                metrics = json.loads(cve['cvss_data'])
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    severity = get_severity_from_cvss(cvss_score).lower()
            except:
                pass
            
            # Create alert template
            template = {
                "cve_id": cve['cve_id'],
                "rule_name": f"SOCca - Detection for {cve['cve_id']}",
                "query": f"{SENTINEL_LOG_TYPE}_CL | where CVE_ID_s == \"{cve['cve_id']}\"",
                "description": f"Detects {severity} severity vulnerability {cve['cve_id']}",
                "severity": severity,
                "threshold": 0,
                "query_frequency": "1h",
                "query_period": "1d"
            }
            
            # Add MITRE ATT&CK tactics if available
            if cve['report']:
                tactics = MITRE_ATTACK_PATTERN.findall(cve['report'])
                if tactics:
                    template["tactics"] = list(set(tactics))
            
            templates["sentinel_alerts"].append(template)
        except Exception as e:
            logger.error(f"Error generating template for {cve['cve_id']}: {e}")
    
    # Save templates to file
    if templates["sentinel_alerts"]:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f'{DATA_DIR}/sentinel_alert_templates_{timestamp}.json'
        with open(output_file, 'w') as f:
            json.dump(templates, f, indent=2)
        logger.info(f"Generated {len(templates['sentinel_alerts'])} alert templates in {output_file}")

# Main functions
def process_cve_batch(cves):
    """Process a batch of CVEs: save, analyze, and send to Sentinel"""
    for cve_raw in cves:
        try:
            # Extract CVE data
            cve_data = process_cve(cve_raw)
            if not cve_data:
                continue
                
            cve_id = cve_data['cve_id']
            
            # Skip if already processed
            if is_cve_processed(cve_id):
                logger.debug(f"Skipping already processed {cve_id}")
                continue
                
            logger.info(f"Processing new CVE: {cve_id}")
            
            # Save CVE data
            save_cve(cve_data)
            
            # Analyze with OpenAI
            analysis = analyze_cve_with_ai(cve_data)
            
            # Send to Sentinel if analysis was successful
            if analysis and SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY:
                send_to_sentinel(cve_id)
            
        except Exception as e:
            logger.error(f"Error processing CVE: {e}")

def poll_nvd():
    """Poll NVD for new CVEs"""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=1)  # Look back 1 hour
    
    try:
        # Fetch CVEs from NVD
        cves = fetch_cves(start_time, end_time)
        
        if cves:
            # Process CVEs
            process_cve_batch(cves)
        else:
            logger.info("No new CVEs found")
    except Exception as e:
        logger.error(f"Error polling NVD: {e}")

def main():
    """Main entry point"""
    logger.info("Starting SOCca container")
    
    # Initialize the database
    initialize_database()
    
    # Initial check: Generate alert templates once at startup
    generate_alert_templates()
    
    # Main polling loop
    try:
        poll_counter = 0
        while True:
            logger.info("Polling NVD for new CVEs")
            poll_nvd()
            
            # Generate alert templates every 6 hours (36 polls at 10-minute intervals)
            poll_counter += 1
            if poll_counter >= 36:
                generate_alert_templates()
                poll_counter = 0
            
            logger.info(f"Waiting {POLLING_INTERVAL} seconds before next poll")
            time.sleep(POLLING_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Shutting down SOCca")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()