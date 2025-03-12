#!/usr/bin/env python3
"""
SOCca Microsoft Sentinel Exporter

A utility for exporting CVE data to Microsoft Sentinel via Log Analytics API.
Also supports file-based export for manual import into Sentinel.
"""

import argparse
import datetime
import json
import logging
import os
import sqlite3
import sys
import time
import re
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to import path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from dotenv import load_dotenv
    load_dotenv()  # Load environment variables from .env file
except ImportError:
    pass  # dotenv is optional

import requests

from kryptos_working.config import (
    PROCESSED_CVES_DB, CVE_REPORTS_DB, 
    CVSS_CRITICAL_THRESHOLD, SITE_URL
)

# Configure logging
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'sentinel_exporter.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file)
    ]
)

logger = logging.getLogger('sentinel_exporter')

# Output directory for file exports
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'data', 'sentinel_output')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Microsoft Sentinel / Azure Log Analytics configuration
SENTINEL_WORKSPACE_ID = os.environ.get('SENTINEL_WORKSPACE_ID')
SENTINEL_PRIMARY_KEY = os.environ.get('SENTINEL_PRIMARY_KEY')
SENTINEL_LOG_TYPE = os.environ.get('SENTINEL_LOG_TYPE', 'SOCcaCVE')
SENTINEL_API_VERSION = os.environ.get('SENTINEL_API_VERSION', '2016-04-01')

# Precompile regular expressions for performance
MITRE_ATTACK_PATTERN = re.compile(r'T\d{4}')


@contextmanager
def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Context manager for database connections to ensure proper closing"""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        yield conn
    finally:
        if conn:
            conn.close()


def parse_cvss_data(cvss_str: str) -> dict:
    """Safely parse CVSS data from string representation"""
    try:
        # Use json.loads instead of eval for safety
        # First replace single quotes with double quotes
        cvss_json = cvss_str.replace("'", '"')
        return json.loads(cvss_json)
    except json.JSONDecodeError:
        # Fallback to ast.literal_eval which is safer than eval
        import ast
        try:
            return ast.literal_eval(cvss_str)
        except (SyntaxError, ValueError):
            logger.error(f"Failed to parse CVSS data: {cvss_str[:100]}...")
            return {}

def get_recent_cves(hours: int = 24, min_cvss: Optional[float] = None) -> List[Dict[str, Any]]:
    """Get CVEs from the last X hours, optionally filtered by minimum CVSS score and unsent status"""
    try:
        # Calculate the timestamp for X hours ago
        time_ago = (datetime.datetime.now() - datetime.timedelta(hours=hours)).isoformat()
        
        # Get unsent CVEs in a single efficient query
        with get_db_connection(PROCESSED_CVES_DB) as conn:
            cursor = conn.cursor()
            
            # Check if the sentinel_exports table exists - do this once per run
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sentinel_exports'")
            sentinel_table_exists = cursor.fetchone() is not None
            
            # Build the query - exclude CVEs already sent to Sentinel if tracking table exists
            if sentinel_table_exists:
                query = """
                    SELECT pc.cve_id, pc.description, pc.pub, pc.data 
                    FROM processed_cves pc
                    WHERE pc.pub >= ?
                    AND NOT EXISTS (
                        SELECT 1 FROM sentinel_exports se 
                        WHERE se.cve_id = pc.cve_id
                    )
                """
                logger.info("Using sentinel tracking table to filter already sent CVEs")
            else:
                query = "SELECT cve_id, description, pub, data FROM processed_cves WHERE pub >= ?"
                logger.warning("Sentinel tracking table not found - may result in duplicate sends")
                
            params = [time_ago]
            
            # Execute query
            results = cursor.execute(query, params).fetchall()
            logger.info(f"Found {len(results)} unsent CVEs from the last {hours} hours")
            
            # If no results, return early
            if not results:
                return []
            
            # Extract CVE IDs to fetch reports in a single query
            cve_ids = [row['cve_id'] for row in results]
        
        # Fetch all reports in a single query
        reports = {}
        with get_db_connection(CVE_REPORTS_DB) as reports_conn:
            # Use parameterized query with placeholders
            placeholders = ','.join(['?'] * len(cve_ids))
            report_query = f"SELECT cve_id, report FROM processed WHERE cve_id IN ({placeholders})"
            for row in reports_conn.execute(report_query, cve_ids).fetchall():
                reports[row['cve_id']] = row['report']
        
        # Process results with cached reports
        cves = []
        for row in results:
            cve = dict(row)
            
            # Skip if no report available
            if cve['cve_id'] not in reports:
                logger.debug(f"No report found for {cve['cve_id']}, skipping")
                continue
            
            # Add report to CVE data
            cve['report'] = reports[cve['cve_id']]
            
            # Parse CVSS data efficiently
            try:
                cvss_data = parse_cvss_data(cve.get('data', '{}'))
                
                # Extract base score
                if 'cvssMetricV31' in cvss_data and cvss_data['cvssMetricV31']:
                    cvss_score = cvss_data['cvssMetricV31'][0]['cvssData']['baseScore']
                    severity = get_severity_from_cvss(cvss_score)
                    
                    # Filter by minimum CVSS if specified
                    if min_cvss is not None and cvss_score < min_cvss:
                        continue
                        
                    cve['cvss_score'] = cvss_score
                    cve['severity'] = severity
                    cves.append(cve)
            except (KeyError, TypeError) as e:
                # Skip CVEs with invalid CVSS data
                logger.debug(f"Skipping CVE {cve.get('cve_id', 'unknown')} due to CVSS error: {e}")
        
        return cves
    except Exception as e:
        logger.error(f"Error fetching recent CVEs: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return []


def get_severity_from_cvss(score: float) -> str:
    """Convert CVSS score to severity string"""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"


def extract_affected_components(cvss_data: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Extract affected products and vendors from CVSS data"""
    affected_products = []
    affected_vendors = []
    
    try:
        # Extract CPE info
        if 'configurations' in cvss_data and cvss_data['configurations']:
            for config in cvss_data['configurations'].get('nodes', []):
                for cpe_match in config.get('cpeMatch', []):
                    cpe = cpe_match.get('criteria', '')
                    if cpe:
                        parts = cpe.split(':')
                        if len(parts) > 4:
                            vendor = parts[3]
                            product = parts[4]
                            if vendor and vendor not in affected_vendors:
                                affected_vendors.append(vendor)
                            if product and product not in affected_products:
                                affected_products.append(product)
    except Exception as e:
        logger.debug(f"Error extracting components from CVSS data: {e}")
        
    return affected_products, affected_vendors

def extract_mitre_tactics(report: str) -> List[str]:
    """Extract MITRE ATT&CK tactics from report using pre-compiled regex"""
    if not report:
        return []
        
    # Use the pre-compiled regex pattern defined at module level
    tactics = set(MITRE_ATTACK_PATTERN.findall(report))
    return list(tactics)

def prepare_cve_for_sentinel(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare a CVE record for export to Microsoft Sentinel"""
    # Create base log with required fields
    sentinel_log = {
        "TimeGenerated": datetime.datetime.now().isoformat(),
        "CVE_ID": cve.get('cve_id', ''),
        "Description": cve.get('description', ''),
        "PublishedDate": cve.get('pub', ''),
        "CVSS_Score": cve.get('cvss_score', 0.0),
        "Severity": cve.get('severity', 'Unknown'),
        "ReferenceURL": f"https://nvd.nist.gov/vuln/detail/{cve.get('cve_id', '')}"
    }
    
    # Get report content if available
    report = cve.get('report', '')
    if report:
        sentinel_log['ReportHighlights'] = report[:1000]  # Limit to 1000 chars for Sentinel
        
        # Extract MITRE ATT&CK tactics
        tactics = extract_mitre_tactics(report)
        if tactics:
            sentinel_log['MitreAttackTactics'] = ','.join(tactics)
    
    # Parse CVSS data once
    try:
        cvss_data = parse_cvss_data(cve.get('data', '{}'))
        
        # Extract affected products and vendors
        affected_products, affected_vendors = extract_affected_components(cvss_data)
        
        if affected_products:
            sentinel_log['AffectedProducts'] = ','.join(affected_products)
        if affected_vendors:
            sentinel_log['AffectedVendors'] = ','.join(affected_vendors)
            
    except Exception as e:
        logger.debug(f"Error parsing CVSS data for {cve.get('cve_id', '')}: {e}")
    
    return sentinel_log


def export_to_sentinel_file(cves: List[Dict[str, Any]], output_format: str = 'json') -> str:
    """Export CVEs to a file for Microsoft Sentinel"""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(OUTPUT_DIR, f"sentinel_cves_{timestamp}.{output_format}")
    
    sentinel_logs = [prepare_cve_for_sentinel(cve) for cve in cves]
    
    with open(output_file, 'w') as f:
        if output_format == 'json':
            json.dump(sentinel_logs, f, indent=2)
        elif output_format == 'ndjson':
            # New-line delimited JSON (better for Azure Log Analytics Data Collector)
            for log in sentinel_logs:
                f.write(json.dumps(log) + '\n')
    
    logger.info(f"Exported {len(sentinel_logs)} logs to {output_file}")
    return output_file


def generate_sentinel_alert_template(cves: List[Dict[str, Any]]) -> str:
    """Generate Microsoft Sentinel alert templates based on CVE data"""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(OUTPUT_DIR, f"sentinel_alert_templates_{timestamp}.json")
    
    alert_templates = {
        "sentinel": []
    }
    
    for cve in cves:
        if 'severity' not in cve or 'cvss_score' not in cve:
            continue
            
        cve_id = cve.get('cve_id', '')
        severity = cve.get('severity', 'Unknown').lower()
        
        # Generate a simple detection rule template
        query = f"SOCcaCVE_CL | where CVE_ID_s == \"{cve_id}\""
        
        if 'report' in cve and cve['report']:
            # Try to extract better query components from the report
            report = cve['report']
            
            # Extract potential indicators
            indicators = []
            
            if "affected_products" in cve:
                for product in cve.get("affected_products", []):
                    query += f"\n| where AffectedProducts_s contains \"{product}\""
                    break  # Add just the first product to avoid over-filtering
        
        alert_template = {
            "cve_id": cve_id,
            "rule_name": f"SOCca - Detection for {cve_id}",
            "query": query,
            "description": f"Detects {cve.get('severity', 'Unknown')} severity vulnerability {cve_id}",
            "severity": severity,
            "tactics": ["InitialAccess", "Execution"],  # Default tactics
            "threshold": 0,  # Alert on any occurrence
            "query_frequency": "1h",
            "query_period": "1d"
        }
        
        alert_templates["sentinel"].append(alert_template)
    
    with open(output_file, 'w') as f:
        json.dump(alert_templates, f, indent=2)
    
    logger.info(f"Generated {len(alert_templates['sentinel'])} Sentinel alert templates in {output_file}")
    return output_file


def build_sentinel_signature(workspace_id: str, date: str, content_length: int, primary_key: str) -> str:
    """Build the signature for Microsoft Sentinel Log Analytics API"""
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


def mark_cves_sent_to_sentinel(cve_ids: List[str]) -> bool:
    """Mark multiple CVEs as sent to Sentinel in a batch"""
    if not cve_ids:
        return True
        
    try:
        with get_db_connection(PROCESSED_CVES_DB) as conn:
            cursor = conn.cursor()
            
            # Ensure the sentinel_exports table exists (once per run)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sentinel_exports (
                    cve_id TEXT PRIMARY KEY,
                    sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create index if it doesn't exist
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sent_date ON sentinel_exports(sent_date)")
            
            # Batch insert with parameterized query
            timestamp = datetime.datetime.now().isoformat()
            values = [(cve_id, timestamp) for cve_id in cve_ids]
            cursor.executemany("""
                INSERT OR REPLACE INTO sentinel_exports (cve_id, sent_date)
                VALUES (?, ?)
            """, values)
            conn.commit()
            
            logger.debug(f"Marked {len(cve_ids)} CVEs as sent to Sentinel")
            return True
    except Exception as e:
        logger.error(f"Error marking CVEs as sent: {e}")
        return False

def send_batch_with_retry(api_url: str, batch: List[Dict[str, Any]], 
                          batch_num: int, total_batches: int, 
                          max_retries: int = 3) -> Tuple[bool, List[str]]:
    """Send a batch of CVEs to Sentinel with retry logic"""
    # Format logs for Log Analytics
    sentinel_logs = [prepare_cve_for_sentinel(cve) for cve in batch]
    
    # Get CVE IDs for tracking
    cve_ids = [cve['cve_id'] for cve in batch]
    
    # Create session for connection pooling
    session = requests.Session()
    
    for attempt in range(max_retries):
        try:
            # Create the signature for this attempt
            rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            body = json.dumps(sentinel_logs)
            content_length = len(body)
            signature = build_sentinel_signature(SENTINEL_WORKSPACE_ID, rfc1123date, content_length, SENTINEL_PRIMARY_KEY)
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': signature,
                'Log-Type': SENTINEL_LOG_TYPE,
                'x-ms-date': rfc1123date
            }
            
            # Send request with timeout
            response = session.post(
                api_url,
                data=body,
                headers=headers,
                timeout=30
            )
            
            if response.status_code in (200, 204):
                # Success - mark CVEs as sent
                if mark_cves_sent_to_sentinel(cve_ids):
                    logger.info(f"Successfully sent batch {batch_num}/{total_batches} with {len(batch)} logs to Microsoft Sentinel")
                    return True, cve_ids
                else:
                    logger.warning(f"Sent batch {batch_num}/{total_batches} to Sentinel but failed to mark as sent in database")
                    return True, cve_ids
            
            # Handle different errors
            elif response.status_code == 429:  # Rate limit
                wait_time = 2 ** attempt + 1  # Exponential backoff with jitter
                logger.warning(f"Rate limited (429) on batch {batch_num}/{total_batches}, retry {attempt+1}/{max_retries} in {wait_time}s")
                time.sleep(wait_time)
            elif response.status_code >= 500:  # Server error, retry
                wait_time = 2 ** attempt + 2  # Exponential backoff with jitter
                logger.warning(f"Server error ({response.status_code}) on batch {batch_num}/{total_batches}, retry {attempt+1}/{max_retries} in {wait_time}s")
                time.sleep(wait_time)
            else:  # Client error, don't retry
                logger.error(f"Client error ({response.status_code}) on batch {batch_num}/{total_batches}: {response.text}")
                return False, []
                
        except requests.exceptions.Timeout:
            wait_time = 2 ** attempt + 3
            logger.warning(f"Timeout on batch {batch_num}/{total_batches}, retry {attempt+1}/{max_retries} in {wait_time}s")
            time.sleep(wait_time)
        except Exception as e:
            logger.error(f"Exception on batch {batch_num}/{total_batches}: {str(e)}")
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt + 4
                logger.warning(f"Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                return False, []
    
    logger.error(f"Failed to send batch {batch_num}/{total_batches} after {max_retries} attempts")
    return False, []

def send_to_sentinel(cves: List[Dict[str, Any]], batch_size: int = 30) -> Tuple[int, int]:
    """Send CVEs directly to Microsoft Sentinel via Log Analytics Data Collector API"""
    if not SENTINEL_WORKSPACE_ID or not SENTINEL_PRIMARY_KEY:
        logger.error("Microsoft Sentinel Workspace ID or Primary Key not configured")
        return 0, 0
    
    if not cves:
        logger.info("No CVEs to send to Microsoft Sentinel")
        return 0, 0
    
    success_count = 0
    error_count = 0
    total_batches = (len(cves) + batch_size - 1) // batch_size  # Ceiling division
    
    api_url = f"https://{SENTINEL_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version={SENTINEL_API_VERSION}"
    
    # Process batches in parallel for better performance
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all batches to thread pool
        futures = []
        for i in range(0, len(cves), batch_size):
            batch = cves[i:i+batch_size]
            batch_num = (i // batch_size) + 1
            futures.append(
                executor.submit(
                    send_batch_with_retry, 
                    api_url, 
                    batch, 
                    batch_num, 
                    total_batches
                )
            )
        
        # Process results as they complete
        for future in as_completed(futures):
            success, sent_cve_ids = future.result()
            if success:
                success_count += len(sent_cve_ids)
            else:
                error_count += batch_size  # Approximate since we don't know exact batch size
    
    return success_count, error_count


def initialize_databases():
    """Initialize database tables and indexes for performance"""
    # Initialize any necessary tables and indexes
    with get_db_connection(PROCESSED_CVES_DB) as conn:
        cursor = conn.cursor()
        
        # Create sentinel tracking table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sentinel_exports (
                cve_id TEXT PRIMARY KEY,
                sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_sent_date ON sentinel_exports(sent_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pub ON processed_cves(pub)")
        
        conn.commit()
        logger.debug("Database tables and indexes initialized")

def main() -> None:
    """Main entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="SOCca Microsoft Sentinel Exporter")
    parser.add_argument("--hours", type=int, default=24,
                      help="Number of hours to look back for CVEs (default: 24)")
    parser.add_argument("--min-cvss", type=float, default=None,
                      help="Minimum CVSS score to include (default: none)")
    parser.add_argument("--direct-send", action="store_true",
                      help="Send directly to Microsoft Sentinel via Log Analytics API")
    parser.add_argument("--file-export", action="store_true",
                      help="Export to files for manual import")
    parser.add_argument("--format", choices=["json", "ndjson"], default="json",
                      help="File export format (json or ndjson)")
    parser.add_argument("--alerts", action="store_true",
                      help="Generate Sentinel alert templates")
    parser.add_argument("--batch-size", type=int, default=30,
                      help="Batch size for sending to Sentinel (default: 30)")
    
    args = parser.parse_args()
    
    # If no action specified, default to direct send if credentials available
    if not args.direct_send and not args.file_export and not args.alerts:
        if SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY:
            args.direct_send = True
        else:
            args.file_export = True
    
    logger.info(f"Starting SOCca Microsoft Sentinel Exporter")
    logger.info(f"Configuration: hours={args.hours}, min_cvss={args.min_cvss}, batch_size={args.batch_size}")
    
    # Initialize database tables and indexes for performance
    try:
        initialize_databases()
    except Exception as e:
        logger.error(f"Error initializing databases: {e}")
    
    # Start timer for performance measurement
    start_time = time.time()
    
    # Get recent CVEs
    cves = get_recent_cves(args.hours, args.min_cvss)
    logger.info(f"Found {len(cves)} CVEs in the last {args.hours} hours" + 
                (f" with CVSS >= {args.min_cvss}" if args.min_cvss else ""))
    
    if not cves:
        logger.warning("No CVEs found, nothing to export")
        elapsed = time.time() - start_time
        logger.info(f"Completed in {elapsed:.2f} seconds")
        return
    
    # Perform requested actions with parallel execution where possible
    tasks = []
    
    # Run direct send and file export in parallel
    with ThreadPoolExecutor(max_workers=3) as executor:
        # Add direct send task
        if args.direct_send:
            if not SENTINEL_WORKSPACE_ID or not SENTINEL_PRIMARY_KEY:
                logger.error("Direct send requires SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY environment variables")
                logger.info("Please set these variables or use --file-export instead")
            else:
                logger.info("Sending directly to Microsoft Sentinel...")
                tasks.append(executor.submit(send_to_sentinel, cves, args.batch_size))
        
        # Add file export task
        if args.file_export:
            logger.info(f"Exporting to files for manual import (format: {args.format})...")
            tasks.append(executor.submit(export_to_sentinel_file, cves, args.format))
        
        # Add alert template generation task
        if args.alerts:
            logger.info("Generating Microsoft Sentinel alert templates...")
            tasks.append(executor.submit(generate_sentinel_alert_template, cves))
        
        # Process the results as they complete
        for i, future in enumerate(as_completed(tasks)):
            try:
                result = future.result()
                
                if i == 0 and args.direct_send:
                    success, errors = result
                    logger.info(f"Microsoft Sentinel: {success} records sent successfully, {errors} errors")
                elif (i == 1 and args.direct_send and args.file_export) or (i == 0 and not args.direct_send and args.file_export):
                    logger.info(f"File exported: {result}")
                elif (i == 2 and args.direct_send and args.file_export) or \
                     (i == 1 and ((args.direct_send and not args.file_export) or (not args.direct_send and args.file_export))) or \
                     (i == 0 and not args.direct_send and not args.file_export):
                    logger.info(f"Alert templates exported: {result}")
            except Exception as e:
                logger.error(f"Error in task: {e}")
    
    # Log performance metrics
    elapsed = time.time() - start_time
    logger.info(f"Microsoft Sentinel Exporter completed successfully in {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()