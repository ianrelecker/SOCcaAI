import sqlite3
import os
import json
import logging
import time
from typing import List, Dict, Any, Optional
from contextlib import contextmanager

import openai

# Import our custom modules
from token_counter import truncate_to_token_limit
from url_processor import get_content_summary

from config import (
    OPENAI_API_KEY, OPENAI_ANALYSIS_MODEL, CVE_REPORTS_DB
)

# Set up logging
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)

logger = logging.getLogger('soccav5')

# Initialize OpenAI API
openai.api_key = OPENAI_API_KEY

# Database connection context manager
@contextmanager
def get_db_connection():
    """Context manager for database connections to ensure proper closing"""
    conn = None
    try:
        conn = sqlite3.connect(CVE_REPORTS_DB)
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()

# Initialize database tables
def initialize_database():
    """Set up database tables and indexes for performance"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Create processed table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed (
                cve_id TEXT PRIMARY KEY,
                report TEXT,
                processed_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create index for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_date ON processed(processed_date)")
        
        conn.commit()
        logger.debug("Database tables and indexes initialized")

# Initialize database on module import
initialize_database()


# Define system prompt just once
SYSTEM_PROMPT = """You are a cybersecurity expert and developer specializing in vulnerability assessment and secure development practices. Your task is to produce a Microsoft Sentinel-ready, structured report with clear machine-parsable sections specifically designed for integration with Microsoft Sentinel. Follow this JSON-like structure exactly:

{
  "cve_id": "[CVE ID]",
  "summary": "[1-2 sentence overview]",
  "affected": {
    "products": ["[product1]", "[product2]"],
    "vendors": ["[vendor1]", "[vendor2]"],
    "versions": ["[version_info]"]
  },
  "vulnerability": {
    "type": "[vulnerability class/category]",
    "technical_details": "[detailed explanation]",
    "root_cause": "[underlying weakness/cause]"
  },
  "severity": {
    "cvss_score": "[CVSS score]",
    "cvss_vector": "[CVSS vector string]",
    "risk_rating": "[Critical/High/Medium/Low]",
    "impact_rationale": "[explanation of impact]",
    "exploitability_ease": "[Easy/Moderate/Difficult]"
  },
  "attack_vector": {
    "prerequisites": ["[prerequisite1]", "[prerequisite2]"],
    "attack_complexity": "[Low/Medium/High]",
    "privileges_required": "[None/Low/High]",
    "user_interaction": "[Required/None]",
    "potential_impact": ["[impact1]", "[impact2]"]
  },
  "detection": {
    "ioc": ["[indicator1]", "[indicator2]"],
    "detection_rules": [
      {
        "type": "Microsoft Sentinel KQL",
        "rule": "[actual KQL query syntax]",
        "description": "[what this rule detects]"
      }
    ],
    "log_sources": ["[log source1]", "[log source2]"]
  },
  "mitre_att_ck": {
    "tactics": ["[tactic1]", "[tactic2]"],
    "techniques": ["[technique1]", "[technique2]"],
    "subtechniques": ["[subtechnique1]", "[subtechnique2]"]
  },
  "remediation": {
    "immediate_actions": ["[action1]", "[action2]"],
    "permanent_fixes": ["[fix1]", "[fix2]"],
    "compensating_controls": ["[control1]", "[control2]"]
  },
  "references": ["[url1]", "[url2]"]
}

Ensure that:
1. Each field contains detailed, accurate information - no placeholders
2. Detection rules use Microsoft Sentinel's KQL (Kusto Query Language)
3. IOCs are specific and usable (file hashes, IP addresses, domains, registry keys)
4. MITRE ATT&CK references use current framework IDs
5. All JSON keys and structure are preserved exactly as shown"""

# Context for Sentinel integration - defined once as a constant
SENTINEL_CONTEXT = """Additional Context (not to be included in the report): You are supported by SOCca, a Microsoft Sentinel integration platform that processes vulnerability data for security operations centers. Your outputs must be structured for automated parsing and ingestion by Microsoft Sentinel. Keep these key Microsoft Sentinel integration requirements in mind: 1) Focus on machine-readable formats while maintaining human readability, 2) Include specific detection rules in KQL (Kusto Query Language), 3) Provide concrete, actionable IOCs that can be implemented in Sentinel analytics rules, 4) Ensure field standardization for Sentinel Log Analytics. The JSON structure is critical as it will be parsed by the sentinel_exporter.py with minimal transformation."""

# The urllogic function has been replaced by url_processor.py
# We'll keep a simple function here for backwards compatibility
def urllogic(url_list: str) -> List[str]:
    """
    Process a list of URLs and extract the main content from each webpage.
    This is a legacy function that uses the new url_processor module.
    
    Args:
        url_list: String representation of a Python list of URLs
        
    Returns:
        List of content strings extracted from each URL
    """
    # Use the new get_content_summary function which returns a formatted string
    content_summary = get_content_summary(url_list)
    
    # Return as a list with a single item for backwards compatibility
    return [content_summary]


def selectcve(cve_id: str) -> List[Dict[str, Any]]:
    """
    Query the database for a specific CVE.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
        
    Returns:
        List of dicts containing CVE records
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM processed WHERE cve_id = ?", (cve_id,))
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error(f"Database error in selectcve: {e}")
        return []


def get_report(cve_id: str) -> Optional[str]:
    """
    Get the AI-generated report for a CVE
    
    Args:
        cve_id: CVE identifier
        
    Returns:
        The report text if found, None otherwise
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT report FROM processed WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            return row['report'] if row else None
    except sqlite3.Error as e:
        logger.error(f"Error getting report for {cve_id}: {e}")
        return None


def call_openai_with_retry(model: str, system_content: str, user_content: str, 
                          max_retries: int = 3) -> Optional[str]:
    """
    Call OpenAI API with retry logic for transient errors
    
    Args:
        model: The OpenAI model to use
        system_content: System prompt content
        user_content: User prompt content
        max_retries: Maximum number of retries
        
    Returns:
        Generated text if successful, None otherwise
    """
    for attempt in range(max_retries):
        try:
            start_time = time.time()
            response = openai.ChatCompletion.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": user_content}
                ]
            )
            elapsed = time.time() - start_time
            logger.info(f"OpenAI API call completed in {elapsed:.2f} seconds")
            
            return response['choices'][0]['message']['content']
        except (openai.error.APIError, openai.error.ServiceUnavailableError, 
                openai.error.Timeout, openai.error.RateLimitError) as e:
            wait_time = (2 ** attempt) + 1  # Exponential backoff
            if attempt < max_retries - 1:
                logger.warning(f"OpenAI API error (attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                logger.error(f"OpenAI API error after {max_retries} attempts: {e}")
                return None
        except Exception as e:
            logger.error(f"Unexpected error calling OpenAI API: {e}")
            return None


def chat(cve_id: str, desc: str, page_list: str, pub: str, cvssdata: str, cata: str) -> None:
    """
    Process a CVE by sending it to the OpenAI API for analysis.
    
    Args:
        cve_id: CVE identifier
        desc: CVE description
        page_list: String representation of a list of reference URLs
        pub: Publication date
        cvssdata: CVSS vulnerability scoring data
        cata: Category data
    """
    # Start timing for performance monitoring
    start_time = time.time()
    
    # Check if we already processed this CVE
    existing_report = get_report(cve_id)
    if existing_report:
        logger.info(f"Report already exists for {cve_id}, skipping processing")
        return
    
    # Extract content from URLs using the improved processor
    # This will prioritize the most relevant URLs, process them in parallel, and cache the results
    logger.info(f"Extracting URL content for {cve_id}")
    url_content = get_content_summary(page_list)
    
    # Prepare user prompt with all information
    user_prompt = (
        f"Here is the new vulnerability information.\n"
        f"CVE ID: {cve_id}\n"
        f"Description: {desc}\n"
        f"CVSS Data: {cvssdata}\n\n"
        f"References covering this vulnerability:\n{url_content}\n\n"
        f"{SENTINEL_CONTEXT}"
    )
    
    # Limit token count to avoid exceeding API limits
    target_token_limit = 16000  # Adjust based on model capabilities
    user_prompt = truncate_to_token_limit(user_prompt, target_token_limit)
    logger.info(f"Prepared prompt for {cve_id} within token limits")

    # Send to OpenAI for analysis
    logger.info(f"Sending {cve_id} to OpenAI for analysis")
    gpt_report = call_openai_with_retry(
        model=OPENAI_ANALYSIS_MODEL,
        system_content=SYSTEM_PROMPT,
        user_content=user_prompt
    )
    
    if gpt_report:
        # Add version info to report
        gpt_report = gpt_report + "\n\nSocca Version 5.0"
        
        # Save the generated report
        savereport(cve_id, gpt_report)
        
        # Log performance metrics
        elapsed = time.time() - start_time
        logger.info(f"Successfully processed {cve_id} in {elapsed:.2f} seconds")
    else:
        logger.error(f"Failed to generate report for {cve_id}")


def savereport(cve_id: str, report: str) -> bool:
    """
    Save a generated report to the database.
    
    Args:
        cve_id: CVE identifier
        report: Generated vulnerability report text
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Insert or replace the report
            cursor.execute("""
                INSERT OR REPLACE INTO processed (cve_id, report)
                VALUES (?, ?)
            """, (cve_id, report))
            conn.commit()
            
        logger.info(f"Report saved for {cve_id}")
        return True
    except sqlite3.Error as e:
        logger.error(f"Database error in savereport: {e}")
        return False