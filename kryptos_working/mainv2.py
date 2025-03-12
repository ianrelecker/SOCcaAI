import sqlite3
import time
import json
from datetime import datetime, timedelta, timezone
import os
import logging
import sys
from contextlib import contextmanager
from typing import List, Dict, Any, Optional, Tuple

import nvdlib
import openai

import soccav5
import sentinel_exporter  # Import the sentinel exporter module for immediate sending
from config import (
    NVD_API_KEY, PROCESSED_CVES_DB, CVE_REPORTS_DB, POLLING_INTERVAL, 
    OPENAI_API_KEY, SENTINEL_WORKSPACE_ID, SENTINEL_PRIMARY_KEY
)

# Define a constant for the sentinel tracking table name
SENTINEL_TRACKING_TABLE = "sentinel_exports"

# Set up logging
log_file = os.path.join(os.path.dirname(__file__), 'logs', 'nvd_monitor.log')
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file)
    ]
)

logger = logging.getLogger('nvd_monitor')

# Initialize OpenAI API
openai.api_key = OPENAI_API_KEY

# Database connection manager
@contextmanager
def get_db_connection(db_path: str):
    """Context manager for database connections to ensure proper closing"""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        if conn:
            conn.close()

# Initialize database tables
def initialize_database():
    """Set up database tables and indexes"""
    with get_db_connection(PROCESSED_CVES_DB) as conn:
        cursor = conn.cursor()
        
        # Ensure the processed_cves table exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                url TEXT,
                pub TEXT,
                data TEXT,
                cata TEXT,
                processed_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create a table to track CVEs sent to Microsoft Sentinel
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {SENTINEL_TRACKING_TABLE} (
                cve_id TEXT PRIMARY KEY,
                sent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_date ON processed_cves(processed_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_pub ON processed_cves(pub)")
        cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_sent_date ON {SENTINEL_TRACKING_TABLE}(sent_date)")
        
        conn.commit()
        logger.info("Database tables and indexes initialized")

# Initialize database on startup
initialize_database()

# Function to check if a CVE has already been processed
def is_cve_processed(cve_id: str) -> bool:
    """Check if a CVE has already been processed"""
    with get_db_connection(PROCESSED_CVES_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM processed_cves WHERE cve_id = ?", (cve_id,))
        return cursor.fetchone() is not None

# Function to mark a CVE as processed
def mark_cve_as_processed(cve_id: str, description: str, url: str, pub: str, data: str, cata: str) -> None:
    """Insert a new CVE into the processed_cves table"""
    with get_db_connection(PROCESSED_CVES_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("""
                INSERT INTO processed_cves (cve_id, description, url, pub, data, cata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (cve_id, description, url, pub, data, cata))
        conn.commit()

# Function to check if a CVE has already been sent to Sentinel
def is_cve_sent_to_sentinel(cve_id: str) -> bool:
    """Check if a CVE has already been sent to Microsoft Sentinel"""
    with get_db_connection(PROCESSED_CVES_DB) as conn:
        cursor = conn.cursor()
        cursor.execute(f"SELECT 1 FROM {SENTINEL_TRACKING_TABLE} WHERE cve_id = ?", (cve_id,))
        return cursor.fetchone() is not None

# Function to mark a CVE as sent to Sentinel
def mark_cve_sent_to_sentinel(cve_id: str) -> None:
    """Mark a CVE as sent to Microsoft Sentinel"""
    with get_db_connection(PROCESSED_CVES_DB) as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
                INSERT OR REPLACE INTO {SENTINEL_TRACKING_TABLE} (cve_id, sent_date)
                VALUES (?, CURRENT_TIMESTAMP)
            """, (cve_id,))
        conn.commit()

# Function to batch mark multiple CVEs as sent
def mark_cves_batch_sent_to_sentinel(cve_ids: List[str]) -> None:
    """Mark multiple CVEs as sent to Microsoft Sentinel in a single transaction"""
    if not cve_ids:
        return
        
    with get_db_connection(PROCESSED_CVES_DB) as conn:
        cursor = conn.cursor()
        timestamp = datetime.now(timezone.utc).isoformat()
        values = [(cve_id, timestamp) for cve_id in cve_ids]
        cursor.executemany(f"""
                INSERT OR REPLACE INTO {SENTINEL_TRACKING_TABLE} (cve_id, sent_date)
                VALUES (?, ?)
            """, values)
        conn.commit()
        logger.debug(f"Marked {len(cve_ids)} CVEs as sent to Sentinel")

# Polling function to fetch and process new vulnerabilities
begin_poll_time = datetime.now(timezone.utc) - timedelta(days=1)


def fetch_nvd_data(start_time, end_time, max_retries=3):
    """Fetch CVE data from NVD with retry logic"""
    logger.info(f"Polling NVD API for new CVEs from {start_time} to {end_time}")
    
    for attempt in range(max_retries):
        try:
            cves = nvdlib.searchCVE(
                pubStartDate=start_time, 
                pubEndDate=end_time, 
                key=NVD_API_KEY,
                delay=1.0  # Rate limiting
            )
            logger.info(f"Found {len(cves)} CVEs")
            return cves
        except Exception as e:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(f"API error, retrying in {wait_time}s: {str(e)}")
                time.sleep(wait_time)
            else:
                logger.error(f"API error after {max_retries} attempts: {str(e)}")
                return []

def get_cve_report(cve_id):
    """Get the AI-generated report for a CVE"""
    with get_db_connection(CVE_REPORTS_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT report FROM processed WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        return row['report'] if row else None

def parse_cvss_data(cvssdata):
    """Safely parse CVSS data from string representation"""
    try:
        # Use json.loads instead of eval for safety
        # First replace single quotes with double quotes
        cvssdata_json = cvssdata.replace("'", '"')
        return json.loads(cvssdata_json)
    except json.JSONDecodeError:
        # Fallback to ast.literal_eval which is safer than eval
        import ast
        try:
            return ast.literal_eval(cvssdata)
        except (SyntaxError, ValueError):
            logger.error(f"Failed to parse CVSS data: {cvssdata[:100]}...")
            return {}

def process_cve_batch(cves, batch_size=10):
    """Process CVEs in batches for efficiency"""
    global begin_poll_time
    end_poll_time = datetime.now(timezone.utc)
    
    processed_count = 0
    sent_to_sentinel_count = 0
    cves_to_send = []
    
    for cve in cves:
        if not is_cve_processed(cve.id):
            logger.info(f"New CVE found: {cve.id}")
            desc = cve.descriptions[0].value
            
            # Extract reference URLs
            page_list = []
            try:
                page_list = [page.url for page in cve.references]
            except Exception as e:
                logger.error(f"Failed to process URLs in NVD data: {str(e)}")

            pub = cve.published
            
            # Get CVE metadata
            cata = ""
            try:
                cata = str(cve.cve)
            except Exception as e:
                logger.debug(f"No CVE metadata available: {str(e)}")
                
            cvssdata = str(cve.metrics)
            
            # Store in database
            mark_cve_as_processed(cve.id, desc, str(page_list), pub, cvssdata, cata)
            processed_count += 1
            
            # Process with AI
            soccav5.chat(cve.id, desc, str(page_list), pub, cvssdata, cata)
            
            # If Sentinel integration is enabled
            if SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY:
                # Get report
                report = get_cve_report(cve.id)
                
                if report:
                    # Prepare CVE record with report data for Sentinel
                    cve_record = {
                        'cve_id': cve.id,
                        'description': desc,
                        'pub': pub,
                        'data': cvssdata,
                        'report': report
                    }
                    
                    # Get CVSS score and severity
                    cvss_data = parse_cvss_data(cvssdata)
                    if cvss_data and 'cvssMetricV31' in cvss_data and cvss_data['cvssMetricV31']:
                        cvss_score = cvss_data['cvssMetricV31'][0]['cvssData']['baseScore']
                        severity = sentinel_exporter.get_severity_from_cvss(cvss_score)
                        cve_record['cvss_score'] = cvss_score
                        cve_record['severity'] = severity
                    
                    # Add to batch for sending
                    cves_to_send.append(cve_record)
                    
                    # Send immediately for real-time processing
                    # The single CVE is sent immediately while still allowing for batching with other CVEs if they exist
                    logger.info(f"Sending {cve.id} immediately to Microsoft Sentinel (real-time integration)...")
                    start_time = time.time()
                    success, errors = sentinel_exporter.send_to_sentinel([cve_record])
                    elapsed = time.time() - start_time
                    
                    if success:
                        mark_cve_sent_to_sentinel(cve.id)
                        sent_to_sentinel_count += 1
                        logger.info(f"✓ Successfully sent {cve.id} to Microsoft Sentinel in {elapsed:.2f}s")
                        
                        # Verify the CVE is marked as sent in the database
                        if is_cve_sent_to_sentinel(cve.id):
                            logger.info(f"✓ Verified {cve.id} is correctly marked as sent in the database")
                        else:
                            logger.warning(f"⚠ {cve.id} was sent but not properly marked in the database - fixing...")
                            mark_cve_sent_to_sentinel(cve.id)
                    else:
                        logger.error(f"✗ Failed to send {cve.id} to Microsoft Sentinel: {errors} errors")
                        
                    # Also add to batch for efficiency if processing multiple CVEs
                    # This allows both immediate sending and batch optimization
                    if len(cves_to_send) >= batch_size:
                        # Remove the CVE we just sent to avoid duplication
                        cves_to_send = [record for record in cves_to_send if record['cve_id'] != cve.id]
                        
                        if cves_to_send:  # Only process if there are other CVEs to send
                            logger.info(f"Sending batch of {len(cves_to_send)} additional CVEs to Microsoft Sentinel...")
                            success, errors = sentinel_exporter.send_to_sentinel(cves_to_send)
                            if success:
                                sent_ids = [record['cve_id'] for record in cves_to_send]
                                mark_cves_batch_sent_to_sentinel(sent_ids)
                                sent_to_sentinel_count += len(cves_to_send)
                                logger.info(f"Successfully sent batch of {len(cves_to_send)} additional CVEs to Microsoft Sentinel")
                            else:
                                logger.error(f"Failed to send batch of {len(cves_to_send)} additional CVEs to Microsoft Sentinel: {errors} errors")
                        
                        cves_to_send = []
                else:
                    logger.warning(f"No report found for {cve.id}, cannot send to Sentinel yet")
    
    # Send any remaining CVEs
    if cves_to_send:
        # Check for any CVEs that haven't been sent yet
        with get_db_connection(PROCESSED_CVES_DB) as conn:
            cursor = conn.cursor()
            # Get list of CVEs that haven't been sent
            unsent_cve_ids = []
            for record in cves_to_send:
                cve_id = record['cve_id']
                cursor.execute(f"SELECT 1 FROM {SENTINEL_TRACKING_TABLE} WHERE cve_id = ?", (cve_id,))
                if cursor.fetchone() is None:  # Not yet sent
                    unsent_cve_ids.append(cve_id)
        
        # Only send CVEs that haven't been sent yet
        unsent_cves = [record for record in cves_to_send if record['cve_id'] in unsent_cve_ids]
        if unsent_cves:
            logger.info(f"Sending remaining {len(unsent_cves)} unsent CVEs to Microsoft Sentinel...")
            success, errors = sentinel_exporter.send_to_sentinel(unsent_cves)
            if success:
                sent_ids = [record['cve_id'] for record in unsent_cves]
                mark_cves_batch_sent_to_sentinel(sent_ids)
                sent_to_sentinel_count += len(unsent_cves)
                logger.info(f"Successfully sent remaining {len(unsent_cves)} CVEs to Microsoft Sentinel")
            else:
                logger.error(f"Failed to send remaining {len(unsent_cves)} CVEs to Microsoft Sentinel: {errors} errors")
    
    # Update poll time for next run
    begin_poll_time = end_poll_time
    
    return processed_count, sent_to_sentinel_count

def poll_nvd():
    """Poll NVD for new CVEs and process them"""
    global begin_poll_time
    end_poll_time = datetime.now(timezone.utc)
    
    # Fetch data from NVD API
    cves = fetch_nvd_data(begin_poll_time, end_poll_time)
    if not cves:
        return False
    
    # Process CVEs in efficient batches
    processed_count, sent_count = process_cve_batch(cves)
    
    if processed_count > 0:
        logger.info(f"Processed {processed_count} new CVEs, sent {sent_count} to Sentinel")
    else:
        logger.info("No new CVEs to process")
    
    return True

def initialize_reports_database():
    """Initialize the reports database and create necessary tables"""
    with get_db_connection(CVE_REPORTS_DB) as conn:
        cursor = conn.cursor()
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
        logger.info("Reports database initialized")

def main():
    """Main function to run the NVD polling process."""
    logger.info("Starting SOCca NVD monitor")
    
    # Validate API key
    if not NVD_API_KEY:
        logger.warning("NVD API key not set. Rate limiting will apply.")
    
    # Initialize reports table
    try:
        initialize_reports_database()
    except Exception as e:
        logger.error(f"Error initializing reports database: {str(e)}")
        return
    
    # Poll continuously
    try:
        # Do an initial poll immediately
        poll_nvd()
        
        # Then continue with regular polling
        while True:
            logger.info(f"Waiting {POLLING_INTERVAL} seconds before next poll")
            time.sleep(POLLING_INTERVAL)
            logger.info("Starting CVE search")
            poll_nvd()
    except KeyboardInterrupt:
        logger.info("Search stopped by user.")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())


if __name__ == "__main__":
    main()