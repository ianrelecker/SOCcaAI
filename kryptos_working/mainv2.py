import sqlite3
import time
from datetime import datetime, timedelta, timezone
import os
import logging
import sys

import nvdlib
import openai

import soccav5
from config import (
    NVD_API_KEY, PROCESSED_CVES_DB, CVE_REPORTS_DB, POLLING_INTERVAL, 
    OPENAI_API_KEY
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('nvd_monitor.log')
    ]
)

logger = logging.getLogger('nvd_monitor')

# Initialize OpenAI API
openai.api_key = OPENAI_API_KEY

# Connect to database and ensure table exists
conn = sqlite3.connect(PROCESSED_CVES_DB)
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
conn.commit()


# Function to check if a CVE has already been processed
def is_cve_processed(cve_id):
    cursor.execute("SELECT 1 FROM processed_cves WHERE cve_id = ?", (cve_id,))
    return cursor.fetchone() is not None


# Function to mark a CVE as processed
def mark_cve_as_processed(cve_id, description, url, pub, data, cata):
    cursor.execute("""
            INSERT INTO processed_cves (cve_id, description, url, pub, data, cata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (cve_id, description, url, pub, data, cata))
    conn.commit()


# Polling function to fetch and process new vulnerabilities
begin_poll_time = datetime.now(timezone.utc) - timedelta(days=1)


def poll_nvd():
    global begin_poll_time
    try:
        logger.info(f"Polling NVD API for new CVEs since {begin_poll_time}")
        cves = nvdlib.searchCVE(
            pubStartDate=begin_poll_time, 
            pubEndDate=datetime.now(timezone.utc), 
            key=NVD_API_KEY
        )
        logger.info(f"Found {len(cves)} CVEs")
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return False
        
    # Process only unprocessed CVEs
    for cve in cves:
        if not is_cve_processed(cve.id):
            logger.info(f"New CVE found: {cve.id}")
            desc = cve.descriptions[0].value
            page_list = []
            try:
                for page in cve.references:
                    logger.debug(f"Reference URL: {page.url}")
                    page_list.append(page.url)
            except Exception as e:
                logger.error(f"Failed to process URLs in NVD data: {str(e)}")

            pub = cve.published
            cata = ""
            try:
                cata = str(cve.cve)
            except Exception as e:
                logger.debug(f"No CVE metadata available: {str(e)}")
                
            cvssdata = str(cve.metrics)
            
            # Store in database
            mark_cve_as_processed(cve.id, desc, str(page_list), pub, cvssdata, cata)
            
            # Process with AI
            soccav5.chat(cve.id, desc, str(page_list), pub, cvssdata, cata)


def main():
    """Main function to run the NVD polling process."""
    logger.info("Starting SOCca NVD monitor")
    
    # Validate API key
    if not NVD_API_KEY:
        logger.warning("NVD API key not set. Rate limiting will apply.")
    
    # Initialize reports table
    try:
        reports_conn = sqlite3.connect(CVE_REPORTS_DB)
        reports_cursor = reports_conn.cursor()
        reports_cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed (
                cve_id TEXT PRIMARY KEY,
                report TEXT,
                processed_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        reports_conn.commit()
        reports_conn.close()
        logger.info("Reports database initialized")
    except Exception as e:
        logger.error(f"Error initializing reports database: {str(e)}")
    
    # Poll continuously
    try:
        while True:
            logger.info("Starting CVE search")
            poll_nvd()
            logger.info(f"Waiting {POLLING_INTERVAL} seconds before next poll")
            time.sleep(POLLING_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Search stopped by user.")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
    finally:
        conn.close()  # Close the database connection
        logger.info("Database connection closed")


if __name__ == "__main__":
    main()