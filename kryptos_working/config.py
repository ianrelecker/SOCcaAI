import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Ensure we're using the parent directory for .env when run from any script
if os.path.basename(os.getcwd()) == 'kryptos_working':
    # Running from kryptos_working directory
    env_path = Path('../.env')
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)

# Helper function to clean environment values
def clean_env_value(value, default):
    if value is None:
        return default
    # Extract only digits and possibly minus sign for numbers
    import re
    matches = re.match(r'^\s*(-?\d+)', value)
    return matches.group(1) if matches else default
    
# API Keys
NVD_API_KEY = os.getenv('NVD_API_KEY')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# SOCca Site URL (for report references)
SITE_URL = os.getenv('SITE_URL', 'https://socca.tech')

# OpenAI Models
OPENAI_REPORT_MODEL = os.getenv('OPENAI_REPORT_MODEL', 'o1-mini-2024-09-12')
OPENAI_ANALYSIS_MODEL = os.getenv('OPENAI_ANALYSIS_MODEL', 'gpt-4o-mini-2024-07-18')

# Database Configuration
PROCESSED_CVES_DB = os.getenv('PROCESSED_CVES_DB', 'processed_cves.db')
CVE_REPORTS_DB = os.getenv('CVE_REPORTS_DB', 'cve_reports.db')
POSTS_DB = os.getenv('POSTS_DB', 'posts.db')
KEV_DATA_DB = os.getenv('KEV_DATA_DB', 'kev_data.db')

# Application Settings

POLLING_INTERVAL = int(clean_env_value(os.getenv('POLLING_INTERVAL'), '60'))
# Parse report hours safely
report_hours_str = os.getenv('REPORT_HOURS', '5,13')
if report_hours_str:
    import re
    # Extract comma-separated numbers
    hours_match = re.findall(r'(\d+)', report_hours_str)
    REPORT_HOURS = [int(h) for h in hours_match] if hours_match else [5, 13]
else:
    REPORT_HOURS = [5, 13]
REPORT_MINUTES = int(clean_env_value(os.getenv('REPORT_MINUTES'), '55'))
TIMEZONE_OFFSET = int(clean_env_value(os.getenv('TIMEZONE_OFFSET'), '-8'))
# Parse CVSS threshold safely
cvss_threshold_str = os.getenv('CVSS_CRITICAL_THRESHOLD', '8.0')
if cvss_threshold_str:
    import re
    cvss_match = re.search(r'(\d+\.\d+|\d+)', cvss_threshold_str)
    CVSS_CRITICAL_THRESHOLD = float(cvss_match.group(1)) if cvss_match else 8.0
else:
    CVSS_CRITICAL_THRESHOLD = 8.0

# Microsoft Sentinel Settings
SENTINEL_WORKSPACE_ID = os.getenv('SENTINEL_WORKSPACE_ID', '')
SENTINEL_PRIMARY_KEY = os.getenv('SENTINEL_PRIMARY_KEY', '')
SENTINEL_LOG_TYPE = os.getenv('SENTINEL_LOG_TYPE', 'SOCcaCVE')
SENTINEL_API_VERSION = os.getenv('SENTINEL_API_VERSION', '2016-04-01')

# Email Notification Settings
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(clean_env_value(os.getenv('SMTP_PORT'), '587'))
EMAIL_USERNAME = os.getenv('EMAIL_USERNAME', '')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
ALERT_RECIPIENTS = os.getenv('ALERT_RECIPIENTS', '').split(',') if os.getenv('ALERT_RECIPIENTS') else []

# Notification Webhooks
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')
TEAMS_WEBHOOK_URL = os.getenv('TEAMS_WEBHOOK_URL', '')

# SOCca Site reference (used in report URLs)
REPORT_URL_BASE = f"{SITE_URL}/cve"

# NVD API Configuration
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 6  # requests per second

# Validation and warnings
if not NVD_API_KEY:
    print("WARNING: NVD_API_KEY is not set. Requests will be rate-limited.")
    
if not OPENAI_API_KEY:
    print("WARNING: OPENAI_API_KEY is not set. AI analysis will not function.")
    
# End of Configuration