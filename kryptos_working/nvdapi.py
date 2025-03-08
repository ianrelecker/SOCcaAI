import requests
import time
import datetime
import logging
from typing import Dict, Optional, Any

from config import NVD_API_KEY, NVD_API_BASE_URL, NVD_RATE_LIMIT

# Set up logging
logger = logging.getLogger('nvdapi')

# Headers for the request
HEADERS = {
    "Content-Type": "application/json",
}
if NVD_API_KEY:
    HEADERS["apiKey"] = NVD_API_KEY


def fetch_cves(start_date: str, end_date: str) -> Optional[Dict[str, Any]]:
    """
    Fetch CVEs from the NVD API within the given date range.

    Args:
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        
    Returns:
        Dict containing CVE data, or None if the request failed
    """
    params = {
        "pubStartDate": f"{start_date}T00:00:00.000Z",
        "pubEndDate": f"{end_date}T23:59:59.999Z",
    }
    
    logger.info(f"Fetching CVEs from {start_date} to {end_date}")

    try:
        response = requests.get(NVD_API_BASE_URL, headers=HEADERS, params=params)

        # Handle rate-limiting
        time.sleep(1 / NVD_RATE_LIMIT)

        if response.status_code == 200:
            data = response.json()
            logger.info(f"Successfully retrieved {len(data.get('vulnerabilities', []))} CVEs")
            return data
        else:
            logger.error(f"API Error: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        return None


def main():
    """Main function to fetch CVEs."""
    # Example: Fetch CVEs from the past day
    end_date = datetime.datetime.utcnow()
    start_date = end_date - datetime.timedelta(days=1)

    start_date_str = start_date.strftime("%Y-%m-%d")
    end_date_str = end_date.strftime("%Y-%m-%d")

    print(f"Fetching CVEs from {start_date_str} to {end_date_str}...")
    cves = fetch_cves(start_date_str, end_date_str)

    if cves:
        print(f"Retrieved {len(cves.get('vulnerabilities', []))} CVEs.")
    else:
        print("No CVEs retrieved.")
    return cves


if __name__ == "__main__":
    # Configure logging for standalone use
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    main()