import requests
import time
import datetime
import logging
import os
import json
from typing import Dict, Optional, Any, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config import NVD_API_KEY, NVD_API_BASE_URL, NVD_RATE_LIMIT

# Set up logging
logger = logging.getLogger('nvdapi')

# Cache directory
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'cache')
os.makedirs(CACHE_DIR, exist_ok=True)

# Headers for the request
HEADERS = {
    "Content-Type": "application/json",
}
if NVD_API_KEY:
    HEADERS["apiKey"] = NVD_API_KEY

# Create a session with retry logic
def create_session():
    """Create a requests session with retry logic"""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,  # Maximum number of retries
        backoff_factor=1,  # Time between retries increases exponentially
        status_forcelist=[429, 500, 502, 503, 504],  # Status codes to retry
        allowed_methods=["GET"]  # Only retry GET requests
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(HEADERS)
    return session

def get_cache_filename(start_date, end_date, params):
    """Generate a unique cache filename based on the request parameters"""
    params_str = json.dumps(params, sort_keys=True)
    import hashlib
    params_hash = hashlib.md5(params_str.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"nvd_cache_{start_date}_{end_date}_{params_hash}.json")

def load_from_cache(filename, max_age_hours=1):
    """Load data from cache if it exists and is not too old"""
    if not os.path.exists(filename):
        return None
        
    # Check if cache is still valid (not too old)
    file_age = time.time() - os.path.getmtime(filename)
    if file_age > max_age_hours * 3600:  # Convert hours to seconds
        logger.debug(f"Cache file {filename} is too old ({file_age/3600:.1f} hours)")
        return None
        
    try:
        with open(filename, 'r') as f:
            logger.debug(f"Loading from cache: {filename}")
            return json.load(f)
    except Exception as e:
        logger.warning(f"Error loading cache file {filename}: {e}")
        return None

def save_to_cache(filename, data):
    """Save data to cache file"""
    try:
        with open(filename, 'w') as f:
            json.dump(data, f)
        logger.debug(f"Saved to cache: {filename}")
    except Exception as e:
        logger.warning(f"Error saving to cache file {filename}: {e}")

def fetch_cves(start_date: str, end_date: str, 
               results_per_page: int = 100, 
               max_pages: int = 50,
               use_cache: bool = True) -> Optional[Dict[str, Any]]:
    """
    Fetch CVEs from the NVD API within the given date range.

    Args:
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        results_per_page: Number of results per page
        max_pages: Maximum number of pages to retrieve
        use_cache: Whether to use cached results if available
        
    Returns:
        Dict containing CVE data, or None if the request failed
    """
    all_vulnerabilities = []
    
    # Base parameters
    params = {
        "pubStartDate": f"{start_date}T00:00:00.000Z",
        "pubEndDate": f"{end_date}T23:59:59.999Z",
        "resultsPerPage": results_per_page,
    }
    
    # Check cache first if enabled
    if use_cache:
        cache_file = get_cache_filename(start_date, end_date, params)
        cached_data = load_from_cache(cache_file)
        if cached_data:
            logger.info(f"Using cached data for {start_date} to {end_date}")
            return cached_data
    
    logger.info(f"Fetching CVEs from {start_date} to {end_date} (up to {max_pages} pages)")
    
    session = create_session()
    current_page = 0
    total_results = None
    
    while current_page < max_pages:
        # If this is not the first page, add startIndex
        if current_page > 0:
            params["startIndex"] = current_page * results_per_page
        
        try:
            # Rate limiting before request to avoid hitting limits
            time.sleep(1 / NVD_RATE_LIMIT)
            
            response = session.get(
                NVD_API_BASE_URL, 
                params=params,
                timeout=30  # Set timeout to prevent hanging
            )
            
            # Check status before parsing
            if response.status_code == 200:
                data = response.json()
                
                # Update total results count
                if total_results is None:
                    total_results = data.get('totalResults', 0)
                    logger.info(f"Total results available: {total_results}")
                
                # Extract vulnerabilities and add to master list
                vulnerabilities = data.get('vulnerabilities', [])
                all_vulnerabilities.extend(vulnerabilities)
                logger.info(f"Retrieved page {current_page + 1} with {len(vulnerabilities)} CVEs")
                
                # If we got fewer results than the page size, or no results, we're done
                if len(vulnerabilities) < results_per_page or len(vulnerabilities) == 0:
                    break
                
                # Move to next page
                current_page += 1
            elif response.status_code == 429:  # Rate limit - already handled by retry logic
                logger.warning(f"Rate limit hit, waiting before retry")
                time.sleep(10)  # More aggressive wait for rate limiting
            else:
                logger.error(f"API Error: {response.status_code} - {response.text}")
                # If first page fails, return None; otherwise return what we have
                if current_page == 0:
                    return None
                break
                
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            logger.error(f"Error during API request: {e}")
            # If first page fails, return None; otherwise return what we have
            if current_page == 0:
                return None
            break
    
    # Construct the full result object
    result = {
        "vulnerabilities": all_vulnerabilities,
        "resultsPerPage": results_per_page,
        "startIndex": 0,
        "totalResults": len(all_vulnerabilities)
    }
    
    # Save to cache if we got results
    if use_cache and all_vulnerabilities:
        cache_file = get_cache_filename(start_date, end_date, {"resultsPerPage": results_per_page})
        save_to_cache(cache_file, result)
    
    logger.info(f"Successfully retrieved a total of {len(all_vulnerabilities)} CVEs")
    return result


def fetch_cves_by_date_range(start_date, end_date, use_cache=True):
    """
    Fetch CVEs for a specific date range, formatting dates appropriately.
    
    Args:
        start_date: datetime object for start date
        end_date: datetime object for end date
        use_cache: Whether to use cached results
    
    Returns:
        Dict containing CVE data
    """
    start_date_str = start_date.strftime("%Y-%m-%d")
    end_date_str = end_date.strftime("%Y-%m-%d")
    
    logger.info(f"Fetching CVEs from {start_date_str} to {end_date_str}...")
    return fetch_cves(start_date_str, end_date_str, use_cache=use_cache)

def fetch_recent_cves(days=1, use_cache=True):
    """
    Fetch CVEs from the last N days
    
    Args:
        days: Number of days to look back
        use_cache: Whether to use cached results
    
    Returns:
        Dict containing CVE data
    """
    end_date = datetime.datetime.utcnow()
    start_date = end_date - datetime.timedelta(days=days)
    
    return fetch_cves_by_date_range(start_date, end_date, use_cache)

def main():
    """Main function to fetch CVEs when run as a standalone script."""
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Fetch CVEs from NVD API")
    parser.add_argument("--days", type=int, default=1, help="Days to look back (default: 1)")
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end-date", help="End date (YYYY-MM-DD)")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    parser.add_argument("--output", help="Output file path (JSON)")
    
    args = parser.parse_args()
    
    # Either use date range or days
    if args.start_date and args.end_date:
        # Parse dates
        try:
            start_date = datetime.datetime.strptime(args.start_date, "%Y-%m-%d")
            end_date = datetime.datetime.strptime(args.end_date, "%Y-%m-%d")
            cves = fetch_cves_by_date_range(start_date, end_date, not args.no_cache)
        except ValueError:
            print("Error: Invalid date format. Use YYYY-MM-DD")
            return None
    else:
        # Use days
        cves = fetch_recent_cves(args.days, not args.no_cache)
    
    if cves:
        num_cves = len(cves.get('vulnerabilities', []))
        print(f"Retrieved {num_cves} CVEs.")
        
        # Save to output file if specified
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(cves, f, indent=2)
                print(f"Saved to {args.output}")
            except Exception as e:
                print(f"Error saving to {args.output}: {e}")
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