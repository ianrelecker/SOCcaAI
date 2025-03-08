"""
URL Processing Module for SOCca

A more efficient and robust URL processor that:
1. Processes URLs in parallel using ThreadPoolExecutor
2. Implements caching to avoid re-fetching the same URL
3. Prioritizes URLs based on domain reputation
4. Handles a wider range of errors
5. Provides better content extraction
"""

import ast
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from readability import Document

# Configure logging
logger = logging.getLogger('url_processor')

# Constants
MAX_WORKERS = 5  # Number of parallel workers
REQUEST_TIMEOUT = 15  # Seconds
CACHE_EXPIRY = 24 * 60 * 60  # 24 hours in seconds
MIN_CONTENT_LENGTH = 100  # Minimum length for content to be considered useful
MAX_CONTENT_LENGTH = 10000  # Maximum length to keep (to avoid huge pages)
URL_CACHE_DB = "url_cache.db"

# URL reputation scores (higher is better)
URL_REPUTATION = {
    'github.com': 10,
    'nvd.nist.gov': 10,
    'cve.mitre.org': 9,
    'exploit-db.com': 9,
    'cisa.gov': 9, 
    'cert.org': 8,
    'kb.cert.org': 8,
    'microsoft.com': 8,
    'oracle.com': 8,
    'cisco.com': 8,
    'ibm.com': 8,
    'adobe.com': 8,
    'apple.com': 8,
    'redhat.com': 8,
    'ubuntu.com': 8,
    'debian.org': 8,
    'canonical.com': 8,
    'suse.com': 8,
    'vmware.com': 8,
    'juniper.net': 8,
    'f5.com': 8,
    'fortinet.com': 8,
    'paloaltonetworks.com': 8,
    'checkpoint.com': 8,
    'citrix.com': 8,
    'akamai.com': 8,
    'cloudflare.com': 8,
    'aws.amazon.com': 8,
    'azure.microsoft.com': 8,
    'cloud.google.com': 8,
    'mozilla.org': 7,
    'wordpress.org': 7,
    'drupal.org': 7,
    'joomla.org': 7,
    'php.net': 7,
    'python.org': 7,
    'ruby-lang.org': 7,
    'nodejs.org': 7,
    'npmjs.com': 7,
    'pypi.org': 7,
    'rubygems.org': 7
}

def init_cache_db():
    """Initialize the URL cache database"""
    conn = sqlite3.connect(URL_CACHE_DB)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS url_cache (
            url_hash TEXT PRIMARY KEY,
            url TEXT,
            content TEXT,
            fetch_time INTEGER,
            status_code INTEGER,
            content_type TEXT
        )
    ''')
    conn.commit()
    conn.close()
    logger.info("URL cache database initialized")

def get_url_hash(url: str) -> str:
    """Generate a hash for the URL to use as a cache key"""
    return hashlib.sha256(url.encode('utf-8')).hexdigest()

def get_cached_content(url: str) -> Optional[str]:
    """
    Check if URL content is cached and not expired
    
    Args:
        url: The URL to check in cache
        
    Returns:
        The cached content if available and fresh, None otherwise
    """
    url_hash = get_url_hash(url)
    now = int(time.time())
    try:
        conn = sqlite3.connect(URL_CACHE_DB)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT content, fetch_time FROM url_cache WHERE url_hash = ?", 
            (url_hash,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            content, fetch_time = result
            # Check if cache is still fresh
            if now - fetch_time < CACHE_EXPIRY:
                logger.debug(f"Cache hit for {url}")
                return content
            else:
                logger.debug(f"Cache expired for {url}")
        else:
            logger.debug(f"Cache miss for {url}")
        
        return None
    except sqlite3.Error as e:
        logger.error(f"Database error when checking cache: {e}")
        return None

def cache_url_content(url: str, content: str, status_code: int = 200, content_type: str = "text/html") -> bool:
    """
    Cache the content of a URL
    
    Args:
        url: The URL being cached
        content: The content to cache
        status_code: HTTP status code of the response
        content_type: Content-Type of the response
    
    Returns:
        True if caching was successful, False otherwise
    """
    url_hash = get_url_hash(url)
    now = int(time.time())
    
    try:
        conn = sqlite3.connect(URL_CACHE_DB)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO url_cache (url_hash, url, content, fetch_time, status_code, content_type) VALUES (?, ?, ?, ?, ?, ?)",
            (url_hash, url, content, now, status_code, content_type)
        )
        conn.commit()
        conn.close()
        logger.debug(f"Cached content for {url}")
        return True
    except sqlite3.Error as e:
        logger.error(f"Database error when caching content: {e}")
        return False

def fetch_url(url: str) -> Dict[str, any]:
    """
    Fetch content from a URL with better error handling
    
    Args:
        url: URL to fetch
        
    Returns:
        Dict with content, status_code, and error information
    """
    # Check cache first
    cached_content = get_cached_content(url)
    if cached_content:
        return {
            "url": url,
            "content": cached_content,
            "status_code": 200,
            "error": None,
            "from_cache": True
        }
        
    headers = {
        "User-Agent": "SOCca/1.0 (Security Vulnerability Research; +https://example.com/socca-bot)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        response.raise_for_status()
        
        # Check if content type is HTML or text
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type or 'text/plain' in content_type:
            content = response.text
            status_code = response.status_code
            
            # Cache the result
            cache_url_content(url, content, status_code, content_type)
            
            return {
                "url": url,
                "content": content,
                "status_code": status_code,
                "error": None,
                "from_cache": False
            }
        else:
            logger.warning(f"Skipping non-HTML content for {url}: {content_type}")
            return {
                "url": url,
                "content": f"[Non-HTML content: {content_type}]",
                "status_code": response.status_code,
                "error": "non-html",
                "from_cache": False
            }
            
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout when fetching {url}")
        return {"url": url, "content": "", "status_code": 0, "error": "timeout", "from_cache": False}
    except requests.exceptions.TooManyRedirects:
        logger.warning(f"Too many redirects for {url}")
        return {"url": url, "content": "", "status_code": 0, "error": "too_many_redirects", "from_cache": False}
    except requests.exceptions.ConnectionError:
        logger.warning(f"Connection error for {url}")
        return {"url": url, "content": "", "status_code": 0, "error": "connection_error", "from_cache": False}
    except requests.exceptions.HTTPError as e:
        logger.warning(f"HTTP error for {url}: {e}")
        return {"url": url, "content": "", "status_code": e.response.status_code if hasattr(e, 'response') else 0, "error": "http_error", "from_cache": False}
    except Exception as e:
        logger.error(f"Unexpected error for {url}: {e}")
        return {"url": url, "content": "", "status_code": 0, "error": str(e), "from_cache": False}

def extract_content(html_content: str, url: str) -> str:
    """
    Extract the main content from HTML using Readability
    
    Args:
        html_content: Raw HTML content
        url: Source URL for logging
        
    Returns:
        Extracted main content as text
    """
    try:
        doc = Document(html_content)
        
        # Get document title
        title = doc.title() or "No Title"
        
        # Get the main content
        main_content_html = doc.summary()
        
        # Convert to text and clean up whitespace
        soup = BeautifulSoup(main_content_html, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "header", "footer", "nav"]):
            script.extract()
        
        # Get text
        text = soup.get_text()
        
        # Normalize whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        # Prepend title
        final_text = f"{title}\n\n{text}"
        
        # Limit content length
        if len(final_text) > MAX_CONTENT_LENGTH:
            final_text = final_text[:MAX_CONTENT_LENGTH] + "... [content truncated]"
            
        # Check if we have enough content
        if len(final_text) < MIN_CONTENT_LENGTH:
            logger.warning(f"Extracted content for {url} is too short ({len(final_text)} chars)")
            return f"[Insufficient content extracted from {url}]"
            
        return final_text
    except Exception as e:
        logger.error(f"Error extracting content from {url}: {e}")
        return f"[Error extracting content from {url}: {str(e)}]"

def score_url(url: str) -> int:
    """
    Score a URL based on its domain and other factors
    
    Args:
        url: URL to score
        
    Returns:
        Score value (higher is better)
    """
    try:
        # Parse the URL
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove www prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Get base score from reputation dict or default to 5
        score = URL_REPUTATION.get(domain, 5)
        
        # Add extra points for specific paths
        path = parsed.path.lower()
        if 'security' in path or 'advisory' in path or 'vulnerability' in path:
            score += 1
        if 'cve-' in path or 'vuln' in path:
            score += 1
            
        # Deduct points for PDFs (harder to extract content)
        if path.endswith('.pdf'):
            score -= 2
            
        # Deduct points for forums (often noisy)
        if 'forum' in domain or 'community' in domain:
            score -= 1
            
        return score
    except Exception:
        # Return a default score if URL parsing fails
        return 3

def prioritize_urls(urls: List[str], max_urls: int = 5) -> List[str]:
    """
    Prioritize URLs by scoring them
    
    Args:
        urls: List of URLs to prioritize
        max_urls: Maximum number of URLs to return
        
    Returns:
        List of highest-scoring URLs, limited to max_urls
    """
    # Score each URL and create (url, score) pairs
    scored_urls = [(url, score_url(url)) for url in urls]
    
    # Sort by score (highest first)
    scored_urls.sort(key=lambda x: x[1], reverse=True)
    
    # Return the top N URLs
    top_urls = [url for url, score in scored_urls[:max_urls]]
    
    return top_urls

def parse_url_list(url_str: str) -> List[str]:
    """
    Parse a string containing a Python list of URLs
    
    Args:
        url_str: String representation of a Python list
        
    Returns:
        List of URLs
    """
    try:
        # Try to parse as a Python list using ast.literal_eval
        urls = ast.literal_eval(url_str)
        
        # Ensure it's a list
        if not isinstance(urls, list):
            logger.error(f"URL list parsing failed: result is not a list")
            return []
            
        # Filter out non-string items
        urls = [url for url in urls if isinstance(url, str)]
        
        return urls
    except (SyntaxError, ValueError) as e:
        logger.error(f"URL list parsing failed: {e}")
        
        # Fallback: try to extract URLs using regex
        try:
            # This regex pattern matches common URL formats
            url_pattern = r'https?://[^\s)"\']+(?:\.[^\s)"\'][^\s)"\']*)+[^\s)\.,"\']+'
            urls = re.findall(url_pattern, url_str)
            
            if urls:
                logger.info(f"Extracted {len(urls)} URLs using regex")
                return urls
        except Exception as e2:
            logger.error(f"Regex URL extraction failed: {e2}")
        
        return []

def process_urls(url_list: str, max_urls: int = 5) -> List[Dict[str, any]]:
    """
    Process a list of URLs to extract content in parallel
    
    Args:
        url_list: String representation of a Python list of URLs
        max_urls: Maximum number of URLs to process
        
    Returns:
        List of dictionaries with URL content, status, and metadata
    """
    # Initialize cache database
    init_cache_db()
    
    # Parse the URL list
    urls = parse_url_list(url_list)
    
    if not urls:
        logger.warning("No valid URLs found in the input")
        return []
    
    # Log the number of URLs found
    logger.info(f"Found {len(urls)} URLs to process")
    
    # Filter out duplicate URLs
    unique_urls = list(set(urls))
    logger.info(f"After removing duplicates: {len(unique_urls)} URLs")
    
    # Prioritize URLs
    prioritized_urls = prioritize_urls(unique_urls, max_urls)
    logger.info(f"Selected {len(prioritized_urls)} highest priority URLs")
    
    # Process URLs in parallel
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit fetch jobs
        future_to_url = {executor.submit(fetch_url, url): url for url in prioritized_urls}
        
        # Process completed jobs
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                data = future.result()
                
                # Skip if there was an error
                if data["error"] and data["error"] != "non-html":
                    continue
                    
                # Extract content if we have HTML
                if data["content"] and "non-html" not in data["content"]:
                    extracted_content = extract_content(data["content"], url)
                    data["extracted_content"] = extracted_content
                else:
                    data["extracted_content"] = data["content"]
                
                results.append(data)
                logger.info(f"Successfully processed {url} ({len(data['extracted_content'])} chars)")
            except Exception as e:
                logger.error(f"Error processing {url}: {e}")
    
    # Sort results by whether they're from cache (fresh data first)
    results.sort(key=lambda x: x.get("from_cache", True))
    
    return results

def get_content_summary(url_list: str, max_urls: int = 5) -> str:
    """
    Get a summary of content from multiple URLs
    
    Args:
        url_list: String representation of a Python list of URLs
        max_urls: Maximum number of URLs to process
        
    Returns:
        A formatted string with content from the URLs
    """
    results = process_urls(url_list, max_urls)
    
    if not results:
        return "No valid content could be extracted from the provided URLs."
    
    # Build a summary
    summary = f"Content extracted from {len(results)} reference URLs:\n\n"
    
    for i, data in enumerate(results, 1):
        url = data["url"]
        content = data.get("extracted_content", "No content extracted")
        
        # Add a separator between entries
        summary += f"--- SOURCE {i}: {url} ---\n"
        summary += content
        summary += "\n\n"
    
    return summary