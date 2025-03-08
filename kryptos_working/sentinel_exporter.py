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
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path

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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'logs', 'sentinel_exporter.log'))
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


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Create a connection to a SQLite database"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn


def get_recent_cves(hours: int = 24, min_cvss: Optional[float] = None) -> List[Dict[str, Any]]:
    """Get CVEs from the last X hours, optionally filtered by minimum CVSS score"""
    try:
        # Calculate the timestamp for X hours ago
        time_ago = (datetime.datetime.now() - datetime.timedelta(hours=hours)).isoformat()
        
        # Build the query
        query = "SELECT cve_id, description, pub, data FROM processed_cves WHERE pub >= ?"
        params = [time_ago]
        
        # Connect to the database
        conn = get_db_connection(PROCESSED_CVES_DB)
        cursor = conn.cursor()
        
        # Execute query
        results = cursor.execute(query, params).fetchall()
        
        # Process results
        cves = []
        for row in results:
            cve = dict(row)
            
            # Parse CVSS data
            try:
                cvss_data = json.loads(cve.get('data', '{}').replace("'", '"'))
                
                # Extract base score
                if 'cvssMetricV31' in cvss_data and cvss_data['cvssMetricV31']:
                    cvss_score = cvss_data['cvssMetricV31'][0]['cvssData']['baseScore']
                    severity = get_severity_from_cvss(cvss_score)
                    
                    # Filter by minimum CVSS if specified
                    if min_cvss is not None and cvss_score < min_cvss:
                        continue
                        
                    cve['cvss_score'] = cvss_score
                    cve['severity'] = severity
                    
                    # Get report content
                    try:
                        reports_conn = get_db_connection(CVE_REPORTS_DB)
                        report_cursor = reports_conn.execute(
                            "SELECT report FROM processed WHERE cve_id = ?", 
                            (cve['cve_id'],)
                        )
                        report = report_cursor.fetchone()
                        reports_conn.close()
                        
                        if report:
                            cve['report'] = report['report']
                    except Exception as e:
                        logger.warning(f"Could not fetch report for {cve['cve_id']}: {e}")
                        cve['report'] = None
                        
                    cves.append(cve)
            except (json.JSONDecodeError, KeyError) as e:
                # Skip CVEs with invalid CVSS data
                logger.debug(f"Skipping CVE {cve.get('cve_id', 'unknown')} due to error: {e}")
                pass
        
        conn.close()
        return cves
    except Exception as e:
        logger.error(f"Error fetching recent CVEs: {e}")
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


def prepare_cve_for_sentinel(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare a CVE record for export to Microsoft Sentinel"""
    sentinel_log = {
        "TimeGenerated": datetime.datetime.now().isoformat(),
        "CVE_ID": cve.get('cve_id', ''),
        "Description": cve.get('description', ''),
        "PublishedDate": cve.get('pub', ''),
        "CVSS_Score": cve.get('cvss_score', 0.0),
        "Severity": cve.get('severity', 'Unknown'),
        "ReferenceURL": f"{SITE_URL}/cve/{cve.get('cve_id', '').lower()}"
    }
    
    # Include the AI-generated report if available
    if 'report' in cve and cve['report']:
        sentinel_log['ReportHighlights'] = cve['report'][:1000]  # Limit to 1000 chars for Sentinel
    
    # Try to extract affected products and vendors
    try:
        data = json.loads(cve.get('data', '{}').replace("'", '"'))
        
        # Extract CPE info
        if 'configurations' in data and data['configurations']:
            affected_products = []
            affected_vendors = []
            
            for config in data['configurations'].get('nodes', []):
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
            
            if affected_products:
                sentinel_log['AffectedProducts'] = ','.join(affected_products)
            if affected_vendors:
                sentinel_log['AffectedVendors'] = ','.join(affected_vendors)
    except Exception as e:
        logger.debug(f"Error extracting affected products: {e}")
    
    # Convert MITRE ATT&CK classifications from the report if available
    if 'report' in cve and cve['report']:
        try:
            # Look for MITRE ATT&CK references in the report
            report = cve['report']
            
            # Simple extraction of T-codes (T####)
            import re
            tactics = re.findall(r'T\d{4}', report)
            if tactics:
                sentinel_log['MitreAttackTactics'] = ','.join(set(tactics))
        except Exception as e:
            logger.debug(f"Error extracting MITRE ATT&CK tactics: {e}")
    
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


def send_to_sentinel(cves: List[Dict[str, Any]], batch_size: int = 30) -> Tuple[int, int]:
    """Send CVEs directly to Microsoft Sentinel via Log Analytics Data Collector API"""
    if not SENTINEL_WORKSPACE_ID or not SENTINEL_PRIMARY_KEY:
        logger.error("Microsoft Sentinel Workspace ID or Primary Key not configured")
        return 0, 0
    
    success_count = 0
    error_count = 0
    total_batches = (len(cves) + batch_size - 1) // batch_size  # Ceiling division
    
    api_url = f"https://{SENTINEL_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version={SENTINEL_API_VERSION}"
    
    for i in range(0, len(cves), batch_size):
        batch = cves[i:i+batch_size]
        batch_num = (i // batch_size) + 1
        
        # Format logs for Log Analytics
        sentinel_logs = [prepare_cve_for_sentinel(cve) for cve in batch]
        
        # Create the signature
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
        
        try:
            response = requests.post(
                api_url,
                data=body,
                headers=headers,
                timeout=30
            )
            
            if response.status_code in (200, 204):
                success_count += len(batch)
                logger.info(f"Successfully sent batch {batch_num}/{total_batches} with {len(batch)} logs to Microsoft Sentinel")
            else:
                error_count += len(batch)
                logger.error(f"Error sending batch {batch_num}/{total_batches} to Microsoft Sentinel: {response.status_code} - {response.text}")
        except Exception as e:
            error_count += len(batch)
            logger.error(f"Exception sending batch {batch_num}/{total_batches} to Microsoft Sentinel: {str(e)}")
    
    return success_count, error_count


def main() -> None:
    """Main entry point"""
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
    
    args = parser.parse_args()
    
    # If no action specified, default to direct send if credentials available
    if not args.direct_send and not args.file_export and not args.alerts:
        if SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY:
            args.direct_send = True
        else:
            args.file_export = True
    
    logger.info(f"Starting SOCca Microsoft Sentinel Exporter")
    logger.info(f"Configuration: hours={args.hours}, min_cvss={args.min_cvss}, " +
                f"direct_send={args.direct_send}, file_export={args.file_export}, format={args.format}")
    
    # Get recent CVEs
    cves = get_recent_cves(args.hours, args.min_cvss)
    logger.info(f"Found {len(cves)} CVEs in the last {args.hours} hours" + 
                (f" with CVSS >= {args.min_cvss}" if args.min_cvss else ""))
    
    if not cves:
        logger.warning("No CVEs found, nothing to export")
        return
    
    # Perform requested actions
    if args.direct_send:
        if not SENTINEL_WORKSPACE_ID or not SENTINEL_PRIMARY_KEY:
            logger.error("Direct send requires SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY environment variables")
            logger.info("Please set these variables or use --file-export instead")
            return
            
        logger.info("Sending directly to Microsoft Sentinel...")
        success, errors = send_to_sentinel(cves)
        logger.info(f"Microsoft Sentinel: {success} records sent successfully, {errors} errors")
    
    if args.file_export:
        logger.info(f"Exporting to files for manual import (format: {args.format})...")
        file_path = export_to_sentinel_file(cves, args.format)
        logger.info(f"File exported: {file_path}")
    
    if args.alerts:
        logger.info("Generating Microsoft Sentinel alert templates...")
        template_path = generate_sentinel_alert_template(cves)
        logger.info(f"Alert templates exported: {template_path}")
    
    logger.info("Microsoft Sentinel Exporter completed successfully")


if __name__ == "__main__":
    main()