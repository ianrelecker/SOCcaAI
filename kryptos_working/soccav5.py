import sqlite3
import logging
from typing import List, Dict, Any

import openai

# Import our custom modules
from token_counter import truncate_to_token_limit
from url_processor import get_content_summary

from config import (
    OPENAI_API_KEY, OPENAI_ANALYSIS_MODEL, CVE_REPORTS_DB
)

# Set up logging
logger = logging.getLogger('soccav5')

# Initialize OpenAI API with older version (0.28.x)
import openai
openai.api_key = OPENAI_API_KEY


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


def selectcve(cve_id: str) -> List[tuple]:
    """
    Query the database for a specific CVE.
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2024-1234)
        
    Returns:
        List of tuples containing CVE records
    """
    try:
        conn = sqlite3.connect(CVE_REPORTS_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM processed_cves WHERE cve_id = ?", (cve_id,))
        result = cursor.fetchall()
        conn.close()
        return result
    except sqlite3.Error as e:
        logger.error(f"Database error in selectcve: {e}")
        return []


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
    # Extract content from URLs using the improved processor
    # This will prioritize the most relevant URLs, process them in parallel, and cache the results
    url_content = get_content_summary(page_list)
    urls = "Here are references covering this vulnerability, please use them to inform your analysis: \n\n" + url_content
    logger.debug(f"URL content extracted for {cve_id}")

    # Prepare CVSS data
    cvss = "and the CVSS data: " + str(cvssdata)
    
    # System context for GPT with Microsoft Sentinel focus
    context = """Additional Context (not to be included in the report): You are supported by SOCca, a Microsoft Sentinel integration platform that processes vulnerability data for security operations centers. Your outputs must be structured for automated parsing and ingestion by Microsoft Sentinel. Keep these key Microsoft Sentinel integration requirements in mind: 1) Focus on machine-readable formats while maintaining human readability, 2) Include specific detection rules in KQL (Kusto Query Language), 3) Provide concrete, actionable IOCs that can be implemented in Sentinel analytics rules, 4) Ensure field standardization for Sentinel Log Analytics. The JSON structure is critical as it will be parsed by the sentinel_exporter.py with minimal transformation."""

    # Prompt for detailed vulnerability report
    helper_prompt = """You are a cybersecurity expert and developer specializing in vulnerability assessment and secure development practices. Your task is to produce a Microsoft Sentinel-ready, structured report with clear machine-parsable sections specifically designed for integration with Microsoft Sentinel. Follow this JSON-like structure exactly:

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

    # Combine all information for the prompt
    helper_info = f"Here is the new vulnerability information. Here is the id: {cve_id}, the description: {desc} {cvss} {urls} {context}"
    
    # Limit token count to avoid exceeding API limits
    target_token_limit = 127000
    helper_info = truncate_to_token_limit(helper_info, target_token_limit)
    logger.info(f"Prepared prompt for {cve_id} within token limits")

    logger.info(f"Sending {cve_id} to OpenAI for analysis")
    try:
        # Use the older OpenAI API format
        helper = openai.ChatCompletion.create(
            model=OPENAI_ANALYSIS_MODEL,
            messages=[
                {"role": "system", "content": helper_prompt},
                {"role": "user", "content": helper_info}
            ]
        )
        gpt_report = helper['choices'][0]['message']['content']
        
        # Add version info to report
        gpt_report = gpt_report + "\n\nSocca Version 5.0"
        
        # Save the generated report
        savereport(cve_id, gpt_report)
        logger.info(f"Successfully processed and saved report for {cve_id}")
    except Exception as e:
        logger.error(f"Error generating report for {cve_id}: {e}")


def savereport(cve_id: str, report: str) -> None:
    """
    Save a generated report to the database.
    
    Args:
        cve_id: CVE identifier
        report: Generated vulnerability report text
    """
    try:
        conn = sqlite3.connect(CVE_REPORTS_DB)
        cursor = conn.cursor()
        
        # Create the table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed (
                cve_id TEXT PRIMARY KEY,
                report TEXT,
                processed_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insert or replace the report
        cursor.execute("""
                    INSERT OR REPLACE INTO processed (cve_id, report)
                    VALUES (?, ?)
                """, (cve_id, report))
        conn.commit()
        conn.close()
        logger.info(f"Report saved for {cve_id}")
    except sqlite3.Error as e:
        logger.error(f"Database error in savereport: {e}")