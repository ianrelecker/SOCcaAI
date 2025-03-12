# SOCca Hunting Queries

Use these specialized KQL queries for proactive threat hunting with your SOCca data in Microsoft Sentinel.

## Zero-Day Vulnerability Hunt

```kql
// Look for vulnerabilities discovered within the last 7 days with high CVSS scores
SOCcaCVE_CL
| where TimeGenerated > ago(7d)
| where AI_Analysis_s has_any("zero day", "zero-day", "unpatched", "no patch available")
| where CVSS_Score_d > 7.0
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
| order by CVSS_Score_d desc, TimeGenerated desc
```

## Supply Chain Vulnerability Hunt

```kql
// Identify vulnerabilities in common software supply chain components
SOCcaCVE_CL
| where TimeGenerated > ago(90d)
| where Description_s has_any("dependency", "package", "library", "framework", "module", "plugin", "component")
| where AI_Analysis_s has_any("supply chain", "dependency", "widespread impact")
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
| order by TimeGenerated desc
```

## Remote Code Execution Hunt

```kql
// Find vulnerabilities that might allow remote code execution
SOCcaCVE_CL
| where AI_Analysis_s has_any("remote code execution", "RCE", "arbitrary code", "command execution", "shell", "command injection")
| where CVSS_Score_d >= 7.0
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
| order by TimeGenerated desc
```

## Authentication Bypass Hunt

```kql
// Identify vulnerabilities that might allow attackers to bypass authentication
SOCcaCVE_CL
| where AI_Analysis_s has_any("authentication bypass", "auth bypass", "bypass authentication", "privilege escalation", "unauthorized access")
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
| order by CVSS_Score_d desc
```

## Critical Infrastructure Vulnerability Hunt

```kql
// Find vulnerabilities affecting industrial/critical infrastructure
SOCcaCVE_CL
| where Description_s has_any("SCADA", "ICS", "industrial control", "OT", "operational technology", "PLC", "HMI", "critical infrastructure")
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
| order by CVSS_Score_d desc
```

## AI Analysis Discrepancy Hunt

```kql
// Identify cases where AI analysis suggests a different severity than CVSS score
SOCcaCVE_CL
| extend CVSS_Severity = case(
    CVSS_Score_d >= 9.0, "Critical",
    CVSS_Score_d >= 7.0, "High",
    CVSS_Score_d >= 4.0, "Medium",
    "Low"
)
| where (CVSS_Severity == "Low" or CVSS_Severity == "Medium") and (AI_Analysis_s has "critical" or AI_Analysis_s has "severe")
   or (CVSS_Severity == "Critical" or CVSS_Severity == "High") and (AI_Analysis_s has "low impact" or AI_Analysis_s has "minimal")
| project TimeGenerated, CVE_s, CVSS_Score_d, CVSS_Severity, AI_Analysis_s, Description_s
| order by TimeGenerated desc
```

## Time-Based Analysis - CVE Spikes

```kql
// Identify unusual spikes in CVE volume by time period
SOCcaCVE_CL
| summarize CVE_Count=count() by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
| extend Previous = prev(CVE_Count)
| extend PercentIncrease = iff(Previous > 0, (CVE_Count - Previous) * 100.0 / Previous, 0)
| where PercentIncrease > 50  // 50% increase from previous day
| order by PercentIncrease desc
```

## Vendor/Product Concentration Analysis

```kql
// Identify vendors or products with unusual concentrations of new CVEs
SOCcaCVE_CL
| where TimeGenerated > ago(30d)
| extend Vendor = extract("(Microsoft|Cisco|VMware|Adobe|Oracle|Linux|Apple|Google|Amazon|IBM)", 1, Description_s)
| where isnotempty(Vendor)
| summarize CVE_Count=count(), AvgCVSS=avg(CVSS_Score_d), MaxCVSS=max(CVSS_Score_d), CVEs=make_set(CVE_s, 10) by Vendor
| order by CVE_Count desc
```