# SOCca KQL Queries

## Basic Queries

### Get All CVEs from Last 24 Hours
```kql
SOCca_CL
| where TimeGenerated > ago(24h)
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
| order by CVSS_Score_d desc
```

### Critical Vulnerabilities
```kql
SOCca_CL
| where CVSS_Score_d >= 9.0
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
| order by TimeGenerated desc
```

### Exploitable Vulnerabilities
```kql
SOCca_CL
| where AI_Analysis_s contains "exploit" or AI_Analysis_s contains "exploitable"
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
| order by CVSS_Score_d desc
```

## Advanced Queries

### CVEs Affecting Your Infrastructure
```kql
SOCca_CL
| where CVE_s in (
    (externaldata(CVE:string) 
    [@"https://your-inventory-api/affected-tech.csv"] 
    with (format="csv"))
)
| project TimeGenerated, CVE_s, CVSS_Score_d, AI_Analysis_s, Description_s
```

### Trend Analysis
```kql
SOCca_CL
| summarize CVE_Count=count() by bin(TimeGenerated, 1d)
| render timechart
```

### CVEs by Technology
```kql
SOCca_CL
| extend Technology = extract("(Windows|Linux|macOS|Cisco|VMware|Azure)", 1, Description_s)
| where isnotempty(Technology)
| summarize CVE_Count=count() by Technology
| order by CVE_Count desc
| render piechart
```

### Compare AI Severity with CVSS Score
```kql
SOCca_CL
| extend AI_Severity = case(
    AI_Analysis_s contains "critical", "Critical",
    AI_Analysis_s contains "severe", "High",
    AI_Analysis_s contains "moderate", "Medium",
    AI_Analysis_s contains "low", "Low",
    "Unknown"
)
| extend CVSS_Severity = case(
    CVSS_Score_d >= 9.0, "Critical",
    CVSS_Score_d >= 7.0, "High",
    CVSS_Score_d >= 4.0, "Medium",
    CVSS_Score_d > 0, "Low",
    "Unknown"
)
| summarize Count=count() by AI_Severity, CVSS_Severity
| extend SeverityMatch = AI_Severity == CVSS_Severity
| order by CVSS_Severity asc, AI_Severity asc
```