# SOCca Microsoft Sentinel Integration Guide

This guide provides detailed information on integrating SOCca's vulnerability intelligence with Microsoft Sentinel.

**Looking for a simpler tutorial?** Check our [Simplified Sentinel Integration Guide](sentinel_integration_simple.md) for a quick step-by-step walkthrough with screenshots.

## Overview

SOCca provides comprehensive Microsoft Sentinel integration through:

1. **Direct API Integration** - Send vulnerability data directly to Sentinel via Log Analytics API
2. **File Export** - Generate structured JSON/NDJSON files for manual import into Sentinel
3. **Alert Templates** - Generate ready-to-use Sentinel analytics rules based on vulnerabilities

## Prerequisites

To use the Microsoft Sentinel integration, you'll need:

1. **Microsoft Sentinel** - Active Log Analytics workspace with Sentinel enabled
2. **API Authentication** - Workspace ID and Primary Key with write permissions
3. **SOCca** - Running SOCca system with CVE monitoring and analysis

## Configuration

### Environment Variables

Set the following environment variables:

```
SENTINEL_WORKSPACE_ID=your-workspace-id
SENTINEL_PRIMARY_KEY=your-workspace-primary-key
SENTINEL_LOG_TYPE=SOCcaCVE
SENTINEL_API_VERSION=2016-04-01
```

- `SENTINEL_WORKSPACE_ID`: Log Analytics workspace ID (GUID format)
- `SENTINEL_PRIMARY_KEY`: Primary key for the Log Analytics workspace
- `SENTINEL_LOG_TYPE`: Custom log type to use (default: SOCcaCVE)
- `SENTINEL_API_VERSION`: API version to use (default: 2016-04-01)

### Log Analytics Configuration

1. In Azure Portal, go to your Log Analytics workspace
2. No custom configuration is needed - logs will automatically create a `SOCcaCVE_CL` table

## Usage

### Direct API Integration

The Docker container automatically handles direct exports to Microsoft Sentinel. To manually trigger:

```bash
# Execute command inside the running container
docker exec -it socca python kryptos_working/sentinel_exporter.py --direct-send

# Send CVEs from the last X hours
docker exec -it socca python kryptos_working/sentinel_exporter.py --direct-send --hours 12

# Send CVEs with minimum CVSS score
docker exec -it socca python kryptos_working/sentinel_exporter.py --direct-send --min-cvss 7.0
```

### File Export

For file-based exports:

```bash
# Export to JSON file for manual import
docker exec -it socca python kryptos_working/sentinel_exporter.py --file-export

# Export in NDJSON format (better for Log Analytics Data Collector)
docker exec -it socca python kryptos_working/sentinel_exporter.py --file-export --format ndjson
```

Files are saved in the container at `/app/kryptos_working/data/sentinel_output/` with timestamps in the filenames. These are mapped to a volume for persistence.

### Alert Templates

```bash
# Generate Microsoft Sentinel alert templates
docker exec -it socca python kryptos_working/sentinel_exporter.py --alerts
```

This creates JSON files containing ready-to-use Sentinel analytics rules with:
- KQL queries customized to each CVE
- Default thresholds and frequencies
- Severity based on CVSS score
- Descriptions and tactics from the AI-generated reports

## Data Structure

SOCca sends the following fields to Microsoft Sentinel:

| Field | Description |
|-------|-------------|
| TimeGenerated | Timestamp when the log was generated |
| CVE_ID | CVE identifier (e.g., CVE-2023-1234) |
| Description | Short description of the vulnerability |
| PublishedDate | Date when the CVE was published |
| CVSS_Score | CVSS base score |
| Severity | Severity rating (Critical, High, Medium, Low) |
| ReferenceURL | URL to SOCca's detailed analysis |
| ReportHighlights | Excerpt from AI-generated report |
| AffectedProducts | Comma-separated list of affected products |
| AffectedVendors | Comma-separated list of affected vendors |
| MitreAttackTactics | MITRE ATT&CK technique IDs extracted from the report |

## Docker Deployment

SOCca is deployed using Docker for consistent operation:

1. Use the Docker helper script to set up:
   ```bash
   chmod +x docker-compose.sh
   ./docker-compose.sh setup
   ```

2. Configure environment variables in `.env` file:
   ```
   SENTINEL_WORKSPACE_ID=your-workspace-id
   SENTINEL_PRIMARY_KEY=your-workspace-primary-key
   OPENAI_API_KEY=your-openai-api-key
   NVD_API_KEY=your-nvd-api-key
   ```

3. Start SOCca:
   ```bash
   ./docker-compose.sh start
   ```

The deployed container will:
- Continuously monitor for new CVEs
- Analyze vulnerabilities using AI
- Automatically export to Microsoft Sentinel
- Generate alert templates

## Sentinel Analytics Rules

After data is in Sentinel, you can create analytics rules:

1. Start with the generated templates in `sentinel_alert_templates_*.json`
2. Import the rules using the Sentinel API or Azure CLI
3. Customize frequencies, thresholds, and actions

Example rule creation using Azure CLI:
```bash
az sentinel alert-rule create --resource-group myResourceGroup \
    --workspace-name myWorkspace \
    --rule-id "CVE-2023-1234" \
    --name "SOCca - Critical CVE-2023-1234" \
    --query-name "SOCca - Detection for CVE-2023-1234" \
    --query "SOCcaCVE_CL | where CVE_ID_s == 'CVE-2023-1234'" \
    --severity "High" \
    --frequency 1 \
    --frequency-unit Hour \
    --query-period 1 \
    --query-period-unit Day
```

## Sentinel Workbooks

Create Sentinel workbooks for visualizing vulnerability data:

1. Go to Microsoft Sentinel > Workbooks > New
2. Add queries to visualize CVE trends:

```kql
SOCcaCVE_CL
| summarize count() by Severity_s, bin(TimeGenerated, 1d)
| render columnchart
```

```kql
SOCcaCVE_CL
| where CVSS_Score_d >= 7.0
| project CVE_ID_s, CVSS_Score_d, Severity_s, Description_s, AffectedProducts_s
| sort by CVSS_Score_d desc
```

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
   - Verify your workspace ID and primary key are correct
   - Check the permissions of the key in Log Analytics

2. **Log Ingestion Delays**:
   - Data may take a few minutes to appear in Log Analytics
   - Check the `sentinel_exporter.log` for sending status

3. **Missing Custom Fields**:
   - Custom fields (with _s suffix) appear only after data ingestion
   - Run a query with project-away to see all available fields:
   ```kql
   SOCcaCVE_CL
   | project-away TenantId, SourceSystem, TimeGenerated, MG, ManagementGroupName, Computer
   ```

### Logging

Logs are accessible through:
- Docker container logs: `docker logs socca` or `./docker-compose.sh logs`
- Container path: `/app/kryptos_working/logs/sentinel_exporter.log`
- Mapped volume on host

View logs specific to Sentinel integration:

```bash
# View Sentinel exporter logs
docker exec -it socca cat /app/kryptos_working/logs/sentinel_exporter.log

# Stream container logs
docker logs -f socca
```

To increase log verbosity:
```bash
# Enter the container
docker exec -it socca bash

# Edit the file
nano kryptos_working/sentinel_exporter.py

# Change logging level from INFO to DEBUG
# logging.basicConfig(level=logging.INFO, ...)
# to:
# logging.basicConfig(level=logging.DEBUG, ...)
```

## References

- [Microsoft Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)
- [Log Analytics Data Collector API](https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)
- [KQL Query Language](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [Sentinel Analytics Rules](https://docs.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
- [Azure DevOps Pipelines](https://docs.microsoft.com/en-us/azure/devops/pipelines/)