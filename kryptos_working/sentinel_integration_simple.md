# Microsoft Sentinel Integration - Simplified Guide

This guide provides a straightforward, step-by-step approach to setting up and using SOCca with Microsoft Sentinel. 

## Getting Started with Sentinel Integration

### Step 1: Set Up Microsoft Sentinel

1. **Create a Log Analytics workspace** (if you don't have one):
   - Go to the [Azure Portal](https://portal.azure.com)
   - Search for "Log Analytics"
   - Click "Create Log Analytics workspace"
   - Fill in the required fields:
     - Subscription: Your Azure subscription
     - Resource group: Create new or use existing
     - Name: Choose a name (e.g., "SOCcaWorkspace")
     - Region: Choose your region
   - Click "Review + Create" and then "Create"

2. **Enable Microsoft Sentinel**:
   - In Azure Portal, search for "Microsoft Sentinel"
   - Click "Add"
   - Select your newly created workspace
   - Click "Add"

3. **Get your Workspace ID and Primary Key**:
   - Go to your Log Analytics workspace
   - Click "Agents management" in the left menu
   - Go to "Log Analytics agent"
   - You'll see your Workspace ID at the top
   - Click "Primary Key" to reveal your primary key
   - Copy both values for the next step

### Step 2: Configure SOCca for Sentinel

1. **Edit your .env file**:
   - Open your `.env` file in the SOCca directory
   - Add the following entries:
   ```
   SENTINEL_WORKSPACE_ID=your-workspace-id
   SENTINEL_PRIMARY_KEY=your-primary-key
   SENTINEL_LOG_TYPE=SOCcaCVE
   SENTINEL_API_VERSION=2016-04-01
   ```

2. **Test your connection**:
   - Run:
   ```bash
   python kryptos_working/sentinel_exporter.py --direct-send --verbose
   ```
   - You should see confirmation of successful data submission

### Step 3: Working with Data in Sentinel

1. **Check that data is arriving**:
   - Go to Microsoft Sentinel in Azure Portal
   - Click on "Logs" in the left menu
   - Run this query:
   ```
   SOCcaCVE_CL
   | limit 10
   ```
   - You should see your vulnerability data

2. **Create a simple dashboard**:
   - Go to "Workbooks" in the left menu
   - Click "Add workbook"
   - Click "Edit"
   - Click "Add query"
   - Paste this KQL query:
   ```
   SOCcaCVE_CL
   | summarize count() by Severity_s
   | render piechart
   ```
   - Click "Run query"
   - Click "Done Editing"
   - Click "Save" to save your workbook

3. **Create a basic alert rule**:
   - Go to "Analytics" in the left menu
   - Click "Create" > "Scheduled query rule"
   - Name your rule (e.g., "Critical CVE Alert")
   - For the KQL query, use:
   ```
   SOCcaCVE_CL
   | where Severity_s == "Critical"
   | where TimeGenerated > ago(1h)
   ```
   - Set alert threshold to 1
   - Configure alert frequency (e.g., 1 hour)
   - Click "Next: Incident settings"
   - Enable incident creation
   - Complete the wizard to create your rule

## Visual Guides

### Dashboard Example

![Sentinel Dashboard Example](https://socca.tech/wp-content/uploads/2023/05/sentinel-dashboard-example.jpg)

### CVE Analytics Example

![CVE Analytics Example](https://socca.tech/wp-content/uploads/2023/05/sentinel-analytics-example.jpg)

## Troubleshooting

- **No data appearing in Sentinel**:
  - Check your SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY values
  - Ensure your kryptos_working/log/sentinel_exporter.log shows successful API calls
  - It can take 5-10 minutes for data to appear in Sentinel

- **Error 403 in logs**:
  - Your Primary Key might have expired or doesn't have write permissions
  - Generate a new key in the Log Analytics workspace

- **Connection issues**:
  - Ensure your network allows outbound connections to *.ods.opinsights.azure.com
  - Check your firewall isn't blocking HTTPS connections

## Next Steps

- Create custom dashboards for different teams
- Set up automated email alerts for critical vulnerabilities
- Configure automated response playbooks
- Correlate CVE data with other security events

For more advanced configurations, see the [Complete Microsoft Sentinel Integration Guide](microsoft_sentinel.md).