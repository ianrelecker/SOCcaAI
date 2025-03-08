# SOCca - AI-Powered CVE Intelligence with Microsoft Sentinel Integration

SOCca is an advanced security vulnerability monitoring and analysis platform that leverages AI to provide actionable intelligence on emerging threats with seamless Microsoft Sentinel integration.

## 🚀 Key Features

- **Real-time CVE Monitoring**: Automatically tracks new vulnerabilities as they're published to the NVD
- **AI-Powered Analysis**: Uses OpenAI models to generate comprehensive vulnerability reports with actionable insights
- **Intelligent Severity Assessment**: Goes beyond CVSS scores to provide context-aware risk evaluations
- **Microsoft Sentinel Integration**: Direct integration with Microsoft Sentinel via Log Analytics API
- **Alert Template Generation**: Creates ready-to-use Sentinel analytics rules based on vulnerabilities

## 📋 Quick Setup Guide

### Prerequisites

- Python 3.8+
- NVD API key (free from https://nvd.nist.gov/developers/request-an-api-key)
- OpenAI API key
- Microsoft Sentinel workspace with Log Analytics access

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/ianrelecker/SOCcaAI.git
cd SOCcaAI

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env  # Edit with your API keys and Sentinel settings

# Initialize databases
python setup.py
```

### 2. Running SOCca

Start each component in a separate terminal:

```bash
# Component 1: CVE Monitor (collects and analyzes vulnerabilities)
python kryptos_working/mainv2.py

# Component 2: Microsoft Sentinel Exporter (sends data to Sentinel)
python kryptos_working/sentinel_exporter.py --direct-send
```

For complete step-by-step instructions, see the [Quick Start Guide](kryptos_working/quickstart.md).

## 🛡️ Microsoft Sentinel Integration Guide

SOCca provides seamless integration with Microsoft Sentinel, allowing you to automatically send enriched vulnerability data to your SIEM for better security monitoring and alerting.

### Setup Microsoft Sentinel Integration

1. **Get Microsoft Sentinel credentials**:
   - Navigate to your Log Analytics workspace in Azure Portal
   - Go to "Agents management" > "Log Analytics agent"
   - Note your Workspace ID and Primary Key

2. **Configure SOCca for Sentinel**:
   - Add these settings to your `.env` file:
   ```
   SENTINEL_WORKSPACE_ID=your-sentinel-workspace-id
   SENTINEL_PRIMARY_KEY=your-sentinel-primary-key
   SENTINEL_LOG_TYPE=SOCcaCVE    # Custom log type name
   SENTINEL_API_VERSION=2016-04-01
   ```

3. **Start the integration**:
   ```bash
   # Send vulnerability data to Sentinel
   python kryptos_working/sentinel_exporter.py --direct-send
   
   # Generate alert templates for Sentinel
   python kryptos_working/sentinel_exporter.py --alerts
   ```

### Using Vulnerability Data in Microsoft Sentinel

#### 1. Query the Data

Once data is in Sentinel, you can query it using KQL:

```kusto
// View all vulnerabilities
SOCcaCVE_CL
| limit 100

// High severity vulnerabilities in the last 24 hours
SOCcaCVE_CL
| where Severity_s == "Critical" or Severity_s == "High"
| where TimeGenerated > ago(24h)
| project CVE_ID_s, Description_s, CVSS_Score_d, AffectedProducts_s, MitreAttackTactics_s
```

#### 2. Create Workbooks

Create a custom workbook in Microsoft Sentinel:

1. Navigate to **Microsoft Sentinel** > **Workbooks** > **New**
2. Add a new query with this KQL:

```kusto
// CVE severity distribution over time
SOCcaCVE_CL
| summarize count() by Severity_s, bin(TimeGenerated, 1d)
| render columnchart
```

#### 3. Set Up Analytics Rules

Import the generated alert templates or create custom rules:

1. Go to **Microsoft Sentinel** > **Analytics** > **Create** > **Scheduled query rule**
2. Configure a rule using KQL like:

```kusto
SOCcaCVE_CL
| where CVSS_Score_d >= 8.0
| where AffectedProducts_s has_any("Windows Server", "Azure", "Office 365")
```

#### 4. Create Incidents from Alerts

Configure analytics rules to generate incidents:

1. Set appropriate alert thresholds (e.g., CVSS ≥ 8.0)
2. Configure incident grouping by CVE ID
3. Set automated response playbooks (optional)

#### 5. Connect to MITRE ATT&CK Framework

Leverage the extracted MITRE ATT&CK data:

```kusto
// Find CVEs related to specific ATT&CK techniques
SOCcaCVE_CL
| where MitreAttackTactics_s has "T1190" // Exploit Public-Facing Application
```

## 🚀 Deployment Options

### Linux Server Deployment

Deploy SOCca on a Linux server using one of these approaches:

#### Quick Start with Startup Script

```bash
# Start all services using the startup script
chmod +x startup.sh
./startup.sh
```

#### Production Deployment with Systemd

For production environments, configure SOCca components as system services:

```bash
# Create systemd service files for reliable operation
sudo cp deployment/socca-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable socca-monitor socca-sentinel
sudo systemctl start socca-monitor socca-sentinel
```

For detailed instructions, see the [Deployment Guide](kryptos_working/deployment.md).

## 📊 Advanced Configuration

### Customizing AI Analysis

To modify how vulnerabilities are analyzed:

1. Edit the system prompts in `soccav5.py` 
2. Adjust the token handling for larger or more detailed reports
3. Update the reporting structure to include additional fields

### Scheduling and Automation

Configure automated exports to Microsoft Sentinel:

```bash
# Add to crontab for scheduled exports
0 * * * * cd /path/to/SOCcaAI && python3 kryptos_working/sentinel_exporter.py --direct-send --hours 1
```

## 📚 Documentation

- [Microsoft Sentinel Integration Guide](kryptos_working/microsoft_sentinel.md) - Comprehensive Sentinel integration details
- [Deployment Guide](kryptos_working/deployment.md) - Linux server deployment instructions
- [Quick Start Guide](kryptos_working/quickstart.md) - Complete setup and usage instructions

## 🔍 Troubleshooting

Common issues and solutions:

1. **Missing data in Sentinel**:
   - Verify SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY are correct
   - Check sentinel_exporter.log for API errors
   - Ensure network allows outbound HTTPS connections

2. **API rate limiting**:
   - Adjust POLLING_INTERVAL in .env file to reduce API calls
   - Consider using --hours parameter to limit data volume

3. **Database errors**:
   - Check file permissions on database files
   - Run `python setup.py` to reinitialize if necessary

## 📄 License

[License information]

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

If you encounter any issues or have questions, please open an issue on GitHub.
