# SOCca Quickstart Guide

This guide provides a quick overview of how to get SOCca up and running with Microsoft Sentinel integration.

## Prerequisites

Before starting, ensure you have:

- Python 3.8 or newer
- An NVD API key (request one at https://nvd.nist.gov/developers/request-an-api-key)
- An OpenAI API key with access to OpenAI's models
- Microsoft Sentinel workspace credentials (Workspace ID and Primary Key)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/soccav2.git
cd soccav2
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Up Environment

```bash
cp .env.example .env
nano .env  # Or use any text editor to edit this file
```

Add your API keys and other settings to the `.env` file:

```
# Required API Keys
NVD_API_KEY=your_nvd_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Microsoft Sentinel Integration
SENTINEL_WORKSPACE_ID=your-sentinel-workspace-id
SENTINEL_PRIMARY_KEY=your-sentinel-primary-key
SENTINEL_LOG_TYPE=SOCcaCVE
SENTINEL_API_VERSION=2016-04-01
```

### 4. Initialize the System

```bash
python setup.py
```

This will:
- Create necessary directories
- Set up database schemas
- Import any available data (if you answer "yes" to the prompt)

## Running SOCca

SOCca consists of several components that work together. You'll need to run each in a separate terminal window:

### Component 1: CVE Monitor

Polls for new vulnerabilities and triggers analysis:

```bash
python kryptos_working/mainv2.py
```

### Component 2: Microsoft Sentinel Exporter

Integrates with Microsoft Sentinel through direct API or file exports:

```bash
# Direct API integration with Microsoft Sentinel
python kryptos_working/sentinel_exporter.py --direct-send

# Export to file for manual import to Sentinel
python kryptos_working/sentinel_exporter.py --file-export

# Generate Sentinel alert templates
python kryptos_working/sentinel_exporter.py --alerts

# Send only high severity CVEs from the last 24 hours
python kryptos_working/sentinel_exporter.py --direct-send --hours 24 --min-cvss 7.0
```

## Testing Your Setup

Once all components are running:

1. Watch the output of `mainv2.py` - it should show "Polling NVD API" messages
2. After a few minutes, you should see new CVEs being processed
3. Check for Sentinel Exporter outputs:
   ```bash
   # Check for generated output files
   ls -la kryptos_working/data/sentinel_output/
   
   # Run with direct integration and check the logs
   python kryptos_working/sentinel_exporter.py --direct-send --verbose
   ```

4. Verify data in Microsoft Sentinel:
   - Log into Azure Portal
   - Navigate to your Log Analytics workspace
   - Run a query like: `SOCcaCVE_CL | limit 10`

## Troubleshooting

If you encounter issues:

- Check log files in the `kryptos_working/logs/` directory
- Verify your API keys are correct in the `.env` file
- Make sure all dependencies were properly installed
- Check that your database files have proper permissions
- Verify Microsoft Sentinel workspace ID and primary key are valid

## Next Steps

Once your basic setup is running:

1. Customize the prompts in `soccav5.py` to match your reporting style
2. Adjust detection thresholds in `.env` file
3. Create Microsoft Sentinel workbooks to visualize the data
4. Set up alert rules based on the generated templates
5. Explore the database exports feature for backing up your data

For more advanced configuration, refer to the [Microsoft Sentinel Integration Guide](microsoft_sentinel.md).

## Running as a Service

For production use, you should run SOCca components as system services.

Example systemd service file (create in `/etc/systemd/system/socca-monitor.service`):

```ini
[Unit]
Description=SOCca CVE Monitor
After=network.target

[Service]
User=youruser
WorkingDirectory=/path/to/soccav2
ExecStart=/usr/bin/python /path/to/soccav2/kryptos_working/mainv2.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Create similar files for each component, then enable and start the services:

```bash
sudo systemctl enable socca-monitor
sudo systemctl start socca-monitor
```

For the Microsoft Sentinel Exporter, you might want to set up a cron job for scheduled exports:

```bash
# Send new CVEs to Microsoft Sentinel every hour
0 * * * * cd /path/to/soccav2 && python kryptos_working/sentinel_exporter.py --direct-send --hours 1

# Generate new alert templates once a day
0 0 * * * cd /path/to/soccav2 && python kryptos_working/sentinel_exporter.py --alerts

# Create file exports as backup once a day
30 0 * * * cd /path/to/soccav2 && python kryptos_working/sentinel_exporter.py --file-export
```

## Linux Server Deployment

For deployment to a Linux server, refer to the [Deployment Guide](deployment.md) for detailed instructions on:

- Setting up systemd services for continuous operation
- Using screen or tmux for development environments
- Running with the provided startup.sh script
- Monitoring and troubleshooting service logs