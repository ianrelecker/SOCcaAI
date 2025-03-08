# SOCca Quickstart Guide

This guide provides step-by-step instructions for setting up SOCca on a Linux server with Microsoft Sentinel integration.

## Prerequisites

Before starting, ensure you have:

- Linux server with Python 3.8 or newer
- An NVD API key (request one at https://nvd.nist.gov/developers/request-an-api-key)
- An OpenAI API key with access to OpenAI's models
- Microsoft Sentinel workspace credentials (Workspace ID and Primary Key)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/ianrelecker/SOCcaAI.git
cd SOCcaAI
```

### 2. Install Dependencies

The easiest way to install dependencies is to use the provided installation script:

```bash
chmod +x install_dependencies.sh
./install_dependencies.sh
```

This script will:
- Check for Python and pip
- Install required system libraries
- Install Python dependencies
- Create necessary directories
- Set executable permissions on scripts

Alternatively, you can manually install the Python dependencies:

```bash
python3 -m pip install -r requirements.txt
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
python3 setup.py
```

This will:
- Create necessary directories
- Set up database schemas
- Import any available data (if you answer "yes" to the prompt)

## Running SOCca

You have several options for running SOCca:

### Option 1: Quick Start with Startup Script (Recommended for Testing)

The startup script will launch all components automatically:

```bash
chmod +x startup.sh
./startup.sh
```

This will start both the CVE Monitor and Sentinel Exporter in the background, with proper logging to the `logs` directory.

### Option 2: Run Components Manually (Development Mode)

You can run each component in a separate terminal window:

```bash
# Terminal 1: CVE Monitor
python3 kryptos_working/mainv2.py

# Terminal 2: Microsoft Sentinel Exporter
python3 kryptos_working/sentinel_exporter.py --direct-send
```

### Option 3: Run as System Services (Production Mode)

For production environments, use the provided systemd service files:

```bash
# Copy service files
sudo cp deployment/socca-*.service /etc/systemd/system/

# Adjust paths in the service files if needed
sudo nano /etc/systemd/system/socca-monitor.service
sudo nano /etc/systemd/system/socca-sentinel.service

# Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable socca-monitor socca-sentinel
sudo systemctl start socca-monitor socca-sentinel
```

## Microsoft Sentinel Integration Options

```bash
# Direct API integration with Microsoft Sentinel
python3 kryptos_working/sentinel_exporter.py --direct-send

# Export to file for manual import to Sentinel
python3 kryptos_working/sentinel_exporter.py --file-export

# Generate Sentinel alert templates
python3 kryptos_working/sentinel_exporter.py --alerts

# Send only high severity CVEs from the last 24 hours
python3 kryptos_working/sentinel_exporter.py --direct-send --hours 24 --min-cvss 7.0
```

## Testing Your Setup

Once all components are running:

1. Check the logs:
   ```bash
   tail -f logs/startup.log
   tail -f kryptos_working/logs/sentinel_exporter.log
   ```

2. Verify files are being created:
   ```bash
   ls -la kryptos_working/data/sentinel_output/
   ```

3. Verify data in Microsoft Sentinel:
   - Log into Azure Portal
   - Navigate to your Log Analytics workspace
   - Run a query like: `SOCcaCVE_CL | limit 10`

## Troubleshooting

If you encounter issues:

- **Missing dependencies**: Run `./install_dependencies.sh` again
- **Permission issues**: Check file permissions with `ls -la` and fix with `chmod`
- **API key issues**: Verify API keys in your `.env` file
- **Python version**: Make sure you're using Python 3.8+ with `python3 --version`
- **Service failures**: Check service logs with `sudo journalctl -u socca-monitor`
- **Network issues**: Verify outbound HTTPS connectivity to Microsoft Sentinel

## Cron Jobs (Alternative to Services)

If you prefer using cron jobs instead of systemd:

```bash
# Edit your crontab
crontab -e

# Add these entries
@reboot cd /path/to/SOCcaAI && ./startup.sh
0 * * * * cd /path/to/SOCcaAI && python3 kryptos_working/sentinel_exporter.py --direct-send --hours 1
0 0 * * * cd /path/to/SOCcaAI && python3 kryptos_working/sentinel_exporter.py --alerts
```

## Next Steps

Once your setup is working:

1. Customize AI analysis in `soccav5.py`
2. Create Sentinel workbooks for visualization
3. Import alert templates into Sentinel
4. Set up a backup strategy for the SQLite databases
5. Explore advanced configuration options in the [Deployment Guide](deployment.md)