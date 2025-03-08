# SOCca Deployment Guide

This document provides detailed instructions for deploying SOCca on a Linux server.

## Linux Server Deployment

### Prerequisites

1. Python 3.8+ installed on your system
2. Git for cloning the repository
3. API keys:
   - NVD API key (free from https://nvd.nist.gov/developers/request-an-api-key)
   - OpenAI API key
   - Microsoft Sentinel workspace credentials (Workspace ID and Primary Key)

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ianrelecker/SOCcaAI.git
   cd SOCcaAI
   ```

2. **Install dependencies**:
   ```bash
   # Make the installation script executable
   chmod +x install_dependencies.sh
   
   # Run the installation script
   ./install_dependencies.sh
   ```
   
   The script will:
   - Install required Python packages
   - Create necessary directories
   - Set up symbolic links for kryptos_working
   - Set executable permissions on scripts

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and configuration
   nano .env
   ```
   
   Key environment variables to configure:
   - `NVD_API_KEY`: Your NVD API key
   - `OPENAI_API_KEY`: Your OpenAI API key
   - Microsoft Sentinel integration settings:
     - `SENTINEL_WORKSPACE_ID`: Your Sentinel workspace ID
     - `SENTINEL_PRIMARY_KEY`: Your Sentinel primary key
     - `SENTINEL_LOG_TYPE`: Custom log type (default: SOCcaCVE)
     - `SENTINEL_API_VERSION`: API version (default: 2016-04-01)

4. **Initialize databases**:
   ```bash
   python setup.py
   ```

### Running SOCca as Services

For production environments, you should configure SOCca components to run as services using systemd:

1. **Create systemd service files**:

   Create a service file for the CVE Monitor (save as `/etc/systemd/system/socca-monitor.service`):
   ```ini
   [Unit]
   Description=SOCca CVE Monitor
   After=network.target
   
   [Service]
   User=youruser
   WorkingDirectory=/path/to/SOCcaAI
   ExecStart=/usr/bin/python /path/to/SOCcaAI/kryptos_working/mainv2.py
   Restart=on-failure
   
   [Install]
   WantedBy=multi-user.target
   ```

   Create a service file for the Sentinel Exporter (save as `/etc/systemd/system/socca-sentinel.service`):
   ```ini
   [Unit]
   Description=SOCca Sentinel Exporter
   After=network.target socca-monitor.service
   
   [Service]
   User=youruser
   WorkingDirectory=/path/to/SOCcaAI
   ExecStart=/bin/bash -c 'while true; do python /path/to/SOCcaAI/kryptos_working/sentinel_exporter.py --direct-send --hours 1; sleep 3600; done'
   Restart=on-failure
   
   [Install]
   WantedBy=multi-user.target
   ```

2. **Enable and start the services**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable socca-monitor socca-sentinel
   sudo systemctl start socca-monitor socca-sentinel
   ```

3. **Check service status**:
   ```bash
   sudo systemctl status socca-monitor
   sudo systemctl status socca-sentinel
   ```

### Alternative: Running with the Startup Script

You can also use the provided startup script to run all components:

```bash
chmod +x startup.sh
./startup.sh
```

This script will start the CVE monitoring and Sentinel export processes, keeping them running in the background.

For long-term deployments with high reliability, the systemd service approach is recommended.

### Running with Screen or Tmux

For testing or development, you can use screen or tmux to run components in detached sessions:

```bash
# Install screen if needed
sudo apt-get install screen

# Start the CVE monitor in a screen session
screen -S socca-monitor
python kryptos_working/mainv2.py
# Press Ctrl+A, D to detach

# Start the Sentinel exporter in another screen session
screen -S socca-sentinel
python kryptos_working/sentinel_exporter.py --direct-send
# Press Ctrl+A, D to detach

# Reattach to sessions when needed
screen -r socca-monitor
screen -r socca-sentinel
```

## Troubleshooting

### Common Deployment Issues

1. **Missing dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Permission issues with scripts**:
   ```bash
   chmod +x kryptos_working/*.py
   ```

3. **Database initialization failures**:
   ```bash
   # Remove existing databases and recreate
   rm -f *.db
   python setup.py
   ```

4. **Service startup failures**:
   ```bash
   # Check service logs
   sudo journalctl -u socca-monitor
   sudo journalctl -u socca-sentinel
   ```

5. **Microsoft Sentinel integration failures**:
   - Verify workspace ID and primary key are correct
   - Check logs for connection errors to Microsoft Sentinel
   - Verify outbound HTTPS traffic is allowed

## References

- [Microsoft Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)
- [Log Analytics Data Collector API](https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)
- [Systemd Service Documentation](https://www.freedesktop.org/software/systemd/man/systemd.service.html)