# SOCca Linux Deployment Files

This directory contains files needed for deploying SOCca on Linux servers.

## Systemd Service Files

The following service files are provided:

1. `socca-monitor.service` - Runs the CVE monitoring component
2. `socca-sentinel.service` - Runs the Microsoft Sentinel export component

## Installation

1. Copy the service files to the systemd directory:
   ```bash
   sudo cp socca-*.service /etc/systemd/system/
   ```

2. Create the socca user and group:
   ```bash
   sudo groupadd socca
   sudo useradd -g socca -m -d /opt/socca socca
   ```

3. Install SOCca to the /opt/socca directory:
   ```bash
   sudo mkdir -p /opt/socca
   sudo git clone https://github.com/ianrelecker/SOCcaAI.git /opt/socca
   sudo chown -R socca:socca /opt/socca
   cd /opt/socca
   sudo -u socca ./install_dependencies.sh
   ```

4. Configure environment variables in `/opt/socca/.env`

5. Enable and start the services:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable socca-monitor socca-sentinel
   sudo systemctl start socca-monitor socca-sentinel
   ```

## Checking Service Status

```bash
sudo systemctl status socca-monitor
sudo systemctl status socca-sentinel
```

## Viewing Logs

```bash
sudo journalctl -u socca-monitor -f
sudo journalctl -u socca-sentinel -f
```

## Manual Operation

If you prefer not to use systemd, you can run SOCca manually:

```bash
cd /opt/socca
./startup.sh
```

This will start all SOCca components with proper logging.