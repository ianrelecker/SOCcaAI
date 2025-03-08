#!/bin/bash
# Startup script for SOCca Microsoft Sentinel integration on Linux

# Create necessary directories
mkdir -p logs
mkdir -p data/exports
mkdir -p kryptos_working/data/sentinel_output
mkdir -p kryptos_working/logs

# Run initialization and setup
python setup.py --skip-import-prompt

# Set up logging
exec > >(tee -a logs/startup.log) 2>&1
echo "$(date) - Starting SOCca services for Microsoft Sentinel..."

# Start CVE monitoring in the background
echo "$(date) - Starting CVE monitoring..."
python kryptos_working/mainv2.py &
MONITOR_PID=$!

# Wait for a few seconds for the services to start
sleep 5

# Check if environment variables are set for Microsoft Sentinel integration
if [[ -n "$SENTINEL_WORKSPACE_ID" && -n "$SENTINEL_PRIMARY_KEY" ]]; then
    echo "$(date) - Microsoft Sentinel integration is configured"
    
    # Run the Sentinel exporter with direct send once at startup
    echo "$(date) - Running initial export to Microsoft Sentinel..."
    python kryptos_working/sentinel_exporter.py --direct-send --hours 24
    
    # Generate alert templates once at startup
    echo "$(date) - Generating Microsoft Sentinel alert templates..."
    python kryptos_working/sentinel_exporter.py --alerts
    
    # Set up a cron-like job to run the Sentinel exporter every hour
    echo "$(date) - Setting up hourly Microsoft Sentinel export job..."
    while true; do
        sleep 3600  # Wait for 1 hour
        echo "$(date) - Running scheduled Microsoft Sentinel export..."
        python kryptos_working/sentinel_exporter.py --direct-send --hours 1
    done &
    SENTINEL_PID=$!
else
    echo "$(date) - WARNING: Microsoft Sentinel integration not configured"
    echo "$(date) - Set SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY environment variables to enable"
    
    # Export to file as a fallback
    echo "$(date) - Running file export mode instead..."
    python kryptos_working/sentinel_exporter.py --file-export --format ndjson
    
    # Set up a cron-like job to run file exports every hour
    echo "$(date) - Setting up hourly file export job..."
    while true; do
        sleep 3600  # Wait for 1 hour
        echo "$(date) - Running scheduled file export..."
        python kryptos_working/sentinel_exporter.py --file-export --format ndjson --hours 1
    done &
    EXPORT_PID=$!
fi

# Wait for the monitor process to complete (this will block)
wait $MONITOR_PID