#!/bin/bash
# Docker-optimized startup script for SOCca Microsoft Sentinel integration

# Use fixed Python command for Docker
PYTHON_CMD="python"

# Set up logging to stdout for Docker
echo "$(date) - SOCca starting up in Docker container..."

# Create necessary directories if they don't exist (should already be created in Dockerfile)
mkdir -p /app/logs
mkdir -p /app/kryptos_working/data/sentinel_output
mkdir -p /app/kryptos_working/logs
mkdir -p /app/kryptos_working/data/cache

# Environment variables are already loaded in Docker container

# Run initialization and setup
$PYTHON_CMD setup.py --skip-import-prompt

echo "$(date) - Starting SOCca services for Microsoft Sentinel..."

# Start CVE monitoring in background
echo "$(date) - Starting CVE monitoring..."
$PYTHON_CMD kryptos_working/mainv2.py &
MONITOR_PID=$!

# Wait for services to start
sleep 5

# Check if environment variables are set for Microsoft Sentinel integration
if [[ -n "$SENTINEL_WORKSPACE_ID" && -n "$SENTINEL_PRIMARY_KEY" ]]; then
    echo "$(date) - Microsoft Sentinel integration is configured"
    
    # Run the Sentinel exporter with direct send once at startup
    echo "$(date) - Running initial export to Microsoft Sentinel..."
    $PYTHON_CMD kryptos_working/sentinel_exporter.py --direct-send --hours 24
    
    # Generate alert templates once at startup
    echo "$(date) - Generating Microsoft Sentinel alert templates..."
    $PYTHON_CMD kryptos_working/sentinel_exporter.py --alerts
    
    # Set up a job to run the Sentinel exporter every hour
    echo "$(date) - Setting up hourly Microsoft Sentinel export job..."
    while true; do
        sleep 3600  # Wait for 1 hour
        echo "$(date) - Running scheduled Microsoft Sentinel export..."
        $PYTHON_CMD kryptos_working/sentinel_exporter.py --direct-send --hours 1
    done &
    SENTINEL_PID=$!
else
    echo "$(date) - WARNING: Microsoft Sentinel integration not configured"
    echo "$(date) - Set SENTINEL_WORKSPACE_ID and SENTINEL_PRIMARY_KEY environment variables to enable"
    
    # Export to file as a fallback
    echo "$(date) - Running file export mode instead..."
    $PYTHON_CMD kryptos_working/sentinel_exporter.py --file-export --format ndjson
    
    # Set up a job to run file exports every hour
    echo "$(date) - Setting up hourly file export job..."
    while true; do
        sleep 3600  # Wait for 1 hour
        echo "$(date) - Running scheduled file export..."
        $PYTHON_CMD kryptos_working/sentinel_exporter.py --file-export --format ndjson --hours 1
    done &
    EXPORT_PID=$!
fi

# Handle Docker stop/term signals
trap 'echo "$(date) - Shutting down SOCca services..."; kill $MONITOR_PID 2>/dev/null; kill $SENTINEL_PID 2>/dev/null; kill $EXPORT_PID 2>/dev/null; exit 0' SIGTERM SIGINT

# Wait for the monitor process (this will keep the container running)
wait $MONITOR_PID