#!/bin/bash
# Startup script for SOCca Microsoft Sentinel integration on Linux

# Determine Python command
PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
  if command -v python &> /dev/null; then
    PYTHON_CMD="python"
  else
    echo "ERROR: Python 3 is not installed. Please install Python 3.8 or later."
    exit 1
  fi
fi

# Check if we can import the required modules
$PYTHON_CMD -c "import openai, requests, sqlite3" 2>/dev/null || {
  echo "ERROR: Required Python modules not found. Running install_dependencies.sh..."
  chmod +x install_dependencies.sh
  ./install_dependencies.sh
}

# Create necessary directories
mkdir -p logs
mkdir -p data/exports
mkdir -p kryptos_working/data/sentinel_output
mkdir -p kryptos_working/logs
mkdir -p kryptos_working/data/cache

# Log startup
echo "$(date) - SOCca starting up..." > logs/startup.log

# Load environment variables if .env exists
if [ -f ".env" ]; then
  export $(grep -v '^#' .env | xargs)
  echo "$(date) - Loaded environment variables from .env file" >> logs/startup.log
else
  echo "WARNING: .env file not found. Using system environment variables."
  echo "$(date) - WARNING: .env file not found" >> logs/startup.log
fi

# Run initialization and setup
$PYTHON_CMD setup.py --skip-import-prompt

# Set up logging
exec > >(tee -a logs/startup.log) 2>&1
echo "$(date) - Starting SOCca services for Microsoft Sentinel..."

# Start CVE monitoring in the background
echo "$(date) - Starting CVE monitoring..."
$PYTHON_CMD kryptos_working/mainv2.py &
MONITOR_PID=$!

# Wait for a few seconds for the services to start
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
    
    # Set up a cron-like job to run the Sentinel exporter every hour
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
    
    # Set up a cron-like job to run file exports every hour
    echo "$(date) - Setting up hourly file export job..."
    while true; do
        sleep 3600  # Wait for 1 hour
        echo "$(date) - Running scheduled file export..."
        $PYTHON_CMD kryptos_working/sentinel_exporter.py --file-export --format ndjson --hours 1
    done &
    EXPORT_PID=$!
fi

# Trap the SIGTERM and SIGINT signals to properly shut down
trap 'echo "$(date) - Shutting down SOCca services..."; kill $MONITOR_PID 2>/dev/null; kill $SENTINEL_PID 2>/dev/null; kill $EXPORT_PID 2>/dev/null; exit 0' SIGTERM SIGINT

# Wait for the monitor process to complete (this will block)
wait $MONITOR_PID