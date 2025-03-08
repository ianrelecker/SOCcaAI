#!/bin/bash
# SOCca Microsoft Sentinel Integration Installation Script

echo "Installing SOCca Microsoft Sentinel Integration dependencies..."

# Upgrade pip
python -m pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Install test dependencies
pip install pytest pytest-cov pytest-mock requests-mock

# Verify kryptos_working directory exists
if [ ! -d "kryptos_working" ]; then
  echo "ERROR: kryptos_working directory not found"
  exit 1
else
  echo "Found kryptos_working directory"
fi

# Create necessary directories
mkdir -p logs
mkdir -p data/exports
mkdir -p kryptos_working/data/sentinel_output
mkdir -p kryptos_working/logs

# Set executable permissions for scripts
chmod +x kryptos_working/sentinel_exporter.py
chmod +x kryptos_working/mainv2.py

echo "Installation complete!"