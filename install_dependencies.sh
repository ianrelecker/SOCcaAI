#!/bin/bash
# SOCca Microsoft Sentinel Integration Installation Script

echo "Installing SOCca Microsoft Sentinel Integration dependencies..."

# Check for Python installation
if ! command -v python3 &> /dev/null; then
  echo "Python 3 is not installed. Please install Python 3.8 or later."
  echo "On Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv"
  echo "On CentOS/RHEL: sudo yum install -y python3 python3-pip"
  exit 1
fi

# Check for pip installation
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
  echo "pip is not installed. Installing pip..."
  if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y python3-pip
  elif command -v yum &> /dev/null; then
    sudo yum install -y python3-pip
  else
    echo "Unsupported package manager. Please install pip manually."
    exit 1
  fi
fi

# Determine pip command (some systems use pip3, others use pip)
PIP_CMD="pip"
if command -v pip3 &> /dev/null; then
  PIP_CMD="pip3"
fi

# Upgrade pip
python3 -m $PIP_CMD install --upgrade pip

# Install system dependencies if needed
if command -v apt-get &> /dev/null; then
  echo "Installing system dependencies..."
  sudo apt-get update && sudo apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    libxml2-dev \
    libxslt1-dev
elif command -v yum &> /dev/null; then
  echo "Installing system dependencies..."
  sudo yum install -y \
    gcc \
    openssl-devel \
    libffi-devel \
    python3-devel \
    libxml2-devel \
    libxslt-devel
fi

# Install dependencies
$PIP_CMD install -r requirements.txt

# Install test dependencies
$PIP_CMD install pytest pytest-cov pytest-mock requests-mock

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
mkdir -p kryptos_working/data/cache

# Set executable permissions for scripts
chmod +x kryptos_working/sentinel_exporter.py
chmod +x kryptos_working/mainv2.py
chmod +x kryptos_working/db_export.py
chmod +x kryptos_working/db_import.py
chmod +x startup.sh

# Check if sqlite3 is installed
if ! command -v sqlite3 &> /dev/null; then
  echo "SQLite3 is not installed. Installing SQLite3..."
  if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y sqlite3
  elif command -v yum &> /dev/null; then
    sudo yum install -y sqlite
  else
    echo "Warning: SQLite3 command-line tool not installed. You may need to install it manually."
  fi
fi

# Verify .env file exists or create from example
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  echo "Creating .env file from example..."
  cp .env.example .env
  echo "Please edit the .env file with your API keys and configuration"
fi

echo "Running a quick import test..."
python3 test_imports.py || echo "Warning: Import test failed. This might be expected if you haven't configured your .env file yet."

echo "Installation complete!"
echo
echo "Next Steps:"
echo "1. Edit the .env file with your API keys and Sentinel workspace credentials"
echo "2. Run 'python3 setup.py' to initialize the database"
echo "3. Start SOCca with './startup.sh' or run individual components"