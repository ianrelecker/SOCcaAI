#!/usr/bin/env python3
"""
SOCca Setup Script

This script initializes the SOCca environment:
1. Creates database schema
2. Sets up directories
3. Imports data if available
"""

import argparse
import os
import shutil
import sys
import logging
from pathlib import Path

# Add project root to path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('setup')

try:
    # Add the kryptos_working directory to the Python path
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "kryptos_working"))
    
    # Try direct imports to avoid package issues
    from db_schema import DatabaseSchema
    from db_import import import_database, import_all_databases
except ImportError as e:
    logger.error(f"Failed to import required modules: {e}")
    logger.error("Make sure you've installed the requirements.")
    logger.error("Run: pip install -r requirements.txt")
    sys.exit(1)

def create_directories():
    """Create necessary directories for SOCca"""
    # Define directories
    directories = [
        "data",
        "data/exports",
        "logs",
    ]
    
    # Create directories
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Created directory: {directory}")


def check_for_data_imports():
    """Check for data imports and import if available"""
    # Check for data directory
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    if not os.path.exists(data_dir):
        return
    
    # Check for exports directory
    exports_dir = os.path.join(data_dir, "exports")
    if not os.path.exists(exports_dir):
        return
    
    # Check for most recent full export
    full_exports = [d for d in os.listdir(exports_dir) if d.startswith("full_export_")]
    if full_exports:
        # Sort by timestamp (assuming format full_export_YYYYMMDD_HHMMSS)
        full_exports.sort(reverse=True)
        latest_export = os.path.join(exports_dir, full_exports[0])
        
        logger.info(f"Found data export: {latest_export}")
        import_choice = input("Do you want to import this data? (y/n): ")
        
        if import_choice.lower() == 'y':
            import_all_databases(latest_export)
    
    # Check for individual exports
    json_files = [f for f in os.listdir(exports_dir) if f.endswith('.json') and not os.path.isdir(os.path.join(exports_dir, f))]
    if json_files and not full_exports:
        logger.info(f"Found {len(json_files)} individual data exports")
        import_choice = input("Do you want to import these files? (y/n): ")
        
        if import_choice.lower() == 'y':
            for json_file in json_files:
                db_name = json_file.split('_')[0]
                if not db_name.endswith(".db"):
                    db_name = f"{db_name}.db"
                import_database(os.path.join(exports_dir, json_file), db_name)


def setup_env_file():
    """Setup environment file if not exists"""
    env_example = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env.example")
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    
    if os.path.exists(env_example) and not os.path.exists(env_file):
        shutil.copy(env_example, env_file)
        logger.info(f"Created .env file from .env.example. Please update with your credentials.")
        
        # Highlight required fields
        print("\n" + "="*80)
        print("IMPORTANT: Edit your .env file to include at least these required settings:")
        print("  - NVD_API_KEY: Get from https://nvd.nist.gov/developers/request-an-api-key")
        print("  - OPENAI_API_KEY: Get from https://platform.openai.com/api-keys")
        print("  - SIEM integration settings (if using direct integration with SIEM platforms)")
        print("="*80 + "\n")


def handle_initial_backup():
    """Check for initial backup data in the repository"""
    backup_dir = None
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "exports")
    
    if os.path.exists(data_dir):
        # Find initial_backup directories
        initial_backups = [d for d in os.listdir(data_dir) if d.startswith("initial_backup_")]
        if initial_backups:
            # Sort by date (assuming format initial_backup_YYYYMMDD)
            initial_backups.sort(reverse=True)
            backup_dir = os.path.join(data_dir, initial_backups[0])
            
    if backup_dir and os.path.isdir(backup_dir):
        logger.info(f"Found initial backup data: {backup_dir}")
        import_choice = input("Would you like to import the initial dataset? This is recommended for first-time setup (y/n): ")
        
        if import_choice.lower() == 'y':
            logger.info("Importing initial data...")
            import_all_databases(backup_dir)
            return True
    
    return False


def main():
    """Main setup function"""
    parser = argparse.ArgumentParser(description="Setup SOCca environment")
    parser.add_argument("--import-data", type=str, help="Path to data export to import")
    parser.add_argument("--skip-import-prompt", action="store_true", help="Skip data import prompt")
    parser.add_argument("--yes", "-y", action="store_true", help="Answer yes to all prompts")
    
    args = parser.parse_args()
    
    print("\n" + "="*80)
    print("                 SOCca - AI-Powered Vulnerability Intelligence Platform")
    print("="*80 + "\n")
    
    logger.info("Setting up SOCca environment...")
    
    # Create directories
    create_directories()
    
    # Setup environment file
    setup_env_file()
    
    # Initialize database schemas
    logger.info("Initializing database schemas...")
    DatabaseSchema.initialize_all_databases()
    
    # Import data if specified
    if args.import_data:
        logger.info(f"Importing data from {args.import_data}...")
        if os.path.isdir(args.import_data):
            import_all_databases(args.import_data)
        else:
            import_database(args.import_data)
    elif not args.skip_import_prompt:
        # Check for initial backup data
        initial_import_success = handle_initial_backup()
        
        # If no initial import, check for other imports
        if not initial_import_success:
            logger.info("Checking for other data imports...")
            check_for_data_imports()
    
    print("\n" + "="*80)
    print("Setup complete! You can now run SOCca.")
    print("\nTo start the platform, run these components in separate terminals:")
    print("1. python kryptos_working/mainv2.py         (CVE Monitor)")
    print("2. python kryptos_working/sentinel_exporter.py --direct-send  (Microsoft Sentinel Integration)")
    print("\nOr run all components with a single command:")
    print("./startup.sh")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()