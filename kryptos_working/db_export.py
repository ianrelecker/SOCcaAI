import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime
from typing import Dict, List, Optional, Union, Any

# Ensure data directory exists
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
EXPORTS_DIR = os.path.join(DATA_DIR, "exports")
os.makedirs(EXPORTS_DIR, exist_ok=True)


def connect_db(db_name: str) -> sqlite3.Connection:
    """
    Connect to a database
    
    Args:
        db_name: Name of the database (with or without .db extension)
        
    Returns:
        sqlite3.Connection: Database connection
    """
    if not db_name.endswith(".db"):
        db_name = f"{db_name}.db"
        
    # Check if database exists
    if not os.path.exists(db_name):
        print(f"Error: Database file {db_name} not found")
        sys.exit(1)
        
    # Connect to the database
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn


def export_table(conn: sqlite3.Connection, table_name: str) -> List[Dict[str, Any]]:
    """
    Export a table to a list of dictionaries
    
    Args:
        conn: Database connection
        table_name: Name of the table to export
        
    Returns:
        List[Dict]: Table data as a list of dictionaries
    """
    cursor = conn.cursor()
    
    # Check if table exists
    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
    if not cursor.fetchone():
        print(f"Error: Table {table_name} not found in the database")
        return []
        
    # Get all rows from the table
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    
    # Convert rows to dictionaries
    return [dict(row) for row in rows]


def export_database(db_name: str, output_path: Optional[str] = None) -> None:
    """
    Export a database to JSON
    
    Args:
        db_name: Name of the database (with or without .db extension)
        output_path: Path to save the JSON file (optional)
    """
    # Clean db_name
    base_name = os.path.basename(db_name)
    if base_name.endswith(".db"):
        base_name = base_name[:-3]
        
    # Connect to the database
    conn = connect_db(db_name)
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row['name'] for row in cursor.fetchall()]
    
    # Export each table
    data = {}
    for table in tables:
        data[table] = export_table(conn, table)
        print(f"Exported {len(data[table])} rows from {table}")
        
    # Close connection
    conn.close()
    
    # Determine output path
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(EXPORTS_DIR, f"{base_name}_{timestamp}.json")
        
    # Save to JSON
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
        
    print(f"Database exported to {output_path}")
    return output_path


def export_all_databases() -> None:
    """Export all databases to JSON"""
    # List of databases to export
    databases = ["processed_cves.db", "cve_reports.db", "posts.db", "kev_data.db"]
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create directory for this export
    export_dir = os.path.join(EXPORTS_DIR, f"full_export_{timestamp}")
    os.makedirs(export_dir, exist_ok=True)
    
    # Export each database
    for db in databases:
        if os.path.exists(db):
            output_path = os.path.join(export_dir, f"{os.path.basename(db)[:-3]}.json")
            export_database(db, output_path)
        else:
            print(f"Warning: Database {db} not found, skipping")
            
    print(f"All databases exported to {export_dir}")


def main() -> None:
    """Main function"""
    parser = argparse.ArgumentParser(description="Export SOCca databases to JSON")
    parser.add_argument("--db", type=str, help="Database to export (omit for all)")
    parser.add_argument("--output", type=str, help="Output path for the JSON file")
    
    args = parser.parse_args()
    
    if args.db:
        export_database(args.db, args.output)
    else:
        export_all_databases()


if __name__ == "__main__":
    main()