import argparse
import json
import os
import sqlite3
import sys
from typing import Dict, List, Optional, Any

from db_schema import DatabaseSchema

# Ensure data directory exists
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
EXPORTS_DIR = os.path.join(DATA_DIR, "exports")


def connect_db(db_name: str, create_if_missing: bool = True) -> sqlite3.Connection:
    """
    Connect to a database
    
    Args:
        db_name: Name of the database (with or without .db extension)
        create_if_missing: Whether to create the database if it doesn't exist
        
    Returns:
        sqlite3.Connection: Database connection
    """
    if not db_name.endswith(".db"):
        db_name = f"{db_name}.db"
        
    # Check if database exists
    db_exists = os.path.exists(db_name)
    
    if not db_exists and not create_if_missing:
        print(f"Error: Database file {db_name} not found")
        sys.exit(1)
        
    # Connect to the database
    conn = sqlite3.connect(db_name)
    
    # Initialize schema if database was just created
    if not db_exists and create_if_missing:
        db_base_name = os.path.basename(db_name)
        if db_base_name.endswith(".db"):
            db_base_name = db_base_name[:-3]
            
        # Check if we have schema for this database
        if db_base_name in DatabaseSchema.SCHEMAS:
            # Create tables
            cursor = conn.cursor()
            for table_name, create_sql in DatabaseSchema.SCHEMAS[db_base_name].items():
                cursor.execute(create_sql)
            conn.commit()
            print(f"Initialized database schema for {db_name}")
            
    return conn


def import_table(conn: sqlite3.Connection, table_name: str, data: List[Dict[str, Any]]) -> int:
    """
    Import data into a table
    
    Args:
        conn: Database connection
        table_name: Name of the table
        data: List of dictionaries with column:value pairs
        
    Returns:
        int: Number of rows imported
    """
    if not data:
        print(f"No data to import for table {table_name}")
        return 0
        
    cursor = conn.cursor()
    
    # Check if table exists
    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
    if not cursor.fetchone():
        print(f"Error: Table {table_name} not found in the database")
        return 0
        
    # Get column names from the first row
    columns = list(data[0].keys())
    
    # Prepare placeholders for the SQL query
    placeholders = ", ".join(["?" for _ in columns])
    column_str = ", ".join(columns)
    
    # Insert data
    count = 0
    for row in data:
        values = [row.get(col) for col in columns]
        try:
            cursor.execute(f"INSERT OR REPLACE INTO {table_name} ({column_str}) VALUES ({placeholders})", values)
            count += 1
        except sqlite3.Error as e:
            print(f"Error importing row: {e}")
    
    # Commit changes
    conn.commit()
    
    return count


def import_database(json_path: str, db_name: Optional[str] = None) -> None:
    """
    Import data from JSON into a database
    
    Args:
        json_path: Path to the JSON file
        db_name: Name of the database to import into (optional)
    """
    # Load JSON data
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading JSON file: {e}")
        sys.exit(1)
        
    # Determine database name if not provided
    if not db_name:
        # Try to infer from JSON filename (assuming export format naming)
        db_name = os.path.basename(json_path).split('_')[0]
        if not db_name.endswith(".db"):
            db_name = f"{db_name}.db"
            
    # Connect to the database
    conn = connect_db(db_name)
    
    # Import each table
    total_rows = 0
    for table_name, table_data in data.items():
        rows_imported = import_table(conn, table_name, table_data)
        print(f"Imported {rows_imported} rows into {table_name}")
        total_rows += rows_imported
        
    # Close connection
    conn.close()
    
    print(f"Database import completed. Total rows imported: {total_rows}")


def import_all_databases(export_dir: str) -> None:
    """
    Import all databases from a directory
    
    Args:
        export_dir: Directory containing exported database JSON files
    """
    if not os.path.isdir(export_dir):
        print(f"Error: Directory {export_dir} not found")
        sys.exit(1)
        
    # Get all JSON files in the directory
    json_files = [f for f in os.listdir(export_dir) if f.endswith('.json')]
    
    if not json_files:
        print(f"No JSON files found in {export_dir}")
        return
        
    # Import each file
    for json_file in json_files:
        # Extract database name
        db_name = json_file.split('.')[0]
        if not db_name.endswith(".db"):
            db_name = f"{db_name}.db"
            
        # Import the database
        import_database(os.path.join(export_dir, json_file), db_name)


def main() -> None:
    """Main function"""
    parser = argparse.ArgumentParser(description="Import SOCca databases from JSON")
    parser.add_argument("--input", type=str, help="JSON file or directory to import")
    parser.add_argument("--db", type=str, help="Database to import into (optional, will try to infer from filename)")
    
    args = parser.parse_args()
    
    if not args.input:
        print("Error: --input argument is required")
        sys.exit(1)
        
    if os.path.isdir(args.input):
        import_all_databases(args.input)
    else:
        import_database(args.input, args.db)


if __name__ == "__main__":
    main()