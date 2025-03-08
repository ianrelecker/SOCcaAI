import os
import sqlite3
from typing import Dict, List, Optional


class DatabaseSchema:
    """Defines the schema for SOCca databases"""

    # Structure format: {table_name: sql_create_statement}
    SCHEMAS = {
        # processed_cves.db schema
        "processed_cves": {
            "processed_cves": """
                CREATE TABLE IF NOT EXISTS processed_cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    url TEXT,
                    pub TEXT,
                    data TEXT,
                    cata TEXT
                )
            """
        },
        
        # cve_reports.db schema
        "cve_reports": {
            "processed": """
                CREATE TABLE IF NOT EXISTS processed (
                    cve_id TEXT PRIMARY KEY,
                    report TEXT
                )
            """
        },
        
        # posts.db schema
        "posts": {
            "posts": """
                CREATE TABLE IF NOT EXISTS posts (
                    id TEXT PRIMARY KEY,
                    report TEXT
                )
            """
        },
        
        # kev_data.db schema
        "kev_data": {
            "kev_data": """
                CREATE TABLE IF NOT EXISTS kev_data (
                    id TEXT PRIMARY KEY,
                    cve_id TEXT,
                    name TEXT,
                    vendor_project TEXT,
                    product TEXT,
                    vulnerability_name TEXT,
                    date_added TEXT,
                    short_description TEXT,
                    required_action TEXT,
                    due_date TEXT,
                    notes TEXT
                )
            """
        },
        
        # alerts.db schema
        "alerts": {
            "sent_alerts": """
                CREATE TABLE IF NOT EXISTS sent_alerts (
                    cve_id TEXT PRIMARY KEY,
                    alert_time TIMESTAMP,
                    alert_type TEXT
                )
            """
        }
    }
    
    @classmethod
    def initialize_database(cls, db_name: str, db_path: Optional[str] = None) -> None:
        """
        Initialize a database with its schema
        
        Args:
            db_name: Name of the database (without .db extension)
            db_path: Path to the database file (optional)
        """
        if db_name not in cls.SCHEMAS:
            raise ValueError(f"Unknown database: {db_name}")
            
        # Determine database path
        if db_path:
            db_file = os.path.join(db_path, f"{db_name}.db")
        else:
            db_file = f"{db_name}.db"
            
        # Connect to the database
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Create tables
        for table_name, create_sql in cls.SCHEMAS[db_name].items():
            cursor.execute(create_sql)
            
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
        print(f"Initialized database: {db_file}")
    
    @classmethod
    def initialize_all_databases(cls, db_path: Optional[str] = None) -> None:
        """
        Initialize all databases with their schemas
        
        Args:
            db_path: Path where database files should be created (optional)
        """
        for db_name in cls.SCHEMAS:
            cls.initialize_database(db_name, db_path)


if __name__ == "__main__":
    # Initialize all databases when run directly
    DatabaseSchema.initialize_all_databases()