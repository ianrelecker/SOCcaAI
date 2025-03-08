import pytest
import json
import sys
import os
import sqlite3
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Since we're testing functions from soccav5.py
from kryptos_working.soccav5 import urllogic, savereport

@pytest.fixture
def setup_db():
    """Create a test database connection and cursor"""
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # Create the necessary tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS processed (
        cve_id TEXT PRIMARY KEY,
        report TEXT
    )
    ''')
    
    yield conn, cursor
    
    # Clean up
    conn.close()

def test_urllogic_success():
    """Test URL parsing with successful requests"""
    with patch('requests.get') as mock_get:
        # Setup mock responses
        mock_response = MagicMock()
        mock_response.text = '<html><body><div class="content">Test content</div></body></html>'
        mock_get.return_value = mock_response
        
        # Create a mock for BeautifulSoup
        with patch('kryptos_working.soccav5.BeautifulSoup') as mock_bs:
            mock_bs_instance = MagicMock()
            mock_bs_instance.get_text.return_value = "Test content extracted"
            mock_bs.return_value = mock_bs_instance
            
            # Create a mock for Document
            with patch('kryptos_working.soccav5.Document') as mock_doc:
                mock_doc_instance = MagicMock()
                mock_doc_instance.summary.return_value = '<div>Test content</div>'
                mock_doc.return_value = mock_doc_instance
                
                # Test the function
                result = urllogic("['http://example.com']")
                
                # Assertions
                assert len(result) == 1
                assert "Test content extracted" in result[0]

def test_urllogic_exception():
    """Test URL parsing with exceptions"""
    with patch('requests.get') as mock_get:
        # Setup mock to raise an exception
        mock_get.side_effect = Exception("Test exception")
        
        # Test the function
        result = urllogic("['http://example.com']")
        
        # Assertions
        assert len(result) == 0  # Should return empty list on exception

def test_savereport(setup_db):
    """Test saving a report to the database"""
    conn, cursor = setup_db
    
    # Mock sqlite3.connect to return our test connection
    with patch('sqlite3.connect', return_value=conn):
        # Call the function
        savereport("CVE-2023-1234", "This is a test report")
        
        # Verify the data was inserted
        cursor.execute("SELECT * FROM processed WHERE cve_id = ?", ("CVE-2023-1234",))
        result = cursor.fetchone()
        
        # Assertions
        assert result is not None
        assert result[0] == "CVE-2023-1234"
        assert result[1] == "This is a test report"