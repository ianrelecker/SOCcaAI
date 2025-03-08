import pytest
import json
from unittest.mock import patch, MagicMock
import sys
import os
from datetime import datetime

# Add the parent directory to the path so we can import the modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kryptos_working.nvdapi import fetch_cves

@pytest.fixture
def mock_successful_response():
    """Mock a successful response from the NVD API"""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-1234",
                    "descriptions": [{"value": "Test vulnerability"}]
                }
            }
        ]
    }
    return mock_response

@pytest.fixture
def mock_error_response():
    """Mock an error response from the NVD API"""
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.text = "API key required"
    return mock_response

def test_fetch_cves_success(requests_mock, mock_successful_response):
    """Test successful CVE fetch"""
    # Mock the requests.get method
    requests_mock.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0", 
        json=mock_successful_response.json()
    )
    
    # Call the function
    result = fetch_cves("2023-01-01", "2023-01-02")
    
    # Check the result
    assert result is not None
    assert "vulnerabilities" in result
    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["cve"]["id"] == "CVE-2023-1234"

def test_fetch_cves_error(requests_mock, mock_error_response):
    """Test error handling in CVE fetch"""
    # Mock the requests.get method to return an error
    requests_mock.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0", 
        status_code=403,
        text="API key required"
    )
    
    # Call the function
    result = fetch_cves("2023-01-01", "2023-01-02")
    
    # Check the result
    assert result is None