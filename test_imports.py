#!/usr/bin/env python3
"""Test script to verify imports work correctly"""

import os
import sys

def test_imports():
    """Test that we can import modules from kryptos_working."""
    print("Current directory:", os.getcwd())
    print("Python path:", sys.path)
    
    # Add current directory to path
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    
    try:
        from kryptos_working.config import SITE_URL, NVD_API_BASE_URL
        print(f"Success! Imported config with SITE_URL={SITE_URL}")
        print(f"NVD API URL: {NVD_API_BASE_URL}")
    except ImportError as e:
        print("Failed to import from kryptos_working.config:", e)
        return False
    
    try:
        import kryptos_working.sentinel_exporter
        print("Success! Imported sentinel_exporter module")
        
        # Check for Microsoft Sentinel support
        if hasattr(kryptos_working.sentinel_exporter, 'send_to_sentinel'):
            print("Success! Microsoft Sentinel support confirmed")
        else:
            print("Warning: Microsoft Sentinel support not found in sentinel_exporter")
            return False
    except ImportError as e:
        print("Failed to import kryptos_working.sentinel_exporter:", e)
        return False
    
    return True

if __name__ == "__main__":
    print("Testing SOCca imports...")
    success = test_imports()
    if success:
        print("\nAll imports successful! SOCca import paths are working correctly.")
    else:
        print("\nImport test failed. Please check your installation.")
        sys.exit(1)