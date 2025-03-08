# This file makes the kryptos_working directory a Python package
import sys
import os

# Add the parent directory to the Python path to enable imports
# This ensures that both relative and absolute imports work properly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))