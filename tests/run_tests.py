#!/usr/bin/env python3

import unittest
import sys
import os

def run_tests():
    """Run all tests in the tests directory."""
    print("Setting up test environment...")
    
    # Add the parent directory to the Python path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    
    # Import the module to test
    import cjwt
    
    print("Test environment set up successfully.\n")
    print("Running tests...\n")
    
    # Discover and run all tests
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return appropriate exit code
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    sys.exit(run_tests()) 