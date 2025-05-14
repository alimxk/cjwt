#!/usr/bin/env python3

import unittest
import os
import sys

# Add the parent directory to the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now import from tests module
from tests.test_utils import generate_test_keys, setup_test_files


def setup_test_environment():
    """Set up the test environment"""
    print("Setting up test environment...")
    
    # Generate test keys and data files
    generate_test_keys()
    setup_test_files()
    
    print("Test environment set up successfully.")


def discover_and_run_tests():
    """Discover and run all tests in the tests directory"""
    # Discover all tests
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir, pattern="test_*.py")
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return the number of failures and errors
    return len(result.failures) + len(result.errors)


if __name__ == "__main__":
    # Set up test environment
    setup_test_environment()
    
    # Run all tests
    print("\nRunning tests...\n")
    exit_code = discover_and_run_tests()
    
    # Exit with appropriate code
    sys.exit(exit_code) 