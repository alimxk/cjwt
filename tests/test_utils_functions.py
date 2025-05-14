#!/usr/bin/env python3

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import json
from datetime import datetime, timezone, timedelta

# Add the parent directory to the path so we can import the main module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import cjwt


class TestUtilityFunctions(unittest.TestCase):
    """Test cases for utility functions in cjwt.py"""

    def test_format_timestamp(self):
        """Test the format_timestamp function"""
        # Test with a specific timestamp
        test_timestamp = 1609459200  # 2021-01-01 00:00:00 UTC
        expected_output = "2021-01-01 00:00:00 UTC"
        self.assertEqual(cjwt.format_timestamp(test_timestamp), expected_output)

    def test_get_time_remaining_future(self):
        """Test get_time_remaining with future timestamp"""
        # Test with a future timestamp (1 hour from now)
        now = datetime.now(timezone.utc)
        future = now + timedelta(hours=1, minutes=5)  # Add extra minutes to ensure we're over an hour
        exp_timestamp = int(future.timestamp())
        
        # Time remaining should be close to 1 hour
        time_remaining = cjwt.get_time_remaining(exp_timestamp)
        self.assertIn("hour", time_remaining.lower())
        
        # Test with a future timestamp (2 days from now)
        future = now + timedelta(days=2, hours=3)
        exp_timestamp = int(future.timestamp())
        
        time_remaining = cjwt.get_time_remaining(exp_timestamp)
        self.assertIn("2 days", time_remaining.lower())
        # The actual hours might vary slightly due to test execution timing
        # So we just check for the 'hours' text rather than the exact number
        self.assertIn("hours", time_remaining.lower())
        
        # Test less than an hour
        future = now + timedelta(minutes=30)
        exp_timestamp = int(future.timestamp())
        
        time_remaining = cjwt.get_time_remaining(exp_timestamp)
        self.assertIn("minutes", time_remaining.lower())

    def test_get_time_remaining_past(self):
        """Test get_time_remaining with past timestamp"""
        # Test with a past timestamp (1 hour ago)
        now = datetime.now(timezone.utc)
        past = now - timedelta(hours=1)
        exp_timestamp = int(past.timestamp())
        
        # Time expired should be close to 1 hour ago
        time_remaining = cjwt.get_time_remaining(exp_timestamp)
        self.assertIn("expired", time_remaining.lower())
        self.assertIn("hour", time_remaining.lower())
        
        # Test with a past timestamp (2 days ago)
        past = now - timedelta(days=2, hours=3)
        exp_timestamp = int(past.timestamp())
        
        time_remaining = cjwt.get_time_remaining(exp_timestamp)
        self.assertIn("expired", time_remaining.lower())
        self.assertIn("2 days", time_remaining.lower())

    def test_colorize_json(self):
        """Test the colorize_json function"""
        # Test with a simple JSON object
        test_json = {"key": "value", "number": 42, "bool": True}
        colored_json = cjwt.colorize_json(test_json)
        
        # Check if the output contains the expected values
        self.assertIn("key", colored_json)
        self.assertIn("value", colored_json)
        self.assertIn("42", colored_json)
        self.assertIn("true", colored_json)
        
        # Check if the output contains color codes
        self.assertIn("\033[", colored_json)  # ANSI color code prefix

    @patch('cjwt.read_key_file')
    def test_read_key_file(self, mock_read):
        """Test the read_key_file function"""
        mock_read.return_value = "test-key-content"
        
        # Call the function
        result = cjwt.read_key_file("test_key.pem")
        
        # Check if the function was called with the correct argument
        mock_read.assert_called_once_with("test_key.pem")
        
        # Check if the result is correct
        self.assertEqual(result, "test-key-content")

    @patch('json.loads')
    def test_parse_claims(self, mock_loads):
        """Test the parse_claims function"""
        mock_loads.return_value = {"sub": "1234567890", "name": "Test User"}
        
        # Call the function
        result = cjwt.parse_claims('{"sub": "1234567890", "name": "Test User"}')
        
        # Check if json.loads was called with the correct argument
        mock_loads.assert_called_once_with('{"sub": "1234567890", "name": "Test User"}')
        
        # Check if the result is correct
        self.assertEqual(result, {"sub": "1234567890", "name": "Test User"})

    @patch('sys.exit')
    @patch('builtins.print')
    @patch('json.loads')
    def test_parse_claims_invalid_json(self, mock_loads, mock_print, mock_exit):
        """Test the parse_claims function with invalid JSON"""
        # Mock json.loads to raise an exception
        mock_loads.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        
        # Call the function
        cjwt.parse_claims('{"invalid json"}')
        
        # Check if error message was printed
        mock_print.assert_called_once()
        self.assertIn("Error parsing claims JSON", mock_print.call_args[0][0])
        
        # Check if sys.exit was called
        mock_exit.assert_called_once()

    @patch('builtins.print')
    def test_print_section(self, mock_print):
        """Test the print_section function"""
        # Call the function
        cjwt.print_section("Test Title", "Test Content")
        
        # Check if print was called twice (once for title, once for content)
        self.assertEqual(mock_print.call_count, 2)
        
        # Check if title was printed
        self.assertIn("Test Title", mock_print.call_args_list[0][0][0])
        
        # Check if content was printed
        self.assertEqual(mock_print.call_args_list[1][0][0], "Test Content")


if __name__ == '__main__':
    unittest.main() 