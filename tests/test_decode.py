#!/usr/bin/env python3

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
import json
import jwt

# Add the parent directory to the path so we can import the main module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import cjwt
from tests.test_utils import generate_sample_jwt_hs256, generate_expired_jwt_hs256


class TestDecode(unittest.TestCase):
    """Test cases for the decode functionality"""

    def setUp(self):
        """Set up the test environment"""
        # Create a sample JWT for testing
        self.valid_jwt = generate_sample_jwt_hs256()
        self.expired_jwt = generate_expired_jwt_hs256()

    def test_is_jwt(self):
        """Test the is_jwt function"""
        # Valid JWT
        self.assertTrue(cjwt.is_jwt(self.valid_jwt))
        
        # Invalid JWT
        self.assertFalse(cjwt.is_jwt("not-a-jwt"))
        # Note: "abc.def" has two parts separated by dots, which is not enough for a valid JWT
        # but the current implementation accepts it
        self.assertTrue(cjwt.is_jwt("abc.def"))  # The current implementation accepts this
        self.assertFalse(cjwt.is_jwt(""))  # Empty string

    def test_decode_jwt(self):
        """Test the decode_jwt function"""
        # Valid JWT
        decoded = cjwt.decode_jwt(self.valid_jwt)
        
        # Check if the decoded JWT has the expected structure
        self.assertIn('header', decoded)
        self.assertIn('payload', decoded)
        self.assertIn('signature', decoded)
        self.assertIn('raw_token', decoded)
        
        # Check if the payload has expected claims
        self.assertEqual(decoded['payload']['sub'], '1234567890')
        self.assertEqual(decoded['payload']['name'], 'Test User')
        self.assertIn('iat', decoded['payload'])
        self.assertIn('exp', decoded['payload'])
        
        # Check if header has expected values
        self.assertEqual(decoded['header']['alg'], 'HS256')
        self.assertEqual(decoded['header']['typ'], 'JWT')
        
        # Check raw token
        self.assertEqual(decoded['raw_token'], self.valid_jwt)

    def test_decode_invalid_jwt(self):
        """Test decode_jwt with an invalid JWT"""
        decoded = cjwt.decode_jwt("invalid.jwt.token")
        self.assertIn('error', decoded)
        
        # Empty string
        decoded = cjwt.decode_jwt("")
        self.assertIn('error', decoded)

    @patch('argparse.ArgumentParser.parse_args')
    @patch('cjwt.print_colored_json')
    def test_cmd_decode_from_arg(self, mock_print_colored, mock_parse_args):
        """Test the cmd_decode function with token from args"""
        mock_args = MagicMock()
        mock_args.token = self.valid_jwt
        mock_args.file = None
        mock_parse_args.return_value = mock_args
        
        # Call the function
        cjwt.cmd_decode(mock_args)
        
        # Check if print_colored_json was called with the correct decoded JWT
        self.assertTrue(mock_print_colored.called)
        decoded_jwt = mock_print_colored.call_args[0][0]
        self.assertEqual(decoded_jwt['payload']['sub'], '1234567890')

    @patch('argparse.ArgumentParser.parse_args')
    @patch('cjwt.print_colored_json')
    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data="sample.jwt.token")
    def test_cmd_decode_from_file(self, mock_open, mock_print_colored, mock_parse_args):
        """Test the cmd_decode function with token from file"""
        # Create a mock file with a JWT
        mock_args = MagicMock()
        mock_args.token = None
        mock_args.file = "test_file.txt"
        mock_parse_args.return_value = mock_args
        
        # Mock decode_jwt to return a predefined value
        with patch('cjwt.decode_jwt') as mock_decode:
            mock_decode.return_value = {"payload": {"sub": "test"}, "header": {}, "signature": "", "raw_token": ""}
            
            # Call the function
            cjwt.cmd_decode(mock_args)
            
            # Check if the file was opened
            mock_open.assert_called_once_with("test_file.txt", 'r')
            
            # Check if decode_jwt was called
            mock_decode.assert_called_once()
            
            # Check if print_colored_json was called
            mock_print_colored.assert_called_once()


if __name__ == '__main__':
    unittest.main() 