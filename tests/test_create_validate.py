#!/usr/bin/env python3

import sys
import os
import unittest
from unittest.mock import patch, MagicMock, call
import json
import jwt
import tempfile

# Add the parent directory to the path so we can import the main module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import cjwt
from tests.test_utils import generate_sample_jwt_hs256, generate_expired_jwt_hs256, read_from_file


class TestCreateValidate(unittest.TestCase):
    """Test cases for the create and validate functionality"""

    def setUp(self):
        """Set up the test environment"""
        self.claims = '{"sub": "1234567890", "name": "Test User"}'
        self.secret = "test-secret"
        self.test_token = generate_sample_jwt_hs256(self.secret)

    @patch('builtins.print')
    def test_cmd_create_with_secret(self, mock_print):
        """Test creating a JWT with a secret key"""
        mock_args = MagicMock()
        mock_args.claims = self.claims
        mock_args.secret = self.secret
        mock_args.exp = 3600  # 1 hour
        mock_args.alg = "HS256"
        mock_args.private_key = None
        mock_args.jwk = None
        mock_args.pem = None

        # Call the function
        cjwt.cmd_create(mock_args)

        # Check if print was called (token was printed)
        mock_print.assert_called_once()
        token = mock_print.call_args[0][0]
        
        # Verify the token
        decoded = jwt.decode(token, self.secret, algorithms=["HS256"])
        self.assertEqual(decoded['sub'], '1234567890')
        self.assertEqual(decoded['name'], 'Test User')
        self.assertIn('iat', decoded)
        self.assertIn('exp', decoded)

    @patch('sys.exit')
    @patch('builtins.print')
    def test_cmd_create_no_secret(self, mock_print, mock_exit):
        """Test creating a JWT without a secret key"""
        mock_args = MagicMock()
        mock_args.claims = self.claims
        mock_args.secret = None
        mock_args.exp = None
        mock_args.alg = "HS256"
        mock_args.private_key = None
        mock_args.jwk = None
        mock_args.pem = None

        # Call the function
        cjwt.cmd_create(mock_args)

        # In the actual implementation, there might be multiple print calls due to error handling
        # We just check if at least one of them contains our expected error message
        error_message_found = False
        for call_args in mock_print.call_args_list:
            if "Error: No key or secret provided" in call_args[0][0]:
                error_message_found = True
                break
                
        self.assertTrue(error_message_found, "Expected error message not found in print calls")

        # Check if sys.exit was called
        mock_exit.assert_called()

    @patch('cjwt.read_key_file')
    @patch('builtins.print')
    def test_cmd_create_with_private_key(self, mock_print, mock_read_key):
        """Test creating a JWT with a private key"""
        # Mock key file content
        mock_read_key.return_value = "mock-private-key"
        
        mock_args = MagicMock()
        mock_args.claims = self.claims
        mock_args.secret = None
        mock_args.exp = None
        mock_args.alg = "RS256"
        mock_args.private_key = "test_key.pem"
        mock_args.jwk = None
        mock_args.pem = None

        # Mock jwt.encode
        with patch('jwt.encode') as mock_encode:
            mock_encode.return_value = "mocked.jwt.token"
            
            # Call the function
            cjwt.cmd_create(mock_args)
            
            # Check if key file was read
            mock_read_key.assert_called_once_with("test_key.pem")
            
            # Check if encode was called with correct params
            mock_encode.assert_called_once()
            args, kwargs = mock_encode.call_args
            self.assertEqual(kwargs['algorithm'], 'RS256')
            self.assertEqual(args[1], 'mock-private-key')

    @patch('builtins.print')
    def test_cmd_validate_valid_token(self, mock_print):
        """Test validating a valid JWT"""
        mock_args = MagicMock()
        mock_args.token = self.test_token
        mock_args.secret = self.secret
        mock_args.file = None
        mock_args.public_key = None

        # Call the function
        with patch('cjwt.print_colored_json') as mock_print_json:
            cjwt.cmd_validate(mock_args)
            
            # Check if success message was printed
            mock_print.assert_called()
            self.assertIn("JWT is valid", mock_print.call_args_list[0][0][0])
            
            # Check if token details were printed
            mock_print_json.assert_called_once()

    @patch('sys.exit')
    @patch('builtins.print')
    def test_cmd_validate_expired_token(self, mock_print, mock_exit):
        """Test validating an expired JWT"""
        expired_token = generate_expired_jwt_hs256(self.secret)
        
        mock_args = MagicMock()
        mock_args.token = expired_token
        mock_args.secret = self.secret
        mock_args.file = None
        mock_args.public_key = None

        # Call the function
        cjwt.cmd_validate(mock_args)
        
        # Check if error message was printed
        mock_print.assert_called_once()
        self.assertIn("JWT has expired", mock_print.call_args[0][0])
        
        # Check if sys.exit was called
        mock_exit.assert_called_once()

    @patch('sys.exit')
    @patch('builtins.print')
    def test_cmd_validate_invalid_token(self, mock_print, mock_exit):
        """Test validating a JWT with wrong secret"""
        wrong_secret = "wrong-secret"
        
        mock_args = MagicMock()
        mock_args.token = self.test_token
        mock_args.secret = wrong_secret
        mock_args.file = None
        mock_args.public_key = None

        # Call the function
        cjwt.cmd_validate(mock_args)
        
        # Check if error message was printed
        mock_print.assert_called_once()
        self.assertIn("Invalid JWT", mock_print.call_args[0][0])
        
        # Check if sys.exit was called
        mock_exit.assert_called_once()

    @patch('cjwt.read_key_file')
    @patch('builtins.print')
    def test_cmd_validate_with_public_key(self, mock_print, mock_read_key):
        """Test validating a JWT with a public key"""
        # This is a simplified test that mocks the jwt.decode function
        mock_read_key.return_value = "mock-public-key"
        
        mock_args = MagicMock()
        mock_args.token = "mocked.jwt.token"
        mock_args.secret = None
        mock_args.file = None
        mock_args.public_key = "test_key.pem"

        # Mock the necessary functions
        with patch('jwt.get_unverified_header') as mock_header:
            mock_header.return_value = {"alg": "RS256", "typ": "JWT"}
            
            with patch('jwt.decode') as mock_decode:
                mock_decode.return_value = {"sub": "1234567890", "name": "Test User"}
                
                with patch('cjwt.print_colored_json') as mock_print_json:
                    # Call the function
                    cjwt.cmd_validate(mock_args)
                    
                    # Check if key file was read
                    mock_read_key.assert_called_once_with("test_key.pem")
                    
                    # Check if jwt.decode was called with correct params
                    mock_decode.assert_called_once()
                    args, kwargs = mock_decode.call_args
                    self.assertEqual(args[0], "mocked.jwt.token")
                    self.assertEqual(args[1], "mock-public-key")
                    self.assertEqual(kwargs['algorithms'], ["RS256"])


if __name__ == '__main__':
    unittest.main() 