#!/usr/bin/env python3

import sys
import os
import unittest
from unittest.mock import patch, MagicMock, call
import json
import argparse
import io

# Add the parent directory to the path so we can import the main module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import cjwt
from tests.test_utils import generate_sample_jwt_hs256


class TestCommandLineInterface(unittest.TestCase):
    """Test cases for the command-line interface"""

    def setUp(self):
        """Set up the test environment"""
        self.test_token = generate_sample_jwt_hs256()

    @patch('sys.argv', ['cjwt', 'decode', '--token', 'test.jwt.token'])
    @patch('cjwt.cmd_decode')
    def test_main_decode(self, mock_decode):
        """Test the main function with decode command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'decode'
            mock_args.token = 'test.jwt.token'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_decode was called
            mock_decode.assert_called_once()
            self.assertEqual(mock_decode.call_args[0][0].token, 'test.jwt.token')

    @patch('sys.argv', ['cjwt', 'create', '--claims', '{"sub":"1234"}', '--secret', 'test-secret'])
    @patch('cjwt.cmd_create')
    def test_main_create(self, mock_create):
        """Test the main function with create command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'create'
            mock_args.claims = '{"sub":"1234"}'
            mock_args.secret = 'test-secret'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_create was called
            mock_create.assert_called_once()
            self.assertEqual(mock_create.call_args[0][0].claims, '{"sub":"1234"}')
            self.assertEqual(mock_create.call_args[0][0].secret, 'test-secret')

    @patch('sys.argv', ['cjwt', 'validate', '--token', 'test.jwt.token', '--secret', 'test-secret'])
    @patch('cjwt.cmd_validate')
    def test_main_validate(self, mock_validate):
        """Test the main function with validate command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'validate'
            mock_args.token = 'test.jwt.token'
            mock_args.secret = 'test-secret'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_validate was called
            mock_validate.assert_called_once()
            self.assertEqual(mock_validate.call_args[0][0].token, 'test.jwt.token')
            self.assertEqual(mock_validate.call_args[0][0].secret, 'test-secret')

    @patch('sys.argv', ['cjwt', 'sign', '--claims', '{"sub":"1234"}', '--secret', 'test-secret'])
    @patch('cjwt.cmd_sign')
    def test_main_sign(self, mock_sign):
        """Test the main function with sign command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'sign'
            mock_args.claims = '{"sub":"1234"}'
            mock_args.secret = 'test-secret'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_sign was called
            mock_sign.assert_called_once()
            self.assertEqual(mock_sign.call_args[0][0].claims, '{"sub":"1234"}')
            self.assertEqual(mock_sign.call_args[0][0].secret, 'test-secret')

    @patch('sys.argv', ['cjwt', 'verify', '--token', 'test.jwt.token', '--secret', 'test-secret', '--required-claims', '["sub"]'])
    @patch('cjwt.cmd_verify')
    def test_main_verify(self, mock_verify):
        """Test the main function with verify command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'verify'
            mock_args.token = 'test.jwt.token'
            mock_args.secret = 'test-secret'
            mock_args.required_claims = '["sub"]'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_verify was called
            mock_verify.assert_called_once()
            self.assertEqual(mock_verify.call_args[0][0].token, 'test.jwt.token')
            self.assertEqual(mock_verify.call_args[0][0].secret, 'test-secret')
            self.assertEqual(mock_verify.call_args[0][0].required_claims, '["sub"]')

    @patch('sys.argv', ['cjwt', 'header', '--token', 'test.jwt.token'])
    @patch('cjwt.cmd_header')
    def test_main_header(self, mock_header):
        """Test the main function with header command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'header'
            mock_args.token = 'test.jwt.token'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_header was called
            mock_header.assert_called_once()
            self.assertEqual(mock_header.call_args[0][0].token, 'test.jwt.token')

    @patch('sys.argv', ['cjwt', 'extract', '--token', 'test.jwt.token', '--claims', '["sub", "name"]'])
    @patch('cjwt.cmd_extract')
    def test_main_extract(self, mock_extract):
        """Test the main function with extract command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'extract'
            mock_args.token = 'test.jwt.token'
            mock_args.claims = '["sub", "name"]'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_extract was called
            mock_extract.assert_called_once()
            self.assertEqual(mock_extract.call_args[0][0].token, 'test.jwt.token')
            self.assertEqual(mock_extract.call_args[0][0].claims, '["sub", "name"]')

    @patch('sys.argv', ['cjwt', 'check-exp', '--token', 'test.jwt.token'])
    @patch('cjwt.cmd_check_exp')
    def test_main_check_exp(self, mock_check_exp):
        """Test the main function with check-exp command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'check-exp'
            mock_args.token = 'test.jwt.token'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_check_exp was called
            mock_check_exp.assert_called_once()
            self.assertEqual(mock_check_exp.call_args[0][0].token, 'test.jwt.token')

    @patch('sys.argv', ['cjwt', 'add-exp', '--token', 'test.jwt.token', '--exp', '3600', '--secret', 'test-secret'])
    @patch('cjwt.cmd_add_exp')
    def test_main_add_exp(self, mock_add_exp):
        """Test the main function with add-exp command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'add-exp'
            mock_args.token = 'test.jwt.token'
            mock_args.exp = 3600
            mock_args.secret = 'test-secret'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_add_exp was called
            mock_add_exp.assert_called_once()
            self.assertEqual(mock_add_exp.call_args[0][0].token, 'test.jwt.token')
            self.assertEqual(mock_add_exp.call_args[0][0].exp, 3600)
            self.assertEqual(mock_add_exp.call_args[0][0].secret, 'test-secret')

    @patch('sys.argv', ['cjwt', 'format', '--token', 'test.jwt.token', '--format', 'json'])
    @patch('cjwt.cmd_format')
    def test_main_format(self, mock_format):
        """Test the main function with format command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'format'
            mock_args.token = 'test.jwt.token'
            mock_args.format = 'json'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_format was called
            mock_format.assert_called_once()
            self.assertEqual(mock_format.call_args[0][0].token, 'test.jwt.token')
            self.assertEqual(mock_format.call_args[0][0].format, 'json')

    @patch('sys.argv', ['cjwt', 'batch', '--file', 'tokens.txt', '--action', 'decode'])
    @patch('cjwt.cmd_batch')
    def test_main_batch(self, mock_batch):
        """Test the main function with batch command"""
        with patch('argparse.ArgumentParser.parse_args') as mock_parse_args:
            mock_args = MagicMock()
            mock_args.command = 'batch'
            mock_args.file = 'tokens.txt'
            mock_args.action = 'decode'
            mock_parse_args.return_value = mock_args
            
            # Call the main function
            cjwt.main()
            
            # Check if cmd_batch was called
            mock_batch.assert_called_once()
            self.assertEqual(mock_batch.call_args[0][0].file, 'tokens.txt')
            self.assertEqual(mock_batch.call_args[0][0].action, 'decode')

    @patch('sys.argv', ['cjwt'])
    @patch('pyperclip.paste')
    @patch('cjwt.print_colored_json')
    def test_main_default(self, mock_print_colored, mock_paste):
        """Test the main function with no command (default behavior)"""
        with self.assertRaises(SystemExit) as cm:
            with patch('sys.argv', ['cjwt']):
                cjwt.main()
        self.assertEqual(cm.exception.code, 1)  # Help should exit with code 1


if __name__ == '__main__':
    unittest.main() 