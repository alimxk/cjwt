#!/usr/bin/env python3

import unittest
from unittest.mock import patch, mock_open
import sys
import io
import json
import cjwt
from tests.test_utils import generate_sample_jwt_hs256

class TestPiping(unittest.TestCase):
    """Test cases for stdin/stdout and piping functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_token = generate_sample_jwt_hs256()
    
    def test_stdin_input(self):
        """Test reading token from stdin."""
        with patch('sys.stdin', io.StringIO(self.test_token)):
            with patch('sys.stdin.isatty', return_value=False):
                with patch('pyperclip.paste', return_value=""):
                    with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                        with patch('sys.argv', ['cjwt', 'decode']):
                            cjwt.main() # Successful execution should not raise SystemExit
                            output = mock_stdout.getvalue()
                            self.assertIn("sub", output)
    
    def test_stdout_no_colors(self):
        """Test output without colors when stdout is not a terminal."""
        with patch('sys.stdin', io.StringIO(self.test_token)):
            with patch('sys.stdin.isatty', return_value=False):
                with patch('pyperclip.paste', return_value=""):
                    with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                        with patch('sys.stdout.isatty', return_value=False):
                            with patch('sys.argv', ['cjwt', 'decode']):
                                cjwt.main() # Successful execution
                                output = mock_stdout.getvalue()
                                self.assertNotIn("\033[", output)  # No ANSI color codes
    
    def test_stdout_with_colors(self):
        """Test output with colors when stdout is a terminal."""
        with patch('sys.stdin', io.StringIO(self.test_token)):
            with patch('sys.stdin.isatty', return_value=False):
                with patch('pyperclip.paste', return_value=""):
                    with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                        with patch('sys.stdout.isatty', return_value=True):
                            with patch('sys.argv', ['cjwt', 'decode']):
                                cjwt.main() # Successful execution
                                output = mock_stdout.getvalue()
                                self.assertIn("\033[", output)  # Should have ANSI color codes
    
    def test_no_colors_flag(self):
        """Test --no-colors flag."""
        with patch('sys.stdin', io.StringIO(self.test_token)):
            with patch('sys.stdin.isatty', return_value=False):
                with patch('pyperclip.paste', return_value=""):
                    with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                        with patch('sys.stdout.isatty', return_value=True):
                            with patch('sys.argv', ['cjwt', '--no-colors', 'decode']):
                                cjwt.main() # Successful execution
                                output = mock_stdout.getvalue()
                                self.assertNotIn("\033[", output)  # No ANSI color codes
    
    def test_pipe_chain(self):
        """Test chaining commands through pipes."""
        # Simulate a pipe chain: echo token | cjwt decode | grep sub
        with patch('sys.stdin', io.StringIO(self.test_token)):
            with patch('sys.stdin.isatty', return_value=False):
                with patch('pyperclip.paste', return_value=""):
                    with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                        with patch('sys.stdout.isatty', return_value=False):
                            with patch('sys.argv', ['cjwt', 'decode']):
                                cjwt.main() # Successful execution
                                output = mock_stdout.getvalue()
                                # The output should be plain text without colors
                                self.assertNotIn("\033[", output)
                                # The output should contain the decoded data
                                self.assertIn("sub", output)
    
    def test_multiple_tokens_stdin(self):
        """Test processing multiple tokens from stdin."""
        multiple_tokens = f"{self.test_token}\n{self.test_token}"
        with patch('sys.stdin', io.StringIO(multiple_tokens)):
            with patch('sys.stdin.isatty', return_value=False):
                with patch('pyperclip.paste', return_value=""):
                    with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                        with patch('sys.argv', ['cjwt', 'decode']):
                            cjwt.main() # Successful execution (processes first token)
                            output = mock_stdout.getvalue()
                            # Should only process the first token
                            self.assertEqual(output.count("sub"), 1)

if __name__ == '__main__':
    unittest.main() 