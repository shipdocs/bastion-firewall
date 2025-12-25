
import unittest
from unittest.mock import patch, MagicMock
import sys
import os
from bastion.utils import require_root

class TestUtils(unittest.TestCase):
    
    @patch('os.geteuid')
    def test_require_root_as_root(self, mock_geteuid):
        # Setup: UID is 0 (root)
        mock_geteuid.return_value = 0
        
        # Should not raise exception or exit
        try:
            require_root()
        except SystemExit:
            self.fail("require_root raised SystemExit unexpectedly!")

    @patch('os.geteuid')
    def test_require_root_as_user(self, mock_geteuid):
        # Setup: UID is 1000 (user)
        mock_geteuid.return_value = 1000
        
        # Should exit
        with self.assertRaises(SystemExit) as cm:
            require_root()
        
        self.assertEqual(cm.exception.code, 1)

    @patch('os.environ.get')
    def test_block_env_bypass(self, mock_env_get):
        # Setup: Env var set
        mock_env_get.return_value = '1'
        
        # Should exit immediately
        with self.assertRaises(SystemExit) as cm:
            require_root()
        self.assertEqual(cm.exception.code, 1)

    @patch('sys.argv', ['script.py', '--build-mode'])
    @patch('os.geteuid')
    def test_build_mode_allowed(self, mock_geteuid):
        # Even if not root (e.g. CI/Build), if build_mode=True and arg is present
        mock_geteuid.return_value = 1000
        
        # Should NOT exit
        try:
            require_root(build_mode=True)
        except SystemExit:
            self.fail("require_root raised SystemExit in allowed build mode")

    @patch('sys.argv', ['script.py', '--build-mode'])
    @patch('os.geteuid')
    def test_build_mode_not_allowed_if_arg_missing(self, mock_geteuid):
        # build_mode param is True, but CLI arg missing
        mock_geteuid.return_value = 1000
        
        with patch('sys.argv', ['script.py']):
            with self.assertRaises(SystemExit):
                require_root(build_mode=True)

if __name__ == '__main__':
    unittest.main()
