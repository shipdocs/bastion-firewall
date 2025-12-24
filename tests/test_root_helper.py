#!/usr/bin/env python3
"""
Root Helper Test Script

Tests the bastion-root-helper CLI for security and correctness.
"""

import sys
import os
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from bastion.root_helper import (
    main,
    validate_key,
    cmd_usb_rule_delete,
    cmd_usb_default_policy_set,
)


def test_validate_key():
    """
    Run assertions to verify that validate_key accepts valid USB key patterns and rejects unsafe or malformed inputs.
    
    This test checks that:
    - Valid device, model, and vendor patterns (e.g., "046d:c52b:ABC123", "046d:c52b:*", "046d:*:*") are accepted.
    - Inputs that represent shell injection, command substitution, path traversal, embedded quotes, semicolons, backticks, excessively long keys, empty or None values, and other malformed formats are rejected.
    
    The function raises an AssertionError if any expectation fails.
    """
    print("=" * 60)
    print("Testing validate_key()")
    print("=" * 60)
    
    # Valid device key
    assert validate_key("046d:c52b:ABC123") == True
    print("✅ Valid device key accepted")
    
    # Valid model key
    assert validate_key("046d:c52b:*") == True
    print("✅ Valid model key accepted")
    
    # Valid vendor key
    assert validate_key("046d:*:*") == True
    print("✅ Valid vendor key accepted")
    
    # Invalid: shell injection attempt
    assert validate_key("046d:c52b:$(whoami)") == False
    print("✅ Shell injection rejected")
    
    # Invalid: path traversal
    assert validate_key("../../../etc:passwd:*") == False
    print("✅ Path traversal rejected")
    
    # Invalid: quotes
    assert validate_key("046d:c52b:'test") == False
    print("✅ Single quote rejected")
    
    assert validate_key('046d:c52b:"test') == False
    print("✅ Double quote rejected")
    
    # Invalid: semicolon
    assert validate_key("046d:c52b:test;rm -rf /") == False
    print("✅ Semicolon rejected")
    
    # Invalid: backticks
    assert validate_key("046d:c52b:`whoami`") == False
    print("✅ Backticks rejected")
    
    # Invalid: too long
    long_key = "046d:c52b:" + "A" * 300
    assert validate_key(long_key) == False
    print("✅ Too long key rejected")
    
    # Invalid: empty
    assert validate_key("") == False
    assert validate_key(None) == False
    print("✅ Empty/None rejected")
    
    # Invalid: wrong format
    assert validate_key("invalid") == False
    assert validate_key("046d") == False
    print("✅ Wrong format rejected")
    
    print("\n" + "=" * 60)
    print("validate_key tests passed! ✅")
    print("=" * 60)


def test_main_help():
    """Test that --help works."""
    print("\n" + "=" * 60)
    print("Testing --help")
    print("=" * 60)
    
    # --help should exit with 0
    try:
        main(['--help'])
    except SystemExit as e:
        assert e.code == 0
        print("✅ --help exits with 0")
    
    print("\n" + "=" * 60)
    print("--help test passed! ✅")
    print("=" * 60)


def test_main_version():
    """
    Verify the CLI exits with status 0 when invoked with `--version`.
    
    This test calls the module's `main` entrypoint with `--version` and asserts that it raises a SystemExit with code 0.
    """
    print("\n" + "=" * 60)
    print("Testing --version")
    print("=" * 60)
    
    # --version should exit with 0
    try:
        main(['--version'])
    except SystemExit as e:
        assert e.code == 0
        print("✅ --version exits with 0")
    
    print("\n" + "=" * 60)
    print("--version test passed! ✅")
    print("=" * 60)


def test_usb_rule_delete_invalid_key():
    """Test that invalid keys are rejected."""
    print("\n" + "=" * 60)
    print("Testing usb-rule delete with invalid key")
    print("=" * 60)
    
    # Invalid key should return error code
    result = main(['usb-rule', 'delete', '--key', '$(whoami)'])
    assert result != 0
    print("✅ Shell injection key rejected")
    
    result = main(['usb-rule', 'delete', '--key', "test';DROP TABLE;--"])
    assert result != 0
    print("✅ SQL injection key rejected")
    
    print("\n" + "=" * 60)
    print("usb-rule delete invalid key tests passed! ✅")
    print("=" * 60)


def test_usb_rule_delete_valid_key():
    """
    Verify that 'usb-rule delete' accepts a valid device key and calls USBRuleManager.remove_rule.
    
    The test patches bastion.usb_rules.USBRuleManager with a mock instance whose remove_rule returns True,
    invokes cmd_usb_rule_delete with a well-formed key, asserts a zero result code, and verifies the
    mock's remove_rule was called once with the provided key.
    """
    print("\n" + "=" * 60)
    print("Testing usb-rule delete with valid key")
    print("=" * 60)

    # Patch at the source module where USBRuleManager is defined
    with patch('bastion.usb_rules.USBRuleManager') as MockManager:
        mock_instance = MagicMock()
        mock_instance.remove_rule.return_value = True
        MockManager.return_value = mock_instance

        result = cmd_usb_rule_delete(key="046d:c52b:ABC123")
        assert result == 0
        mock_instance.remove_rule.assert_called_once_with("046d:c52b:ABC123")
        print("✅ Valid key processed correctly")

    print("\n" + "=" * 60)
    print("usb-rule delete valid key tests passed! ✅")
    print("=" * 60)


if __name__ == "__main__":
    test_validate_key()
    test_main_help()
    test_main_version()
    test_usb_rule_delete_invalid_key()
    test_usb_rule_delete_valid_key()
    print("\n🎉 All root helper tests passed!")
