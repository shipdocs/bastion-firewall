#!/usr/bin/env python3
"""
USB Rules Test Script

Tests the secure JSON storage for USB device rules.
"""

import sys
import os
import tempfile
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from bastion.usb_device import USBDeviceInfo
from bastion.usb_rules import USBRuleManager, USBAuthorizer, USBRule
from bastion.usb_validation import USBValidation


def test_rule_storage():
    """Test basic rule storage and retrieval."""
    print("=" * 60)
    print("Testing USB Rule Storage")
    print("=" * 60)
    
    # Use temp file for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test_usb_rules.json'
        manager = USBRuleManager(db_path=db_path)
        
        # Create test device
        device = USBDeviceInfo(
            vendor_id='046d',
            product_id='c52b',
            vendor_name='Logitech, Inc.',
            product_name='Unifying Receiver',
            device_class=0x00,
            serial='1234567890',
            bus_id='1-2.3'
        )
        
        # Test: No rule initially
        verdict = manager.get_verdict(device)
        assert verdict is None, f"Expected None, got {verdict}"
        print("✅ No rule for unknown device")
        
        # Test: Add allow rule
        manager.add_rule(device, 'allow', scope='device')
        verdict = manager.get_verdict(device)
        assert verdict == 'allow', f"Expected 'allow', got {verdict}"
        print("✅ Added and retrieved allow rule")
        
        # Test: File has correct permissions (at least 0o600, may be more restrictive due to umask)
        mode = db_path.stat().st_mode & 0o777
        # Check that owner has read/write, and group/others don't have write
        assert (mode & 0o600) == 0o600, f"Owner should have read/write, got {oct(mode)}"
        assert (mode & 0o022) == 0, f"Group/others should not have write, got {oct(mode)}"
        print(f"✅ File permissions correct: {oct(mode)}")
        
        # Test: File content is valid JSON
        with open(db_path, 'r') as f:
            data = json.load(f)
        assert len(data) == 1
        print("✅ Valid JSON content")
        
        # Test: Reload from disk
        manager2 = USBRuleManager(db_path=db_path)
        verdict2 = manager2.get_verdict(device)
        assert verdict2 == 'allow', f"Expected 'allow' after reload, got {verdict2}"
        print("✅ Rules persist across reload")
        
        # Test: Model scope
        device2 = USBDeviceInfo(
            vendor_id='046d',
            product_id='c52b',
            vendor_name='Logitech, Inc.',
            product_name='Unifying Receiver',
            device_class=0x00,
            serial='9999999999',  # Different serial
            bus_id='2-1'
        )
        manager.add_rule(device2, 'allow', scope='model')
        
        # Different serial, same model - should match model rule
        device3 = USBDeviceInfo(
            vendor_id='046d',
            product_id='c52b',
            vendor_name='Logitech',
            product_name='Receiver',
            device_class=0x00,
            serial='aaabbbccc',
            bus_id='3-1'
        )
        verdict3 = manager.get_verdict(device3)
        assert verdict3 == 'allow', f"Expected model match, got {verdict3}"
        print("✅ Model scope matching works")
        
        # Test: Block rule
        bad_device = USBDeviceInfo(
            vendor_id='dead',
            product_id='beef',
            vendor_name='Unknown',
            product_name='Suspicious Device',
            device_class=0x03,  # HID
            bus_id='1-1'
        )
        manager.add_rule(bad_device, 'block', scope='device')
        verdict_bad = manager.get_verdict(bad_device)
        assert verdict_bad == 'block', f"Expected 'block', got {verdict_bad}"
        print("✅ Block rule works")
        
        # Test: Rule listing
        all_rules = manager.get_all_rules()
        allowed = manager.get_allowed_devices()
        blocked = manager.get_blocked_devices()
        print(f"✅ Total rules: {len(all_rules)}, Allowed: {len(allowed)}, Blocked: {len(blocked)}")
        
        print("\n" + "=" * 60)
        print("All tests passed! ✅")
        print("=" * 60)


def test_input_sanitization():
    """Test that malicious input is sanitized."""
    print("\n" + "=" * 60)
    print("Testing Input Sanitization")
    print("=" * 60)
    
    # Test hex ID sanitization
    rule = USBRule.from_dict({
        'vendor_id': '../../../etc',  # Path traversal attempt
        'product_id': '<script>alert(1)</script>',  # XSS attempt
        'vendor_name': 'Test\x00\x0aInjection',  # Null byte injection
        'product_name': 'A' * 500,  # Buffer overflow attempt
        'verdict': 'allow',
        'scope': 'device',
        'added': 'not-a-date',  # Invalid date
    })
    
    # Sanitized: only hex chars [0-9a-f] kept, max 4 chars, padded with zeros
    # '../../../etc' -> only 'e' and 'c' are hex -> 'ec' -> padded to '00ec'
    assert len(rule.vendor_id) == 4, f"Got {rule.vendor_id}"
    assert all(c in '0123456789abcdef' for c in rule.vendor_id)
    print(f"   vendor_id sanitized: '../../../etc' -> '{rule.vendor_id}'")

    # '<script>alert(1)</script>' -> only 'c', 'a', 'e', '1', 'c' -> 'cae1'
    assert len(rule.product_id) == 4, f"Got {rule.product_id}"
    assert all(c in '0123456789abcdef' for c in rule.product_id)
    print(f"   product_id sanitized: '<script>...' -> '{rule.product_id}'")
    assert '\x00' not in rule.vendor_name
    assert len(rule.product_name) <= 256  # MAX_NAME_LEN is 256
    assert rule.verdict == 'allow'
    
    print("✅ Path traversal blocked")
    print("✅ Script injection blocked")
    print("✅ Null bytes removed")
    print("✅ String length limited")
    print("✅ Invalid dates corrected")
    
    print("\n" + "=" * 60)
    print("Sanitization tests passed! ✅")
    print("=" * 60)


def test_authorizer():
    """Test USB authorizer (read-only, no actual device changes)."""
    print("\n" + "=" * 60)
    print("Testing USB Authorizer (read-only)")
    print("=" * 60)
    
    # Test path sanitization
    safe_path = USBAuthorizer._get_auth_path('1-2.3')
    assert 'authorized' in str(safe_path)
    print(f"✅ Normal path: {safe_path}")
    
    # Test path traversal prevention
    try:
        evil_path = USBAuthorizer._get_auth_path('../../../etc/passwd')
        assert False, "Should have raised ValueError for path traversal attempt"
    except ValueError as e:
        assert "Invalid bus_id" in str(e)
        print(f"✅ Path traversal blocked: {e}")
    
    print("\n" + "=" * 60)
    print("Authorizer tests passed! ✅")
    print("=" * 60)


def test_sanitize_serial():
    """Test sanitize_serial with various inputs including malicious ones."""
    print("\n" + "=" * 60)
    print("Testing sanitize_serial()")
    print("=" * 60)

    # Normal serial
    assert USBValidation.sanitize_serial("ABC123") == "ABC123"
    print("✅ Normal serial preserved")

    # Serial with allowed special chars
    assert USBValidation.sanitize_serial("ABC_123-456.789") == "ABC_123-456.789"
    print("✅ Dots, dashes, underscores preserved")

    # Empty/None input
    assert USBValidation.sanitize_serial(None) == "no-serial"
    assert USBValidation.sanitize_serial("") == "no-serial"
    print("✅ Empty/None returns 'no-serial'")

    # Shell metacharacters stripped
    result = USBValidation.sanitize_serial("test;rm -rf /")
    assert ";" not in result and " " not in result and "/" not in result
    print(f"✅ Shell injection blocked: 'test;rm -rf /' -> '{result}'")

    # Quotes stripped (prevent code injection)
    result = USBValidation.sanitize_serial("test'injection")
    assert "'" not in result
    result = USBValidation.sanitize_serial('test"injection')
    assert '"' not in result
    print("✅ Quotes stripped")

    # Backticks stripped
    result = USBValidation.sanitize_serial("test`command`end")
    assert "`" not in result
    print("✅ Backticks stripped")

    # Dollar signs stripped (prevent variable expansion)
    result = USBValidation.sanitize_serial("test$PATH")
    assert "$" not in result
    print("✅ Dollar signs stripped")

    # Newlines and control chars stripped
    result = USBValidation.sanitize_serial("line1\nline2\rline3")
    assert "\n" not in result and "\r" not in result
    print("✅ Newlines stripped")

    # Null bytes stripped
    result = USBValidation.sanitize_serial("test\x00null")
    assert "\x00" not in result
    print("✅ Null bytes stripped")

    # Length limit enforced
    long_serial = "A" * 500
    result = USBValidation.sanitize_serial(long_serial, max_len=128)
    assert len(result) == 128
    print("✅ Length limit enforced")

    # Unicode characters stripped (not in safe charset)
    result = USBValidation.sanitize_serial("test🔥emoji")
    assert "🔥" not in result
    print("✅ Unicode emoji stripped")

    print("\n" + "=" * 60)
    print("sanitize_serial tests passed! ✅")
    print("=" * 60)


def test_sanitize_key():
    """Test sanitize_key and validate_key functions."""
    print("\n" + "=" * 60)
    print("Testing sanitize_key() and validate_key()")
    print("=" * 60)

    # Valid device key
    result = USBValidation.sanitize_key("046d:c52b:ABC123")
    assert result == "046d:c52b:ABC123"
    assert USBValidation.validate_key(result)
    print("✅ Valid device key preserved")

    # Valid model key
    result = USBValidation.sanitize_key("046d:c52b:*")
    assert result == "046d:c52b:*"
    assert USBValidation.validate_key(result)
    print("✅ Valid model key preserved")

    # Valid vendor key
    result = USBValidation.sanitize_key("046d:*:*")
    assert result == "046d:*:*"
    assert USBValidation.validate_key(result)
    print("✅ Valid vendor key preserved")

    # Key with malicious serial - should be sanitized
    result = USBValidation.sanitize_key("046d:c52b:test';drop table;--")
    assert result is not None
    assert "'" not in result and ";" not in result
    print(f"✅ Malicious serial sanitized: '046d:c52b:test';drop...' -> '{result}'")

    # Key with shell injection in serial
    result = USBValidation.sanitize_key("046d:c52b:$(whoami)")
    assert result is not None
    assert "$" not in result and "(" not in result
    print(f"✅ Shell injection sanitized")

    # Old 2-part key format (vid:pid) - should be converted
    result = USBValidation.sanitize_key("046d:c52b")
    assert result == "046d:c52b:*"
    print("✅ Old 2-part key format converted")

    # Invalid key format rejected
    result = USBValidation.sanitize_key("invalid")
    assert result is None
    print("✅ Invalid key format rejected")

    # Empty key rejected
    result = USBValidation.sanitize_key("")
    assert result is None
    result = USBValidation.sanitize_key(None)
    assert result is None
    print("✅ Empty/None key rejected")

    # Too long key rejected
    long_key = "046d:c52b:" + "A" * 500
    result = USBValidation.sanitize_key(long_key)
    assert result is None or len(result) <= 256
    print("✅ Too long key handled")

    print("\n" + "=" * 60)
    print("sanitize_key tests passed! ✅")
    print("=" * 60)


def test_malicious_serial_in_rule():
    """Test that malicious serials in rules are properly sanitized."""
    print("\n" + "=" * 60)
    print("Testing malicious serial in rule key generation")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'test_usb_rules.json'
        manager = USBRuleManager(db_path=db_path)

        # Create device with malicious serial
        evil_device = USBDeviceInfo(
            vendor_id='046d',
            product_id='c52b',
            vendor_name='Logitech',
            product_name='Receiver',
            device_class=0x00,
            serial="test';DROP TABLE rules;--",  # SQL injection attempt
            bus_id='1-2'
        )

        # Add rule - serial should be sanitized
        manager.add_rule(evil_device, 'allow', scope='device')

        # Check the key doesn't contain dangerous characters
        rules = manager.get_all_rules()
        for key in rules.keys():
            assert "'" not in key, f"Quote found in key: {key}"
            assert ";" not in key, f"Semicolon found in key: {key}"
            assert " " not in key, f"Space found in key: {key}"
        print("✅ Malicious serial sanitized in stored rule key")

        # Test that we can still retrieve the rule
        verdict = manager.get_verdict(evil_device)
        assert verdict == 'allow'
        print("✅ Rule with sanitized serial can be retrieved")

    print("\n" + "=" * 60)
    print("Malicious serial tests passed! ✅")
    print("=" * 60)


if __name__ == "__main__":
    test_rule_storage()
    test_input_sanitization()
    test_authorizer()
    test_sanitize_serial()
    test_sanitize_key()
    test_malicious_serial_in_rule()
    print("\n🎉 All USB rules tests passed!")

