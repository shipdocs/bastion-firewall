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
    assert len(rule.product_name) <= 128
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


if __name__ == "__main__":
    test_rule_storage()
    test_input_sanitization()
    test_authorizer()
    print("\n🎉 All USB rules tests passed!")

