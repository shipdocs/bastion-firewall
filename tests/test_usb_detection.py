#!/usr/bin/env python3
"""
USB Detection Test Script

Run this script and insert/remove USB devices to verify detection works.
Press Ctrl+C to stop.

Usage:
    python3 tests/test_usb_detection.py
"""

import sys
import time
import signal
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from bastion.usb_monitor import USBMonitor, list_usb_devices, is_pyudev_available
from bastion.usb_device import USBDeviceInfo


def on_device_event(device: USBDeviceInfo, action: str):
    """Called when USB device is inserted or removed."""
    if action == 'add':
        emoji = "🔌"
        color = "\033[92m"  # Green
    else:
        emoji = "⏏️ "
        color = "\033[91m"  # Red
    
    reset = "\033[0m"
    
    print(f"\n{color}{emoji} USB Device {action.upper()}{reset}")
    print(f"   Device: {device.product_name}")
    print(f"   Vendor: {device.vendor_name}")
    print(f"   ID: {device.vendor_id}:{device.product_id}")
    print(f"   Class: {device.class_name}")
    print(f"   Bus ID: {device.bus_id}")
    
    if device.is_high_risk:
        print(f"   \033[93m⚠️  HIGH RISK: This device type can pose security risks!\033[0m")
    elif device.is_low_risk:
        print(f"   \033[92m✅ Low risk device\033[0m")
    
    if device.serial:
        print(f"   Serial: {device.serial}")


def main():
    print("=" * 60)
    print("USB Device Detection Test")
    print("=" * 60)
    
    if not is_pyudev_available():
        print("\n❌ ERROR: pyudev is not installed!")
        print("   Install with: sudo apt install python3-pyudev")
        sys.exit(1)
    
    print(f"\n✅ pyudev is available")
    
    # List current devices
    print("\n📋 Currently connected USB devices:")
    print("-" * 60)
    
    devices = list_usb_devices()
    for device in devices:
        risk_icon = "⚠️ " if device.is_high_risk else "✅" if device.is_low_risk else "  "
        print(f"  {risk_icon} {device.product_name} ({device.class_name})")
    
    print(f"\nTotal: {len(devices)} devices")
    
    # Start monitoring
    print("\n" + "=" * 60)
    print("🔍 Monitoring for USB events... (Press Ctrl+C to stop)")
    print("=" * 60)
    
    monitor = USBMonitor(on_device_event)
    
    if not monitor.start():
        print("\n❌ Failed to start USB monitor!")
        sys.exit(1)
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n\nStopping USB monitor...")
        monitor.stop()
        print("Done!")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Keep running until Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()

