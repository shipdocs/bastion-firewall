#!/usr/bin/env python3
"""
Test script for Douane firewall functionality.
"""

import os
import sys
import time
import subprocess
from pathlib import Path

def test_imports():
    """Test that all required dependencies are installed."""
    print("Testing imports...")
    
    try:
        import psutil
        print("  ✓ psutil")
    except ImportError:
        print("  ✗ psutil - Run: pip3 install psutil")
        return False
    
    try:
        import tabulate
        print("  ✓ tabulate")
    except ImportError:
        print("  ✗ tabulate - Run: pip3 install tabulate")
        return False
    
    try:
        import gi
        gi.require_version('Gtk', '3.0')
        from gi.repository import Gtk
        print("  ✓ GTK3")
    except (ImportError, ValueError):
        print("  ✗ GTK3 - Run: sudo apt-get install python3-gi gir1.2-gtk-3.0")
        return False
    
    return True


def test_database():
    """Test database creation and operations."""
    print("\nTesting database operations...")
    
    # Import after checking dependencies
    sys.path.insert(0, str(Path(__file__).parent))
    from douane_daemon import RulesDatabase
    
    # Use test database
    test_db = Path("/tmp/douane_test.db")
    if test_db.exists():
        test_db.unlink()
    
    db = RulesDatabase(test_db)
    print("  ✓ Database created")
    
    # Add a rule
    db.set_rule("/usr/bin/firefox", "allow", "always")
    print("  ✓ Rule added")
    
    # Get rule
    rule = db.get_rule("/usr/bin/firefox")
    assert rule == ("allow", "always"), "Rule mismatch"
    print("  ✓ Rule retrieved")
    
    # Log connection
    db.log_connection("/usr/bin/firefox", "93.184.216.34", 443, "tcp", "allow")
    print("  ✓ Connection logged")
    
    # Clean up
    test_db.unlink()
    print("  ✓ Database test passed")
    
    return True


def test_gui():
    """Test the GUI dialog."""
    print("\nTesting GUI dialog...")
    print("  A dialog window should appear. Close it to continue...")
    
    result = subprocess.run([
        sys.executable,
        "douane_gui.py",
        "--test"
    ], capture_output=False)
    
    if result.returncode == 0:
        print("  ✓ GUI test completed")
        return True
    else:
        print("  ✗ GUI test failed")
        return False


def test_application_identifier():
    """Test application identification."""
    print("\nTesting application identification...")
    
    sys.path.insert(0, str(Path(__file__).parent))
    from douane_daemon import ApplicationIdentifier
    
    # Get info about current process
    identifier = ApplicationIdentifier()
    info = identifier.get_process_info(os.getpid())
    
    if info:
        print(f"  ✓ Process identified: {info['name']}")
        print(f"    Executable: {info['exe_path']}")
        return True
    else:
        print("  ✗ Failed to identify process")
        return False


def main():
    """Run all tests."""
    print("=== Douane Test Suite ===\n")
    
    tests = [
        ("Import Dependencies", test_imports),
        ("Database Operations", test_database),
        ("Application Identifier", test_application_identifier),
        ("GUI Dialog", test_gui),
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"  ✗ Error: {e}")
            results.append((name, False))
    
    print("\n=== Test Results ===\n")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nPassed: {passed}/{total}")
    
    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed. Please check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
