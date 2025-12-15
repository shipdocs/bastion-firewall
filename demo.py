#!/usr/bin/env python3
"""
Example script demonstrating UFW Firewall GUI components

This script shows how to use the individual components of the firewall GUI
without requiring root privileges or actual network monitoring.
"""

import sys
import os

# Add parent directory to path to import our module
sys.path.insert(0, os.path.dirname(__file__))

def demo_ufw_manager():
    """Demonstrate UFW Manager functionality"""
    print("="*60)
    print("UFW Manager Demo")
    print("="*60)
    print("\nThis would normally interact with UFW, but in this demo")
    print("we just show what commands would be executed.\n")
    
    # Simulate what would happen
    examples = [
        {
            "action": "Allow",
            "app": "/usr/bin/firefox",
            "ip": "93.184.216.34",
            "port": 443,
            "protocol": "tcp"
        },
        {
            "action": "Deny",
            "app": "/usr/bin/curl",
            "ip": "1.1.1.1",
            "port": 80,
            "protocol": "tcp"
        }
    ]
    
    for ex in examples:
        print(f"Application: {ex['app']}")
        print(f"Destination: {ex['ip']}:{ex['port']} ({ex['protocol']})")
        print(f"Action: {ex['action']}")
        
        if ex['action'] == 'Allow':
            cmd = f"ufw allow out to {ex['ip']} port {ex['port']} proto {ex['protocol']}"
        else:
            cmd = f"ufw deny out to {ex['ip']} port {ex['port']} proto {ex['protocol']}"
        
        print(f"UFW Command: {cmd}")
        print("-"*60 + "\n")


def demo_connection_info():
    """Demonstrate ConnectionInfo class"""
    print("="*60)
    print("Connection Info Demo")
    print("="*60)
    print("\nCreating connection information objects...\n")
    
    # Create a mock connection class
    class MockConnection:
        def __init__(self, app_name, app_path, dest_ip, dest_port, protocol):
            self.app_name = app_name
            self.app_path = app_path
            self.dest_ip = dest_ip
            self.dest_port = dest_port
            self.protocol = protocol
        
        def __str__(self):
            return f"{self.app_name} -> {self.dest_ip}:{self.dest_port} ({self.protocol})"
    
    connections = [
        MockConnection("firefox", "/usr/bin/firefox", "93.184.216.34", 443, "tcp"),
        MockConnection("chrome", "/usr/bin/google-chrome", "142.250.185.46", 443, "tcp"),
        MockConnection("ssh", "/usr/bin/ssh", "192.168.1.100", 22, "tcp"),
    ]
    
    for conn in connections:
        print(f"Connection: {conn}")
        print(f"  Application: {conn.app_name}")
        print(f"  Path: {conn.app_path}")
        print(f"  Destination: {conn.dest_ip}:{conn.dest_port}")
        print(f"  Protocol: {conn.protocol}")
        print()


def demo_config():
    """Demonstrate configuration loading"""
    print("="*60)
    print("Configuration Demo")
    print("="*60)
    print("\nDefault configuration settings:\n")
    
    import json
    
    config_file = os.path.join(os.path.dirname(__file__), 'config.json')
    
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        print(json.dumps(config, indent=2))
    else:
        print("config.json not found")
    
    print("\n" + "-"*60)


def demo_decision_cache():
    """Demonstrate decision caching"""
    print("="*60)
    print("Decision Cache Demo")
    print("="*60)
    print("\nShowing how decisions are cached to avoid repeated prompts...\n")
    
    cache = {}
    
    # Simulate some decisions
    decisions = [
        ("/usr/bin/firefox", "93.184.216.34", 443, "allow"),
        ("/usr/bin/chrome", "142.250.185.46", 443, "allow"),
        ("/usr/bin/curl", "1.1.1.1", 80, "deny"),
    ]
    
    for app_path, ip, port, decision in decisions:
        cache_key = f"{app_path}:{ip}:{port}"
        cache[cache_key] = decision
        print(f"Cached: {cache_key} -> {decision}")
    
    print(f"\nTotal cached decisions: {len(cache)}")
    
    # Simulate checking cache
    print("\nChecking cache for new connection...")
    check_key = "/usr/bin/firefox:93.184.216.34:443"
    if check_key in cache:
        print(f"✓ Found in cache: {cache[check_key]}")
        print("  No dialog needed, using cached decision")
    else:
        print("✗ Not in cache, would show dialog")
    
    print("-"*60 + "\n")


def main():
    """Run all demos"""
    print("\n" + "="*60)
    print("UFW Firewall GUI - Component Demonstration")
    print("="*60)
    print("\nThis script demonstrates the individual components")
    print("of the UFW Firewall GUI without requiring root access")
    print("or actual network monitoring.\n")
    
    input("Press Enter to continue...")
    print()
    
    # Run demos
    demo_config()
    print()
    
    input("Press Enter to continue...")
    print()
    
    demo_connection_info()
    
    input("Press Enter to continue...")
    print()
    
    demo_ufw_manager()
    
    input("Press Enter to continue...")
    print()
    
    demo_decision_cache()
    
    print("="*60)
    print("Demo Complete!")
    print("="*60)
    print("\nTo run the full application (requires root):")
    print("  sudo python3 ufw_firewall_gui.py")
    print("\nFor more information, see:")
    print("  - README.md for overview")
    print("  - INSTALL.md for installation guide")
    print("  - FAQ.md for common questions")
    print("  - IMPLEMENTATION.md for technical details")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
