
import unittest
import pytest
from bastion.service_whitelist import (
    should_auto_allow, is_system_service, get_app_category, 
    is_critical_system_service
)

class TestServiceWhitelist:
    
    def test_is_system_service(self):
        assert is_system_service('/usr/bin/python')
        assert is_system_service('/bin/ls')
        assert is_system_service('/usr/sbin/service')
        assert is_system_service('/lib/systemd/systemd')
        
        assert not is_system_service('/home/user/malware')
        assert not is_system_service('/tmp/test')
        assert not is_system_service(None)
        assert not is_system_service('')

    @pytest.mark.parametrize("app_name, app_path, port, dest_ip, expected_allow, description", [
        # --- PHASE 1: Localhost ---
        ("systemd-resolved", "/usr/lib/systemd/systemd-resolved", 53, "127.0.0.53", True, "DNS to localhost resolver"),
        ("malware", "/tmp/malware", 8080, "127.0.0.1", False, "Unknown app to localhost"),
        
        # --- PHASE 2: DHCP ---
        ("dhclient", "/usr/sbin/dhclient", 67, "255.255.255.255", True, "Valid DHCP broadcast"),
        ("dhclient", "/tmp/fake_dhclient", 67, "255.255.255.255", False, "DHCP spoofing attempt (wrong path)"),
        ("unknown", "/bin/unknown", 67, "255.255.255.255", False, "Unknown DHCP client"),
        
        # --- PHASE 3: Trusted Apps ---
        ("NetworkManager", "/usr/sbin/NetworkManager", 53, "8.8.8.8", True, "NetworkManager DNS (Trusted)"),
        ("NetworkManager", "/usr/sbin/NetworkManager", 80, "1.1.1.1", False, "NetworkManager HTTP (Blocked port)"),
        
        # --- PHASE 4: Service Whitelist ---
        ("apt-get", "/usr/bin/apt-get", 80, "93.184.216.34", True, "Apt-get HTTP"),
        ("apt-get", "/usr/bin/apt-get", 443, "93.184.216.34", True, "Apt-get HTTPS"),
        ("snapd", "/usr/lib/snapd/snapd", 443, "1.1.1.1", True, "Snapd HTTPS"),
        
        # --- Edge Cases ---
        (None, None, 80, "1.1.1.1", False, "No app info"),
        ("", "", 80, "1.1.1.1", False, "Empty strings"),
    ])
    def test_should_auto_allow_scenarios(self, app_name, app_path, port, dest_ip, expected_allow, description):
        """Data-driven test for auto-allow logic"""
        allow, reason = should_auto_allow(app_name, app_path, port, dest_ip)
        
        # We assert the outcome matches our expectation
        assert allow == expected_allow, f"Failed scenario: {description}"

    def test_get_app_category(self):
        assert get_app_category("Firefox", "/usr/bin/firefox") == "Web Browser"
        assert get_app_category("Thunderbird", "/usr/bin/thunderbird") == "Email Client"
        assert get_app_category("Code", "/usr/bin/code") == "Development Tool"
        assert get_app_category("Systemd", "/usr/lib/systemd/systemd") == "System Service"
        assert get_app_category("UnknownApp", "/usr/bin/unknown") == "System Application"
        assert get_app_category("Game", "/home/user/game") == "Application"
        assert get_app_category(None, None) == "Unknown"

    def test_is_critical_system_service(self):
        # DNS to localhost is critical for ANY app
        assert is_critical_system_service(None, None, 53, '127.0.0.53')
        
        # Systemd-resolved outbound DNS
        assert is_critical_system_service('systemd-resolved', '/usr/lib/systemd/systemd-resolved', 53, '8.8.8.8')
        
        # DHCP
        assert is_critical_system_service('NetworkManager', '/usr/sbin/NetworkManager', 67, '255.255.255.255')
        
        # Browser is NOT critical
        assert not is_critical_system_service('firefox', '/usr/bin/firefox', 443, '1.1.1.1')


