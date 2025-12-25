
import pytest
from unittest.mock import patch, MagicMock, mock_open
from bastion.inbound_firewall import InboundFirewallDetector

class TestInboundFirewallDetector:

    @pytest.mark.parametrize("shutil_which_map, systemctl_output, ufw_status_output, iptables_output, expected_result", [
        # 1. UFW Active via Systemd
        ({'ufw': '/usr/bin/ufw'}, 'active', '', '', {'has_protection': True, 'firewall': 'ufw', 'status': 'active'}),
        
        # 2. UFW Inactive via Systemd, Active via CLI
        ({'ufw': '/usr/bin/ufw'}, 'inactive', 'Status: active', '', {'has_protection': True, 'firewall': 'ufw', 'status': 'active'}),
        
        # 3. UFW Installed but Inactive
        ({'ufw': '/usr/bin/ufw'}, 'inactive', 'Status: inactive', '', {'has_protection': False, 'firewall': 'ufw', 'status': 'inactive'}),
        
        # 4. Firewalld Active via Systemd
        ({'firewall-cmd': '/usr/bin/firewall-cmd'}, 'active', '', '', {'has_protection': True, 'firewall': 'firewalld', 'status': 'active'}),
        
        # 5. IPTables Rules Found (DROP rule)
        ({}, '', '', 'Chain INPUT (policy ACCEPT)\n... DROP ...', {'has_protection': True, 'firewall': 'iptables', 'status': 'active'}),
        
        # 6. No Protection
        ({}, '', '', '', {'has_protection': False, 'firewall': None, 'status': 'not_installed'}),
    ])
    def test_detect_firewall_scenarios(self, shutil_which_map, systemctl_output, ufw_status_output, iptables_output, expected_result):
        """Smart parametrized test for all firewall detection logic paths"""
        
        with patch('shutil.which', side_effect=lambda x: shutil_which_map.get(x)), \
             patch('subprocess.run') as mock_run:
            
            # Setup mock behavior based on command args
            def mock_run_side_effect(cmd, **kwargs):
                cmd_str = ' '.join(cmd)
                mock_res = MagicMock()
                mock_res.returncode = 0
                mock_res.stdout = ""
                
                if 'systemctl' in cmd_str and 'ufw' in cmd_str:
                    mock_res.stdout = systemctl_output
                elif 'ufw' in cmd_str and 'status' in cmd_str:
                    mock_res.stdout = ufw_status_output
                elif 'systemctl' in cmd_str and 'firewalld' in cmd_str:
                    mock_res.stdout = systemctl_output # reusing var for simplicity
                elif 'iptables' in cmd_str:
                    mock_res.stdout = iptables_output
                    if not iptables_output: mock_res.returncode = 1
                
                return mock_res
            
            mock_run.side_effect = mock_run_side_effect
            
            result = InboundFirewallDetector.detect_firewall()
            
            # assert subset match
            for key, val in expected_result.items():
                assert result[key] == val, f"Failed for {key}: expected {val}, got {result[key]}"

    @pytest.mark.parametrize("os_release_content, expected_distro", [
        ('PRETTY_NAME="Ubuntu 22.04 LTS"', 'debian'),
        ('NAME="Debian GNU/Linux"', 'debian'),
        ('NAME="Fedora Linux"', 'fedora'),
        ('NAME="CentOS Linux"', 'fedora'),
        ('NAME="Arch Linux"', 'arch'),
        ('NAME="Unknown Distro"', 'unknown'),
    ])
    def test_detect_distro(self, os_release_content, expected_distro):
        """Verify distro detection logic"""
        with patch('builtins.open', mock_open(read_data=os_release_content)):
            assert InboundFirewallDetector.detect_distro() == expected_distro

    @pytest.mark.parametrize("distro, cmd_success, expected_success, expected_cmd_part", [
        ('debian', True, True, 'apt-get install'),
        ('debian', False, False, 'apt-get install'),
        ('fedora', True, True, 'dnf install'),
        ('arch', True, True, 'pacman -S'),
        ('unknown', True, False, None),
    ])
    def test_install_ufw_scenarios(self, distro, cmd_success, expected_success, expected_cmd_part):
        """Smart test for installation commands per distro"""
        with patch.object(InboundFirewallDetector, 'detect_distro', return_value=distro), \
             patch('subprocess.run') as mock_run:
            
            mock_res = MagicMock()
            mock_res.returncode = 0 if cmd_success else 1
            mock_res.stderr = "Error details" if not cmd_success else ""
            mock_run.return_value = mock_res
            
            success, msg = InboundFirewallDetector.install_ufw()
            
            assert success == expected_success
            
            if expected_cmd_part:
                # Verify correct command was called
                args, _ = mock_run.call_args
                cmd_called = ' '.join(args[0])
                assert expected_cmd_part in cmd_called
            elif distro == 'unknown':
                assert not mock_run.called

    def test_configure_ufw_stateful(self):
        """Verify the configuration command chain is correct"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            
            success, msg = InboundFirewallDetector.configure_ufw_stateful()
            
            assert success is True
            assert "stateful rules" in msg
            
            # Verify the exact safety commands are sent
            args, _ = mock_run.call_args
            cmd_called = args[0] # ['pkexec', 'sh', '-c', '...']
            shell_cmd = cmd_called[3]
            
            assert 'ufw --force reset' in shell_cmd
            assert 'default deny incoming' in shell_cmd
            assert 'default allow outgoing' in shell_cmd
            assert '--force enable' in shell_cmd

