"""Tests for inbound firewall detection."""

import pytest
from unittest.mock import patch, MagicMock
from bastion.inbound_firewall import InboundFirewallDetector


class TestInboundFirewallDetector:
    """Tests for InboundFirewallDetector class."""

    def test_detect_ufw_active(self):
        """Test detection of active UFW via config file."""
        with patch.object(InboundFirewallDetector, '_run_cmd') as mock_run, \
             patch('builtins.open', MagicMock(return_value=MagicMock(
                 __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value='ENABLED=yes\n'))),
                 __exit__=MagicMock(return_value=False)
             ))):
            mock_run.return_value = (0, '/usr/sbin/ufw', '')  # which ufw succeeds

            result = InboundFirewallDetector._detect_ufw()
            assert result['active'] is True
            assert result['installed'] is True

    def test_detect_ufw_inactive(self):
        """Test detection of inactive UFW via config file."""
        with patch.object(InboundFirewallDetector, '_run_cmd') as mock_run, \
             patch('builtins.open', MagicMock(return_value=MagicMock(
                 __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value='ENABLED=no\n'))),
                 __exit__=MagicMock(return_value=False)
             ))):
            mock_run.return_value = (0, '/usr/sbin/ufw', '')  # which ufw succeeds

            result = InboundFirewallDetector._detect_ufw()
            assert result['active'] is False
            assert result['installed'] is True

    def test_detect_firewalld_active(self):
        """Test detection of active firewalld."""
        with patch.object(InboundFirewallDetector, '_run_cmd') as mock_run:
            def run_side_effect(cmd, **kwargs):
                if 'which' in cmd:
                    return (0, '/usr/bin/firewall-cmd', '')
                if 'systemctl' in cmd and 'firewalld' in cmd:
                    return (0, 'active', '')
                return (1, '', '')
            mock_run.side_effect = run_side_effect

            result = InboundFirewallDetector._detect_firewalld()
            assert result['active'] is True

    def test_detect_iptables_blocking_rules(self):
        """Test detection of iptables blocking rules."""
        iptables_output = """Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
DROP       all  --  0.0.0.0/0            0.0.0.0/0
"""
        with patch.object(InboundFirewallDetector, '_run_cmd') as mock_run:
            mock_run.return_value = (0, iptables_output, '')

            result = InboundFirewallDetector._detect_iptables_input()
            assert result['has_rules'] is True
            assert result['blocking_count'] == 1

    def test_detect_iptables_bastion_rules(self):
        """Test detection of Bastion's own rules."""
        iptables_output = """Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            /* BASTION_INBOUND */
DROP       all  --  0.0.0.0/0            0.0.0.0/0            /* BASTION_INBOUND */
"""
        with patch.object(InboundFirewallDetector, '_run_cmd') as mock_run:
            mock_run.return_value = (0, iptables_output, '')

            result = InboundFirewallDetector._detect_iptables_input()
            assert result['has_bastion'] is True
            assert result['bastion_count'] == 2
            # Bastion's own DROP rules don't count as external blocking rules
            assert result['has_rules'] is False

    def test_detect_bastion_state_file(self):
        """Test detection via state file."""
        with patch('builtins.open', MagicMock(return_value=MagicMock(
            __enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value='active'))),
            __exit__=MagicMock(return_value=False)
        ))):
            result = InboundFirewallDetector._detect_bastion_state_file()
            assert result is True

    def test_detect_firewall_returns_required_keys(self):
        """Test that detect_firewall returns all required keys."""
        with patch.object(InboundFirewallDetector, '_detect_ufw', return_value={'installed': False, 'active': False}), \
             patch.object(InboundFirewallDetector, '_detect_firewalld', return_value={'installed': False, 'active': False}), \
             patch.object(InboundFirewallDetector, '_detect_nftables', return_value={'installed': False, 'active': False}), \
             patch.object(InboundFirewallDetector, '_detect_iptables_input', return_value={'has_rules': False, 'has_bastion': False, 'blocking_count': 0}), \
             patch.object(InboundFirewallDetector, '_detect_bastion_state_file', return_value=False), \
             patch.object(InboundFirewallDetector, '_detect_docker', return_value=False):

            result = InboundFirewallDetector.detect_firewall()

            # Check all required keys are present
            assert 'type' in result
            assert 'active' in result
            assert 'status' in result
            assert 'firewall' in result
            assert 'message' in result
            assert 'recommendation' in result
            assert 'has_docker' in result

    def test_detect_firewall_ufw_priority(self):
        """Test that UFW takes priority over other firewalls."""
        with patch.object(InboundFirewallDetector, '_detect_ufw', return_value={'installed': True, 'active': True}), \
             patch.object(InboundFirewallDetector, '_detect_firewalld', return_value={'installed': True, 'active': True}), \
             patch.object(InboundFirewallDetector, '_detect_nftables', return_value={'installed': True, 'active': True}), \
             patch.object(InboundFirewallDetector, '_detect_iptables_input', return_value={'has_rules': True, 'has_bastion': False, 'blocking_count': 1}), \
             patch.object(InboundFirewallDetector, '_detect_docker', return_value=False):

            result = InboundFirewallDetector.detect_firewall()

            assert result['type'] == 'ufw'
            assert result['active'] is True

    def test_detect_firewall_bastion_detection(self):
        """Test that Bastion's own rules are detected."""
        with patch.object(InboundFirewallDetector, '_detect_ufw', return_value={'installed': False, 'active': False}), \
             patch.object(InboundFirewallDetector, '_detect_firewalld', return_value={'installed': False, 'active': False}), \
             patch.object(InboundFirewallDetector, '_detect_nftables', return_value={'installed': False, 'active': False}), \
             patch.object(InboundFirewallDetector, '_detect_iptables_input', return_value={'has_rules': False, 'has_bastion': True, 'blocking_count': 0, 'bastion_count': 4}), \
             patch.object(InboundFirewallDetector, '_detect_bastion_state_file', return_value=True), \
             patch.object(InboundFirewallDetector, '_detect_docker', return_value=False):

            result = InboundFirewallDetector.detect_firewall()

            assert result['type'] == 'bastion'
            assert result['active'] is True
            assert result['firewall'] == 'Bastion Basic'

    def test_setup_inbound_protection_when_already_active(self):
        """Test setup_inbound_protection returns early when already protected."""
        with patch.object(InboundFirewallDetector, 'detect_firewall') as mock_detect:
            mock_detect.return_value = {'active': True, 'type': 'ufw', 'firewall': 'UFW'}

            success, msg = InboundFirewallDetector.setup_inbound_protection()

            assert success is True
            assert 'already' in msg.lower() or 'ufw' in msg.lower()

    def test_remove_bastion_rules(self):
        """Test remove_bastion_rules removes rules correctly."""
        iptables_output = """Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            /* BASTION_INBOUND */
2    DROP       all  --  0.0.0.0/0            0.0.0.0/0            /* BASTION_INBOUND */
"""
        with patch.object(InboundFirewallDetector, '_run_cmd') as mock_run:
            def run_side_effect(cmd, **kwargs):
                if 'iptables' in cmd and '-L' in cmd:
                    return (0, iptables_output, '')
                if 'iptables' in cmd and '-D' in cmd:
                    return (0, '', '')
                return (0, '', '')
            mock_run.side_effect = run_side_effect

            success, msg = InboundFirewallDetector.remove_bastion_rules()

            assert success is True
