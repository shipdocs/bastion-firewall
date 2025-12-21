#!/usr/bin/env python3
"""
Inbound Firewall Detection and Configuration

This module detects if the user has inbound firewall protection and offers
to configure UFW with stateful rules if no protection is detected.

DESIGN PHILOSOPHY:
- Douane = Outbound firewall (always, independent)
- UFW/firewalld = Inbound firewall (optional, recommended)
- No dependencies: Douane works without any inbound firewall
- Helpful: Suggest UFW if user has no protection
"""

import logging
import shutil
import subprocess
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class InboundFirewallDetector:
    """Detect and configure inbound firewall protection"""
    
    @staticmethod
    def detect_firewall() -> Dict[str, any]:
        """
        Detect what inbound firewall is active.
        
        Returns:
            {
                'has_protection': bool,
                'firewall': 'ufw' | 'firewalld' | 'iptables' | 'nftables' | None,
                'status': 'active' | 'inactive' | 'not_installed',
                'recommendation': str | None
            }
        """
        # Check UFW (Debian/Ubuntu)
        if shutil.which('ufw'):
            try:
                result = subprocess.run(['ufw', 'status'], 
                                      capture_output=True, text=True, timeout=5)
                if 'Status: active' in result.stdout:
                    return {
                        'has_protection': True,
                        'firewall': 'ufw',
                        'status': 'active',
                        'recommendation': None
                    }
                else:
                    return {
                        'has_protection': False,
                        'firewall': 'ufw',
                        'status': 'inactive',
                        'recommendation': 'UFW is installed but not active. Enable it for inbound protection.'
                    }
            except Exception as e:
                logger.warning(f"Error checking UFW: {e}")
        
        # Check firewalld (Fedora/RHEL/CentOS)
        if shutil.which('firewall-cmd'):
            try:
                result = subprocess.run(['firewall-cmd', '--state'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and 'running' in result.stdout.lower():
                    return {
                        'has_protection': True,
                        'firewall': 'firewalld',
                        'status': 'active',
                        'recommendation': None
                    }
            except Exception as e:
                logger.warning(f"Error checking firewalld: {e}")
        
        # Check raw iptables rules
        try:
            result = subprocess.run(['iptables', '-L', 'INPUT', '-n'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Check if there are any DROP/REJECT rules
                if 'DROP' in result.stdout or 'REJECT' in result.stdout:
                    return {
                        'has_protection': True,
                        'firewall': 'iptables',
                        'status': 'active',
                        'recommendation': None
                    }
        except Exception as e:
            logger.warning(f"Error checking iptables: {e}")
        
        # Check nftables
        if shutil.which('nft'):
            try:
                result = subprocess.run(['nft', 'list', 'ruleset'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    return {
                        'has_protection': True,
                        'firewall': 'nftables',
                        'status': 'active',
                        'recommendation': None
                    }
            except Exception as e:
                logger.warning(f"Error checking nftables: {e}")
        
        # No firewall detected
        return {
            'has_protection': False,
            'firewall': None,
            'status': 'not_installed',
            'recommendation': 'No inbound firewall detected. Install UFW for complete protection.'
        }
    
    @staticmethod
    def detect_distro() -> str:
        """Detect Linux distribution"""
        try:
            with open('/etc/os-release') as f:
                content = f.read().lower()
                if 'debian' in content or 'ubuntu' in content:
                    return 'debian'
                elif 'fedora' in content or 'rhel' in content or 'centos' in content:
                    return 'fedora'
                elif 'arch' in content:
                    return 'arch'
        except Exception:
            pass
        return 'unknown'

    @staticmethod
    def install_ufw() -> tuple[bool, str]:
        """
        Install UFW package.

        Returns:
            (success, message) tuple
        """
        distro = InboundFirewallDetector.detect_distro()

        try:
            if distro == 'debian':
                logger.info("Installing UFW via apt...")
                result = subprocess.run(
                    ['pkexec', 'apt-get', 'install', '-y', 'ufw'],
                    capture_output=True, text=True, timeout=300
                )
            elif distro == 'fedora':
                logger.info("Installing UFW via dnf...")
                result = subprocess.run(
                    ['pkexec', 'dnf', 'install', '-y', 'ufw'],
                    capture_output=True, text=True, timeout=300
                )
            elif distro == 'arch':
                logger.info("Installing UFW via pacman...")
                result = subprocess.run(
                    ['pkexec', 'pacman', '-S', '--noconfirm', 'ufw'],
                    capture_output=True, text=True, timeout=300
                )
            else:
                return (False, f"Unsupported distribution: {distro}")

            if result.returncode == 0:
                return (True, "UFW installed successfully")
            else:
                return (False, f"Installation failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            return (False, "Installation timed out")
        except Exception as e:
            return (False, f"Installation error: {e}")

    @staticmethod
    def configure_ufw_stateful() -> tuple[bool, str]:
        """
        Configure UFW with stateful firewall rules.

        This sets up:
        - Default DENY incoming (blocks all new inbound connections)
        - Default ALLOW outgoing (allows all outbound - Douane handles this)
        - Stateful connection tracking (allows responses to outbound connections)

        This is the recommended server configuration and safe for desktops.

        Returns:
            (success, message) tuple
        """
        try:
            commands = [
                # Set defaults
                ['pkexec', 'ufw', 'default', 'deny', 'incoming'],
                ['pkexec', 'ufw', 'default', 'allow', 'outgoing'],

                # Enable UFW
                ['pkexec', 'ufw', '--force', 'enable'],
            ]

            for cmd in commands:
                logger.info(f"Running: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    return (False, f"Command failed: {' '.join(cmd)}\n{result.stderr}")

            return (True, "UFW configured with stateful rules (ESTABLISHED,RELATED allowed, NEW denied)")

        except subprocess.TimeoutExpired:
            return (False, "Configuration timed out")
        except Exception as e:
            return (False, f"Configuration error: {e}")

    @staticmethod
    def setup_inbound_protection() -> tuple[bool, str]:
        """
        Complete setup: Install and configure UFW if needed.

        Returns:
            (success, message) tuple
        """
        # Check if UFW is already installed
        if not shutil.which('ufw'):
            logger.info("UFW not found, installing...")
            success, msg = InboundFirewallDetector.install_ufw()
            if not success:
                return (False, f"Failed to install UFW: {msg}")

        # Configure UFW
        logger.info("Configuring UFW...")
        success, msg = InboundFirewallDetector.configure_ufw_stateful()
        if not success:
            return (False, f"Failed to configure UFW: {msg}")

        return (True, "Inbound firewall protection enabled successfully!\n\n" +
                      "UFW is now active with stateful rules:\n" +
                      "✅ Outbound: Allowed (Douane controls this)\n" +
                      "✅ Established/Related: Allowed (responses to your requests)\n" +
                      "❌ New Inbound: Denied (blocks unsolicited connections)")


