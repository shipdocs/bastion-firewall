"""
Inbound firewall detection and integration.
Detects UFW, firewalld, nftables, iptables and provides status.
Can also set up minimal INPUT rules if no other firewall is detected.
"""

import subprocess
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class InboundFirewallDetector:
    """
    Detects and manages inbound firewall integration.
    Supports UFW, firewalld, nftables, and iptables detection.
    """

    # Our comment marker for iptables rules
    BASTION_COMMENT = "BASTION_INBOUND"
    # State file that indicates Bastion's rules are active (readable by regular users)
    STATE_FILE = "/var/run/bastion/inbound-active"

    @staticmethod
    def _run_cmd(cmd: list, timeout: int = 5) -> tuple:
        """Run a command and return (returncode, stdout, stderr)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return (result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            return (-1, "", "timeout")
        except FileNotFoundError:
            return (-1, "", "not found")
        except Exception as e:
            return (-1, "", str(e))

    @classmethod
    def _detect_ufw(cls) -> dict:
        """Detect UFW status."""
        # First check if UFW is installed
        rc, stdout, _ = cls._run_cmd(['which', 'ufw'])
        if rc != 0:
            return {'installed': False, 'active': False}

        # Method 1: Read /etc/ufw/ufw.conf (readable by regular users)
        # This is the most reliable way without requiring root
        try:
            with open('/etc/ufw/ufw.conf', 'r') as f:
                content = f.read()
                if 'ENABLED=yes' in content:
                    return {'installed': True, 'active': True}
                elif 'ENABLED=no' in content:
                    return {'installed': True, 'active': False}
        except (IOError, PermissionError):
            pass  # Fall through to other methods

        # Method 2: Try with sudo (non-interactive, requires passwordless sudo)
        rc, stdout, _ = cls._run_cmd(['sudo', '-n', 'ufw', 'status'])
        if rc == 0:
            if 'Status: active' in stdout:
                return {'installed': True, 'active': True, 'output': stdout}
            elif 'Status: inactive' in stdout:
                return {'installed': True, 'active': False}

        # Method 3: Try without sudo (may work on some systems)
        rc, stdout, _ = cls._run_cmd(['ufw', 'status'])
        if rc == 0:
            if 'Status: active' in stdout:
                return {'installed': True, 'active': True, 'output': stdout}
            elif 'Status: inactive' in stdout:
                return {'installed': True, 'active': False}

        # Note: We do NOT check systemctl is-active ufw because UFW's
        # systemd service stays "active" even when firewall is disabled.

        # If we can't determine status, assume inactive (safer default)
        return {'installed': True, 'active': False}

    @classmethod
    def _detect_firewalld(cls) -> dict:
        """Detect firewalld status."""
        # Check if firewalld is installed
        rc, stdout, _ = cls._run_cmd(['which', 'firewall-cmd'])
        if rc != 0:
            return {'installed': False, 'active': False}

        # Check service status
        rc, stdout, _ = cls._run_cmd(['systemctl', 'is-active', 'firewalld'])
        if rc == 0 and stdout.strip() == 'active':
            return {'installed': True, 'active': True}

        return {'installed': True, 'active': False}

    @classmethod
    def _detect_nftables(cls) -> dict:
        """Detect nftables with input chain configured."""
        # Check if nft is available
        rc, stdout, _ = cls._run_cmd(['which', 'nft'])
        if rc != 0:
            return {'installed': False, 'active': False}

        # Check for input chain rules (requires root for full output)
        rc, stdout, _ = cls._run_cmd(['nft', 'list', 'ruleset'])
        if rc == 0 and 'chain input' in stdout.lower():
            return {'installed': True, 'active': True}

        return {'installed': True, 'active': False}

    @classmethod
    def _detect_iptables_input(cls) -> dict:
        """Detect if iptables INPUT chain has actual blocking rules."""
        rc, stdout, _ = cls._run_cmd(['iptables', '-L', 'INPUT', '-n'])
        if rc != 0:
            return {'has_rules': False, 'has_bastion': False, 'blocking_count': 0}

        lines = stdout.strip().split('\n')
        # Skip header lines: "Chain INPUT..." and "target prot..."
        rules = [l for l in lines[2:] if l.strip()]

        # Count Bastion's rules
        bastion_count = sum(1 for l in rules if cls.BASTION_COMMENT in l)

        # Count actual blocking rules (DROP/REJECT) that aren't Bastion's
        # Chain jumps (LIBVIRT_INP, ufw-*) don't count as actual protection
        blocking_rules = [l for l in rules
                        if ('DROP' in l or 'REJECT' in l)
                        and cls.BASTION_COMMENT not in l]

        # Also check if policy is DROP/REJECT
        policy_line = lines[0] if lines else ''
        has_drop_policy = 'policy DROP' in policy_line or 'policy REJECT' in policy_line

        return {
            'has_rules': len(blocking_rules) > 0 or has_drop_policy,
            'has_bastion': bastion_count > 0,
            'blocking_count': len(blocking_rules),
            'bastion_count': bastion_count,
            'has_drop_policy': has_drop_policy
        }

    @classmethod
    def _detect_docker(cls) -> bool:
        """Detect if Docker is installed and running."""
        rc, stdout, _ = cls._run_cmd(['systemctl', 'is-active', 'docker'])
        return rc == 0 and stdout.strip() == 'active'

    @classmethod
    def _detect_bastion_state_file(cls) -> bool:
        """Check if Bastion's inbound protection state file exists.

        This is used because regular users can't read iptables rules.
        The state file is created by bastion-setup-inbound when rules are added.
        """
        try:
            with open(cls.STATE_FILE, 'r') as f:
                return f.read().strip() == 'active'
        except (IOError, PermissionError):
            return False

    @classmethod
    def detect_firewall(cls) -> dict:
        """
        Detect which inbound firewall is active.

        Returns:
            dict: Firewall status with keys:
                - type: 'ufw' | 'firewalld' | 'nftables' | 'iptables' | 'bastion' | 'none'
                - active: bool - whether inbound protection is active
                - status: 'active' | 'inactive' | 'not_configured'
                - firewall: Human-readable firewall name
                - message: Detailed status message
                - recommendation: Actionable advice or None
                - has_docker: bool - Docker detected (for UI warnings)
        """
        result = {
            'type': 'none',
            'active': False,
            'status': 'not_configured',
            'firewall': 'None',
            'message': '',
            'recommendation': None,
            'has_docker': cls._detect_docker()
        }

        # Priority 1: Check UFW (most common on Ubuntu/Zorin)
        ufw = cls._detect_ufw()
        if ufw.get('active'):
            result.update({
                'type': 'ufw',
                'active': True,
                'status': 'active',
                'firewall': 'UFW',
                'message': 'UFW firewall is active and protecting inbound connections.'
            })
            return result

        # Priority 2: Check firewalld (Fedora, RHEL, CentOS)
        firewalld = cls._detect_firewalld()
        if firewalld.get('active'):
            result.update({
                'type': 'firewalld',
                'active': True,
                'status': 'active',
                'firewall': 'firewalld',
                'message': 'firewalld is active and protecting inbound connections.'
            })
            return result

        # Priority 3: Check nftables (modern replacement)
        nftables = cls._detect_nftables()
        if nftables.get('active'):
            result.update({
                'type': 'nftables',
                'active': True,
                'status': 'active',
                'firewall': 'nftables',
                'message': 'nftables is configured with input filtering.'
            })
            return result

        # Priority 4: Check iptables INPUT blocking rules (not just chain jumps)
        iptables = cls._detect_iptables_input()
        if iptables.get('has_rules'):
            count = iptables.get('blocking_count', 0)
            msg = f'iptables has {count} blocking INPUT rules configured.'
            if iptables.get('has_drop_policy'):
                msg = 'iptables INPUT chain has DROP policy.'
            result.update({
                'type': 'iptables',
                'active': True,
                'status': 'active',
                'firewall': 'iptables',
                'message': msg
            })
            return result

        # Priority 5: Check if Bastion's own rules are present
        # First check state file (works without root), then iptables output
        if cls._detect_bastion_state_file() or iptables.get('has_bastion'):
            result.update({
                'type': 'bastion',
                'active': True,
                'status': 'active',
                'firewall': 'Bastion Basic',
                'message': 'Bastion basic inbound protection is active.'
            })
            return result

        # No firewall detected
        result.update({
            'type': 'none',
            'active': False,
            'status': 'inactive',
            'firewall': 'None',
            'message': 'No inbound firewall detected. Your system may be exposed.',
            'recommendation': 'Enable UFW or click "Setup Protection" to add basic rules.'
        })

        # Add Docker warning if applicable
        if result['has_docker']:
            result['message'] += ' (Docker detected - container networking may need special handling)'

        return result

    @classmethod
    def setup_inbound_protection(cls) -> tuple:
        """
        Set up inbound firewall protection.
        Tries UFW first (preferred), falls back to basic iptables if UFW unavailable.

        Returns:
            tuple: (success: bool, message: str)
        """
        # Check current status first
        status = cls.detect_firewall()
        if status['active']:
            return (True, f"Inbound protection already active ({status['firewall']}).")

        # Try UFW first (best UX on Ubuntu/Zorin)
        ufw = cls._detect_ufw()
        if ufw.get('installed'):
            return cls._setup_ufw()

        # Try to install UFW
        logger.info("UFW not installed, attempting to install...")
        install_success = cls._install_ufw()
        if install_success:
            return cls._setup_ufw()

        # Fall back to basic iptables rules
        return cls._setup_basic_iptables()

    @classmethod
    def _install_ufw(cls) -> bool:
        """Attempt to install UFW using apt."""
        try:
            # Use pkexec for privilege escalation
            rc, stdout, stderr = cls._run_cmd(
                ['pkexec', 'apt-get', 'install', '-y', 'ufw'],
                timeout=120
            )
            return rc == 0
        except Exception as e:
            logger.error(f"Failed to install UFW: {e}")
            return False

    @classmethod
    def _setup_ufw(cls) -> tuple:
        """Enable and configure UFW."""
        try:
            # Enable UFW with default deny incoming, allow outgoing
            commands = [
                ['pkexec', 'ufw', 'default', 'deny', 'incoming'],
                ['pkexec', 'ufw', 'default', 'allow', 'outgoing'],
                ['pkexec', 'ufw', '--force', 'enable'],
            ]

            for cmd in commands:
                rc, stdout, stderr = cls._run_cmd(cmd, timeout=30)
                if rc != 0:
                    return (False, f"Failed to configure UFW: {stderr}")

            return (True, "UFW enabled successfully!\n\n"
                         "Default policy: deny incoming, allow outgoing.\n"
                         "Use 'sudo ufw allow <port>' to open specific ports.")
        except Exception as e:
            return (False, f"Failed to enable UFW: {e}")

    @classmethod
    def _setup_basic_iptables(cls) -> tuple:
        """Set up minimal iptables INPUT rules as fallback."""
        try:
            # Commands for basic protection
            # Note: These would need root/pkexec
            commands = [
                # IPv4 rules
                ['pkexec', 'iptables', '-A', 'INPUT', '-i', 'lo',
                 '-m', 'comment', '--comment', cls.BASTION_COMMENT, '-j', 'ACCEPT'],
                ['pkexec', 'iptables', '-A', 'INPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED',
                 '-m', 'comment', '--comment', cls.BASTION_COMMENT, '-j', 'ACCEPT'],
                ['pkexec', 'iptables', '-A', 'INPUT', '-p', 'icmp', '--icmp-type', 'echo-request',
                 '-m', 'comment', '--comment', cls.BASTION_COMMENT, '-j', 'ACCEPT'],
                ['pkexec', 'iptables', '-A', 'INPUT',
                 '-m', 'comment', '--comment', cls.BASTION_COMMENT, '-j', 'DROP'],
            ]

            for cmd in commands:
                rc, stdout, stderr = cls._run_cmd(cmd, timeout=10)
                if rc != 0:
                    return (False, f"Failed to configure iptables: {stderr}")

            return (True, "Basic inbound protection enabled!\n\n"
                         "Allowing: localhost, established connections, ping.\n"
                         "Blocking: all other incoming connections.\n\n"
                         "Note: For more control, install UFW: sudo apt install ufw")
        except Exception as e:
            return (False, f"Failed to setup iptables: {e}")

    @classmethod
    def remove_bastion_rules(cls) -> tuple:
        """Remove Bastion's iptables INPUT rules."""
        try:
            # Get current rules
            rc, stdout, stderr = cls._run_cmd(['iptables', '-L', 'INPUT', '-n', '--line-numbers'])
            if rc != 0:
                return (False, f"Failed to list rules: {stderr}")

            # Find rule numbers with our comment (parse in reverse to avoid index shift)
            lines = stdout.strip().split('\n')
            rule_nums = []
            for line in lines:
                if cls.BASTION_COMMENT in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        rule_nums.append(int(parts[0]))

            # Delete in reverse order
            for num in sorted(rule_nums, reverse=True):
                cls._run_cmd(['iptables', '-D', 'INPUT', str(num)])

            # Also try ip6tables
            rc, stdout, _ = cls._run_cmd(['ip6tables', '-L', 'INPUT', '-n', '--line-numbers'])
            if rc == 0:
                lines = stdout.strip().split('\n')
                rule_nums = []
                for line in lines:
                    if cls.BASTION_COMMENT in line:
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            rule_nums.append(int(parts[0]))
                for num in sorted(rule_nums, reverse=True):
                    cls._run_cmd(['ip6tables', '-D', 'INPUT', str(num)])

            return (True, "Bastion inbound rules removed.")
        except Exception as e:
            return (False, f"Failed to remove rules: {e}")

    @classmethod
    def open_port(cls, port: int, protocol: str = 'tcp') -> tuple:
        """
        Open a port for inbound connections.
        Works with both UFW (if active) and Bastion's iptables rules.

        Args:
            port: Port number (1-65535)
            protocol: 'tcp', 'udp', or 'both'

        Returns:
            tuple: (success: bool, message: str)
        """
        if not 1 <= port <= 65535:
            return (False, f"Invalid port number: {port}")

        if protocol not in ('tcp', 'udp', 'both'):
            return (False, f"Invalid protocol: {protocol}")

        # Detect current firewall type
        status = cls.detect_firewall()
        fw_type = status.get('type', 'none')

        if fw_type == 'ufw':
            return cls._open_port_ufw(port, protocol)
        elif fw_type == 'bastion':
            return cls._open_port_iptables(port, protocol)
        elif fw_type == 'iptables':
            return cls._open_port_iptables(port, protocol)
        else:
            return (False, "No inbound firewall is active. Enable protection first.")

    @classmethod
    def _open_port_ufw(cls, port: int, protocol: str) -> tuple:
        """Open port using UFW."""
        try:
            if protocol == 'both':
                rc1, _, err1 = cls._run_cmd(['pkexec', 'ufw', 'allow', f'{port}/tcp'])
                rc2, _, err2 = cls._run_cmd(['pkexec', 'ufw', 'allow', f'{port}/udp'])
                if rc1 == 0 and rc2 == 0:
                    return (True, f"Port {port} (TCP+UDP) opened via UFW.")
                return (False, f"Failed to open port: {err1 or err2}")
            else:
                rc, _, err = cls._run_cmd(['pkexec', 'ufw', 'allow', f'{port}/{protocol}'])
                if rc == 0:
                    return (True, f"Port {port}/{protocol} opened via UFW.")
                return (False, f"Failed to open port: {err}")
        except Exception as e:
            return (False, f"UFW error: {e}")

    @classmethod
    def _open_port_iptables(cls, port: int, protocol: str) -> tuple:
        """Open port using iptables (for Bastion's basic protection)."""
        try:
            # We need to insert ACCEPT rules BEFORE the DROP rule
            # Find the DROP rule position
            rc, stdout, _ = cls._run_cmd(['iptables', '-L', 'INPUT', '-n', '--line-numbers'])
            if rc != 0:
                return (False, "Failed to read iptables rules")

            # Find the DROP rule with BASTION_INBOUND comment
            drop_line = None
            for line in stdout.strip().split('\n'):
                if 'DROP' in line and cls.BASTION_COMMENT in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        drop_line = int(parts[0])
                        break

            if drop_line is None:
                return (False, "Bastion DROP rule not found. Is inbound protection active?")

            # Insert ACCEPT rule before DROP
            protocols = ['tcp', 'udp'] if protocol == 'both' else [protocol]
            comment = f"{cls.BASTION_COMMENT}_PORT"

            for proto in protocols:
                cmd = [
                    'pkexec', 'iptables', '-I', 'INPUT', str(drop_line),
                    '-p', proto, '--dport', str(port),
                    '-m', 'comment', '--comment', comment,
                    '-j', 'ACCEPT'
                ]
                rc, _, err = cls._run_cmd(cmd)
                if rc != 0:
                    return (False, f"Failed to add rule: {err}")
                # Increment drop_line for next insertion
                drop_line += 1

            proto_str = "TCP+UDP" if protocol == 'both' else protocol.upper()
            return (True, f"Port {port} ({proto_str}) opened via iptables.")
        except Exception as e:
            return (False, f"iptables error: {e}")

    @classmethod
    def close_port(cls, port: int, protocol: str = 'tcp') -> tuple:
        """
        Close a previously opened port.

        Args:
            port: Port number (1-65535)
            protocol: 'tcp', 'udp', or 'both'

        Returns:
            tuple: (success: bool, message: str)
        """
        status = cls.detect_firewall()
        fw_type = status.get('type', 'none')

        if fw_type == 'ufw':
            return cls._close_port_ufw(port, protocol)
        elif fw_type in ('bastion', 'iptables'):
            return cls._close_port_iptables(port, protocol)
        else:
            return (False, "No inbound firewall is active.")

    @classmethod
    def _close_port_ufw(cls, port: int, protocol: str) -> tuple:
        """Close port using UFW."""
        try:
            if protocol == 'both':
                cls._run_cmd(['pkexec', 'ufw', 'delete', 'allow', f'{port}/tcp'])
                cls._run_cmd(['pkexec', 'ufw', 'delete', 'allow', f'{port}/udp'])
                return (True, f"Port {port} (TCP+UDP) closed via UFW.")
            else:
                rc, _, err = cls._run_cmd(['pkexec', 'ufw', 'delete', 'allow', f'{port}/{protocol}'])
                if rc == 0:
                    return (True, f"Port {port}/{protocol} closed via UFW.")
                return (False, f"Failed to close port: {err}")
        except Exception as e:
            return (False, f"UFW error: {e}")

    @classmethod
    def _close_port_iptables(cls, port: int, protocol: str) -> tuple:
        """Close port by removing iptables ACCEPT rule."""
        try:
            protocols = ['tcp', 'udp'] if protocol == 'both' else [protocol]

            for proto in protocols:
                # Find and delete rules matching port and protocol
                while True:
                    rc, stdout, _ = cls._run_cmd(['iptables', '-L', 'INPUT', '-n', '--line-numbers'])
                    if rc != 0:
                        break

                    found = False
                    for line in stdout.strip().split('\n'):
                        if (f'dpt:{port}' in line and proto in line and
                            f'{cls.BASTION_COMMENT}_PORT' in line):
                            parts = line.split()
                            if parts and parts[0].isdigit():
                                cls._run_cmd(['pkexec', 'iptables', '-D', 'INPUT', parts[0]])
                                found = True
                                break
                    if not found:
                        break

            proto_str = "TCP+UDP" if protocol == 'both' else protocol.upper()
            return (True, f"Port {port} ({proto_str}) closed.")
        except Exception as e:
            return (False, f"iptables error: {e}")
