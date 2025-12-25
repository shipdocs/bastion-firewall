#!/usr/bin/env python3
"""
Bastion Firewall - Production outbound firewall with GUI

This is the main production application that:
1. Intercepts outbound packets using netfilter
2. Identifies the application making each connection
3. Shows GUI dialogs for user decisions
4. Caches decisions and integrates with UFW
5. Provides a safe, user-friendly firewall experience

Requires root privileges.
"""

import os
import sys
import json
import logging
import signal
import socket
import threading
from pathlib import Path
from typing import Optional, Dict
import tkinter as tk
from tkinter import ttk, messagebox

# Setup logging
log_dir = Path.home() / '.config' / 'bastion'
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'bastion_firewall.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import our modules
try:
    # Try to import from installed package first
    try:
        from bastion.firewall_core import PacketProcessor, PacketInfo, IPTablesManager, NETFILTER_AVAILABLE
        from bastion.ufw_manager import UFWManager, ConnectionInfo
        from bastion.gui_improved import ImprovedFirewallDialog
        from bastion.utils import require_root
        from bastion.ttl_cache import TTLCache
    except ImportError:
        # Fall back to local imports for development
        from firewall_core import PacketProcessor, PacketInfo, IPTablesManager, NETFILTER_AVAILABLE
        from ufw_firewall_gui import UFWManager, ConnectionInfo
        from bastion_gui_improved import ImprovedFirewallDialog
        from ttl_cache import TTLCache
        # Local fallback for require_root
        require_root = None
except ImportError as e:
    logger.error(f"Failed to import required modules: {e}")
    print(f"ERROR: {e}")
    print("Make sure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)


class FirewallDecisionEngine:
    """
    Manages firewall decisions with caching and UFW integration.
    
    This is the brain of the firewall - it decides whether to allow or deny
    each connection based on user rules, cached decisions, and user input.
    """
    
    def __init__(self, config_path='config.json'):
        self.config = self._load_config(config_path)
        self.ufw_manager = UFWManager()
        
        # Decision cache with TTL to prevent stale entries
        # Connection-specific: 5 minutes (port reuse, dynamic IPs)
        # App-level rules: 24 hours (more stable, less churndecisions)
        self.decision_cache = TTLCache(max_size=10000, default_ttl=300)  # 5 min default
        
        # Application-level rules cache (longer TTL)
        self.app_rules = TTLCache(max_size=5000, default_ttl=86400)  # 24 hours
        
        # Pending decisions (for GUI thread coordination)
        self.pending_decisions = {}
        self.decision_lock = threading.Lock()
        
        logger.info("Firewall decision engine initialized with TTL caching")
        logger.info(f"  Connection cache: {self.decision_cache.stats()}")
        logger.info(f"  App rules cache: {self.app_rules.stats()}")
    
    def _load_config(self, config_path):
        """Load configuration with validation"""
        default_config = {
            "cache_decisions": True,  # bool
            "default_action": "deny", # str: 'allow' or 'deny'
            "timeout_seconds": 30,    # int: 1-300
            "allow_localhost": True,  # bool
            "allow_lan": False,       # bool
            "mode": "enforcement"     # str: 'enforcement' or 'learning'
        }
        
        config = default_config.copy()
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded = json.load(f)
                    
                # Validate and merge known keys
                for key, value in loaded.items():
                    if key not in default_config:
                        logger.warning(f"Unknown config key: {key}")
                        continue
                        
                    # Type validation
                    expected_type = type(default_config[key])
                    if not isinstance(value, expected_type):
                        # Handle int/float mismatch
                        if expected_type == int and isinstance(value, float):
                            value = int(value)
                        else:
                            logger.error(f"Config type mismatch for {key}: expected {expected_type}, got {type(value)}")
                            continue
                    
                    # Value validation
                    if key == "default_action" and value not in ("allow", "deny"):
                        logger.error(f"Invalid default_action: {value}")
                        continue
                        
                    if key == "mode" and value not in ("enforcement", "learning"):
                        logger.error(f"Invalid mode: {value}")
                        continue
                        
                    if key == "timeout_seconds" and not (0 < value <= 600):
                        logger.error(f"Invalid timeout_seconds: {value} (must be 1-600)")
                        continue
                        
                    config[key] = value
                    
            except Exception as e:
                logger.warning(f"Error loading config: {e}, using defaults")
        
        return config
    
    def should_allow_packet(self, pkt_info: PacketInfo) -> bool:
        """
        Decide whether to allow a packet.

        This is called for every outbound packet and must be fast.
        Returns True to allow, False to deny.
        """
        # Quick checks first
        if self.config.get('allow_localhost') and pkt_info.dest_ip.startswith('127.'):
            return True

        if self.config.get('allow_lan') and self._is_lan_ip(pkt_info.dest_ip):
            return True

        # Check if we have an application-level rule (from TTL cache)
        if pkt_info.app_path:
            decision = self.app_rules.get(pkt_info.app_path)
            if decision is not None:
                logger.debug(f"Using app rule for {pkt_info.app_name}: {decision}")

                # In learning mode, always allow but still show popup for new connections
                if self.config.get('mode') == 'learning':
                    return True

                return decision == 'allow'

        # Check decision cache (TTL-based)
        cache_key = self._get_cache_key(pkt_info)
        decision = self.decision_cache.get(cache_key)
        if decision is not None:
            logger.debug(f"Using cached decision for {pkt_info}: {decision}")

            # In learning mode, always allow but still show popup for new connections
            if self.config.get('mode') == 'learning':
                return True

            return decision == 'allow'

        # No rule found - need to ask user
        decision = self._prompt_user(pkt_info)

        # In learning mode, ALWAYS allow (just learning user preferences)
        if self.config.get('mode') == 'learning':
            logger.info(f"Learning mode: Allowing {pkt_info.app_name} (user said: {decision})")
            return True

        # In enforcement mode, respect user decision
        return decision == 'allow'
    
    def _get_cache_key(self, pkt_info: PacketInfo) -> str:
        """Generate cache key for a packet"""
        return f"{pkt_info.app_path}:{pkt_info.dest_ip}:{pkt_info.dest_port}"
    
    def _is_lan_ip(self, ip: str) -> bool:
        """Check if IP is in private LAN range"""
        return (ip.startswith('192.168.') or 
                ip.startswith('10.') or 
                ip.startswith('172.16.') or
                ip.startswith('172.17.') or
                ip.startswith('172.18.') or
                ip.startswith('172.19.') or
                ip.startswith('172.20.') or
                ip.startswith('172.21.') or
                ip.startswith('172.22.') or
                ip.startswith('172.23.') or
                ip.startswith('172.24.') or
                ip.startswith('172.25.') or
                ip.startswith('172.26.') or
                ip.startswith('172.27.') or
                ip.startswith('172.28.') or
                ip.startswith('172.29.') or
                ip.startswith('172.30.') or
                ip.startswith('172.31.'))

    def _prompt_user(self, pkt_info: PacketInfo) -> str:
        """
        Prompt user for decision via GUI.

        This runs in the packet processing thread, so we need to be careful
        about thread safety and timeouts.
        """
        if not pkt_info.app_name:
            # Can't identify app, deny by default
            logger.warning(f"Cannot identify application for {pkt_info}, denying")
            return 'deny'

        # Create connection info for GUI
        conn_info = ConnectionInfo(
            app_name=pkt_info.app_name,
            app_path=pkt_info.app_path or 'unknown',
            dest_ip=pkt_info.dest_ip,
            dest_port=pkt_info.dest_port,
            protocol=pkt_info.protocol
        )

        # Show dialog (this blocks until user responds or timeout)
        try:
            learning_mode = self.config.get('mode') == 'learning'
            dialog = ImprovedFirewallDialog(
                conn_info,
                timeout=self.config.get('timeout_seconds', 30),
                learning_mode=learning_mode
            )
            decision, permanent = dialog.show()

            if decision is None:
                decision = 'deny'  # Default to deny on timeout/close

            logger.info(f"User decision for {pkt_info.app_name}: {decision} (permanent: {permanent})")

            # Cache the decision
            if permanent and pkt_info.app_path:
                # Application-level rule (uses default 24h TTL)
                self.app_rules.set(pkt_info.app_path, decision)

                # Add to UFW if requested
                if decision == 'allow':
                    self.ufw_manager.add_allow_rule(
                        app_path=pkt_info.app_path,
                        ip=pkt_info.dest_ip,
                        port=pkt_info.dest_port,
                        protocol=pkt_info.protocol
                    )
                else:
                    self.ufw_manager.add_deny_rule(
                        app_path=pkt_info.app_path,
                        ip=pkt_info.dest_ip,
                        port=pkt_info.dest_port,
                        protocol=pkt_info.protocol
                    )
            else:
                # Connection-specific rule (uses default 5m TTL)
                cache_key = self._get_cache_key(pkt_info)
                self.decision_cache.set(cache_key, decision)

            return decision

        except Exception as e:
            logger.error(f"Error prompting user: {e}", exc_info=True)
            return 'deny'  # Fail closed


class SystemdNotifier:
    """Simple systemd notification handler (sd_notify)"""
    def __init__(self):
        self.socket_path = os.environ.get('NOTIFY_SOCKET')
        self.sock = None
        if self.socket_path:
            # Handle abstract socket namespace (prefix @)
            # Convert to bytes for proper handling across platforms
            if self.socket_path.startswith('@'):
                self.socket_path = b'\0' + self.socket_path[1:].encode()
            elif isinstance(self.socket_path, str):
                self.socket_path = self.socket_path.encode()
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            except Exception as e:
                logger.warning(f"Failed to create systemd notify socket: {e}")
                self.sock = None

    def notify(self, msg: str) -> bool:
        """Send notification to systemd. Returns True on success."""
        if not self.sock:
            return False
        try:
            self.sock.sendto(msg.encode(), self.socket_path)
            return True
        except Exception as e:
            # Log failures but don't crash - notifications are best-effort
            logger.debug(f"Systemd notification failed: {e}")
            return False

    def ready(self):
        if self.notify("READY=1"):
            logger.info("Sent systemd READY=1")

    def ping(self):
        self.notify("WATCHDOG=1")

class BastionFirewall:
    """Main firewall application"""

    def __init__(self):
        self.decision_engine = FirewallDecisionEngine()
        self.packet_processor = None
        self.running = False
        self.monitor_thread = None
        self.systemd = SystemdNotifier()

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, _frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)

    def _monitor_loop(self):
        """Background thread for systemd watchdog and health checks"""
        logger.info("Health monitor thread started")
        self.systemd.ready()
        
        last_rule_check = 0
        rule_check_interval = 60 # Check every minute
        
        import time
        import subprocess
        
        while self.running:
            try:
                # 1. Ping systemd watchdog each loop (every 5s)
                self.systemd.ping()
                
                # 2. Periodic Rule Check
                now = time.time()
                if now - last_rule_check > rule_check_interval:
                    # Verify iptables rules exist and aren't duplicated
                    try:
                        # Quick counts
                        result = subprocess.run(
                            ['iptables', '-S', 'OUTPUT'], 
                            capture_output=True, text=True, timeout=2
                        )
                        output = result.stdout
                        nfqueue_count = output.count('NFQUEUE')
                        bypass_count = output.count('BASTION_BYPASS')
                        
                        if nfqueue_count != 1:
                            logger.warning(f"HEALTH CHECK WARNING: Found {nfqueue_count} NFQUEUE rules (expected 1)")
                        
                        if bypass_count != 2: # Root + systemd-network
                            logger.warning(f"HEALTH CHECK WARNING: Found {bypass_count} BYPASS rules (expected 2)")
                            
                        # Auto-repair could go here in future
                        
                    except Exception as e:
                        logger.error(f"Health check failed: {e}")
                    
                    last_rule_check = now
                
                time.sleep(5) # Watchdog interval is typically 10-30s, pinging every 5s is safe
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                time.sleep(5)

    def start(self):
        """Start the firewall"""
        logger.info("=" * 60)
        logger.info("Bastion Firewall Starting")
        logger.info("=" * 60)

        # Check dependencies
        if not NETFILTER_AVAILABLE:
            logger.error("NetfilterQueue not available!")
            print("\nERROR: NetfilterQueue library not installed.")
            print("Install with: sudo apt-get install build-essential python3-dev libnetfilter-queue-dev")
            print("Then: pip3 install NetfilterQueue")
            return False

        if not IPTablesManager.check_iptables_available():
            logger.error("iptables not available!")
            print("\nERROR: iptables not found on system")
            return False

        if not self.decision_engine.ufw_manager.check_ufw_installed():
            logger.error("UFW not installed!")
            print("\nERROR: UFW not installed. Install with: sudo apt-get install ufw")
            return False

        # Setup iptables rules
        logger.info("Setting up iptables NFQUEUE rules...")
        if not IPTablesManager.setup_nfqueue(queue_num=1):
            logger.error("Failed to setup iptables rules")
            return False

        # Create packet processor
        self.packet_processor = PacketProcessor(
            decision_callback=self.decision_engine.should_allow_packet
        )

        # Start processing
        self.running = True
        
        # Start health monitor
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        logger.info("Firewall is now active and monitoring outbound connections")
        logger.info("Press Ctrl+C to stop")

        try:
            self.packet_processor.start(queue_num=1)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception as e:
            logger.error(f"Error running firewall: {e}", exc_info=True)
        finally:
            self.stop()

        return True

    def stop(self):
        """Stop the firewall"""
        if not self.running:
            return

        logger.info("Stopping firewall...")
        self.running = False
        
        # Wait for monitor thread slightly? No, it's daemon.
        
        # Remove iptables rules
        IPTablesManager.remove_nfqueue(queue_num=1)

        # Stop packet processor
        if self.packet_processor:
            self.packet_processor.stop()

        logger.info("Firewall stopped")


def main():
    """Main entry point"""
    # Use secure require_root from bastion.utils
    # No dev mode bypass allowed for security
    require_root()

    print("\n" + "=" * 60)
    print("Bastion Firewall - Outbound Connection Control")
    print("=" * 60)
    print()

    # Create and start firewall
    firewall = BastionFirewall()
    firewall.start()


if __name__ == '__main__':
    main()

