#!/usr/bin/env python3
"""
Douane Firewall Daemon - Backend that runs as root

This daemon:
- Runs as root (for packet interception)
- Listens on a Unix socket for GUI commands
- Sends connection requests to the GUI via socket
- Handles packet accept/deny based on GUI responses
"""

import os
import sys
import json
import socket
import logging
import signal
import atexit
import time
from pathlib import Path

# Check for root privileges
if os.geteuid() != 0:
    print("ERROR: Daemon must be run as root (use sudo)")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/douane-daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import firewall modules
try:
    from douane.firewall_core import PacketProcessor, PacketInfo, IPTablesManager, NETFILTER_AVAILABLE
except ImportError as e:
    logger.error(f"Failed to import modules: {e}")
    sys.exit(1)

# Import service whitelist
try:
    from douane.service_whitelist import should_auto_allow, get_app_category
except ImportError:
    # Try local import
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    try:
        from service_whitelist import should_auto_allow, get_app_category
    except ImportError:
        logger.warning("Service whitelist not available")
        def should_auto_allow(app_name, app_path, dest_port, dest_ip):
            return (False, "")
        def get_app_category(app_name, app_path):
            return "Application"


class DouaneDaemon:
    """Backend daemon that handles packet interception"""

    def __init__(self):
        self.socket_path = '/tmp/douane-daemon.sock'
        self.rules_file = Path('/etc/douane/rules.json')
        self.server_socket = None
        self.gui_socket = None
        self.packet_processor = None
        self.running = False
        self.config = self.load_config()
        self.decision_cache = self.load_rules()  # Load saved rules
        self.pending_requests = {}  # Track pending GUI requests to avoid duplicates
        self.last_request_time = {}  # Rate limiting

    def load_config(self):
        """Load configuration"""
        config_path = Path('/etc/douane/config.json')
        if config_path.exists():
            try:
                with open(config_path) as f:
                    return json.load(f)
            except:
                pass
        return {'mode': 'learning'}

    def load_rules(self):
        """Load saved rules from disk"""
        if self.rules_file.exists():
            try:
                with open(self.rules_file) as f:
                    rules = json.load(f)
                    logger.info(f"Loaded {len(rules)} saved rules")
                    return rules
            except Exception as e:
                logger.error(f"Error loading rules: {e}")
        return {}

    def save_rules(self):
        """Save rules to disk"""
        try:
            self.rules_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.rules_file, 'w') as f:
                json.dump(self.decision_cache, f, indent=2)
            logger.info(f"Saved {len(self.decision_cache)} rules to {self.rules_file}")
        except Exception as e:
            logger.error(f"Error saving rules: {e}")

    def add_ufw_rule(self, pkt_info, allow):
        """Add permanent rule to UFW - per application + port"""
        try:
            import subprocess

            action = "allow" if allow else "deny"

            # UFW rule: allow/deny outgoing on specific port (for any destination)
            # This matches our cache key: app_path:port
            # Note: UFW doesn't support per-application rules, so this allows ANY app on this port
            # Our daemon will still enforce per-app rules via the cache
            cmd = ['ufw', action, 'out', 'port', str(pkt_info.dest_port), 'proto', pkt_info.protocol, 'comment', f'{pkt_info.app_name}:{pkt_info.dest_port}']

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Added UFW rule: {' '.join(cmd)}")
            else:
                logger.warning(f"Failed to add UFW rule: {result.stderr}")
        except Exception as e:
            logger.error(f"Error adding UFW rule: {e}")
        
    def start(self):
        """Start the daemon"""
        logger.info("Starting Douane Daemon...")
        
        # Remove old socket if exists
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        
        # Create Unix socket for GUI communication
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.socket_path)
        os.chmod(self.socket_path, 0o666)  # Allow user to connect
        self.server_socket.listen(1)
        
        logger.info(f"Listening on {self.socket_path}")
        
        # Setup iptables
        if not IPTablesManager.setup_nfqueue(queue_num=1):
            logger.error("Failed to setup iptables")
            return False
        
        # Wait for GUI to connect
        logger.info("Waiting for GUI to connect...")
        self.gui_socket, addr = self.server_socket.accept()
        logger.info("GUI connected!")
        
        # Start packet processor
        self.packet_processor = PacketProcessor(
            decision_callback=self.handle_packet
        )
        
        self.running = True
        self.packet_processor.start(queue_num=1)
        
        logger.info("Daemon running")
        
        # Keep running
        try:
            while self.running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def handle_packet(self, pkt_info: PacketInfo) -> bool:
        """
        Handle a packet - ask GUI for decision
        """
        # In learning mode, ALWAYS allow (just show popups)
        learning_mode = self.config.get('mode') == 'learning'

        # Normalize app info for consistent cache keys
        app_path = pkt_info.app_path or "unknown"
        app_name = pkt_info.app_name or "Unknown Application"

        # Check cache first - per-application + port (e.g., "firefox:443")
        cache_key = f"{app_path}:{pkt_info.dest_port}"
        if cache_key in self.decision_cache:
            logger.debug(f"Using cached decision for {cache_key} (allows {app_name} to any destination on port {pkt_info.dest_port})")
            if learning_mode:
                return True  # Always allow in learning mode
            return self.decision_cache[cache_key]

        # Rate limiting: If we asked about this app+port in the last 5 seconds, auto-allow
        current_time = time.time()
        if cache_key in self.last_request_time:
            time_since_last = current_time - self.last_request_time[cache_key]
            if time_since_last < 5.0:  # 5 second window
                logger.debug(f"Rate limiting: Auto-allowing {cache_key} (asked {time_since_last:.1f}s ago)")
                return True

        # If there's already a pending request for this app+port, auto-allow
        if cache_key in self.pending_requests:
            logger.debug(f"Pending request exists for {cache_key}, auto-allowing")
            return True

        # Check if this should be auto-allowed (smart whitelist)
        auto_allow, reason = should_auto_allow(
            pkt_info.app_name,
            pkt_info.app_path,
            pkt_info.dest_port,
            pkt_info.dest_ip
        )

        if auto_allow:
            logger.info(f"Auto-allowing: {pkt_info.app_name} -> {pkt_info.dest_ip}:{pkt_info.dest_port} ({reason})")
            # Cache this decision
            self.decision_cache[cache_key] = True
            return True

        # If app is unknown, allow in learning mode, ask in enforcement mode
        if not pkt_info.app_name or not pkt_info.app_path:
            logger.warning(f"Unknown application for {pkt_info.dest_ip}:{pkt_info.dest_port}")
            if learning_mode:
                return True  # Allow unknown apps in learning mode

        # Use normalized values
        pkt_info.app_name = app_name
        pkt_info.app_path = app_path

        # Send packet info to GUI
        app_category = get_app_category(app_name, app_path)

        request = {
            'type': 'connection_request',
            'app_name': app_name,
            'app_path': app_path,
            'app_category': app_category,
            'dest_ip': pkt_info.dest_ip,
            'dest_port': pkt_info.dest_port,
            'protocol': pkt_info.protocol
        }

        try:
            # Mark as pending and record time
            self.pending_requests[cache_key] = True
            self.last_request_time[cache_key] = current_time

            # In learning mode, send notification but DON'T wait for response
            # This prevents blocking internet while waiting for GUI
            if learning_mode:
                try:
                    self.gui_socket.sendall(json.dumps(request).encode() + b'\n')
                except:
                    pass  # Ignore send errors in learning mode
                self.pending_requests.pop(cache_key, None)
                # Cache this decision so we don't show popup again for same app+port
                self.decision_cache[cache_key] = True
                logger.info(f"Learning mode: Auto-allowing {app_name}:{pkt_info.dest_port} (cached for future)")
                return True

            # Enforcement mode: send and wait for response
            self.gui_socket.sendall(json.dumps(request).encode() + b'\n')

            # Wait for response
            response = self.gui_socket.recv(4096).decode().strip()
            decision_data = json.loads(response)

            allow = decision_data.get('allow', False)
            permanent = decision_data.get('permanent', False)

            # Remove from pending
            self.pending_requests.pop(cache_key, None)

            # Cache the decision if permanent
            if permanent:
                self.decision_cache[cache_key] = allow
                logger.info(f"Cached decision for {cache_key}: {allow}")
                # Save rules to disk
                self.save_rules()
                # Add UFW rule
                self.add_ufw_rule(pkt_info, allow)

            return allow

        except Exception as e:
            logger.error(f"Error communicating with GUI: {e}")
            # Remove from pending
            self.pending_requests.pop(cache_key, None)
            # Default to allow in learning mode, deny in enforcement mode
            return learning_mode
    
    def stop(self):
        """Stop the daemon"""
        logger.info("Stopping daemon...")
        self.running = False

        # Save rules before stopping
        self.save_rules()
        
        if self.packet_processor:
            self.packet_processor.stop()
        
        IPTablesManager.cleanup_nfqueue(queue_num=1)
        
        if self.gui_socket:
            self.gui_socket.close()
        
        if self.server_socket:
            self.server_socket.close()
        
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        
        logger.info("Daemon stopped")


if __name__ == '__main__':
    daemon = DouaneDaemon()

    # Register cleanup handlers
    def cleanup_handler(signum=None, frame=None):
        """Clean up on exit or signal"""
        logger.info(f"Received signal {signum}, cleaning up...")
        daemon.stop()
        sys.exit(0)

    # Register signal handlers
    signal.signal(signal.SIGINT, cleanup_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, cleanup_handler)  # kill command

    # Register atexit handler as backup
    atexit.register(lambda: daemon.stop())

    try:
        daemon.start()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
        daemon.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        daemon.stop()
        raise

