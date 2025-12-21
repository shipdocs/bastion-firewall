
import os
import sys
import json
import socket
import logging
import signal
import time
import subprocess
from pathlib import Path
from typing import Dict, Optional
import threading

from .config import ConfigManager
from .rules import RuleManager
from .firewall_core import PacketProcessor, PacketInfo, IPTablesManager
from .service_whitelist import should_auto_allow, get_app_category

logger = logging.getLogger(__name__)

class DouaneDaemon:
    """Core Daemon Logic"""
    
    SOCKET_PATH = '/tmp/bastion-daemon.sock'
    
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.rule_manager = RuleManager()
        self.packet_processor: Optional[PacketProcessor] = None
        self.server_socket: Optional[socket.socket] = None
        self.gui_socket: Optional[socket.socket] = None
        self.running = False
        
        # Rate limiting and pending requests
        self.pending_requests: Dict[str, float] = {}
        self.last_request_time: Dict[str, float] = {}
        self.request_lock = threading.Lock() # Protects shared state (pending_requests)
        self.socket_lock = threading.Lock() # Protects socket writes

        # Statistics
        self.stats = {
            'total_connections': 0,
            'allowed_connections': 0,
            'blocked_connections': 0
        }

    def start(self):
        """Start the daemon"""
        logger.info("Starting Douane Daemon...")
        
        # Setup signals
        self._setup_signals()
        
        # Setup Socket
        self._setup_socket()
        
        # Setup iptables
        if not IPTablesManager.setup_nfqueue(queue_num=1):
            logger.error("Failed to setup iptables")
            return

        # Start Packet Processor IMMEDIATELY
        # Don't wait for GUI - use intelligent fallback for system services
        self.packet_processor = PacketProcessor(self._handle_packet)
        self.running = True

        # Start processor in background thread
        processor_thread = threading.Thread(target=self._run_processor, daemon=True)
        processor_thread.start()
        logger.info("Packet processor started")

        # Start GUI connection acceptor in background thread
        gui_thread = threading.Thread(target=self._accept_gui_connections, daemon=True)
        gui_thread.start()
        logger.info("Waiting for GUI to connect...")

        # Watchdog loop
        self._run_watchdog()

        # Cleanup - threads are daemon threads, they'll stop automatically
        self.stop()

    def _accept_gui_connections(self):
        """Accept GUI connections in background"""
        try:
            self.server_socket.settimeout(1.0)
            while self.running:
                try:
                    if not self.gui_socket:  # Only accept if not already connected
                        gui_socket, addr = self.server_socket.accept()
                        logger.info(f"GUI connected from {addr}")
                        self.gui_socket = gui_socket
                    else:
                        time.sleep(1)  # Already connected, just wait
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # Only log if not shutting down
                        logger.error(f"Error accepting GUI connection: {e}")
                    break
        except Exception as e:
            logger.error(f"GUI acceptor thread error: {e}")

    def _run_processor(self):
        """Run the packet processor"""
        try:
            self.packet_processor.start(queue_num=1)
        except Exception as e:
            logger.error(f"Packet processor error: {e}")
            self.running = False

    def _run_watchdog(self):
        """Main loop watchdog"""
        watchdog_counter = 0
        try:
            while self.running:
                time.sleep(1)
                
                # Check connection to GUI
                # If GUI disconnects, we might want to fail open or waiting?
                # For now just keep running.
                
                watchdog_counter += 1
                if watchdog_counter >= 30: # 30 seconds
                    watchdog_counter = 0
                    self._check_nfqueue_rule()
                
                # Send statistics update to GUI every 2 seconds
                if self.gui_socket and (watchdog_counter % 2 == 0):
                    self._send_stats_update()
        except KeyboardInterrupt:
            self.stop()

    def _send_stats_update(self):
        """Send statistics to GUI"""
        if not self.gui_socket:
            return
            
        try:
            msg = {
                'type': 'stats_update',
                'stats': self.stats
            }
            with self.socket_lock:
                self.gui_socket.sendall(json.dumps(msg).encode() + b'\n')
        except Exception as e:
            logger.error(f"Error sending stats: {e}")
            # Don't stop daemon, just log. Socket might be broken, 
            # but we usually handle that in main loop or send failure.

    def _setup_socket(self):
        """Setup Unix domain socket"""
        if os.path.exists(self.SOCKET_PATH):
            os.remove(self.SOCKET_PATH)
            
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.SOCKET_PATH)
        os.chmod(self.SOCKET_PATH, 0o666)
        self.server_socket.listen(1)

    def reload_config(self):
        """Reload configuration and rules"""
        logger.info("Reloading configuration and rules...")
        try:
            self.config = ConfigManager.load_config()
            self.rule_manager.reload_rules()
            logger.info(f"Config reloaded. Mode: {self.config.get('mode', 'learning')}")
        except Exception as e:
            logger.error(f"Error reloading config: {e}")

    def _setup_signals(self):
        signal.signal(signal.SIGHUP, lambda s, f: self.reload_config())
        signal.signal(signal.SIGTERM, lambda s, f: self.stop())
        signal.signal(signal.SIGINT, lambda s, f: self.stop())

    def _check_nfqueue_rule(self):
        """Ensure NFQUEUE rule exists"""
        # Logic to check external command
        res = subprocess.run(['iptables', '-S', 'OUTPUT'], capture_output=True, text=True)
        if 'NFQUEUE' not in res.stdout:
            logger.warning("NFQUEUE rule missing! Re-adding...")
            IPTablesManager.setup_nfqueue(queue_num=1)

    def _handle_packet(self, pkt_info: PacketInfo) -> bool:
        """Handle a packet decision"""
        self.stats['total_connections'] += 1

        # Always use current config
        learning_mode = self.config.get('mode') == 'learning'

        # APP INFO - Keep as None if not identified (security fix v2.0.18)
        # This prevents "Unknown Application" string from bypassing whitelist checks
        app_path = pkt_info.app_path  # Can be None
        app_name = pkt_info.app_name  # Can be None

        # For display purposes only
        display_name = app_name or "Unknown Application"
        display_path = app_path or "unknown"

        # CACHE CHECK - use actual path (can be None)
        cached_decision = self.rule_manager.get_decision(display_path, pkt_info.dest_port)
        if cached_decision is not None:
            # If we have a decision (Allow or Deny), we obey it.
            # In learning mode, we obey Allow, but what about Deny?
            # Usually learning mode shouldn't block even if rule says deny?
            # But the user might want to test "what happens if I block".
            # Standard logic: Learning mode = Log/Prompt but always ALLOW traffic in the end?
            # Or just "Don't create Deny rules automatically?"
            # Let's stick to: Learning Mode = Always Allow in the end, but maybe prompt.
            if learning_mode:
                 self.stats['allowed_connections'] += 1
                 return True
            
            if cached_decision:
                self.stats['allowed_connections'] += 1
            else:
                self.stats['blocked_connections'] += 1
            return cached_decision

        # RATE LIMITING / PENDING
        cache_key = f"{display_path}:{pkt_info.dest_port}"
        now = time.time()

        with self.request_lock:
            if cache_key in self.pending_requests:
                return True # Auto-allow if already asking to prevent blocking

            if cache_key in self.last_request_time:
                if now - self.last_request_time[cache_key] < 5.0:
                    self.stats['allowed_connections'] += 1 # Auto-allow is technically an allow
                    return True # Auto-allow recent

        # WL CHECK - Pass actual values (can be None) for security validation
        auto_allow, reason = should_auto_allow(app_name, app_path, pkt_info.dest_port, pkt_info.dest_ip)
        if auto_allow:
            logger.info(f"Auto-allowing {display_name} ({reason})")
            self.stats['allowed_connections'] += 1
            return True

        # In learning mode, if we don't know the app, we log/notify but ALLOW.
        # But we still want to show the popup so the user can "Learn" (create a rule).
        # So we proceed to _ask_gui.

        # ASK GUI - Pass display values for UI
        return self._ask_gui(pkt_info, display_name, display_path, cache_key, learning_mode)

    def _ask_gui(self, pkt_info, app_name, app_path, cache_key, learning_mode) -> bool:
        """Communicate with GUI"""
        if not self.gui_socket:
            logger.warning(f"No GUI connected for {app_name or 'unknown'} -> {pkt_info.dest_ip}:{pkt_info.dest_port}")

            # SMART FALLBACK: In enforcement mode without GUI, allow essential system services
            # This prevents breaking the system when GUI is not running
            if not learning_mode:
                # Check if this is a critical system service that should always work
                from bastion.service_whitelist import is_critical_system_service
                if is_critical_system_service(app_name, app_path, pkt_info.dest_port):
                    logger.info(f"Auto-allowing critical system service without GUI: {app_name}")
                    self.stats['allowed_connections'] += 1
                    return True

                # Not a critical service and no GUI - block it
                logger.warning(f"Blocking non-critical service without GUI: {app_name or 'unknown'}")
                self.stats['blocked_connections'] += 1
                return False

            # Learning mode - allow everything
            self.stats['allowed_connections'] += 1
            return True

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

        with self.request_lock:
            self.pending_requests[cache_key] = time.time()
            self.last_request_time[cache_key] = time.time()

        try:
            with self.socket_lock:
                self.gui_socket.sendall(json.dumps(request).encode() + b'\n')
            
            if learning_mode:
                # In learning mode, we essentially "Allow Temporary" immediately
                # The GUI might show a notification or a non-blocking dialog (handled by client)
                # But here in the daemon, we can't block the packet too long or timeout.
                # Actually, the GUI client shows the dialog. If we return True immediately here,
                # the packet goes through. The GUI event is just "informational".
                # BUT: If we return True immediately, the "pending_requests" logic might need adjustment.
                
                # Simpler: We wait for the "Okay" from GUI? 
                # If we want Learning Mode to be "Non-Blocking", we should return True immediately.
                # But then the user can't "Deny" it in the GUI to create a Deny rule.
                
                # Hybrid approach:
                # Learning Mode = We wait for user input, BUT if it times out, we Allow.
                # AND: The GUI shows "Allow / Deny" buttons.
                # If user clicks Deny, we save Deny rule.
                # BUT the packet that triggered it is... well, if we waited, we drop it.
                # IF we truly want "Never block connectivity in Learning Mode", we should return True immediately
                # and handle the rule creation asynchronously.
                # Given existing architecture, let's treat Learning Mode as:
                # "Show Popup, Wait for User. If User Denies -> Save Rule, Block Packet (for testing). Timeout -> Allow."
                
                # WAIT, existing code logic for learning mode int `_handle_packet` was:
                # if learning_mode: return True (if cached decision exists)
                
                pass # Proceed to wait for response

            # Wait for response
            # Set a timeout on recv?
            self.gui_socket.settimeout(60.0) # 1 min timeout for user response
            try:
                response = self.gui_socket.recv(4096).decode().strip()
            except socket.timeout:
                logger.warning("GUI socket timeout waiting for user decision")
                return True if learning_mode else False
            finally:
                self.gui_socket.settimeout(None)

            if not response:
                return False
                
            data = json.loads(response)
            allow = data.get('allow', False)
            permanent = data.get('permanent', False)
            
            if allow:
                self.stats['allowed_connections'] += 1
            else:
                self.stats['blocked_connections'] += 1
            
            with self.request_lock:
                self.pending_requests.pop(cache_key, None)

            if permanent:
                self.rule_manager.add_rule(app_path, pkt_info.dest_port, allow)
            
            # NO UFW calls here anymore.
            
            return allow

        except Exception as e:
            logger.error(f"GUI communication error: {e}")
            with self.request_lock:
                self.pending_requests.pop(cache_key, None)
            
            # Default action on error
            allowed = True if learning_mode else False
            if allowed:
                self.stats['allowed_connections'] += 1
            else:
                self.stats['blocked_connections'] += 1
            return allowed

    def stop(self):
        """Stop daemon"""
        if not self.running:
             return
             
        self.running = False
        logger.info("Stopping daemon...")
        
        # Close GUI socket first to unblock any pending recv
        if self.gui_socket:
            try:
                self.gui_socket.shutdown(socket.SHUT_RDWR)
                self.gui_socket.close()
            except:
                pass
            self.gui_socket = None

        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
            
        if self.packet_processor:
            self.packet_processor.stop()
            
        IPTablesManager.cleanup_nfqueue(queue_num=1)
        
        if os.path.exists(self.SOCKET_PATH):
            try:
                os.remove(self.SOCKET_PATH)
            except:
                pass
        logger.info("Daemon stopped")
