
import os
import sys
import json
import socket
import logging
import signal
import time
import subprocess
import secrets
from pathlib import Path
from typing import Dict, Optional
from collections import deque
import threading

from .config import ConfigManager
from .rules import RuleManager
from .firewall_core import PacketProcessor, PacketInfo, IPTablesManager
from .service_whitelist import should_auto_allow, get_app_category
from .usb_monitor import USBMonitor, is_pyudev_available
from .usb_device import USBDeviceInfo
from .usb_rules import USBRuleManager, USBAuthorizer, Verdict
from .gui_manager import GUIManager

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple sliding window rate limiter."""

    def __init__(self, max_requests_per_second: int = 10, window_seconds: int = 1):
        self.max_requests = max_requests_per_second
        self.window = window_seconds
        self.requests = deque()
        self.lock = threading.Lock()

    def allow_request(self) -> bool:
        with self.lock:
            now = time.time()
            while self.requests and now - self.requests[0] > self.window:
                self.requests.popleft()
            if len(self.requests) >= self.max_requests:
                return False
            self.requests.append(now)
            return True
    
    def get_current_rate(self) -> int:
        with self.lock:
            now = time.time()
            return sum(1 for t in self.requests if now - t <= self.window)


class SystemdNotifier:
    """Simple systemd notification handler (sd_notify)"""
    def __init__(self):
        self.socket_path = os.environ.get('NOTIFY_SOCKET')
        self.sock = None
        if self.socket_path:
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


class BastionDaemon:
    """Core Daemon Logic"""

    # Socket in /run for security (not world-writable like /tmp)
    SOCKET_DIR = '/run/bastion'
    SOCKET_PATH = '/run/bastion/daemon.sock'
    
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.rule_manager = RuleManager()
        self.packet_processor: Optional[PacketProcessor] = None
        self.server_socket: Optional[socket.socket] = None
        self.gui_socket: Optional[socket.socket] = None
        self.running = False

        self.systemd = SystemdNotifier()
        self.monitor_thread = None

        # GUI Manager - ensures GUI is always running
        self.gui_manager = GUIManager()
        self.last_gui_check = 0
        self.gui_check_interval = 10  # Check GUI every 10 seconds

        self.pending_requests: Dict[str, float] = {}
        self.last_request_time: Dict[str, float] = {}
        self.request_lock = threading.Lock()
        self.socket_lock = threading.Lock()
        self.rate_limiter = RateLimiter(max_requests_per_second=10, window_seconds=1)

        # USB Device Control
        self.usb_monitor: Optional[USBMonitor] = None
        self.usb_rule_manager = USBRuleManager()
        self.usb_rules_lock = threading.Lock()  # Lock for thread-safe rule reloading
        self.usb_rules_last_modified = 0  # Track last modification time
        self.usb_pending_lock = threading.Lock()
        self.usb_pending_device: Optional[USBDeviceInfo] = None
        self.usb_pending_nonce: Optional[str] = None  # Anti-spoofing nonce
        self.usb_response_event = threading.Event()
        self.usb_response_verdict: Optional[Verdict] = None
        self.usb_response_scope: str = 'device'
        self.usb_response_save_rule: bool = True

        # Statistics
        self.stats = {
            'total_connections': 0,
            'allowed_connections': 0,
            'blocked_connections': 0,
            'rate_limited': 0,  # Track rate-limited requests
            'usb_devices_allowed': 0,
            'usb_devices_blocked': 0
        }

    def start(self):
        """Start the daemon"""
        logger.info("Starting Bastion Daemon...")

        # Setup signals
        self._setup_signals()

        # Setup Socket
        self._setup_socket()

        # Setup iptables
        if not IPTablesManager.setup_nfqueue(queue_num=1):
            logger.error("Failed to setup iptables")
            return

        # Start Packet Processor IMMEDIATELY
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

        # NOTE: GUI is started by user session via autostart, not by daemon
        # Wait for GUI to connect (with timeout)
        # 30 seconds allows time for user to log in and GUI to start
        self._wait_for_gui_connection(timeout=30)

        # Start health monitor
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

        # Start USB Device Monitor (if pyudev available)
        self._start_usb_monitor()

        # Watchdog loop (legacy main loop, now just fallback/keepalive)
        self._run_watchdog()

        # Cleanup - threads are daemon threads, they'll stop automatically
        self.stop()

    def _monitor_loop(self):
        """Background thread for systemd watchdog and health checks"""
        logger.info("Health monitor thread started")
        self.systemd.ready()

        last_rule_check = 0
        rule_check_interval = 60 # Check every minute
        last_usb_rule_check = 0
        usb_rule_check_interval = 5  # Check USB rules every 5 seconds

        while self.running:
            try:
                # 1. Ping systemd watchdog each loop (every 5s)
                self.systemd.ping()

                # Check if USB rules file has been modified
                current_time = time.time()
                if current_time - last_usb_rule_check >= usb_rule_check_interval:
                    self._reload_usb_rules_if_changed()
                    last_usb_rule_check = current_time

                # Check if GUI is running and restart if needed
                if current_time - self.last_gui_check >= self.gui_check_interval:
                    self._ensure_gui_running()
                    self.last_gui_check = current_time

                # 2. Periodic Rule Check
                now = time.time()
                if now - last_rule_check > rule_check_interval:
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
                        
                        # Root + systemd-network = 2
                        if bypass_count < 1: 
                            logger.warning(f"HEALTH CHECK WARNING: Found {bypass_count} BYPASS rules (expected at least 1 for root)")
                        elif bypass_count < 2:
                             # Just debug, could be systemd-network missing
                             logger.debug(f"Health check: Found {bypass_count} BYPASS rules (usually 2)")
                            
                    except Exception as e:
                        logger.error(f"Health check failed: {e}")
                    
                    last_rule_check = now
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                time.sleep(5)

    def _wait_for_gui_connection(self, timeout=10):
        """Wait for GUI to connect with timeout"""
        logger.info(f"Waiting for GUI connection (timeout: {timeout}s)...")
        start_time = time.time()

        while self.running and (time.time() - start_time) < timeout:
            if self.gui_socket:
                logger.info("✅ GUI connected successfully")
                return True
            time.sleep(0.5)

        if self.gui_socket:
            logger.info("✅ GUI connected successfully")
            return True

        logger.warning(f"⚠️ GUI did not connect within {timeout}s - continuing anyway")
        return False

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
                        # Start reader thread for this connection
                        reader = threading.Thread(target=self._read_gui_messages, daemon=True)
                        reader.start()
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

    def _read_gui_messages(self):
        """Read messages from GUI in background (for USB responses etc.)"""
        buffer = ""
        MAX_BUFFER_SIZE = 65536  # 64KB limit to prevent memory exhaustion
        try:
            while self.running and self.gui_socket:
                # Avoid race with _ask_gui: if there are pending connection requests,
                # let _ask_gui own socket reads to prevent stealing responses
                with self.request_lock:
                    has_pending = bool(self.pending_requests)
                if has_pending:
                    time.sleep(0.1)
                    continue
                try:
                    data = self.gui_socket.recv(4096)
                    if not data:
                        logger.warning("GUI disconnected")
                        break
                    try:
                        buffer += data.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        logger.warning("Invalid UTF-8 data from GUI, skipping")
                        continue
                    # Prevent buffer overflow from malicious/buggy GUI
                    if len(buffer) > MAX_BUFFER_SIZE:
                        logger.warning("GUI message buffer overflow, resetting")
                        buffer = ""
                        continue
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line.strip():
                            self._process_gui_message(line)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug(f"GUI read error: {e}")
                    break
        except Exception as e:
            logger.error(f"GUI reader thread error: {e}")
        finally:
            # Mark socket as disconnected
            with self.socket_lock:
                if self.gui_socket:
                    try:
                        self.gui_socket.close()
                    except OSError:
                        pass
                    self.gui_socket = None

    def _process_gui_message(self, line: str):
        """Process a message from GUI"""
        try:
            msg = json.loads(line)
            msg_type = msg.get('type', '')
            if msg_type == 'usb_response':
                self.handle_usb_response(msg)
            else:
                logger.debug(f"Unknown GUI message type: {msg_type}")
        except json.JSONDecodeError:
            logger.debug(f"Invalid JSON from GUI: {line[:50]}")

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
        except (BrokenPipeError, ConnectionResetError, OSError):
            # GUI disconnected - clear socket so we stop trying
            logger.debug("GUI disconnected")
            self.gui_socket = None
        except Exception as e:
            logger.error(f"Error sending stats: {e}")

    def _setup_socket(self):
        """Setup Unix domain socket in /run/bastion for security"""
        import grp

        # Create socket directory if it doesn't exist
        # /run is tmpfs, so this needs to be created each boot
        if not os.path.exists(self.SOCKET_DIR):
            os.makedirs(self.SOCKET_DIR, mode=0o755)
            logger.info(f"Created socket directory: {self.SOCKET_DIR}")

        if os.path.exists(self.SOCKET_PATH):
            os.remove(self.SOCKET_PATH)

        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.SOCKET_PATH)

        # Set socket permissions: owner (root) + group read/write
        # Try to use 'bastion' group, fall back to 'users' or world-readable
        try:
            socket_gid = None
            socket_mode = 0o660  # rw-rw---- by default

            # Try bastion group first (preferred for multi-user security)
            for group_name in ['bastion', 'users']:
                try:
                    socket_gid = grp.getgrnam(group_name).gr_gid
                    logger.info(f"Using group '{group_name}' for socket access")
                    break
                except KeyError:
                    continue

            if socket_gid is not None:
                os.chown(self.SOCKET_PATH, 0, socket_gid)  # root:bastion or root:users
                os.chmod(self.SOCKET_PATH, socket_mode)
                logger.info(f"Socket created at {self.SOCKET_PATH} (mode={oct(socket_mode)})")
            else:
                # Fallback: world-readable for single-user systems without proper groups
                os.chmod(self.SOCKET_PATH, 0o666)
                logger.warning(f"Socket created at {self.SOCKET_PATH} with world-writable permissions (no suitable group found)")
        except Exception as e:
            logger.warning(f"Could not set socket permissions: {e}")

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

        # Always use current config (defaults to learning mode for safety)
        learning_mode = self.config.get('mode', 'learning') == 'learning'

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
            # Check if there is already a PENDING request for this flow
            # We want to BLOCK/WAIT for the verdict, not just auto-allow,
            # otherwise we leak packets while the user is deciding.
            # But we can't block the logic loop here too long.
            
            # Better approach: 
            # If a request is pending, we should probably DROP this packet 
            # (or queue it, but NFQUEUE has limits).
            # Dropping is safer than leaking. The app will retry.
            if cache_key in self.pending_requests:
                return False 

            # Check rate limiting for recently treated flows
            if cache_key in self.last_request_time:
                # If we asked recently (5s), check if we have a standard rule now?
                # No, standard rules are checked above.
                # So this means user ignored it or we are in a "grace period"?
                # Let's simple ignore/drop to avoid spamming the GUI logic.
                if now - self.last_request_time[cache_key] < 2.0:
                     return False

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
                if is_critical_system_service(app_name, app_path, pkt_info.dest_port, pkt_info.dest_ip):
                    logger.info(f"Auto-allowing critical system service without GUI: {app_name}")
                    self.stats['allowed_connections'] += 1
                    return True

                # Not a critical service and no GUI - block it
                logger.warning(f"Blocking non-critical service without GUI: {app_name or 'unknown'}")
                self.stats['blocked_connections'] += 1
                return False

            # Learning mode - allow everything (don't block when GUI not connected)
            logger.debug(f"Learning mode: allowing {app_name or 'unknown'} (no GUI connected yet)")
            self.stats['allowed_connections'] += 1
            return True

        # GUI is connected - apply rate limiting only when we're about to ask GUI
        # SECURITY: Apply global rate limiting to prevent DoS (VULN-009)
        if not self.rate_limiter.allow_request():
            logger.warning(f"Rate limit exceeded - dropping packet from {app_name or 'unknown'}")
            logger.warning(f"Current rate: {self.rate_limiter.get_current_rate()} requests/second")

            # PHASE 3: Notify User
            self._notify_gui_rate_limit(app_name)

            self.stats['rate_limited'] += 1
            self.stats['blocked_connections'] += 1
            # Drop packet to prevent flooding
            return False

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
                # In learning mode, we wait for response but allow timeout logic to handle defaults
                pass 

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

            # Handle case where a USB response arrives while waiting for connection decision
            # This is a race condition - keep reading until we get the connection response
            original_timeout = self.gui_socket.gettimeout()
            try:
                self.gui_socket.settimeout(60.0)
                while data.get('type') == 'usb_response':
                    self.handle_usb_response(data)
                    # Read next message to get the actual connection response
                    try:
                        response = self.gui_socket.recv(4096).decode().strip()
                        if not response:
                            logger.warning("Empty response after handling USB response")
                            return True if learning_mode else False
                        data = json.loads(response)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Error parsing connection response after USB: {e}")
                        return True if learning_mode else False
            except socket.timeout:
                logger.warning("Socket timeout waiting for connection response after USB")
                return True if learning_mode else False
            finally:
                self.gui_socket.settimeout(original_timeout)

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

    def _notify_gui_rate_limit(self, app_name):
        """Send rate limit notification to GUI"""
        if not self.gui_socket:
             return
        
        # Prevent flooding the GUI with notifications
        # Only notify once every 5 seconds for rate limit warnings
        now = time.time()
        last_time = self.last_request_time.get('global_notification_limit', 0)
        
        if now - last_time < 5.0:
            return
            
        self.last_request_time['global_notification_limit'] = now
        
        msg = {
            'type': 'notification',
            'title': 'High Network Activity Detected',
            'message': f"Bastion blocked high frequency requests from {app_name or 'unknown'} to prevent overload.",
            'level': 'warning'
        }
        try:
            with self.socket_lock:
                self.gui_socket.sendall(json.dumps(msg).encode() + b'\n')
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.gui_socket = None
        except Exception:
            pass

    def stop(self):
        """Stop daemon"""
        if not self.running:
             return
             
        self.running = False
        logger.info("Stopping daemon...")

        # NOTE: GUI is managed by user session, not by daemon
        # Close GUI socket first to unblock any pending recv
        if self.gui_socket:
            try:
                self.gui_socket.shutdown(socket.SHUT_RDWR)
                self.gui_socket.close()
            except OSError:
                pass
            self.gui_socket = None

        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
            self.server_socket = None
            
        if self.packet_processor:
            self.packet_processor.stop()

        # Stop USB monitor and restore default policy
        if self.usb_monitor:
            self.usb_monitor.stop()
            self.usb_monitor = None
            # Restore default USB policy to allow (so system works normally without daemon)
            USBAuthorizer.set_default_policy(authorize=True)
            logger.info("USB default policy restored to allow")

        IPTablesManager.cleanup_nfqueue(queue_num=1)

        if os.path.exists(self.SOCKET_PATH):
            try:
                os.remove(self.SOCKET_PATH)
            except OSError:
                pass
        logger.info("Daemon stopped")

    # ========== USB DEVICE CONTROL ==========

    def _ensure_gui_running(self):
        """
        Ensure GUI is running. If it's not, start it.
        This ensures the tray icon is always available.
        """
        try:
            if not self.gui_manager.is_gui_running():
                logger.warning("GUI is not running, attempting to start it...")
                if self.gui_manager.start_gui():
                    logger.info("GUI restarted successfully")
                else:
                    logger.error("Failed to restart GUI")
        except Exception as e:
            logger.error(f"Error checking/starting GUI: {e}")

    def _reload_usb_rules_if_changed(self):
        """
        Check if USB rules file has been modified and reload if needed.
        This allows the daemon to pick up rule changes from the GUI without restart.
        """
        try:
            rules_path = self.usb_rule_manager.db_path
            if not rules_path.exists():
                return

            # Get current modification time
            current_mtime = rules_path.stat().st_mtime

            # If file has been modified, reload rules
            if current_mtime > self.usb_rules_last_modified:
                with self.usb_rules_lock:
                    # Reload rules from disk
                    self.usb_rule_manager = USBRuleManager()
                    self.usb_rules_last_modified = current_mtime
                    logger.info(f"USB rules reloaded from disk (mtime: {current_mtime})")
        except Exception as e:
            logger.error(f"Error checking USB rules file: {e}")

    def _start_usb_monitor(self):
        """Start USB device monitoring."""
        if not is_pyudev_available():
            logger.warning("USB monitoring disabled: pyudev not available")
            return

        try:
            # Set default policy to BLOCK new USB devices
            # This ensures devices are blocked until user explicitly allows them
            if USBAuthorizer.set_default_policy(authorize=False):
                logger.info("USB default policy: block new devices")
            else:
                logger.warning("Could not set USB default policy - devices may auto-authorize")

            self.usb_monitor = USBMonitor(callback=self._handle_usb_event)
            if self.usb_monitor.start():
                logger.info("USB device monitor started")
            else:
                logger.warning("Failed to start USB device monitor")
                self.usb_monitor = None
        except Exception as e:
            logger.error(f"Error starting USB monitor: {e}")
            self.usb_monitor = None

    def _handle_usb_event(self, device: USBDeviceInfo, action: str):
        """Handle USB device insert/remove event."""
        if action != 'add':
            # Only handle device additions
            logger.debug(f"USB device removed: {device.product_name}")
            return

        logger.info(f"USB device inserted: {device.product_name} ({device.vendor_id}:{device.product_id})")

        # Check existing rules (with thread-safe access)
        with self.usb_rules_lock:
            verdict = self.usb_rule_manager.get_verdict(device)

        if verdict == 'allow':
            logger.info(f"USB device allowed by rule: {device.product_name}")
            self.stats['usb_devices_allowed'] += 1
            USBAuthorizer.authorize(device.bus_id)
            return

        if verdict == 'block':
            logger.info(f"USB device blocked by rule: {device.product_name}")
            self.stats['usb_devices_blocked'] += 1
            USBAuthorizer.deauthorize(device.bus_id)
            return

        # No rule - prompt user
        self._prompt_usb_decision(device)

    def _prompt_usb_decision(self, device: USBDeviceInfo):
        """Prompt user for USB device decision via GUI."""
        if not self.gui_socket:
            logger.warning("No GUI connected - cannot prompt for USB device decision")
            # Default: block high-risk, allow low-risk
            if device.is_high_risk:
                logger.warning(f"Blocking high-risk USB device without GUI: {device.product_name}")
                USBAuthorizer.deauthorize(device.bus_id)
                self.stats['usb_devices_blocked'] += 1
            else:
                logger.info(f"Allowing low-risk USB device without GUI: {device.product_name}")
                self.stats['usb_devices_allowed'] += 1
            return

        # Generate anti-spoofing nonce (32 bytes, hex encoded = 64 chars)
        nonce = secrets.token_hex(32)

        # Send USB request to GUI
        request = {
            'type': 'usb_request',
            'nonce': nonce,  # Anti-spoofing: GUI must echo this back
            'vendor_id': device.vendor_id,
            'product_id': device.product_id,
            'vendor_name': device.vendor_name,
            'product_name': device.product_name,
            'device_class': device.device_class,
            'serial': device.serial,
            'bus_id': device.bus_id,
            'is_high_risk': device.is_high_risk,
            'class_name': device.class_name
        }

        try:
            with self.usb_pending_lock:
                self.usb_pending_device = device
                self.usb_pending_nonce = nonce
                self.usb_response_event.clear()

            with self.socket_lock:
                self.gui_socket.sendall(json.dumps(request).encode() + b'\n')

            logger.debug(f"USB request sent, waiting for GUI response...")

            # Wait for response (60 second timeout)
            if self.usb_response_event.wait(timeout=60):
                with self.usb_pending_lock:
                    verdict = self.usb_response_verdict
                    scope = self.usb_response_scope
                    save_rule = self.usb_response_save_rule
                    self.usb_pending_device = None

                if verdict == 'allow':
                    action = "allowed" if save_rule else "allowed once"
                    logger.info(f"User {action} USB device: {device.product_name}")
                    if save_rule:
                        self.usb_rule_manager.add_rule(device, 'allow', scope)
                    USBAuthorizer.authorize(device.bus_id)
                    self.stats['usb_devices_allowed'] += 1
                else:
                    action = "blocked" if save_rule else "blocked once"
                    logger.info(f"User {action} USB device: {device.product_name}")
                    if save_rule:
                        self.usb_rule_manager.add_rule(device, 'block', scope)
                    USBAuthorizer.deauthorize(device.bus_id)
                    self.stats['usb_devices_blocked'] += 1
            else:
                # Timeout - default based on risk
                logger.warning(f"USB decision timeout for: {device.product_name}")
                with self.usb_pending_lock:
                    self.usb_pending_device = None
                    self.usb_pending_nonce = None

                if device.is_high_risk:
                    logger.warning(f"Blocking high-risk USB device on timeout: {device.product_name}")
                    USBAuthorizer.deauthorize(device.bus_id)
                    self.stats['usb_devices_blocked'] += 1
                else:
                    logger.info(f"Allowing low-risk USB device on timeout: {device.product_name}")
                    self.stats['usb_devices_allowed'] += 1

        except Exception as e:
            logger.error(f"Error prompting for USB decision: {e}")
            with self.usb_pending_lock:
                self.usb_pending_device = None
                self.usb_pending_nonce = None

    def handle_usb_response(self, response: dict):
        """Handle USB decision response from GUI.

        Security: Validates nonce to prevent spoofed responses from malicious
        local processes. Only responses with the correct nonce are accepted.
        """
        response_nonce = response.get('nonce', '')

        # Validate verdict and scope values (sanitize untrusted input)
        raw_verdict = response.get('verdict', 'block')
        verdict = raw_verdict if raw_verdict in ('allow', 'block') else 'block'

        raw_scope = response.get('scope', 'device')
        scope = raw_scope if raw_scope in ('device', 'model', 'vendor') else 'device'

        save_rule = bool(response.get('save_rule', True))  # Coerce to bool

        with self.usb_pending_lock:
            # Validate nonce to prevent spoofing attacks
            if not self.usb_pending_nonce:
                logger.warning("USB response received but no request pending - ignoring")
                return

            if not secrets.compare_digest(response_nonce, self.usb_pending_nonce):
                logger.warning("USB response nonce mismatch - possible spoofing attempt")
                return

            # Valid response - clear nonce and process
            self.usb_pending_nonce = None
            self.usb_response_verdict = verdict
            self.usb_response_scope = scope
            self.usb_response_save_rule = save_rule
            self.usb_response_event.set()
