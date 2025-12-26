
import os
import sys
import json
import socket
import logging
import signal
import time
import subprocess
import stat
from pathlib import Path
from typing import Dict, Optional
from collections import deque
import threading
from concurrent.futures import ThreadPoolExecutor

from .config import ConfigManager
from .rules import RuleManager
from .firewall_core import PacketProcessor, PacketInfo, IPTablesManager
from .service_whitelist import should_auto_allow, get_app_category
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
    
    # Use secure runtime directory instead of /tmp to prevent TOCTOU attacks
    SOCKET_PATH = '/var/run/bastion/bastion-daemon.sock'
    
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.rule_manager = RuleManager()
        self.gui_manager = GUIManager()
        self.packet_processor: Optional[PacketProcessor] = None
        self.server_socket: Optional[socket.socket] = None
        self.gui_socket: Optional[socket.socket] = None
        self.running = False

        self.systemd = SystemdNotifier()
        self.monitor_thread = None

        self.pending_requests: Dict[str, float] = {}
        self.last_request_time: Dict[str, float] = {}
        self.request_lock = threading.Lock()
        self.socket_lock = threading.Lock()
        self.rate_limiter = RateLimiter(max_requests_per_second=10, window_seconds=1)

        # Statistics
        self.stats = {
            'total_connections': 0,
            'allowed_connections': 0,
            'blocked_connections': 0,
            'rate_limited': 0,  # Track rate-limited requests
            'pending_gui': 0
        }
        
        # Async handling pool
        self.async_pool = ThreadPoolExecutor(max_workers=10, thread_name_prefix='AsyncVerifier')
        
        # Startup buffer: Queue packets while waiting for GUI to connect (max 100 items)
        # format: (time, nfpacket, pkt_info, app_name, app_path, cache_key, learning_mode)
        self.startup_queue = deque(maxlen=100)
        self.startup_mode = True # True until first GUI connection or timeout

    def start(self):
        """Start the daemon"""
        logger.info("Starting Bastion Daemon...")

        # Setup signals
        self._setup_signals()

        # Setup Socket
        self._setup_socket()

        # Setup iptables
        allow_root = self.config.get('allow_root_bypass', True)
        allow_systemd = self.config.get('allow_systemd_bypass', True)
        logger.info(f"Configuring iptables (Root Bypass: {allow_root}, Systemd Bypass: {allow_systemd})")
        
        if not IPTablesManager.setup_nfqueue(queue_num=1, allow_root=allow_root, allow_systemd=allow_systemd):
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

        # Smart GUI launch: attempt to start gui for all active graphical sessions
        logger.info("Triggering smart GUI auto-start for active sessions...")
        self.gui_manager.start_gui()

        # Wait for GUI to connect (timeout allows for user login)
        self._wait_for_gui_connection(timeout=30)

        # Start health monitor
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

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

        while self.running:
            try:
                # 1. Ping systemd watchdog each loop (every 5s)
                self.systemd.ping()

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
                logger.info("GUI connected successfully")
                return True
            time.sleep(0.5)

        if self.gui_socket:
            logger.info("GUI connected successfully")
            self.startup_mode = False
            self._process_startup_queue()
            return True

        logger.warning(f"GUI did not connect within {timeout}s - disabling startup buffer")
        self.startup_mode = False
        # Flush queue (fail open/closed based on mode)
        self._flush_startup_queue()
        return False

    def _process_startup_queue(self):
        """Process queued packets now that GUI is connected"""
        while self.startup_queue:
            try:
                # (time, nfpacket, pkt_info, ...)
                item = self.startup_queue.popleft()
                # If packet is too old (>30s), drop/allow based on policy?
                # For now, just resubmit to async handler
                _, nfpacket, pkt_info, app_name, app_path, cache_key, learning_mode = item
                self.async_pool.submit(
                    self._handle_async_decision,
                    nfpacket, pkt_info, app_name, app_path, cache_key, learning_mode
                )
            except Exception as e:
                logger.error(f"Error processing startup queue item: {e}")

    def _flush_startup_queue(self):
        """Flush queue if GUI never connected"""
        # In learning mode, we should probably allow these to avoid breaking boot
        # In strict mode, drop.
        learning_mode = self.config.get('mode', 'learning') == 'learning'
        while self.startup_queue:
            try:
                item = self.startup_queue.popleft()
                nfpacket = item[1]
                pkt_info = item[2]
                app_name = item[3]
                
                if learning_mode:
                    logger.info(f"Startup timeout: Auto-allowing {app_name} (Learning Mode)")
                    nfpacket.accept()
                else:
                    logger.warning(f"Startup timeout: Blocking {app_name} (Strict Mode)")
                    nfpacket.drop()
            except:
                pass

    def _accept_gui_connections(self):
        """Accept GUI connections in background with credential verification"""
        try:
            self.server_socket.settimeout(1.0)
            while self.running:
                try:
                    if not self.gui_socket:  # Only accept if not already connected
                        gui_socket, addr = self.server_socket.accept()
                        
                        # SECURITY: Verify peer credentials (SO_PEERCRED on Linux)
                        # This hardens against misconfigured permissions or group memberships
                        try:
                            import struct
                            # SO_PEERCRED = 17 on Linux
                            creds = gui_socket.getsockopt(socket.SOL_SOCKET, 17, struct.calcsize('3i'))
                            pid, uid, gid = struct.unpack('3i', creds)
                            
                            # Log the connection for security audit
                            logger.info(f"GUI connection from PID {pid}, UID {uid}, GID {gid}")
                            
                            # Reject connections from root (UID 0) unless explicitly allowed
                            # GUI should run as normal user, not root
                            if uid == 0:
                                logger.warning(f"Rejected GUI connection from root (UID 0) - GUI should run as normal user")
                                gui_socket.close()
                                continue
                            
                            # Accept the connection
                            logger.info(f"GUI connected from {addr}")
                            self.gui_socket = gui_socket
                            
                        except (OSError, struct.error) as e:
                            # SO_PEERCRED not supported on this platform (non-Linux)
                            # Fall back to file permission-based security
                            logger.debug(f"Peer credential check not available: {e}")
                            logger.info(f"GUI connected from {addr} (credentials not verified)")
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
        except (BrokenPipeError, ConnectionResetError, OSError):
            # GUI disconnected - clear socket so we stop trying
            logger.debug("GUI disconnected")
            self.gui_socket = None
        except Exception as e:
            logger.error(f"Error sending stats: {e}")

    def _setup_socket(self):
        """Setup Unix domain socket with security hardening"""
        # SECURITY: Use secure directory with proper permissions
        socket_dir = os.path.dirname(self.SOCKET_PATH)
        
        # Create secure directory if it doesn't exist
        os.makedirs(socket_dir, mode=0o755, exist_ok=True)
        
        # SECURITY: Check for symlink attacks before removing
        if os.path.exists(self.SOCKET_PATH):
            try:
                # Verify it's a socket and not a symlink
                stat_info = os.lstat(self.SOCKET_PATH)
                if stat.S_ISSOCK(stat_info.st_mode) and not os.path.islink(self.SOCKET_PATH):
                    os.remove(self.SOCKET_PATH)
                    logger.info("Removed existing socket file")
                else:
                    logger.error("SECURITY: Socket path exists but is not a regular socket or is a symlink")
                    logger.error(f"Path: {self.SOCKET_PATH}")
                    raise RuntimeError("Socket path security check failed")
            except OSError as e:
                logger.error(f"SECURITY: Failed to check socket path: {e}")
                raise RuntimeError("Socket path security check failed")
            
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.SOCKET_PATH)
        
        try:
            # SECURITY: Set restrictive permissions immediately after bind
            os.chmod(self.SOCKET_PATH, 0o660)
            logger.info("Socket permissions set to 0660")
            
            # Try to set group ownership to 'bastion' group if it exists
            try:
                import grp
                import stat as stat_module
                bastion_gid = grp.getgrnam('bastion').gr_gid
                os.chown(self.SOCKET_PATH, 0, bastion_gid)  # root:bastion
                logger.info("Socket ownership set to root:bastion")
                
                # Verify ownership was set correctly
                stat_info = os.stat(self.SOCKET_PATH)
                if stat_info.st_uid != 0 or stat_info.st_gid != bastion_gid:
                    logger.warning("Socket ownership verification failed")
            except KeyError:
                logger.warning("Group 'bastion' does not exist. Run: sudo groupadd bastion")
            except Exception as e:
                logger.warning(f"Could not set socket group ownership: {e}")
        except Exception as e:
            logger.error(f"CRITICAL: Failed to secure socket: {e}")
            # Clean up on failure
            try:
                os.remove(self.SOCKET_PATH)
            except:
                pass
            raise RuntimeError("Socket security setup failed")
            
        self.server_socket.listen(1)
        logger.info(f"Secure socket established at {self.SOCKET_PATH}")

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
            allow_root = self.config.get('allow_root_bypass', True)
            allow_systemd = self.config.get('allow_systemd_bypass', True)
            IPTablesManager.setup_nfqueue(queue_num=1, allow_root=allow_root, allow_systemd=allow_systemd)

    def _handle_packet(self, pkt_info: PacketInfo, nfpacket=None) -> Optional[bool]:
        """
        Handle a packet decision.
        
        Args:
            pkt_info: Extracted packet information
            nfpacket: The raw NetfilterQueue packet object (needed for async verdict)
            
        Returns:
            True: Accept
            False: Drop
            None: Async (handled later)
        """
        self.stats['total_connections'] += 1

        # Always use current config (defaults to learning mode for safety)
        learning_mode = self.config.get('mode', 'learning') == 'learning'

        # App identification
        app_path = pkt_info.app_path
        app_name = pkt_info.app_name

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
        # ASK GUI - Pass display values for UI
        # This is SLOW (can take seconds). We must NOT block here if we have `nfpacket`.
        if nfpacket:
            # CHECK STARTUP QUEUE
            if self.startup_mode and not self.gui_socket:
                if learning_mode:
                    # Fail-Open in Learning Mode during startup
                    # Don't queue/block network while waiting for GUI
                    logger.info(f"Startup: Auto-allowing {display_name} (Learning Mode)")
                    self.stats['allowed_connections'] += 1
                    nfpacket.accept() # Immediate accept
                    pkt_info.accepted = True # Mark for logging if needed
                    return None # Handled explicitly
                else:
                    # Strict Mode: Queue (Hold) until GUI connects
                    logger.debug(f"Queuing packet for GUI (startup): {display_name}")
                    self.startup_queue.append(
                        (time.time(), nfpacket, pkt_info, display_name, display_path, cache_key, learning_mode)
                    )
                    return None

            # Offload to thread pool
            self.async_pool.submit(
                self._handle_async_decision, 
                nfpacket, pkt_info, display_name, display_path, cache_key, learning_mode
            )
            return None # Signal PacketProcessor that we are handling this async
        else:
            # Fallback for sync calls (e.g. testing)
            return self._ask_gui(pkt_info, display_name, display_path, cache_key, learning_mode)

    def _handle_async_decision(self, nfpacket, pkt_info, app_name, app_path, cache_key, learning_mode):
        """Background worker to ask GUI and issue verdict"""
        try:
            allow = self._ask_gui(pkt_info, app_name, app_path, cache_key, learning_mode)
            if allow:
                nfpacket.accept()
            else:
                nfpacket.drop()
        except Exception as e:
            logger.error(f"Async decision failed: {e}")
            try:
                # Default fail-closed
                nfpacket.drop()
            except:
                pass

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

            # Learning mode - FAIL OPEN if GUI is missing!
            # The user expects "Learning" to mean "Don't break my stuff, just tell me".
            # If we block because the GUI crashed or isn't there, we are breaking the system.
            logger.warning(f"Learning mode: Auto-allowing {app_name or 'unknown'} because GUI is unavailable (Fail-Open)")
            logger.info("Please start the Bastion GUI to see these requests.")
            self.stats['allowed_connections'] += 1
            return True


        # Rate limiting to prevent DoS
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
                self.stats['blocked_connections'] += 1
                return False
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
            
            return allow

        except Exception as e:
            logger.error(f"GUI communication error: {e}")
            with self.request_lock:
                self.pending_requests.pop(cache_key, None)
            
            # Default action on error
            self.stats['blocked_connections'] += 1
            return False

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
        except Exception as e:
            logger.debug(f"Error sending rate limit notification: {e}")

    def stop(self):
        """Stop daemon"""
        if not self.running:
             return
             
        self.running = False
        logger.info("Stopping daemon...")

        if self.gui_socket:
            try:
                # self.gui_socket.shutdown(socket.SHUT_RDWR) # Can cause issues if other end is gone
                self.gui_socket.close()
            except (OSError, socket.error) as e:
                logger.debug(f"Error closing GUI socket: {e}")
            self.gui_socket = None

        if self.server_socket:
            try:
                self.server_socket.close()
            except (OSError, socket.error) as e:
                logger.debug(f"Error closing server socket: {e}")
            self.server_socket = None
            
        if self.packet_processor:
            self.packet_processor.stop()
            
        self.async_pool.shutdown(wait=False)
            
        IPTablesManager.cleanup_nfqueue(queue_num=1)
        
        if os.path.exists(self.SOCKET_PATH):
            try:
                os.remove(self.SOCKET_PATH)
            except (OSError, PermissionError) as e:
                logger.debug(f"Error removing socket file: {e}")
        logger.info("Daemon stopped")
