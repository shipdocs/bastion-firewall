
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
    
    SOCKET_PATH = '/tmp/douane-daemon.sock'
    
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
        self.request_lock = threading.Lock()

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

        # Start Packet Processor
        self.packet_processor = PacketProcessor(self._handle_packet)
        self.running = True
        
        # Start processor in a separate thread so we can accept GUI connections
        # Actually, in the original code, it waited for GUI connection first.
        # Let's keep that behavior for now, or make it async.
        # Original: Wait for GUI to connect, THEN start processor.
        
        logger.info("Waiting for GUI to connect...")
        try:
            self.gui_socket, addr = self.server_socket.accept()
            logger.info(f"GUI connected from {addr}")
        except Exception as e:
            logger.error(f"Error accepting GUI connection: {e}")
            self.stop()
            return

        # Start processor
        processor_thread = threading.Thread(target=self._run_processor)
        processor_thread.start()
        
        # Watchdog loop
        self._run_watchdog()
        
        # Cleanup
        processor_thread.join(timeout=1.0)
        self.stop()

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
                if watchdog_counter >= 30:
                    watchdog_counter = 0
                    self._check_nfqueue_rule()
        except KeyboardInterrupt:
            self.stop()

    def _setup_socket(self):
        """Setup Unix domain socket"""
        if os.path.exists(self.SOCKET_PATH):
            os.remove(self.SOCKET_PATH)
            
        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.SOCKET_PATH)
        os.chmod(self.SOCKET_PATH, 0o666)
        self.server_socket.listen(1)

    def _setup_signals(self):
        signal.signal(signal.SIGHUP, lambda s, f: self.rule_manager.reload_rules())
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
        learning_mode = self.config.get('mode') == 'learning'
        
        # APP INFO
        app_path = pkt_info.app_path or "unknown"
        app_name = pkt_info.app_name or "Unknown Application"
        
        # CACHE CHECK
        cached_decision = self.rule_manager.get_decision(app_path, pkt_info.dest_port)
        if cached_decision is not None:
            if learning_mode: return True
            return cached_decision

        # RATE LIMITING / PENDING
        cache_key = f"{app_path}:{pkt_info.dest_port}"
        now = time.time()
        
        with self.request_lock:
            if cache_key in self.pending_requests:
                return True # Auto-allow if already asking
            
            if cache_key in self.last_request_time:
                if now - self.last_request_time[cache_key] < 5.0:
                    return True # Auto-allow recent
                    
        # WL CHECK
        auto_allow, reason = should_auto_allow(app_name, app_path, pkt_info.dest_port, pkt_info.dest_ip)
        if auto_allow:
            logger.info(f"Auto-allowing {app_name} ({reason})")
            # We don't necessarily save this unless we want to pollute rules
            # But the original code saved it to cache.
            # self.rule_manager.add_rule(app_path, pkt_info.dest_port, True) 
            # Ideally WL is dynamic, so maybe don't persist? Original persisted it in cache.
            # Let's persist it in memory for this run at least?
            # Actually simplest is just return True.
            return True

        if not pkt_info.app_name and learning_mode:
            return True

        # ASK GUI
        return self._ask_gui(pkt_info, app_name, app_path, cache_key, learning_mode)

    def _ask_gui(self, pkt_info, app_name, app_path, cache_key, learning_mode) -> bool:
        """Communicate with GUI"""
        if not self.gui_socket:
            logger.warning("No GUI connected, using default action")
            return True if learning_mode else False

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
            self.gui_socket.sendall(json.dumps(request).encode() + b'\n')
            
            if learning_mode:
                # Don't wait for response in learning mode
                with self.request_lock:
                    self.pending_requests.pop(cache_key, None)
                
                # Auto-add temporary rule to suppress further popups for this session
                # Or just rely on rate limits.
                # Original code: self.decision_cache[cache_key] = True
                self.rule_manager._rules[cache_key] = True # Hacky access or add method
                # Correct way:
                # self.rule_manager.add_rule(app_path, pkt_info.dest_port, True) # But this persists!
                # Maybe add a volatile cache method? For now stick to original behavior: save it.
                self.rule_manager.add_rule(app_path, pkt_info.dest_port, True)
                self._add_ufw_rule(pkt_info, True)
                return True

            # Wait for response
            response = self.gui_socket.recv(4096).decode().strip()
            if not response:
                return False
                
            data = json.loads(response)
            allow = data.get('allow', False)
            permanent = data.get('permanent', False)
            
            with self.request_lock:
                self.pending_requests.pop(cache_key, None)

            if permanent:
                self.rule_manager.add_rule(app_path, pkt_info.dest_port, allow)
            
            self._add_ufw_rule(pkt_info, allow)
            return allow

        except Exception as e:
            logger.error(f"GUI communication error: {e}")
            with self.request_lock:
                self.pending_requests.pop(cache_key, None)
            return True if learning_mode else False

    def _add_ufw_rule(self, pkt_info, allow):
        """Add UFW rule"""
        action = "allow" if allow else "deny"
        cmd = ['ufw', action, 'out', str(pkt_info.dest_port) + '/' + pkt_info.protocol, 
               'comment', f'{pkt_info.app_name}:{pkt_info.dest_port}']
        try:
             subprocess.run(cmd, capture_output=True)
        except Exception:
            pass

    def stop(self):
        """Stop daemon"""
        self.running = False
        if self.packet_processor:
            self.packet_processor.stop()
        IPTablesManager.cleanup_nfqueue(queue_num=1)
        if self.server_socket:
            self.server_socket.close()
        if os.path.exists(self.SOCKET_PATH):
            os.remove(self.SOCKET_PATH)
        logger.info("Daemon stopped")
