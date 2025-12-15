#!/usr/bin/env python3
"""
Douane Firewall Daemon
Monitors and controls outgoing network connections per application.
"""

import os
import sys
import json
import signal
import logging
import sqlite3
import psutil
from pathlib import Path
from typing import Dict, Optional, Tuple
from threading import Thread, Lock
from queue import Queue, Empty

# Configuration
CONFIG_DIR = Path.home() / ".config" / "douane"
DB_PATH = CONFIG_DIR / "rules.db"
LOG_PATH = CONFIG_DIR / "douane.log"

# Ensure config directory exists
CONFIG_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("douane-daemon")


class RulesDatabase:
    """Database to store application network access rules."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.lock = Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize the database schema."""
        with self.lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Create rules table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    executable_path TEXT NOT NULL UNIQUE,
                    permission TEXT NOT NULL CHECK(permission IN ('allow', 'deny')),
                    duration TEXT NOT NULL CHECK(duration IN ('once', 'always')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create connection log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connection_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    executable_path TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    port INTEGER,
                    protocol TEXT,
                    action TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {self.db_path}")
    
    def get_rule(self, executable_path: str) -> Optional[Tuple[str, str]]:
        """
        Get rule for an application.
        Returns: (permission, duration) or None
        """
        with self.lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT permission, duration FROM rules WHERE executable_path = ?",
                (executable_path,)
            )
            result = cursor.fetchone()
            conn.close()
            
            return result
    
    def set_rule(self, executable_path: str, permission: str, duration: str):
        """Set or update a rule for an application."""
        with self.lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO rules (executable_path, permission, duration)
                VALUES (?, ?, ?)
                ON CONFLICT(executable_path) 
                DO UPDATE SET 
                    permission = excluded.permission,
                    duration = excluded.duration,
                    updated_at = CURRENT_TIMESTAMP
            """, (executable_path, permission, duration))
            
            conn.commit()
            conn.close()
            logger.info(f"Rule set: {executable_path} -> {permission} ({duration})")
    
    def delete_once_rules(self):
        """Delete all 'once' rules after they've been used."""
        with self.lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM rules WHERE duration = 'once'")
            deleted = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            if deleted > 0:
                logger.info(f"Deleted {deleted} 'once' rules")
    
    def log_connection(self, executable_path: str, destination: str, 
                      port: int, protocol: str, action: str):
        """Log a connection attempt."""
        with self.lock:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO connection_log 
                (executable_path, destination, port, protocol, action)
                VALUES (?, ?, ?, ?, ?)
            """, (executable_path, destination, port, protocol, action))
            
            conn.commit()
            conn.close()


class ApplicationIdentifier:
    """Identifies applications making network connections."""
    
    @staticmethod
    def get_process_info(pid: int) -> Optional[Dict]:
        """Get process information including executable path and name."""
        try:
            process = psutil.Process(pid)
            exe_path = process.exe()
            name = process.name()
            cmdline = ' '.join(process.cmdline())
            
            return {
                'pid': pid,
                'name': name,
                'exe_path': exe_path,
                'cmdline': cmdline
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
    
    @staticmethod
    def get_application_name(exe_path: str) -> str:
        """Get a human-readable application name from executable path."""
        return Path(exe_path).name


class ConnectionMonitor:
    """Monitors network connections and enforces rules."""
    
    def __init__(self, rules_db: RulesDatabase):
        self.rules_db = rules_db
        self.app_identifier = ApplicationIdentifier()
        self.pending_requests = Queue()
        self.running = False
        self.once_rules_cache = {}  # Cache for 'once' rules during session
        
    def start(self):
        """Start monitoring network connections."""
        self.running = True
        logger.info("Connection monitor started")
        
        # Start the monitoring thread
        monitor_thread = Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        
        return monitor_thread
    
    def stop(self):
        """Stop monitoring."""
        self.running = False
        logger.info("Connection monitor stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        logger.info("Monitoring loop started")
        
        # Track known connections to avoid duplicate prompts
        known_connections = set()
        
        while self.running:
            try:
                # Get current network connections
                connections = psutil.net_connections(kind='inet')
                
                for conn in connections:
                    # Only monitor outgoing connections
                    if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                        # Skip if we've already handled this connection
                        conn_key = (conn.pid, conn.raddr.ip, conn.raddr.port)
                        if conn_key in known_connections:
                            continue
                        
                        # Get process info
                        if conn.pid:
                            proc_info = self.app_identifier.get_process_info(conn.pid)
                            if proc_info:
                                decision = self._check_connection(
                                    proc_info['exe_path'],
                                    conn.raddr.ip,
                                    conn.raddr.port,
                                    'tcp' if conn.type == 1 else 'udp'
                                )
                                
                                known_connections.add(conn_key)
                                
                                # In a real implementation, we would block/allow here
                                # For now, just log the decision
                                if decision:
                                    logger.info(
                                        f"Connection: {proc_info['name']} -> "
                                        f"{conn.raddr.ip}:{conn.raddr.port} - {decision}"
                                    )
                
                # Clean up old known connections periodically
                if len(known_connections) > 1000:
                    known_connections.clear()
                
                # Sleep to avoid high CPU usage
                import time
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                import time
                time.sleep(1)
    
    def _check_connection(self, exe_path: str, dest_ip: str, 
                         port: int, protocol: str) -> str:
        """
        Check if a connection should be allowed.
        Returns: 'allow' or 'deny'
        """
        # Check if we have a rule for this application
        rule = self.rules_db.get_rule(exe_path)
        
        if rule:
            permission, duration = rule
            
            # If it's a 'once' rule and we've already used it, prompt again
            if duration == 'once' and exe_path in self.once_rules_cache:
                # Rule was already used, need new decision
                pass
            else:
                # Apply the rule
                if duration == 'once':
                    self.once_rules_cache[exe_path] = True
                
                self.rules_db.log_connection(
                    exe_path, dest_ip, port, protocol, permission
                )
                return permission
        
        # No rule found, need to prompt user
        # In a real implementation, this would trigger the GUI popup
        # For now, we'll add to pending requests
        request = {
            'exe_path': exe_path,
            'dest_ip': dest_ip,
            'port': port,
            'protocol': protocol,
            'app_name': self.app_identifier.get_application_name(exe_path)
        }
        
        self.pending_requests.put(request)
        logger.info(f"Permission request queued: {request['app_name']}")
        
        # Default to deny until user responds
        return 'deny'
    
    def handle_user_response(self, exe_path: str, permission: str, duration: str):
        """Handle user's decision from the GUI."""
        self.rules_db.set_rule(exe_path, permission, duration)
        
        if duration == 'once':
            self.once_rules_cache[exe_path] = True


class DouaneDaemon:
    """Main daemon class."""
    
    def __init__(self):
        self.rules_db = RulesDatabase(DB_PATH)
        self.monitor = ConnectionMonitor(self.rules_db)
        self.running = False
    
    def start(self):
        """Start the daemon."""
        logger.info("Starting Douane daemon...")
        self.running = True
        
        # Start connection monitor
        monitor_thread = self.monitor.start()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("Douane daemon started successfully")
        
        # Keep main thread alive
        try:
            monitor_thread.join()
        except KeyboardInterrupt:
            pass
    
    def stop(self):
        """Stop the daemon."""
        logger.info("Stopping Douane daemon...")
        self.running = False
        self.monitor.stop()
        
        # Clean up 'once' rules
        self.rules_db.delete_once_rules()
        
        logger.info("Douane daemon stopped")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}")
        self.stop()
        sys.exit(0)


def main():
    """Main entry point."""
    # Check if running as root (required for network monitoring)
    if os.geteuid() != 0:
        logger.warning("Douane daemon should be run as root for full functionality")
    
    daemon = DouaneDaemon()
    
    try:
        daemon.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
