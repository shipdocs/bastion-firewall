#!/usr/bin/env python3
"""
UFW Firewall GUI - Interactive outbound connection monitor with UFW integration

This application monitors outbound network connections and presents GUI dialogs
to allow users to permit or deny connections, with options to store rules in UFW.

Requires root privileges to run.
"""

import os
import sys
import json
import logging
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk

# Check for root privileges
if os.geteuid() != 0:
    print("ERROR: This application must be run as root (use sudo)")
    sys.exit(1)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/ufw_firewall_gui.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class UFWManager:
    """Manages UFW firewall rules"""
    
    @staticmethod
    def check_ufw_installed():
        """Check if UFW is installed and available"""
        try:
            result = subprocess.run(['which', 'ufw'], 
                                  capture_output=True, 
                                  text=True)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error checking UFW: {e}")
            return False
    
    @staticmethod
    def get_ufw_status():
        """Get UFW status"""
        try:
            result = subprocess.run(['ufw', 'status'], 
                                  capture_output=True, 
                                  text=True, 
                                  check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting UFW status: {e}")
            return None
    
    @staticmethod
    def add_allow_rule(app_path=None, ip=None, port=None, protocol='tcp'):
        """Add an allow rule to UFW"""
        try:
            if ip and port:
                # IP and port-based rule (primary method)
                cmd = ['ufw', 'allow', 'out', 'to', ip, 'port', str(port), 
                       'proto', protocol]
                comment = f"Allow {os.path.basename(app_path) if app_path else 'app'}"
            else:
                logger.warning("Insufficient information to add allow rule")
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Added UFW allow rule: {' '.join(cmd)}")
                return True
            else:
                logger.error(f"Failed to add UFW rule: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error adding UFW allow rule: {e}")
            return False
    
    @staticmethod
    def add_deny_rule(app_path=None, ip=None, port=None, protocol='tcp'):
        """Add a deny rule to UFW
        
        Note: UFW deny rules are IP/port-based. Application-based deny rules
        are not consistently supported across UFW versions.
        """
        try:
            if ip and port:
                # IP and port-based rule
                cmd = ['ufw', 'deny', 'out', 'to', ip, 'port', str(port), 
                       'proto', protocol]
                comment = f"Deny {os.path.basename(app_path) if app_path else 'app'}"
            else:
                logger.warning("Insufficient information to add deny rule")
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Added UFW deny rule: {' '.join(cmd)}")
                return True
            else:
                logger.error(f"Failed to add UFW rule: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error adding UFW deny rule: {e}")
            return False


class ConnectionInfo:
    """Represents a network connection attempt"""
    
    def __init__(self, app_name, app_path, dest_ip, dest_port, protocol):
        self.app_name = app_name
        self.app_path = app_path
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.protocol = protocol
        self.timestamp = datetime.now()
    
    def __str__(self):
        return f"{self.app_name} -> {self.dest_ip}:{self.dest_port} ({self.protocol})"


class FirewallDialog:
    """GUI dialog for allowing/denying connections"""
    
    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.decision = None
        self.permanent = False
        self.root = None
    
    def show(self):
        """Display the dialog and wait for user decision"""
        self.root = tk.Tk()
        self.root.title("Firewall Alert")
        self.root.geometry("500x300")
        self.root.resizable(False, False)
        
        # Make window appear on top
        self.root.attributes('-topmost', True)
        self.root.focus_force()
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="Network Connection Request",
            font=('Arial', 14, 'bold')
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Connection details
        details_frame = ttk.LabelFrame(main_frame, text="Connection Details", 
                                       padding="10")
        details_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), 
                          pady=(0, 20))
        
        ttk.Label(details_frame, text="Application:").grid(row=0, column=0, 
                                                            sticky=tk.W, pady=5)
        ttk.Label(details_frame, text=self.connection_info.app_name, 
                 font=('Arial', 10, 'bold')).grid(row=0, column=1, sticky=tk.W, 
                                                   pady=5)
        
        ttk.Label(details_frame, text="Path:").grid(row=1, column=0, 
                                                    sticky=tk.W, pady=5)
        path_label = ttk.Label(details_frame, text=self.connection_info.app_path,
                              wraplength=350)
        path_label.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(details_frame, text="Destination:").grid(row=2, column=0, 
                                                           sticky=tk.W, pady=5)
        ttk.Label(details_frame, 
                 text=f"{self.connection_info.dest_ip}:{self.connection_info.dest_port}",
                 font=('Arial', 10, 'bold')).grid(row=2, column=1, sticky=tk.W, 
                                                   pady=5)
        
        ttk.Label(details_frame, text="Protocol:").grid(row=3, column=0, 
                                                        sticky=tk.W, pady=5)
        ttk.Label(details_frame, text=self.connection_info.protocol.upper()).grid(
            row=3, column=1, sticky=tk.W, pady=5)
        
        # Permanent option
        self.permanent_var = tk.BooleanVar()
        permanent_check = ttk.Checkbutton(
            main_frame,
            text="Remember this decision (add UFW rule)",
            variable=self.permanent_var
        )
        permanent_check.grid(row=2, column=0, columnspan=2, pady=(0, 20))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2)
        
        allow_btn = ttk.Button(
            button_frame,
            text="✓ Allow",
            command=self._allow,
            width=15
        )
        allow_btn.grid(row=0, column=0, padx=5)
        
        deny_btn = ttk.Button(
            button_frame,
            text="✗ Deny",
            command=self._deny,
            width=15
        )
        deny_btn.grid(row=0, column=1, padx=5)
        
        # Bind Enter and Escape keys
        self.root.bind('<Return>', lambda e: self._allow())
        self.root.bind('<Escape>', lambda e: self._deny())
        
        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (self.root.winfo_width() // 2)
        y = (self.root.winfo_screenheight() // 2) - (self.root.winfo_height() // 2)
        self.root.geometry(f'+{x}+{y}')
        
        self.root.mainloop()
        
        return self.decision, self.permanent
    
    def _allow(self):
        """User chose to allow the connection"""
        self.decision = 'allow'
        self.permanent = self.permanent_var.get()
        self.root.destroy()
    
    def _deny(self):
        """User chose to deny the connection"""
        self.decision = 'deny'
        self.permanent = self.permanent_var.get()
        self.root.destroy()


class NetworkMonitor:
    """Monitors network connections and prompts for decisions"""
    
    def __init__(self, config_path='config.json'):
        self.config = self._load_config(config_path)
        self.ufw_manager = UFWManager()
        self.decision_cache = {}  # Cache decisions to avoid repeated prompts
        
        # Check UFW
        if not self.ufw_manager.check_ufw_installed():
            logger.error("UFW is not installed!")
            sys.exit(1)
        
        logger.info("UFW Firewall GUI started")
        logger.info(f"UFW Status:\n{self.ufw_manager.get_ufw_status()}")
    
    def _load_config(self, config_path):
        """Load configuration from file"""
        default_config = {
            "log_decisions": True,
            "cache_decisions": True,
            "default_action": "prompt",
            "timeout_seconds": 30
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return {**default_config, **json.load(f)}
            except Exception as e:
                logger.warning(f"Error loading config: {e}, using defaults")
        
        return default_config
    
    def _get_cache_key(self, conn_info):
        """Generate cache key for a connection"""
        return f"{conn_info.app_path}:{conn_info.dest_ip}:{conn_info.dest_port}"
    
    def handle_connection(self, app_name, app_path, dest_ip, dest_port, 
                         protocol='tcp'):
        """Handle a new connection attempt"""
        conn_info = ConnectionInfo(app_name, app_path, dest_ip, dest_port, 
                                   protocol)
        
        logger.info(f"Connection attempt: {conn_info}")
        
        # Check cache
        cache_key = self._get_cache_key(conn_info)
        if self.config.get('cache_decisions') and cache_key in self.decision_cache:
            cached_decision = self.decision_cache[cache_key]
            logger.info(f"Using cached decision: {cached_decision}")
            return cached_decision == 'allow'
        
        # Show dialog
        dialog = FirewallDialog(conn_info)
        decision, permanent = dialog.show()
        
        if decision is None:
            decision = 'deny'  # Default to deny if dialog is closed
        
        logger.info(f"User decision: {decision} (permanent: {permanent})")
        
        # Add to cache
        if self.config.get('cache_decisions'):
            self.decision_cache[cache_key] = decision
        
        # Add UFW rule if permanent
        if permanent:
            if decision == 'allow':
                self.ufw_manager.add_allow_rule(
                    app_path=app_path,
                    ip=dest_ip,
                    port=dest_port,
                    protocol=protocol
                )
            else:
                self.ufw_manager.add_deny_rule(
                    ip=dest_ip,
                    port=dest_port,
                    protocol=protocol
                )
        
        return decision == 'allow'
    
    def run_demo(self):
        """Run a demo showing how the application works"""
        print("\n" + "="*60)
        print("UFW Firewall GUI - Demo Mode")
        print("="*60)
        print("\nThis demo shows how the application would work.")
        print("In production, it would use netfilter to intercept actual packets.\n")
        
        # Simulate some connection attempts
        test_connections = [
            ("firefox", "/usr/bin/firefox", "93.184.216.34", 443, "tcp"),
            ("chrome", "/usr/bin/google-chrome", "142.250.185.46", 443, "tcp"),
            ("curl", "/usr/bin/curl", "1.1.1.1", 80, "tcp"),
        ]
        
        for app_name, app_path, ip, port, proto in test_connections:
            print(f"\n[SIMULATED] Connection attempt:")
            print(f"  Application: {app_name}")
            print(f"  Path: {app_path}")
            print(f"  Destination: {ip}:{port} ({proto})")
            print(f"  A dialog would appear asking to allow or deny...")
            
            # In demo mode, just log it
            allowed = self.handle_connection(app_name, app_path, ip, port, proto)
            print(f"  Decision: {'ALLOWED' if allowed else 'DENIED'}")
            print("-" * 60)
        
        print("\nDemo complete!")
        print("\nNote: In production mode, this would:")
        print("  1. Use iptables NFQUEUE to intercept packets")
        print("  2. Identify the application making the connection")
        print("  3. Show a GUI dialog for each new connection")
        print("  4. Apply the decision to allow/deny the packet")
        print("  5. Optionally store the rule in UFW")


def main():
    """Main entry point"""
    print("UFW Firewall GUI v1.0")
    print("=" * 60)
    
    # Check dependencies
    try:
        import tkinter
    except ImportError:
        print("ERROR: Tkinter not installed. Install with:")
        print("  sudo apt-get install python3-tk")
        sys.exit(1)
    
    # Create monitor
    monitor = NetworkMonitor()
    
    # For now, run in demo mode
    # In a full implementation, this would set up netfilter queue
    print("\nRunning in DEMO mode...")
    print("(Full netfilter integration requires additional setup)")
    
    try:
        monitor.run_demo()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        logger.info("Application terminated by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
