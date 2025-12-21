#!/usr/bin/env python3
"""
Douane Firewall GUI Client - Runs as user

This client:
- Runs as your user (has access to DISPLAY)
- Connects to the daemon via Unix socket
- Shows GUI popups for connection requests
- Sends decisions back to daemon
- Starts daemon with sudo if needed
"""

import os
import sys
import json
import socket
import subprocess
import time
import threading
import signal
from pathlib import Path
from tkinter import messagebox
import tkinter as tk

# Application Indicator Support (Zorin 18 / GNOME)
TRAY_AVAILABLE = False
try:
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import Gtk, AyatanaAppIndicator3, GLib
    TRAY_AVAILABLE = True
except (ImportError, ValueError):
    print("Warning: AyatanaAppIndicator3 not found. Tray icon will be disabled.")
    print("Install with: sudo apt install libayatana-appindicator3-1 gir1.2-ayatanaappindicator3-0.1 python3-gi")

# Import GUI module
try:
    from douane.gui import ImprovedFirewallDialog
except ImportError:
    # Try local import if package structure is different
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from douane.gui import ImprovedFirewallDialog
    except ImportError as e:
        print(f"ERROR: Could not import GUI module: {e}")
        sys.exit(1)


# Simple ConnectionInfo class (avoid importing modules that require root)
class ConnectionInfo:
    def __init__(self, app_name, app_path, dest_ip, dest_port, protocol, app_category=None):
        self.app_name = app_name
        self.app_path = app_path
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.protocol = protocol
        self.app_category = app_category


class DouaneGUIClient:
    """GUI client that shows popups and communicates with daemon"""

    def __init__(self):
        self.socket_path = '/tmp/douane-daemon.sock'
        self.daemon_socket = None
        self.running = False
        self.config = self.load_config()
        self.indicator = None
        self.connection_count = 0
        self.blocked_count = 0
        self.allowed_count = 0
        self.tray_thread = None
        
    def load_config(self):
        """Load configuration"""
        config_path = Path('/etc/douane/config.json')
        if config_path.exists():
            try:
                with open(config_path) as f:
                    return json.load(f)
            except:
                pass
        return {'mode': 'learning', 'timeout_seconds': 30}
    
    def start_daemon(self):
        """Start the daemon with sudo"""
        print("Starting Douane daemon (will ask for sudo password)...")
        
        # Check if daemon is already running
        if os.path.exists(self.socket_path):
            try:
                # Try to connect
                test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                test_sock.connect(self.socket_path)
                test_sock.close()
                print("Daemon already running!")
                return True
            except:
                # Socket exists but daemon not running, remove it
                os.remove(self.socket_path)
        
        # Start daemon with pkexec (GUI sudo) or sudo
        # Try installed path first, then local
        daemon_paths = [
            '/usr/local/bin/douane-daemon',
            os.path.join(os.path.dirname(__file__), 'douane-daemon.py')
        ]

        daemon_path = None
        for path in daemon_paths:
            if os.path.exists(path):
                daemon_path = path
                break

        if not daemon_path:
            print("ERROR: Could not find douane-daemon")
            return False

        # Try pkexec first (GUI password prompt)
        try:
            subprocess.Popen(['pkexec', 'python3', daemon_path],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            print("Daemon started with pkexec")
            # Give daemon time to start and create socket
            time.sleep(2)
            return True
        except FileNotFoundError:
            # pkexec not available, try sudo
            try:
                subprocess.Popen(['sudo', 'python3', daemon_path],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
                print("Daemon started with sudo")
                # Give daemon time to start and create socket
                time.sleep(2)
                return True
            except Exception as e:
                print(f"ERROR: Could not start daemon: {e}")
                return False
    
    def setup_system_tray(self):
        """Setup system tray icon using AppIndicator3"""
        if not TRAY_AVAILABLE:
            print("System tray not available")
            return

        # Create Indicator
        # ID, Icon Name, Category
        self.indicator = AyatanaAppIndicator3.Indicator.new(
            "douane-firewall",
            "security-high",  # Standard icon name (usually a shield or lock)
            AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS
        )
        self.indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_title("Douane Firewall")

        # Create Menu
        menu = Gtk.Menu()

        # Connections Item (Disabled/Info)
        self.stats_item = Gtk.MenuItem(label=f"Connections: {self.connection_count}")
        self.stats_item.set_sensitive(False)
        menu.append(self.stats_item)
        
        # Separator
        menu.append(Gtk.SeparatorMenuItem())

        # Control Panel
        item_cp = Gtk.MenuItem(label="Control Panel")
        item_cp.connect("activate", lambda _: self.show_control_panel())
        menu.append(item_cp)

        # Statistics
        item_stats = Gtk.MenuItem(label="Show Statistics")
        item_stats.connect("activate", lambda _: self.show_statistics())
        menu.append(item_stats)

        # Logs
        item_logs = Gtk.MenuItem(label="View Logs")
        item_logs.connect("activate", lambda _: self.view_logs())
        menu.append(item_logs)

        # Separator
        menu.append(Gtk.SeparatorMenuItem())

        # Start/Stop/Restart
        item_start = Gtk.MenuItem(label="Start Firewall")
        item_start.connect("activate", lambda _: self.start_firewall_service())
        menu.append(item_start)

        item_restart = Gtk.MenuItem(label="Restart Firewall")
        item_restart.connect("activate", lambda _: self.restart_firewall_service())
        menu.append(item_restart)

        item_stop = Gtk.MenuItem(label="Stop Firewall")
        item_stop.connect("activate", lambda _: self.stop_firewall_service())
        menu.append(item_stop)

        # Separator
        menu.append(Gtk.SeparatorMenuItem())

        # Quit (only quit tray icon, not firewall)
        item_quit = Gtk.MenuItem(label="Quit Tray Icon")
        item_quit.connect("activate", lambda _: self.quit_tray_only())
        menu.append(item_quit)

        menu.show_all()
        self.indicator.set_menu(menu)
        
        print("✓ System tray icon created (AyatanaAppIndicator3)")

        # Run Gtk main loop in a separate thread
        self.tray_thread = threading.Thread(target=Gtk.main, daemon=True)
        self.tray_thread.start()

    def update_tray_icon(self, color='green'):
        """Update tray icon"""
        if self.indicator and TRAY_AVAILABLE:
            # Update icon based on status
            icon_name = "security-high"
            if color == 'red':
                icon_name = "security-low" # Or security-medium, or dialog-warning
            elif color == 'orange':
                icon_name = "security-medium"
            
            # Update GUI in main thread
            GLib.idle_add(self.indicator.set_icon, icon_name)
            
            # Update stats text
            stats_text = f"Conn: {self.connection_count} (✓{self.allowed_count} ✗{self.blocked_count})"
            GLib.idle_add(self.stats_item.set_label, stats_text)

    def show_control_panel(self):
        """Show control panel window"""
        try:
            subprocess.Popen(['python3', '/usr/local/bin/douane-control-panel'])
        except Exception as e:
            print(f"Error opening control panel: {e}")
            # Fallback to showing statistics
            self.show_statistics()

    def show_statistics(self):
        """Show statistics window"""
        # We need to run tkinter in the main thread or a thread that isn't the Gtk thread
        # Since this method might be called from Gtk thread, we use a simple subprocess or just print for now
        # But we can use tkinter here carefully as long as we create a new root
        
        def _show():
            try:
                root = tk.Tk()
                root.withdraw() # Hide main window
                stats_msg = f"""Douane Firewall Statistics

Mode: {self.config.get('mode', 'learning').title()}
Total Connections: {self.connection_count}
Allowed: {self.allowed_count}
Blocked: {self.blocked_count}

Learning Mode: Connections are always allowed
Enforcement Mode: Connections can be blocked
"""
                messagebox.showinfo("Douane Firewall Statistics", stats_msg)
                root.destroy()
            except Exception as e:
                print(f"Error showing stats: {e}")

        # Run in a separate thread to avoid blocking Gtk
        threading.Thread(target=_show).start()

    def view_logs(self):
        """Open log file"""
        try:
            subprocess.Popen(['xdg-open', '/var/log/douane-daemon.log'])
        except:
            print("Error opening logs")

    def start_firewall_service(self):
        """Start the firewall via systemctl"""
        print("\nStarting firewall service...")
        try:
            subprocess.run(['pkexec', 'systemctl', 'start', 'douane-firewall'], check=True)
            print("✓ Firewall service started")
            # Update icon to orange (connecting)
            self.update_tray_icon('orange')
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to start firewall: {e}")
        except Exception as e:
            print(f"✗ Error starting firewall: {e}")

    def restart_firewall_service(self):
        """Restart the firewall via systemctl"""
        print("\nRestarting firewall service...")
        try:
            subprocess.run(['pkexec', 'systemctl', 'restart', 'douane-firewall'], check=True)
            print("✓ Firewall service restarted")
            # Update icon to orange (connecting)
            self.update_tray_icon('orange')
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to restart firewall: {e}")
        except Exception as e:
            print(f"✗ Error restarting firewall: {e}")

    def stop_firewall_service(self):
        """Stop the firewall via systemctl"""
        print("\nStopping firewall service...")
        try:
            subprocess.run(['pkexec', 'systemctl', 'stop', 'douane-firewall'], check=True)
            print("✓ Firewall service stopped")
            # Update icon to red (stopped)
            self.update_tray_icon('red')
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to stop firewall: {e}")
        except Exception as e:
            print(f"✗ Error stopping firewall: {e}")

    def quit_tray_only(self):
        """Quit only the tray icon, leave firewall running"""
        print("\nQuitting tray icon (firewall keeps running)...")
        self.running = False

        if TRAY_AVAILABLE:
            GLib.idle_add(Gtk.main_quit)

        # Close socket connection but don't kill daemon
        if self.daemon_socket:
            try:
                self.daemon_socket.close()
            except:
                pass

        sys.exit(0)

    def connect_to_daemon(self):
        """Connect to the daemon"""
        print("Connecting to daemon...")

        # Wait for socket to appear
        for i in range(10):
            if os.path.exists(self.socket_path):
                break
            time.sleep(0.5)
        else:
            print("ERROR: Daemon socket not found")
            return False

        # Connect
        try:
            self.daemon_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.daemon_socket.connect(self.socket_path)
            print("Connected to daemon!")
            return True
        except Exception as e:
            # make this less alarmist as we might retry
            # print(f"ERROR: Could not connect to daemon: {e}") 
            return False
    
    def handle_requests(self):
        """Handle connection requests from daemon"""
        print("Waiting for connection requests...")
        print("Mode:", self.config.get('mode', 'learning'))
        print("")
        
        buffer = ""
        
        while self.running:
            try:
                # Receive data
                data = self.daemon_socket.recv(4096).decode()
                if not data:
                    break
                
                buffer += data
                
                # Process complete messages (newline-delimited)
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    request = json.loads(line)

                    if request['type'] == 'connection_request':
                        # Update statistics
                        self.connection_count += 1

                        # Show GUI and get decision
                        decision, permanent = self.show_dialog(request)

                        # Update statistics based on decision
                        if decision:
                            self.allowed_count += 1
                            self.update_tray_icon('green')
                        else:
                            self.blocked_count += 1
                            self.update_tray_icon('red')

                        # Send response
                        response = json.dumps({
                            'allow': decision,
                            'permanent': permanent
                        }) + '\n'
                        self.daemon_socket.sendall(response.encode())
                        
                    elif request['type'] == 'stats_update':
                        # Update statistics from daemon
                        stats = request.get('stats', {})
                        self.connection_count = stats.get('total_connections', 0)
                        self.allowed_count = stats.get('allowed_connections', 0)
                        self.blocked_count = stats.get('blocked_connections', 0)
                        self.update_tray_icon()
                        
            except Exception as e:
                print(f"ERROR: {e}")
                break
    
    def show_dialog(self, request):
        """Show GUI dialog and return decision (decision, permanent)"""
        # If showing statistics overlaps with this, we might have tkinter threading issues
        # But ImprovedFirewallDialog creates its own Tk instance which is ... risky but worked before
        
        conn_info = ConnectionInfo(
            app_name=request['app_name'],
            app_path=request['app_path'],
            dest_ip=request['dest_ip'],
            dest_port=request['dest_port'],
            protocol=request['protocol'],
            app_category=request.get('app_category')
        )

        learning_mode = self.config.get('mode') == 'learning'

        # Run dialog in main thread (this function is called from handle_requests which is main thread)
        dialog = ImprovedFirewallDialog(
            conn_info,
            timeout=self.config.get('timeout_seconds', 30),
            learning_mode=learning_mode
        )

        decision, permanent = dialog.show()

        # In learning mode, always allow
        if learning_mode:
            return True, False

        return (decision == 'allow'), permanent
    
    def start(self):
        """Start the GUI client with persistent connection loop"""
        print("=" * 60)
        print("Douane Firewall GUI Client (Tray Icon)")
        print("=" * 60)
        print("")
        print("Tray icon will run independently and auto-connect to daemon")
        print("Use tray menu to Start/Stop/Restart the firewall service")
        print("")

        # Setup system tray once - this runs independently
        self.setup_system_tray()

        # Don't auto-start daemon - let user control via tray menu
        # This makes tray icon independent and always running

        self.running = True

        while self.running:
            try:
                # Try to connect
                if self.connect_to_daemon():
                    # Update tray to green (connected and running)
                    self.update_tray_icon('green')
                    print("✓ Connected to daemon")

                    # Handle requests (blocks until connection drops)
                    self.handle_requests()

                    # If we return here, connection dropped
                    print("⚠ Connection lost. Waiting for daemon...")
                    self.update_tray_icon('red') # Indicate disconnected/stopped
                else:
                    # Connection failed, wait before retry
                    # Show orange if daemon might be starting, red if definitely stopped
                    daemon_running = os.path.exists(self.socket_path)
                    if daemon_running:
                        self.update_tray_icon('orange')  # Socket exists but can't connect
                        print("⚠ Daemon socket exists but can't connect, retrying...")
                    else:
                        self.update_tray_icon('red')  # Daemon not running
                        # Only print this once every 10 attempts to avoid spam
                        if not hasattr(self, '_connection_attempts'):
                            self._connection_attempts = 0
                        self._connection_attempts += 1
                        if self._connection_attempts % 10 == 1:
                            print("⚠ Daemon not running. Use tray menu to start firewall.")

                if self.running:
                    time.sleep(2)

            except KeyboardInterrupt:
                self.stop()
                break
            except Exception as e:
                print(f"Error in main loop: {e}")
                time.sleep(2)

        return True
    
    def stop(self):
        """Stop the client"""
        print("\nStopping GUI client...")
        self.running = False
        if self.daemon_socket:
            try:
                self.daemon_socket.close()
            except:
                pass
            
        if TRAY_AVAILABLE:
            GLib.idle_add(Gtk.main_quit)
        
        # Note: We do NOT kill the daemon here anymore, as the GUI might be stopped independently
        # or the user might just be quitting the tray icon.
        # If the user wants to stop the firewall, they use the menu item "Stop Firewall"
        pass


if __name__ == '__main__':
    # Add signal handler for Ctrl+C
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    
    client = DouaneGUIClient()
    try:
        client.start()
    except Exception as e:
        print(f"\nError: {e}")
        client.stop()


