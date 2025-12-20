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
import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import threading

# Force AppIndicator backend for Gnome/Zorin
import os
os.environ['PYSTRAY_BACKEND'] = 'appindicator'

# Try to import system tray support
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    print("Note: Install 'pystray' and 'pillow' for system tray support")
    try:
        import tkinter
        import tkinter.messagebox
        root = tkinter.Tk()
        root.withdraw()
        tkinter.messagebox.showwarning(
            "Missing Dependencies",
            "System tray icon will not be available.\n\nPlease install 'pystray' and 'Pillow' to enable it."
        )
        root.destroy()
    except:
        pass


def create_tray_icon(color='green'):
    """Create a simple shield icon for system tray"""
    if not TRAY_AVAILABLE:
        return None

    # Create a 64x64 image
    width = 64
    height = 64
    image = Image.new('RGBA', (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Color mapping
    colors = {
        'green': (39, 174, 96, 255),    # Active/Safe
        'red': (231, 76, 60, 255),      # Blocked
        'orange': (230, 126, 34, 255),  # Warning
        'gray': (149, 165, 166, 255),   # Inactive
    }

    fill_color = colors.get(color, colors['green'])

    # Draw shield shape
    # Top part (rectangle)
    draw.rectangle([16, 8, 48, 32], fill=fill_color, outline=(0, 0, 0, 255), width=2)
    # Bottom part (triangle)
    draw.polygon([16, 32, 32, 56, 48, 32], fill=fill_color, outline=(0, 0, 0, 255))

    # Draw a checkmark or X
    if color == 'green':
        # Checkmark
        draw.line([24, 28, 28, 34], fill='white', width=3)
        draw.line([28, 34, 40, 18], fill='white', width=3)
    elif color == 'red':
        # X mark
        draw.line([24, 20, 40, 36], fill='white', width=3)
        draw.line([40, 20, 24, 36], fill='white', width=3)

    return image


# Simple ConnectionInfo class (avoid importing modules that require root)
class ConnectionInfo:
    def __init__(self, app_name, app_path, dest_ip, dest_port, protocol, app_category=None):
        self.app_name = app_name
        self.app_path = app_path
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.protocol = protocol
        self.app_category = app_category

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


class DouaneGUIClient:
    """GUI client that shows popups and communicates with daemon"""

    def __init__(self):
        self.socket_path = '/tmp/douane-daemon.sock'
        self.daemon_socket = None
        self.running = False
        self.config = self.load_config()
        self.tray_icon = None
        self.connection_count = 0
        self.blocked_count = 0
        self.allowed_count = 0
        
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
        """Setup system tray icon"""
        if not TRAY_AVAILABLE:
            print("System tray not available (install pystray and pillow)")
            return

        icon_image = create_tray_icon('green')

        # Create menu
        menu = pystray.Menu(
            pystray.MenuItem(
                lambda: f"Douane Firewall - {self.config.get('mode', 'learning').title()} Mode",
                lambda: None,
                enabled=False
            ),
            pystray.MenuItem(
                lambda: f"Connections: {self.connection_count} (✓{self.allowed_count} ✗{self.blocked_count})",
                lambda: None,
                enabled=False
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Control Panel', self.show_control_panel),
            pystray.MenuItem('Show Statistics', self.show_statistics),
            pystray.MenuItem('View Logs', self.view_logs),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Stop Firewall', self.stop_firewall),
            pystray.MenuItem('Quit', self.quit_application)
        )

        self.tray_icon = pystray.Icon(
            "douane-firewall",
            icon_image,
            "Douane Firewall",
            menu
        )

        # Run tray icon in separate thread
        try:
            tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
            tray_thread.start()
            print("✓ System tray icon created (AppIndicator)")
        except Exception as e:
            print(f"ERROR creating tray icon: {e}")

    def update_tray_icon(self, color='green'):
        """Update tray icon color"""
        if self.tray_icon and TRAY_AVAILABLE:
            self.tray_icon.icon = create_tray_icon(color)

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
        stats_msg = f"""Douane Firewall Statistics

Mode: {self.config.get('mode', 'learning').title()}
Total Connections: {self.connection_count}
Allowed: {self.allowed_count}
Blocked: {self.blocked_count}

Learning Mode: Connections are always allowed
Enforcement Mode: Connections can be blocked
"""
        messagebox.showinfo("Douane Firewall Statistics", stats_msg)

    def view_logs(self):
        """Open log file"""
        try:
            subprocess.Popen(['xdg-open', '/var/log/douane-daemon.log'])
        except:
            messagebox.showerror("Error", "Could not open log file")

    def stop_firewall(self):
        """Stop the firewall"""
        print("\nStopping firewall...")
        self.running = False
        if self.tray_icon:
            self.tray_icon.stop()
        # Send SIGTERM to daemon for proper cleanup
        subprocess.run(['pkill', '-TERM', '-f', 'douane-daemon'])
        time.sleep(1)  # Give daemon time to cleanup
        print("Firewall stopped")
        sys.exit(0)

    def quit_application(self):
        """Quit application"""
        self.stop_firewall()

    def connect_to_daemon(self):
        """Connect to the daemon"""
        print("Connecting to daemon...")

        # Wait for socket to appear
        import time
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
            print(f"ERROR: Could not connect to daemon: {e}")
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
                        
            except Exception as e:
                print(f"ERROR: {e}")
                break
    
    def show_dialog(self, request):
        """Show GUI dialog and return decision (decision, permanent)"""
        conn_info = ConnectionInfo(
            app_name=request['app_name'],
            app_path=request['app_path'],
            dest_ip=request['dest_ip'],
            dest_port=request['dest_port'],
            protocol=request['protocol'],
            app_category=request.get('app_category')
        )

        learning_mode = self.config.get('mode') == 'learning'

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
        """Start the GUI client"""
        print("=" * 60)
        print("Douane Firewall GUI Client")
        print("=" * 60)
        print("")

        # Start daemon
        if not self.start_daemon():
            return False

        # Connect to daemon
        if not self.connect_to_daemon():
            return False

        # Setup system tray
        self.setup_system_tray()

        # Handle requests
        self.running = True
        self.handle_requests()

        return True
    
    def stop(self):
        """Stop the client and cleanup daemon"""
        print("\nStopping GUI client...")
        self.running = False
        if self.daemon_socket:
            self.daemon_socket.close()

        # Send SIGTERM to daemon for proper cleanup
        print("Stopping daemon...")
        subprocess.run(['pkill', '-TERM', '-f', 'douane-daemon'], stderr=subprocess.DEVNULL)
        time.sleep(1)  # Give daemon time to cleanup
        print("Stopped")


if __name__ == '__main__':
    client = DouaneGUIClient()
    try:
        client.start()
    except KeyboardInterrupt:
        print("\nStopping...")
        client.stop()
    except Exception as e:
        print(f"\nError: {e}")
        client.stop()

