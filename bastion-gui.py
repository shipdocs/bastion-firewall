#!/usr/bin/env python3
"""
Bastion Firewall GUI Client - Qt Implementation
Runs as user, connects to daemon, handles tray icon and popups.
"""

import sys
import os

# Support private module install (RPM/Fedora)
if os.path.exists("/usr/share/bastion-firewall"):
    sys.path.append("/usr/share/bastion-firewall")
import json
import socket
import signal
import fcntl
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QMessageBox
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QObject, pyqtSignal, QTimer, QSocketNotifier
from bastion.gui.dialogs.firewall_dialog import FirewallDialog
from bastion.icon_manager import IconManager

# Lock file to prevent multiple instances
LOCK_FILE = f'/tmp/bastion-gui-{os.getuid()}.lock'

def acquire_lock():
    try:
        lock_fd = open(LOCK_FILE, 'a+')
        lock_fd.seek(0)

        # Try to get exclusive lock (non-blocking)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError):
            # Another process has the lock
            lock_fd.close()
            return None

        # We have the lock - check if there's a stale PID
        content = lock_fd.read().strip()
        if content:
            try:
                old_pid = int(content)
                # Check if it's our own PID (re-acquiring)
                if old_pid == os.getpid():
                    return lock_fd
                # Check if process is still running
                os.kill(old_pid, 0)
                # Process exists - but we have the lock, so it must be stale
            except (ValueError, OSError):
                pass  # Stale or invalid PID

        lock_fd.seek(0)
        lock_fd.truncate()
        lock_fd.write(str(os.getpid()))
        lock_fd.flush()
        return lock_fd
    except (IOError, OSError) as e:
        print(f"[LOCK] Error acquiring lock: {e}")
        return None

class BastionClient(QObject):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.socket_path = '/var/run/bastion/bastion-daemon.sock'
        self.sock = None
        self.notifier = None
        self.buffer = ""
        self.connected = False
        self.learning_mode = False  # Track current learning mode state

        # Tray Icon
        self.tray_icon = QSystemTrayIcon()

        # Check if tray is available
        if not QSystemTrayIcon.isSystemTrayAvailable():
            print("[TRAY] WARNING: System tray not available on this desktop")

        # Set initial icon using IconManager
        icon = IconManager.get_status_icon(connected=False)
        print(f"[TRAY] Icon obtained: isNull={icon.isNull()}, availableSizes={icon.availableSizes()}")

        # If icon is null, try to create a pixmap-based icon
        if icon.isNull():
            print("[TRAY] Icon is null, trying to create pixmap-based icon")
            try:
                pixmap = IconManager.create_status_pixmap('disconnected', size=64)
                icon = QIcon(pixmap)
                print(f"[TRAY] Created pixmap icon: isNull={icon.isNull()}")
            except Exception as e:
                print(f"[TRAY] Failed to create pixmap icon: {e}")

        self.tray_icon.setIcon(icon)
        self.tray_icon.setVisible(True)
        print(f"[TRAY] Tray icon visible: {self.tray_icon.isVisible()}")
        
        # Menu
        self.menu = QMenu()
        
        self.action_status = self.menu.addAction("Status: Connecting...")
        self.action_status.setEnabled(False)
        self.menu.addSeparator()
        
        self.action_cp = self.menu.addAction("Control Panel")
        self.action_cp.triggered.connect(self.open_control_panel)
        
        self.menu.addSeparator()
        
        self.action_start = self.menu.addAction("Start Firewall")
        self.action_start.triggered.connect(lambda: self.run_service("start"))
        
        self.action_stop = self.menu.addAction("Stop Firewall")
        self.action_stop.triggered.connect(lambda: self.run_service("stop"))
        
        self.action_restart = self.menu.addAction("Restart Firewall")
        self.action_restart.triggered.connect(lambda: self.run_service("restart"))

        self.tray_icon.setContextMenu(self.menu)

        # Connect tray icon activation (for GNOME/AppIndicator compatibility)
        self.tray_icon.activated.connect(self.on_tray_activated)

        # Connect Timer
        self.connect_timer = QTimer()
        self.connect_timer.timeout.connect(self.try_connect)
        self.connect_timer.start(2000)
        
        # Initial connection attempt
        self.try_connect()

    def try_connect(self):
        if self.connected:
            return
            
        if not os.path.exists(self.socket_path):
            self.update_status("Daemon not running", "security-low")
            return
            
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.socket_path)
            self.sock.setblocking(False)
            
            self.notifier = QSocketNotifier(self.sock.fileno(), QSocketNotifier.Type.Read)
            self.notifier.activated.connect(self.on_ready_read)
            
            self.connected = True
            self.connect_timer.stop()
            self.update_status("Connected", "connected")
            print("Connected to daemon")

        except Exception as e:
            print(f"Connection failed: {e}")
            self.update_status("Connection failed", "error")

    def get_safe_icon(self, icon_name):
        """Try to load icon from theme, falling back to standard icons if missing"""
        # List of fallbacks in order of preference
        fallbacks = [
            icon_name,
            'security-high',
            'security-medium', 
            'system-lock-screen', 
            'changes-prevent',
            'emblem-locked', 
            'network-wired', 
            'applications-internet'
        ]
        
        for name in fallbacks:
            if not name: continue
            icon = QIcon.fromTheme(name)
            # Check if icon actually has available sizes (exists)
            if not icon.isNull() and icon.availableSizes():
                return icon
                
        # If all else fails, return a generic fallback (or keep empty which shows dots)
        return QIcon.fromTheme('system-help')

    def on_tray_activated(self, reason):
        """Handle tray icon activation (click)"""
        # On Wayland (Pop!_OS/COSMIC), manual menu.popup() doesn't position correctly
        # Right-click context menu is handled natively by setContextMenu() and works fine
        # Left-click: no action (Wayland limitation)
        pass

    def update_status(self, text, status='connected'):
        """Update tray icon and status text"""
        self.action_status.setText(f"Status: {text}")
        # Use IconManager for consistent, professional icons
        self.tray_icon.setIcon(IconManager.get_status_icon(
            connected=(status != 'disconnected'),
            learning_mode=self.learning_mode,
            error=(status == 'error')
        ))

    def on_ready_read(self):
        try:
            data = self.sock.recv(4096).decode()
            if not data:
                # Disconnected
                self.handle_disconnect()
                return
                
            self.buffer += data
            while '\n' in self.buffer:
                line, self.buffer = self.buffer.split('\n', 1)
                self.process_message(line)
        except Exception as e:
            print(f"Socket error: {e}")
            self.handle_disconnect()

    def handle_disconnect(self):
        print("Disconnected from daemon")
        self.connected = False
        if self.notifier:
            self.notifier.setEnabled(False)
            self.notifier = None
        if self.sock:
            self.sock.close()
            self.sock = None

        self.update_status("Disconnected", "disconnected")
        self.connect_timer.start(2000)

    def process_message(self, line):
        try:
            req = json.loads(line)
            if req['type'] == 'connection_request':
                self.handle_connection_request(req)
            elif req['type'] == 'stats_update':
                # Extract learning_mode from stats and update icon if changed
                stats = req.get('stats', {})
                new_learning_mode = stats.get('learning_mode', False)
                if new_learning_mode != self.learning_mode:
                    self.learning_mode = new_learning_mode
                    # Update icon to reflect new learning mode
                    self.update_status("Connected" if self.connected else "Disconnected",
                                      "connected" if self.connected else "disconnected")
            elif req['type'] == 'notification':
                self.handle_notification(req)
        except json.JSONDecodeError:
            pass

    def handle_notification(self, req):
        title = req.get('title', 'Bastion Firewall')
        message = req.get('message', '')
        level = req.get('level', 'info')
        
        icon = QSystemTrayIcon.MessageIcon.Information
        if level == 'warning':
            icon = QSystemTrayIcon.MessageIcon.Warning
        elif level == 'error':
            icon = QSystemTrayIcon.MessageIcon.Critical
            
        self.tray_icon.showMessage(title, message, icon, 5000)

    def handle_connection_request(self, req):
        print(f"[GUI] Popup request: app_name='{req.get('app_name')}' app_path='{req.get('app_path')}' dst={req.get('dest_ip')}:{req.get('dest_port')}")
        dialog = FirewallDialog(req, timeout=60)
        decision_id = req.get('decision_id', 0)

        # Handle dialog completion (non-modal)
        learning_mode = req.get('learning_mode', False)
        
        def on_dialog_finished():
            decision = (dialog.decision == 'allow')
            permanent = dialog.permanent
            all_ports = dialog.all_ports  # Wildcard port support (issue #13)

            # Send response
            if self.connected and self.sock:
                if learning_mode:
                    # In learning mode, we only care about permanent rules
                    if permanent:
                        resp = json.dumps({
                            'type': 'add_rule',
                            'app_name': req.get('app_name'),
                            'app_path': req.get('app_path'),
                            'port': req.get('dest_port'),
                            'dest_ip': req.get('dest_ip'),  # For @dest rules on unknown apps
                            'allow': decision,
                            'all_ports': all_ports
                        }) + '\n'
                        print(f"[GUI] Sending async rule addition: {req.get('app_name')} -> {req.get('dest_port')}")
                    else:
                        return # No-op for temporary decisions in learning mode
                else:
                    # Normal enforcement mode - response to blocking request
                    resp = json.dumps({
                        'type': 'gui_response',
                        'allow': decision,
                        'permanent': permanent,
                        'all_ports': all_ports,
                        'decision_id': decision_id
                    }) + '\n'
                
                try:
                    self.sock.sendall(resp.encode())
                except (OSError, BrokenPipeError, ConnectionResetError):
                    self.handle_disconnect()

            dialog.deleteLater()  # Clean up dialog

        dialog.finished.connect(on_dialog_finished)
        dialog.show()  # Non-modal - doesn't steal focus!

    def open_control_panel(self):
        import subprocess
        try:
            env = os.environ.copy()
            subprocess.Popen(['/usr/bin/bastion-control-panel'], env=env)
            print("[TRAY] Control Panel launched")
        except Exception as e:
            print(f"[TRAY] Failed to launch Control Panel: {e}")
            QMessageBox.critical(None, "Error", f"Failed to open Control Panel: {e}")

    def run_service(self, action):
        """Run systemctl action in background thread to avoid blocking GUI."""
        import threading

        # Update status immediately
        self.update_status(f"{action.capitalize()}ing...", "disconnected")

        def do_action():
            import subprocess
            try:
                result = subprocess.run(['pkexec', 'systemctl', action, 'bastion-firewall'],
                                       capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    print(f"[TRAY] {action} failed: {result.stderr}")
                    return

                print(f"[TRAY] Firewall {action} successful")

            except Exception as e:
                print(f"[TRAY] Failed to {action} firewall: {e}")

        # Run in background thread
        thread = threading.Thread(target=do_action, daemon=True)
        thread.start()

        # Schedule reconnection attempt after action completes
        if action in ('start', 'restart'):
            QTimer.singleShot(2500, self.try_connect)
        elif action == 'stop':
            QTimer.singleShot(1000, lambda: self.update_status("Stopped", "disconnected"))

if __name__ == '__main__':
    # Prevent multiple instances
    lock_fd = acquire_lock()
    if lock_fd is None:
        print("Bastion GUI is already running. Exiting.")
        sys.exit(0)

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    # Handle Ctrl+C
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    client = BastionClient(app)
    sys.exit(app.exec())