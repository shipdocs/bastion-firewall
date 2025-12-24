#!/usr/bin/env python3
"""
Bastion Firewall GUI Client - Qt Implementation
Runs as user, connects to daemon, handles tray icon and popups.
"""

import sys
import os
import json
import socket
import signal
import fcntl
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QMessageBox
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QObject, pyqtSignal, QTimer, QSocketNotifier
from bastion.gui_qt import FirewallDialog
from bastion.icon_manager import IconManager

# Lock file to prevent multiple instances
# Lock file in user's runtime dir (XDG_RUNTIME_DIR) or fallback to /tmp
# This is user-writable and cleared on logout
import os as _os
LOCK_FILE = _os.path.join(_os.environ.get('XDG_RUNTIME_DIR', '/tmp'), 'bastion-gui.lock')

def acquire_lock():
    """
    Acquire a single-instance lock using the configured lock file.
    
    If an existing lock file contains a PID whose process is no longer running, the stale lock file is removed before acquiring a new lock. On success this function leaves the lock file open and written with the current PID; keep the returned file handle open to maintain the lock and close it to release the lock.
    
    Returns:
        file handle: Open file object for the lock file while the lock is held, or `None` if the lock could not be acquired.
    """
    try:
        # Check if stale lock (process died without cleanup)
        if os.path.exists(LOCK_FILE):
            try:
                with open(LOCK_FILE, 'r') as f:
                    old_pid = int(f.read().strip())
                # Check if process is still running
                os.kill(old_pid, 0)  # Raises OSError if not running
            except (ValueError, OSError):
                # Stale lock or invalid PID - remove it
                os.remove(LOCK_FILE)

        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.write(str(os.getpid()))
        lock_fd.flush()
        return lock_fd
    except (IOError, OSError):
        return None

class BastionClient(QObject):
    def __init__(self, app):
        """
        Initialize the BastionClient GUI: configure internal state, create the system tray icon and context menu, start timers, and begin polling the daemon socket.
        
        Sets default attributes (socket path, buffers, connection state and control_panel handle), prepares a tray icon with a pixmap fallback if necessary, installs a periodic tray-visibility checker, builds the context menu (status label, Control Panel, firewall Start/Stop/Restart, Quit), starts a connect timer that calls try_connect every 2 seconds, and performs the initial connection attempt.
        Parameters:
            app (QApplication): The QApplication instance used to integrate with the Qt event loop and to call quit from the tray menu.
        """
        super().__init__()
        self.app = app
        self.socket_path = '/run/bastion/daemon.sock'
        self.sock = None
        self.notifier = None
        self.buffer = ""
        self.connected = False
        self.control_panel = None  # Track control panel window

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

        # Timer to check tray icon visibility (in case it disappears)
        self.tray_check_timer = QTimer()
        self.tray_check_timer.timeout.connect(self._ensure_tray_visible)
        self.tray_check_timer.start(5000)  # Check every 5 seconds
        
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
        
        self.menu.addSeparator()
        self.action_quit = self.menu.addAction("Quit Tray")
        self.action_quit.triggered.connect(self.app.quit)
        
        self.tray_icon.setContextMenu(self.menu)
        
        # Connect Timer
        self.connect_timer = QTimer()
        self.connect_timer.timeout.connect(self.try_connect)
        self.connect_timer.start(2000)
        
        # Initial connection attempt
        self.try_connect()

    def _ensure_tray_visible(self):
        """
        Ensure the system tray icon is visible.
        
        If the tray icon is currently hidden, make it visible.
        """
        if not self.tray_icon.isVisible():
            print("[TRAY] Tray icon is hidden, making it visible again")
            self.tray_icon.setVisible(True)

    def try_connect(self):
        """
        Attempt to establish a connection to the daemon and update client state accordingly.
        
        If the daemon socket is missing, updates the tray status to indicate the daemon is not running.
        On successful connection, creates and configures a non-blocking Unix-domain socket, installs a read notifier, marks the client as connected, stops the reconnect timer, and updates the tray status to connected.
        On any connection error, updates the tray status to indicate the failure.
        """
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

    def update_status(self, text, status='connected'):
        """Update tray icon and status text"""
        self.action_status.setText(f"Status: {text}")
        # Use IconManager for consistent, professional icons
        self.tray_icon.setIcon(IconManager.get_status_icon(
            connected=(status != 'disconnected'),
            learning_mode=(status == 'learning'),
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
        """
        Process a single newline-delimited JSON message from the daemon and dispatch it to the appropriate handler.
        
        Parameters:
            line (str): A single JSON-encoded message received from the daemon.
        
        Description:
            Parses `line` as JSON and dispatches based on the message `type` field. Supported types:
            - "connection_request": forwards to the connection request handler.
            - "usb_request": forwards to the USB request handler.
            - "stats_update": acknowledged but no action taken here.
            - "notification": forwards to the notification handler.
        
        Behavior:
            Calls the corresponding handler for recognized message types and silently ignores malformed JSON or unrecognized message types.
        """
        try:
            req = json.loads(line)
            if req['type'] == 'connection_request':
                self.handle_connection_request(req)
            elif req['type'] == 'usb_request':
                self.handle_usb_request(req)
            elif req['type'] == 'stats_update':
                # Update stats in menu if needed
                pass
            elif req['type'] == 'notification':
                self.handle_notification(req)
        except json.JSONDecodeError:
            pass

    def handle_notification(self, req):
        """Show a system tray notification"""
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
        """
        Prompt the user to allow or deny an incoming connection request and send the decision to the daemon.
        
        Displays a FirewallDialog prefilled with data from the daemon `req`, waits up to 30 seconds for the user's decision, and—if the client is connected—sends a JSON response of the form `{"allow": <bool>, "permanent": <bool>}\n` back over the control socket. If sending fails the client will be disconnected.
        
        Parameters:
            req (dict): The daemon-provided connection request payload used to populate the dialog.
        """
        dialog = FirewallDialog(req, timeout=30)
        result = dialog.exec()

        decision = (dialog.decision == 'allow')
        permanent = dialog.permanent

        # Send response
        if self.connected and self.sock:
            resp = json.dumps({'allow': decision, 'permanent': permanent}) + '\n'
            try:
                self.sock.sendall(resp.encode())
            except:
                self.handle_disconnect()

    def handle_usb_request(self, req):
        """
        Present a user prompt for an incoming USB device authorization request and send the user's decision back to the daemon.
        
        Constructs a USBDeviceInfo from the provided request dictionary, displays a USBPromptDialog (30-second timeout) to obtain the user's `verdict`, `scope`, and `save_rule`, and, when connected, sends a newline-terminated JSON message of type `usb_response` containing those fields to the daemon. If sending the response fails, the client disconnects; if not connected, no response is sent.
        
        Parameters:
        	req (dict): Daemon-provided USB attributes (expected keys include `vendor_id`, `product_id`, `vendor_name`, `product_name`, `device_class`, `serial`, `bus_id`). Default values are used for missing keys.
        """
        from bastion.usb_device import USBDeviceInfo
        from bastion.usb_gui import USBPromptDialog

        print(f"[USB] Received USB request: {req.get('product_name', 'Unknown')}")

        # Convert request to USBDeviceInfo
        device = USBDeviceInfo(
            vendor_id=req.get('vendor_id', '0000'),
            product_id=req.get('product_id', '0000'),
            vendor_name=req.get('vendor_name', 'Unknown'),
            product_name=req.get('product_name', 'Unknown Device'),
            device_class=req.get('device_class', 0),
            serial=req.get('serial'),
            bus_id=req.get('bus_id', '1-1')
        )

        # Show USB prompt dialog
        print(f"[USB] Showing prompt dialog for: {device.product_name}")
        dialog = USBPromptDialog(device, timeout=30)

        # Make sure dialog is shown (raise to top, set focus)
        dialog.raise_()
        dialog.activateWindow()
        dialog.setFocus()

        result = dialog.exec()

        print(f"[USB] Dialog result: {dialog.verdict} (scope={dialog.scope}, save_rule={dialog.save_rule})")

        # Send response
        if self.connected and self.sock:
            resp = json.dumps({
                'type': 'usb_response',
                'verdict': dialog.verdict or 'block',
                'scope': dialog.scope,
                'save_rule': dialog.save_rule
            }) + '\n'
            try:
                self.sock.sendall(resp.encode())
                print(f"[USB] Response sent: {dialog.verdict} (save_rule={dialog.save_rule})")
            except Exception as e:
                print(f"[USB] Failed to send response: {e}")
                self.handle_disconnect()
        else:
            print(f"[USB] Not connected, cannot send response")

    def open_control_panel(self):
        """
        Launches the external Bastion Control Panel application.
        
        Attempts to start the `/usr/bin/bastion-control-panel` executable using the current environment. On failure, displays a critical QMessageBox with the error and logs an error message to standard output.
        """
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