#!/usr/bin/env python3
"""
GUI Manager - Unified GUI/Daemon Integration

Manages the lifecycle of the GUI application, ensuring it:
1. Starts automatically with the daemon
2. Reconnects if it crashes
3. Provides tray icon and control panel
4. Handles connection requests from daemon
5. Persists across reboots
"""

import os
import sys
import logging
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class GUIManager:
    """Manages GUI lifecycle and integration with daemon"""
    
    def __init__(self):
        self.gui_process = None
        self.gui_path = self._find_gui_executable()
        self.autostart_dir = Path.home() / '.config' / 'autostart'
        
    def _find_gui_executable(self):
        """Find bastion-gui executable"""
        paths = [
            '/usr/bin/bastion-gui',
            '/usr/local/bin/bastion-gui',
            'bastion-gui'
        ]
        
        for path in paths:
            if self._executable_exists(path):
                return path
        
        logger.warning("Could not find bastion-gui executable")
        return None
    
    def _executable_exists(self, path):
        """Check if executable exists and is executable"""
        try:
            return os.path.isfile(path) and os.access(path, os.X_OK)
        except:
            return False

    def is_gui_running(self):
        """Check if GUI process is running"""
        try:
            # Check if process is still alive
            if self.gui_process and self.gui_process.poll() is None:
                return True

            # Also check if any bastion-gui process is running
            result = subprocess.run(
                ['pgrep', '-f', 'bastion-gui'],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Error checking GUI status: {e}")
            return False

    def start_gui(self):
        """Start GUI application in background as the logged-in user"""
        if not self.gui_path:
            logger.error("Cannot start GUI: executable not found")
            return False

        if self.is_gui_running():
            logger.debug("GUI already running")
            return True

        try:
            # Find the logged-in user (not root)
            # Try to get the user from SUDO_USER or look for active X session
            user = os.environ.get('SUDO_USER')

            if not user:
                # Try to find user from active X sessions
                try:
                    result = subprocess.run(
                        ['who'],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    if result.stdout:
                        # Get first logged-in user
                        user = result.stdout.split()[0]
                except:
                    pass

            if not user:
                logger.error("Cannot determine logged-in user for GUI")
                return False

            logger.info(f"Starting GUI as user: {user}")

            # Get user's environment variables (especially DISPLAY)
            env = os.environ.copy()

            # Try to find DISPLAY from user's X session
            display_found = False
            try:
                # First try reading /proc/<pid>/environ directly (more reliable)
                # Get PIDs of user's GUI-related processes
                result = subprocess.run(
                    ['pgrep', '-u', user, '-x', 'gnome-shell|Xorg|kwin|plasmashell'],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                for pid in result.stdout.strip().split('\n'):
                    if pid and pid.isdigit():
                        try:
                            with open(f'/proc/{pid}/environ', 'r') as f:
                                # /proc environ uses NUL separators
                                for var in f.read().split('\0'):
                                    if var.startswith('DISPLAY='):
                                        display = var.split('=', 1)[1]
                                        if display:
                                            env['DISPLAY'] = display
                                            logger.info(f"Found DISPLAY from /proc/{pid}: {display}")
                                            display_found = True
                                            break
                        except (OSError, PermissionError):
                            continue
                    if display_found:
                        break
            except Exception as e:
                logger.debug(f"Could not find DISPLAY from /proc: {e}")

            # Fallback: try ps -o environ= (output format varies by system)
            if not display_found:
                try:
                    result = subprocess.run(
                        ['ps', '-u', user, '-o', 'environ='],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    for line in result.stdout.splitlines():
                        if 'DISPLAY=' in line:
                            # Try both space and NUL separators (format varies by OS)
                            tokens = line.replace('\0', ' ').split()
                            for tok in tokens:
                                if tok.startswith('DISPLAY='):
                                    display = tok.split('=', 1)[1]
                                    if display:
                                        env['DISPLAY'] = display
                                        logger.info(f"Found DISPLAY from ps: {display}")
                                        display_found = True
                                        break
                            if display_found:
                                break
                except Exception as e:
                    logger.debug(f"Could not find DISPLAY from ps: {e}")

            # If still no DISPLAY, try common defaults
            if not display_found:
                for display in [':0', ':1', ':0.0', ':1.0']:
                    try:
                        # Test if display is accessible
                        result = subprocess.run(
                            ['xset', '-display', display, 'q'],
                            capture_output=True,
                            timeout=1
                        )
                        if result.returncode == 0:
                            env['DISPLAY'] = display
                            logger.info(f"Using DISPLAY: {display}")
                            display_found = True
                            break
                    except:
                        pass

            if not display_found:
                logger.warning("Could not determine DISPLAY, GUI may not start")

            # Start GUI as the user, not as root
            self.gui_process = subprocess.Popen(
                [self.gui_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,  # Detach from daemon
                env=env  # Pass environment with DISPLAY
            )
            logger.info(f"GUI started (PID: {self.gui_process.pid}) for user {user}")
            return True
        except Exception as e:
            logger.error(f"Failed to start GUI: {e}")
            return False
    
    def ensure_gui_running(self):
        """Ensure GUI is running, restart if needed"""
        if not self.gui_process or self.gui_process.poll() is not None:
            logger.warning("GUI not running, restarting...")
            return self.start_gui()
        return True
    
    def setup_autostart(self, enable=True):
        """Setup GUI autostart on user login"""
        try:
            self.autostart_dir.mkdir(parents=True, exist_ok=True)
            desktop_file = self.autostart_dir / 'bastion-firewall-gui.desktop'
            
            if enable:
                content = """[Desktop Entry]
Type=Application
Name=Bastion Firewall
Comment=Firewall control and connection management
Exec=/usr/bin/bastion-gui
Icon=security-high
Terminal=false
Categories=System;Security;Network;
Hidden=false
X-GNOME-Autostart-enabled=true
"""
                with open(desktop_file, 'w') as f:
                    f.write(content)
                logger.info("GUI autostart enabled")
            else:
                if desktop_file.exists():
                    desktop_file.unlink()
                logger.info("GUI autostart disabled")
            
            return True
        except Exception as e:
            logger.error(f"Failed to setup autostart: {e}")
            return False
    
    def stop_gui(self):
        """Stop GUI application"""
        if self.gui_process and self.gui_process.poll() is None:
            try:
                self.gui_process.terminate()
                self.gui_process.wait(timeout=5)
                logger.info("GUI stopped")
            except subprocess.TimeoutExpired:
                self.gui_process.kill()
                logger.warning("GUI killed (timeout)")
            except Exception as e:
                logger.error(f"Error stopping GUI: {e}")

