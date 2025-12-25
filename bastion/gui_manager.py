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
        except (OSError, PermissionError) as e:
            logger.debug(f"Failed to check executable {path}: {e}")
            return False
    
    def start_gui_for_all_users(self):
        """
        Smart GUI launch: Find all active graphical sessions and launch GUI as those users.
        Runs from root daemon.
        """
        if not self.gui_path:
            return False

        try:
            # 1. Get active sessions from loginctl
            result = subprocess.run(['loginctl', 'list-sessions', '--no-legend'], 
                                   capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                logger.debug("loginctl list-sessions failed")
                return False

            active_launched = False
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) < 3: continue
                
                session_id = parts[0]
                uid = parts[1]
                user = parts[2]
                
                # Check session type
                session_info = subprocess.run(['loginctl', 'show-session', session_id], 
                                            capture_output=True, text=True, timeout=2)
                
                info = {}
                for s_line in session_info.stdout.split('\n'):
                    if '=' in s_line:
                        parts_info = s_line.split('=', 1)
                        if len(parts_info) == 2:
                            info[parts_info[0]] = parts_info[1]

                # Only launch for graphical sessions (X11 or Wayland)
                if info.get('Type') in ('x11', 'wayland') and info.get('Active') == 'yes':
                    logger.info(f"Detected active {info.get('Type')} session for user {user}")
                    if self._launch_as_user(user, uid):
                        active_launched = True

            return active_launched
        except Exception as e:
            logger.error(f"Error in start_gui_for_all_users: {e}")
            return False

    def _launch_as_user(self, user, uid):
        """Launch GUI for a specific user session from root"""
        try:
            # Check if already running for this user
            try:
                subprocess.run(['pgrep', '-u', user, '-f', 'bastion-gui'], check=True, capture_output=True)
                logger.debug(f"GUI already running for user {user}")
                return True
            except subprocess.CalledProcessError:
                pass # Not running

            # Set environment for the user
            # Use systemd-run --user for modern session integration if possible
            # This is the "smartest" way as it inherits user environment properly
            launch_cmd = [
                'systemd-run',
                '--user',
                '--machine', f"{user}@.host",
                '--collect',
                '--description', 'Bastion Firewall GUI',
                self.gui_path
            ]
            
            # Fallback if systemd-run fails or machine name not recognized
            fallback_cmd = [
                'sudo', '-u', user, 
                'env', f"XDG_RUNTIME_DIR=/run/user/{uid}",
                'env', f"DISPLAY=:0",
                self.gui_path
            ]

            logger.info(f"Attempting to launch GUI for {user} via systemd-run")
            res = subprocess.run(launch_cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return True
                
            logger.warning(f"systemd-run failed for {user}, trying fallback: {res.stderr}")
            subprocess.Popen(fallback_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
            
        except Exception as e:
            logger.error(f"Failed to launch GUI for user {user}: {e}")
            return False

    def start_gui(self):
        """Start GUI application"""
        if os.getuid() == 0:
            return self.start_gui_for_all_users()
            
        if not self.gui_path:
            return False
        
        try:
            self.gui_process = subprocess.Popen(
                [self.gui_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            return True
        except Exception as e:
            logger.error(f"Failed to start GUI: {e}")
            return False

    def ensure_gui_running(self):
        """Ensure GUI is running, restart if needed"""
        return self.start_gui()
    
    def setup_autostart(self, enable=True):
        """Setup GUI autostart on user login"""
        # This is for user-level calls
        autostart_dir = Path.home() / '.config' / 'autostart'
        try:
            autostart_dir.mkdir(parents=True, exist_ok=True)
            desktop_file = autostart_dir / 'bastion-firewall-gui.desktop'
            
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
        """Stop GUI for current user"""
        if self.gui_process and self.gui_process.poll() is None:
            self.gui_process.terminate()
        else:
            # Try to pkill it if we don't have a handle
            subprocess.run(['pkill', '-f', 'bastion-gui'], capture_output=True)


