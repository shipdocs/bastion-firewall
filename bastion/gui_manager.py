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
    
    def start_gui(self):
        """Start GUI application in background"""
        if not self.gui_path:
            logger.error("Cannot start GUI: executable not found")
            return False
        
        if self.gui_process and self.gui_process.poll() is None:
            logger.debug("GUI already running")
            return True
        
        try:
            self.gui_process = subprocess.Popen(
                [self.gui_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True  # Detach from daemon
            )
            logger.info(f"GUI started (PID: {self.gui_process.pid})")
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

