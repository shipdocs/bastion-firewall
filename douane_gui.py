#!/usr/bin/env python3
"""
Douane GUI - Popup dialog for application internet access requests.
"""

import sys
import json
import logging
from pathlib import Path
from typing import Optional

try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, GLib, Gdk
except ImportError:
    print("Error: GTK3 is required. Install with: sudo apt-get install python3-gi")
    sys.exit(1)

# Configuration
CONFIG_DIR = Path.home() / ".config" / "douane"
LOG_PATH = CONFIG_DIR / "douane-gui.log"

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
logger = logging.getLogger("douane-gui")


class PermissionDialog(Gtk.Window):
    """Dialog window for asking user permission for application internet access."""
    
    def __init__(self, app_name: str, exe_path: str, dest_ip: str, 
                 port: int, callback=None):
        super().__init__(title="Douane - Network Access Request")
        
        self.app_name = app_name
        self.exe_path = exe_path
        self.dest_ip = dest_ip
        self.port = port
        self.callback = callback
        self.response = None
        
        # Window properties
        self.set_border_width(20)
        self.set_default_size(500, 300)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_keep_above(True)
        self.set_urgency_hint(True)
        
        # Make window modal
        self.set_modal(True)
        
        # Create UI
        self._create_ui()
        
        # Handle window close
        self.connect("delete-event", self._on_delete)
    
    def _create_ui(self):
        """Create the dialog UI."""
        # Main container
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        self.add(vbox)
        
        # Icon and title section
        header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        vbox.pack_start(header_box, False, False, 0)
        
        # Icon (using system icon)
        icon = Gtk.Image.new_from_icon_name("dialog-question", Gtk.IconSize.DIALOG)
        header_box.pack_start(icon, False, False, 0)
        
        # Title label
        title_label = Gtk.Label()
        title_label.set_markup(
            f"<big><b>Network Access Request</b></big>\n"
            f"<span size='small'>An application wants to connect to the internet</span>"
        )
        title_label.set_line_wrap(True)
        title_label.set_xalign(0)
        header_box.pack_start(title_label, True, True, 0)
        
        # Separator
        separator1 = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        vbox.pack_start(separator1, False, False, 0)
        
        # Application information
        info_frame = Gtk.Frame(label="Application Details")
        info_frame.set_shadow_type(Gtk.ShadowType.IN)
        vbox.pack_start(info_frame, True, True, 0)
        
        info_grid = Gtk.Grid()
        info_grid.set_row_spacing(8)
        info_grid.set_column_spacing(10)
        info_grid.set_border_width(10)
        info_frame.add(info_grid)
        
        # Application name
        app_label = Gtk.Label()
        app_label.set_markup("<b>Application:</b>")
        app_label.set_xalign(0)
        info_grid.attach(app_label, 0, 0, 1, 1)
        
        app_value = Gtk.Label(label=self.app_name)
        app_value.set_xalign(0)
        app_value.set_selectable(True)
        info_grid.attach(app_value, 1, 0, 1, 1)
        
        # Executable path
        exe_label = Gtk.Label()
        exe_label.set_markup("<b>Executable:</b>")
        exe_label.set_xalign(0)
        info_grid.attach(exe_label, 0, 1, 1, 1)
        
        exe_value = Gtk.Label(label=self.exe_path)
        exe_value.set_xalign(0)
        exe_value.set_line_wrap(True)
        exe_value.set_selectable(True)
        info_grid.attach(exe_value, 1, 1, 1, 1)
        
        # Destination
        dest_label = Gtk.Label()
        dest_label.set_markup("<b>Connecting to:</b>")
        dest_label.set_xalign(0)
        info_grid.attach(dest_label, 0, 2, 1, 1)
        
        dest_value = Gtk.Label(label=f"{self.dest_ip}:{self.port}")
        dest_value.set_xalign(0)
        dest_value.set_selectable(True)
        info_grid.attach(dest_value, 1, 2, 1, 1)
        
        # Question label
        question_label = Gtk.Label()
        question_label.set_markup(
            f"<b>Do you want to allow <span color='#2196F3'>{self.app_name}</span> "
            f"to connect to the internet?</b>"
        )
        question_label.set_line_wrap(True)
        question_label.set_xalign(0)
        vbox.pack_start(question_label, False, False, 0)
        
        # Separator
        separator2 = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        vbox.pack_start(separator2, False, False, 0)
        
        # Button box
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        button_box.set_homogeneous(False)
        vbox.pack_start(button_box, False, False, 0)
        
        # Duration selection
        duration_label = Gtk.Label(label="Duration:")
        button_box.pack_start(duration_label, False, False, 0)
        
        self.duration_combo = Gtk.ComboBoxText()
        self.duration_combo.append("once", "This time only")
        self.duration_combo.append("always", "Always allow")
        self.duration_combo.set_active(0)
        button_box.pack_start(self.duration_combo, False, False, 0)
        
        # Spacer
        button_box.pack_start(Gtk.Label(), True, True, 0)
        
        # Deny button
        deny_button = Gtk.Button(label="Deny")
        deny_button.connect("clicked", self._on_deny)
        deny_button.get_style_context().add_class("destructive-action")
        button_box.pack_end(deny_button, False, False, 0)
        
        # Allow button
        allow_button = Gtk.Button(label="Allow")
        allow_button.connect("clicked", self._on_allow)
        allow_button.get_style_context().add_class("suggested-action")
        button_box.pack_end(allow_button, False, False, 0)
        
        # Set focus to allow button
        allow_button.grab_focus()
    
    def _on_allow(self, button):
        """Handle allow button click."""
        duration = self.duration_combo.get_active_id()
        self.response = {
            'permission': 'allow',
            'duration': duration,
            'exe_path': self.exe_path
        }
        logger.info(f"User allowed: {self.app_name} ({duration})")
        self._close()
    
    def _on_deny(self, button):
        """Handle deny button click."""
        duration = self.duration_combo.get_active_id()
        self.response = {
            'permission': 'deny',
            'duration': duration,
            'exe_path': self.exe_path
        }
        logger.info(f"User denied: {self.app_name} ({duration})")
        self._close()
    
    def _on_delete(self, widget, event):
        """Handle window close event."""
        # Default to deny if user closes window
        if self.response is None:
            self.response = {
                'permission': 'deny',
                'duration': 'once',
                'exe_path': self.exe_path
            }
            logger.info(f"User closed dialog for: {self.app_name} (defaulting to deny)")
        self._close()
        return True
    
    def _close(self):
        """Close the dialog and execute callback."""
        if self.callback and self.response:
            self.callback(self.response)
        self.destroy()
        Gtk.main_quit()


class DouaneGUI:
    """Main GUI application."""
    
    def __init__(self):
        self.dialog = None
    
    def show_permission_dialog(self, app_name: str, exe_path: str, 
                              dest_ip: str, port: int, callback=None):
        """Show a permission dialog."""
        self.dialog = PermissionDialog(app_name, exe_path, dest_ip, port, callback)
        self.dialog.show_all()
        Gtk.main()
    
    @staticmethod
    def test_dialog():
        """Test the dialog with sample data."""
        def on_response(response):
            print(f"User response: {json.dumps(response, indent=2)}")
        
        gui = DouaneGUI()
        gui.show_permission_dialog(
            app_name="firefox",
            exe_path="/usr/bin/firefox",
            dest_ip="93.184.216.34",
            port=443,
            callback=on_response
        )


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Douane GUI - Network permission dialogs")
    parser.add_argument("--test", action="store_true", help="Test the dialog")
    parser.add_argument("--app-name", help="Application name")
    parser.add_argument("--exe-path", help="Executable path")
    parser.add_argument("--dest-ip", help="Destination IP")
    parser.add_argument("--port", type=int, help="Destination port")
    
    args = parser.parse_args()
    
    if args.test:
        DouaneGUI.test_dialog()
    elif args.app_name and args.exe_path and args.dest_ip and args.port:
        def on_response(response):
            print(json.dumps(response))
            sys.stdout.flush()
        
        gui = DouaneGUI()
        gui.show_permission_dialog(
            app_name=args.app_name,
            exe_path=args.exe_path,
            dest_ip=args.dest_ip,
            port=args.port,
            callback=on_response
        )
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
