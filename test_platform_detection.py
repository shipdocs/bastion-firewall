#!/usr/bin/env python3
"""
Test script to verify platform detection and window behavior
Run this to test if the dialog appears without stealing focus
"""

import sys
import os

# Add bastion to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget
from PyQt6.QtCore import QTimer
from bastion.gui_qt import FirewallDialog, get_platform_name, is_wayland

class TestWindow(QMainWindow):
    """Main window to test if dialogs steal focus"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Focus Test - Type here to test focus stealing")
        self.setGeometry(100, 100, 600, 400)
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Text edit to test focus
        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText(
            "Type here and keep typing when the dialog appears.\n"
            "If focus is NOT stolen, you should be able to continue typing.\n\n"
            f"Platform detected: {get_platform_name()}\n"
            f"Is Wayland: {is_wayland()}"
        )
        layout.addWidget(self.text_edit)
        
        # Button to trigger dialog
        btn = QPushButton("Show Firewall Dialog (in 3 seconds)")
        btn.clicked.connect(self.schedule_dialog)
        layout.addWidget(btn)
        
        # Set focus to text edit
        self.text_edit.setFocus()
    
    def schedule_dialog(self):
        """Schedule dialog to appear in 3 seconds"""
        print("Dialog will appear in 3 seconds. Start typing now!")
        QTimer.singleShot(3000, self.show_dialog)
    
    def show_dialog(self):
        """Show the firewall dialog"""
        print("Showing dialog...")
        conn_info = {
            'app_name': 'Firefox',
            'app_path': '/usr/bin/firefox',
            'dest_ip': '1.1.1.1',
            'dest_port': 443,
            'protocol': 'TCP'
        }
        
        dialog = FirewallDialog(conn_info, timeout=30)
        
        # Show non-modally
        dialog.show()
        
        print(f"Dialog shown. Window flags: {dialog.windowFlags()}")
        print(f"Has focus: {dialog.hasFocus()}")
        print(f"Main window has focus: {self.text_edit.hasFocus()}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    print("=" * 60)
    print("Platform Detection Test")
    print("=" * 60)
    print(f"Qt Platform: {get_platform_name()}")
    print(f"Is Wayland: {is_wayland()}")
    print(f"WAYLAND_DISPLAY: {os.environ.get('WAYLAND_DISPLAY', 'not set')}")
    print(f"DISPLAY: {os.environ.get('DISPLAY', 'not set')}")
    print("=" * 60)
    
    window = TestWindow()
    window.show()
    
    sys.exit(app.exec())

