#!/usr/bin/env python3
"""
Bastion Firewall - Qt GUI
Modern interface using PyQt6.
Handles both the Decision Dialog (Popup) and the Control Panel (Dashboard).

DEPRECATED: This file is maintained for backward compatibility.
New code should import from bastion.gui.* modules directly.
"""

import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import from new modular structure
from .gui.platform import get_platform_name, is_wayland
from .gui.theme import COLORS, STYLESHEET
from .gui.dialogs import FirewallDialog
from .gui.dashboard import DashboardWindow, run_dashboard

# Re-export for backward compatibility
__all__ = [
    'get_platform_name',
    'is_wayland',
    'COLORS',
    'STYLESHEET',
    'FirewallDialog',
    'DashboardWindow',
    'run_dashboard',
    'test_dialog',
]


def test_dialog():
    """Test function for the firewall dialog."""
    from PyQt6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    conn = {'app_name': 'Firefox', 'app_path': '/usr/bin/firefox', 'dest_ip': '1.1.1.1', 'dest_port': 443, 'protocol': 'TCP'}
    d = FirewallDialog(conn, timeout=30)
    d.exec()
    sys.exit(0)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--test-popup':
        test_dialog()
    else:
        run_dashboard()
