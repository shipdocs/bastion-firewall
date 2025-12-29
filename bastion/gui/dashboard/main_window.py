#!/usr/bin/env python3
"""
Main Dashboard Window for Bastion Firewall Control Panel.
Provides status monitoring, rules management, logs, and settings.
"""

import sys
import os
import json
import logging
import subprocess
import tempfile
import threading
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                            QLabel, QPushButton, QFrame, QStackedWidget,
                            QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
                            QMessageBox, QCheckBox, QScrollArea, QAbstractItemView,
                            QApplication)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon, QFont, QColor

from ..theme import COLORS, STYLESHEET
from ..platform import is_wayland
from ...inbound_firewall import InboundFirewallDetector
from ...icon_manager import IconManager
from ...notification import show_notification
from ... import __version__

logger = logging.getLogger(__name__)


class DashboardWindow(QMainWindow):
    """
    Main Control Panel Dashboard with Sidebar.
    Connects to live system data.
    """
    def __init__(self):
        super().__init__()
        self.config_path = Path("/etc/bastion/config.json")
        self.rules_path = Path("/etc/bastion/rules.json")
        self.log_path = Path("/var/log/bastion-daemon.log")
        
        self.data_rules = {}
        self.data_config = {'mode': 'learning', 'timeout_seconds': 30}
        self.inbound_status = {}
        
        self.init_ui()
        
        # Initial Data Load
        self.load_data()
        self.refresh_ui()
        
        # Auto Refresh
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_status)
        self.timer.start(3000)

    def load_data(self):
        # Load Rules
        try:
            if self.rules_path.exists():
                with open(self.rules_path) as f:
                    self.data_rules = json.load(f)
            else:
                self.data_rules = {}
        except Exception as e:
            print(f"Error loading rules: {e}")

        # Load Config
        try:
            if self.config_path.exists():
                with open(self.config_path) as f:
                    self.data_config = json.load(f)
                    
            # Update UI from config
            is_learning = self.data_config.get('mode', 'learning') == 'learning'
            if hasattr(self, 'chk_learning'):
                self.chk_learning.setChecked(is_learning)
                
        except Exception as e:
            print(f"Error loading config: {e}")
            
        # Check Inbound
        try:
            self.inbound_status = InboundFirewallDetector.detect_firewall()
        except Exception as e:
            logger.debug(f"Failed to detect inbound firewall: {e}")

    def init_ui(self):
        self.setWindowTitle("Bastion Firewall")
        self.resize(1100, 750)
        self.setStyleSheet(STYLESHEET)
        
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(0, 30, 0, 20)
        sb_layout.setSpacing(10)
        
        # Logo/Brand
        brand_layout = QHBoxLayout()
        brand_layout.setContentsMargins(25, 0, 0, 20)
        # Use castle icon from resources
        logo = QLabel()
        logo_pixmap = IconManager.get_icon().pixmap(28, 28)
        logo.setPixmap(logo_pixmap)
        title = QLabel("Bastion")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['header']}; margin-left: 10px;")
        brand_layout.addWidget(logo)
        brand_layout.addWidget(title)
        brand_layout.addStretch()
        sb_layout.addLayout(brand_layout)
        
        # Navigation
        self.nav_btns = []
        self.add_nav_btn(sb_layout, "Status", "")
        self.add_nav_btn(sb_layout, "Rules", "")
        self.add_nav_btn(sb_layout, "Logs", "")
        self.add_nav_btn(sb_layout, "Settings", "")
        
        sb_layout.addStretch()
        
        ver = QLabel(f"v{__version__}")
        ver.setObjectName("muted")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sb_layout.addWidget(ver)
        
        main_layout.addWidget(sidebar)
        
        # Content Stack
        self.stack = QStackedWidget()
        self.stack.setContentsMargins(30, 30, 30, 30)

        self.page_status = self.create_status_page()
        self.page_rules = self.create_rules_page()
        self.page_logs = self.create_logs_page()
        self.page_settings = self.create_settings_page()

        self.stack.addWidget(self.page_status)
        self.stack.addWidget(self.page_rules)
        self.stack.addWidget(self.page_logs)
        self.stack.addWidget(self.page_settings)

        main_layout.addWidget(self.stack)
        self.nav_btns[0].setChecked(True)

    def add_nav_btn(self, layout, text, icon_char):
        btn = QPushButton(f"  {icon_char}   {text}")
        btn.setObjectName("nav_btn")
        btn.setCheckable(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(lambda: self.navigate(btn, text))
        layout.addWidget(btn)
        self.nav_btns.append(btn)

    def navigate(self, sender, page_name):
        for btn in self.nav_btns:
            btn.setChecked(False)
        sender.setChecked(True)
        if page_name == "Status":
            self.stack.setCurrentWidget(self.page_status)
            self.refresh_status()
        elif page_name == "Rules":
            self.stack.setCurrentWidget(self.page_rules)
            self.refresh_rules_table()
        elif page_name == "Logs":
            self.stack.setCurrentWidget(self.page_logs)
            self.refresh_logs()
        elif page_name == "Settings":
            self.stack.setCurrentWidget(self.page_settings)

    # --- PAGES ---

    def create_status_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        layout.addWidget(QLabel("System Status", objectName="page_title"))

        # Status Card Horizontal Layout
        status_cards = QHBoxLayout()
        status_cards.setSpacing(20)

        # 1. Bastion (Outbound) Card
        card_out = QFrame(objectName="card")
        card_out_layout = QVBoxLayout(card_out)
        card_out_layout.setContentsMargins(20, 20, 20, 20)

        # Card title - fixed label
        card_out_title_layout = QHBoxLayout()
        icon_out = QLabel()
        icon_pixmap = IconManager.get_icon().pixmap(24, 24)
        icon_out.setPixmap(icon_pixmap)
        card_out_title_layout.addWidget(icon_out)
        lbl_out_title = QLabel("Outbound")
        lbl_out_title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['header']};")
        card_out_title_layout.addWidget(lbl_out_title)
        card_out_title_layout.addStretch()
        card_out_layout.addLayout(card_out_title_layout)

        # Status - dynamic
        self.lbl_status_title = QLabel("Checking...")
        self.lbl_status_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['text_primary']}; margin-top: 8px;")
        card_out_layout.addWidget(self.lbl_status_title)

        self.lbl_status_desc = QLabel("Bastion Outbound Firewall")
        self.lbl_status_desc.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-bottom: 10px;")
        card_out_layout.addWidget(self.lbl_status_desc)

        self.btn_toggle = QPushButton("Start")
        self.btn_toggle.setObjectName("action_btn")
        self.btn_toggle.clicked.connect(self.toggle_firewall)
        card_out_layout.addWidget(self.btn_toggle)

        status_cards.addWidget(card_out)

        # 2. UFW (Inbound) Card
        card_in = QFrame(objectName="card")
        card_in_layout = QVBoxLayout(card_in)
        card_in_layout.setContentsMargins(20, 20, 20, 20)

        # Card title - fixed label
        card_in_title_layout = QHBoxLayout()
        icon_in = QLabel()
        icon_in_pixmap = IconManager.get_icon().pixmap(24, 24)
        icon_in.setPixmap(icon_in_pixmap)
        card_in_title_layout.addWidget(icon_in)
        lbl_in_title = QLabel("Inbound")
        lbl_in_title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['header']};")
        card_in_title_layout.addWidget(lbl_in_title)
        card_in_title_layout.addStretch()
        card_in_layout.addLayout(card_in_title_layout)

        # Status - dynamic
        self.lbl_inbound_title = QLabel("Checking...")
        self.lbl_inbound_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['text_primary']}; margin-top: 8px;")
        card_in_layout.addWidget(self.lbl_inbound_title)

        self.lbl_inbound_desc = QLabel("UFW Inbound Firewall")
        self.lbl_inbound_desc.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-bottom: 10px;")
        card_in_layout.addWidget(self.lbl_inbound_desc)

        self.btn_inbound = QPushButton("Configure")
        self.btn_inbound.setObjectName("action_btn")
        self.btn_inbound.clicked.connect(lambda: self.navigate(self.nav_btns[3], "Settings")) # Go to settings
        card_in_layout.addWidget(self.btn_inbound)

        status_cards.addWidget(card_in)

        layout.addLayout(status_cards)

        # Stats
        layout.addSpacing(30)
        layout.addWidget(QLabel("Statistics (Live)", objectName="h2"))
        layout.addSpacing(15)

        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(20)

        self.stat_connections, self.stat_connections_label = self.create_stat_card("Approx. Events", "0", COLORS["accent"])
        self.stat_blocked, self.stat_blocked_label = self.create_stat_card("Deny Events", "0", COLORS["danger"])
        self.stat_rules, self.stat_rules_label = self.create_stat_card("Active Rules", "0", COLORS["warning"])

        stats_layout.addWidget(self.stat_connections)
        stats_layout.addWidget(self.stat_blocked)
        stats_layout.addWidget(self.stat_rules)

        layout.addLayout(stats_layout)
        layout.addStretch()
        return page

    def create_stat_card(self, title, value, accent_color):
        card = QFrame(objectName="card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 20, 20, 20)
        lbl_title = QLabel(title)
        lbl_title.setObjectName("muted")
        lbl_val = QLabel(value)
        lbl_val.setStyleSheet(f"font-size: 32px; font-weight: bold; color: {accent_color};")
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        return card, lbl_val

    def create_rules_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        layout.addWidget(QLabel("Firewall Rules", objectName="page_title"))

        self.table_rules = QTableWidget()
        self.table_rules.setColumnCount(4)
        self.table_rules.setHorizontalHeaderLabels(["Application", "Path", "Destination", "Action"])
        self.table_rules.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_rules.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_rules.verticalHeader().setVisible(False)
        self.table_rules.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_rules.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table_rules)

        btn_box = QHBoxLayout()
        btn_box.addStretch()

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setObjectName("action_btn")
        btn_refresh.setStyleSheet(f"background-color: {COLORS['sidebar']}; color: {COLORS['text_primary']};")
        btn_refresh.clicked.connect(self.load_data)
        btn_refresh.clicked.connect(self.refresh_rules_table)
        btn_box.addWidget(btn_refresh)

        btn_delete = QPushButton("Delete Selected")
        btn_delete.setObjectName("danger_btn")
        btn_delete.clicked.connect(self.delete_selected_rule)
        btn_box.addWidget(btn_delete)

        layout.addLayout(btn_box)
        return page

    def create_logs_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Connection Logs (Last 50 Lines)", objectName="page_title"))

        self.table_logs = QTableWidget()
        self.table_logs.setColumnCount(1)
        self.table_logs.horizontalHeader().setVisible(False)
        self.table_logs.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table_logs.verticalHeader().setVisible(False)

        # Enable selection and copy
        self.table_logs.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table_logs.setTextElideMode(Qt.TextElideMode.ElideNone)

        # Monospace font for logs
        font = QFont("Monospace")
        font.setStyleHint(QFont.StyleHint.TypeWriter)
        self.table_logs.setFont(font)

        layout.addWidget(self.table_logs)

        btn_box = QHBoxLayout()
        btn_refresh = QPushButton("Refresh Logs")
        btn_refresh.setObjectName("action_btn")
        btn_refresh.clicked.connect(self.refresh_logs)
        btn_box.addWidget(btn_refresh)
        btn_box.addStretch()

        layout.addLayout(btn_box)
        return page

    def create_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        layout.addWidget(QLabel("Settings", objectName="page_title"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        # Transparent background for scroll area
        scroll.setStyleSheet("background-color: transparent; border: none;")

        scroll_content = QWidget()
        scroll_content.setStyleSheet(f"background-color: {COLORS['background']};")
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 0, 0)

        # 1. Operational Mode
        card_mode = QFrame(objectName="card")
        cl_mode = QVBoxLayout(card_mode)
        cl_mode.setContentsMargins(30, 30, 30, 30)

        cl_mode.addWidget(QLabel("Operational Mode", objectName="h2"))

        self.chk_learning = QCheckBox("Learning Mode")
        # Set initial state during creation if config loaded
        is_learning = self.data_config.get('mode', 'learning') == 'learning'
        self.chk_learning.setChecked(is_learning)

        self.chk_learning.setToolTip("In Learning Mode, unknown connections are allowed if the GUI times out.\nIn Enforcement Mode, they are blocked.")
        cl_mode.addWidget(self.chk_learning)

        lbl_hint = QLabel("• <b>Learning Mode</b>: Popups appear for new connections. Default action is <b>ALLOW</b>.<br>"
                         "• <b>Enforcement Mode</b>: Popups appear for new connections. Default action is <b>DENY</b>.")
        lbl_hint.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px; margin-top: 5px;")
        cl_mode.addWidget(lbl_hint)

        self.btn_save_config = QPushButton("Save Configuration")
        self.btn_save_config.setObjectName("action_btn")
        self.btn_save_config.setFixedWidth(200)
        self.btn_save_config.clicked.connect(self.save_config)
        cl_mode.addWidget(self.btn_save_config)

        scroll_layout.addWidget(card_mode)
        scroll_layout.addSpacing(20)

        # 2. Startup Settings
        card_boot = QFrame(objectName="card")
        cl_boot = QVBoxLayout(card_boot)
        cl_boot.setContentsMargins(30, 30, 30, 30)

        cl_boot.addWidget(QLabel("Startup Behavior", objectName="h2"))

        self.chk_autostart = QCheckBox("Run Bastion Firewall on System Startup")
        self.chk_autostart.setToolTip("Automatically start protection when the computer turns on.")
        self.chk_autostart.clicked.connect(self.toggle_autostart)
        cl_boot.addWidget(self.chk_autostart)

        scroll_layout.addWidget(card_boot)
        scroll_layout.addSpacing(20)

        # 3. Inbound Firewall (UFW)
        card_ufw = QFrame(objectName="card")
        cl_ufw = QVBoxLayout(card_ufw)
        cl_ufw.setContentsMargins(30, 30, 30, 30)

        cl_ufw.addWidget(QLabel("Inbound Firewall (UFW)", objectName="h2"))

        self.lbl_ufw_status = QLabel("Checking...")
        self.lbl_ufw_status.setStyleSheet("font-size: 16px; margin-bottom: 10px;")
        cl_ufw.addWidget(self.lbl_ufw_status)

        ufw_btns = QHBoxLayout()
        self.btn_ufw_enable = QPushButton("Enable / Install UFW")
        self.btn_ufw_enable.setObjectName("action_btn")
        self.btn_ufw_enable.clicked.connect(self.enable_ufw)

        self.btn_ufw_disable = QPushButton("Disable UFW")
        self.btn_ufw_disable.setObjectName("danger_btn")
        self.btn_ufw_disable.clicked.connect(self.disable_ufw)

        ufw_btns.addWidget(self.btn_ufw_enable)
        ufw_btns.addWidget(self.btn_ufw_disable)
        ufw_btns.addStretch()
        cl_ufw.addLayout(ufw_btns)

        scroll_layout.addWidget(card_ufw)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return page

    # --- LOGIC ---

    def refresh_ui(self):
        self.refresh_status()
        self.refresh_rules_table()
        self.refresh_logs()

    def refresh_status(self):
        # 1. Outbound (Bastion)
        try:
            # Check Active
            res = subprocess.run(['systemctl', 'is-active', 'bastion-firewall'],
                               capture_output=True, text=True)
            is_active = res.stdout.strip() == 'active'

            # Check Enabled (Boot)
            res_en = subprocess.run(['systemctl', 'is-enabled', 'bastion-firewall'],
                                   capture_output=True, text=True)
            is_enabled = res_en.stdout.strip() == 'enabled'

            # Update Settings Checkbox
            if hasattr(self, 'chk_autostart'):
                self.chk_autostart.blockSignals(True)
                self.chk_autostart.setChecked(is_enabled)
                self.chk_autostart.blockSignals(False)

            if is_active:
                self.lbl_status_title.setText("Protected")
                self.lbl_status_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['success']}; margin-top: 8px;")

                desc = "Blocking unauthorized outbound connections"
                if is_enabled:
                    desc += " • Autostart ON"
                else:
                    desc += " • Autostart OFF"
                self.lbl_status_desc.setText(desc)

                self.btn_toggle.setText("Stop")
                self.btn_toggle.setStyleSheet(f"background-color: {COLORS['danger']}; color: white; border: none; padding: 6px 12px; border-radius: 4px;")
            else:
                self.lbl_status_title.setText("Stopped")
                self.lbl_status_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['danger']}; margin-top: 8px;")
                self.lbl_status_desc.setText("Outbound traffic is not monitored")
                self.btn_toggle.setText("Start")
                self.btn_toggle.setStyleSheet(f"background-color: {COLORS['success']}; color: white; border: none; padding: 6px 12px; border-radius: 4px;")
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            logger.error(f"Failed to check bastion firewall status: {e}")
            self.lbl_status_title.setText("Error")

        # 2. Inbound (UFW)
        try:
            self.inbound_status = InboundFirewallDetector.detect_firewall()
            if self.inbound_status.get('status') == 'active':
                self.lbl_inbound_title.setText("Protected")
                self.lbl_inbound_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['success']}; margin-top: 8px;")
                fw_name = self.inbound_status.get('firewall', 'UFW')
                self.lbl_inbound_desc.setText(f"Blocking unauthorized inbound • {fw_name}")
                self.lbl_ufw_status.setText(f"Status: <b>Active</b> using {fw_name}")
                self.btn_ufw_enable.setVisible(False)
                self.btn_ufw_disable.setVisible(True)
            else:
                self.lbl_inbound_title.setText("Exposed")
                self.lbl_inbound_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['warning']}; margin-top: 8px;")
                self.lbl_inbound_desc.setText("Inbound traffic is not filtered")
                self.lbl_ufw_status.setText("Status: <b>Inactive</b>. Enable UFW to block inbound threats.")
                self.btn_ufw_enable.setVisible(True)
                self.btn_ufw_disable.setVisible(False)
        except (subprocess.SubprocessError, OSError) as e:
            logger.error(f"Failed to check UFW status: {e}")
            self.lbl_inbound_title.setText("Unknown")

        # 3. Update Stats (Approximate from rules and logs)
        self.stat_rules_label.setText(str(len(self.data_rules)))

        try:
            if self.log_path.exists():
                if os.access(self.log_path, os.R_OK):
                    # We can read it directly
                    # SECURITY FIX: Use list arguments instead of shell=True to prevent command injection
                    res = subprocess.run(['wc', '-l', str(self.log_path)], capture_output=True, text=True)
                    total = res.stdout.strip().split()[0] if res.returncode == 0 else "0"
                    self.stat_connections_label.setText(total)

                    res = subprocess.run(['grep', '-c', 'decision: deny', str(self.log_path)],
                                       capture_output=True, text=True)
                    denied = res.stdout.strip() if res.returncode == 0 else "0"
                    self.stat_blocked_label.setText(denied)
                else:
                    # Need elevated privileges
                    cmd = ['pkexec', 'sh', '-c', f'wc -l "{self.log_path}" | cut -d" " -f1']
                    res = subprocess.run(cmd, capture_output=True, text=True)
                    total = res.stdout.strip() if res.returncode == 0 else "0"
                    self.stat_connections_label.setText(total)

                    cmd = ['pkexec', 'sh', '-c', f'grep -c "decision: deny" "{self.log_path}"']
                    res = subprocess.run(cmd, capture_output=True, text=True)
                    denied = res.stdout.strip() if res.returncode == 0 else "0"
                    self.stat_blocked_label.setText(denied)
        except Exception as e:
            # Log the error but don't crash the GUI
            logger.error(f"Error updating statistics: {e}")

    def toggle_autostart(self):
        should_enable = self.chk_autostart.isChecked()
        action = "enable" if should_enable else "disable"

        # SECURITY: Validate action parameter to prevent command injection
        ALLOWED_ACTIONS = ['enable', 'disable', 'start', 'stop', 'restart']
        if action not in ALLOWED_ACTIONS:
            logger.error(f"Invalid systemctl action: {action}")
            QMessageBox.critical(self, "Security Error", f"Invalid action: {action}")
            return

        cmd = ['pkexec', 'systemctl', action, 'bastion-firewall']
        ok = self._run_privileged(cmd, success_message=None, error_hint=f"Failed to {action} autostart. Please check system logs.")
        if ok:
            # 2. User GUI (Tray) - Manage ~/.config/autostart
            self._manage_gui_autostart(should_enable)
            self.refresh_status() # Updates text
        else:
            # Revert checkbox state
            self.chk_autostart.blockSignals(True)
            self.chk_autostart.setChecked(not should_enable)
            self.chk_autostart.blockSignals(False)

    def _manage_gui_autostart(self, enable: bool):
        try:
            autostart_dir = Path.home() / ".config/autostart"
            autostart_dir.mkdir(parents=True, exist_ok=True)
            desktop_file = autostart_dir / "bastion-tray.desktop"

            if enable:
                content = """[Desktop Entry]
Type=Application
Name=Bastion Firewall Tray Icon
Comment=System tray icon for Bastion Firewall
Exec=/usr/bin/bastion-gui
Icon=security-high
Terminal=false
Categories=System;Security;Network;
Hidden=false
X-GNOME-Autostart-enabled=true
"""
                with open(desktop_file, "w") as f:
                    f.write(content)

                # Make executable just in case
                desktop_file.chmod(0o755)
            else:
                if desktop_file.exists():
                    desktop_file.unlink()
        except Exception as e:
            print(f"Failed to manage GUI autostart: {e}")

    def enable_ufw(self):
        # Modern notification for start
        show_notification(self, "Info", "Setup process will start.\n\nYou may be asked for your password to install/configure UFW.")

        # Use a small delay to allow dialog to close/paint
        QApplication.processEvents()

        success, msg = InboundFirewallDetector.setup_inbound_protection()
        if success:
            show_notification(self, "Success", msg)
        else:
            show_notification(self, "Action Failed", msg)
        self.refresh_ui()

    def disable_ufw(self):
        if QMessageBox.question(self, "Confirm", "Disable Inbound Protection (UFW)?\nYour computer will be exposed to inbound connections.") != QMessageBox.StandardButton.Yes:
            return

        if self._run_privileged(['pkexec', 'ufw', 'disable'], success_message="UFW disabled.", error_hint="Failed to disable UFW."):
            pass
        self.refresh_ui()

    def refresh_rules_table(self):
        self.table_rules.setRowCount(0)

        # self.data_rules is dict: "app_path:port": allow_bool
        for key, allow in self.data_rules.items():
            row = self.table_rules.rowCount()
            self.table_rules.insertRow(row)

            # Parse key (format: /path/to/app:port)
            try:
                parts = key.rsplit(':', 1)
                path = parts[0]
                port = parts[1]
                app_name = os.path.basename(path)
            except (ValueError, IndexError) as e:
                logger.debug(f"Failed to parse rule key {key}: {e}")
                path = key
                port = "?"
                app_name = key

            action = "ALLOW" if allow else "DENY"

            self.table_rules.setItem(row, 0, QTableWidgetItem(app_name))
            self.table_rules.setItem(row, 1, QTableWidgetItem(path))
            self.table_rules.setItem(row, 2, QTableWidgetItem(port))

            item_act = QTableWidgetItem(action)
            item_act.setForeground(QColor(COLORS['success'] if allow else COLORS['danger']))
            item_act.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self.table_rules.setItem(row, 3, item_act)

            # Store key in user data for deletion using setData(Qt.UserRole, ...) on first item
            self.table_rules.item(row, 0).setData(Qt.ItemDataRole.UserRole, key)

    def refresh_logs(self):
        def load_logs():
            try:
                # Check if we can read the log file directly
                if os.access(self.log_path, os.R_OK):
                    # We can read it directly
                    cmd = ['tail', '-n', '50', str(self.log_path)]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    lines = res.stdout.strip().split('\n') if res.stdout else []
                    logger.info(f"Successfully read {len(lines)} log lines directly")
                else:
                    # Need elevated privileges to read the log
                    # Use pkexec with a shell command to properly handle the path
                    cmd = ['pkexec', 'sh', '-c', f'tail -n 50 "{self.log_path}"']
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    lines = res.stdout.strip().split('\n') if res.stdout else []
                    logger.info(f"Successfully read {len(lines)} log lines with pkexec")
            except Exception as e:
                lines = [f"Error reading logs: {e}"]
                logger.error(f"Failed to read logs: {e}")

            # Use QTimer.singleShot to ensure _populate_logs runs in main thread
            QTimer.singleShot(0, lambda: self._populate_logs(lines))

        logger.info(f"Starting log refresh thread")
        threading.Thread(target=load_logs, daemon=True).start()

    def _populate_logs(self, lines):
        logger.info(f"Populating logs table with {len(lines)} lines")
        self.table_logs.setRowCount(0)
        for line in reversed(lines):  # Newest first
            if not line.strip():
                continue
            row = self.table_logs.rowCount()
            self.table_logs.insertRow(row)
            item = QTableWidgetItem(line)
            item.setForeground(QColor(COLORS['text_primary']))
            self.table_logs.setItem(row, 0, item)

        if self.table_logs.rowCount() == 0:
            logger.warning("No log entries to display")
            self.table_logs.insertRow(0)
            item = QTableWidgetItem("No log entries available.")
            item.setForeground(QColor(COLORS['text_secondary']))
            self.table_logs.setItem(0, 0, item)
        else:
            logger.info(f"Successfully populated {self.table_logs.rowCount()} log entries")
        # Force UI update
        self.table_logs.viewport().update()
        self.table_logs.update()

    def toggle_firewall(self):
        is_active = "Stop" in self.btn_toggle.text()

        # Use enable --now / disable --now for persistence across reboots
        if is_active:
            cmd = ['pkexec', 'systemctl', 'disable', '--now', 'bastion-firewall']
        else:
            cmd = ['pkexec', 'systemctl', 'enable', '--now', 'bastion-firewall']

        state = "stopped" if is_active else "started"
        if self._run_privileged(cmd, success_message=f"Firewall {state} successfully.", error_hint="Unable to change firewall state. Check system logs."):
            self.refresh_status()

    def delete_selected_rule(self):
        rows = self.table_rules.selectionModel().selectedRows()
        if not rows:
            QMessageBox.warning(self, "Select Rule", "Please select a rule to delete.")
            return

        if QMessageBox.question(self, "Confirm", "Delete selected rules?") != QMessageBox.StandardButton.Yes:
            return

        keys_to_delete = []
        for index in rows:
            # Get key from UserRole
            item = self.table_rules.item(index.row(), 0)
            key = item.data(Qt.ItemDataRole.UserRole)
            keys_to_delete.append(key)

        for k in keys_to_delete:
            if k in self.data_rules:
                del self.data_rules[k]

        self.save_rules_to_disk()
        self.refresh_rules_table()

    def save_rules_to_disk(self):
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                json.dump(self.data_rules, tmp, indent=2)
                tmp_path = tmp.name

            # Use single helper script to move, chmod, and signal daemon (only 1 password prompt)
            if not self._run_privileged(['pkexec', '/usr/bin/bastion-reload-rules', tmp_path, str(self.rules_path)],
                                        error_hint="Failed to save rules."):
                return
        except Exception as e:
            show_notification(self, "Error", f"Failed to save rules: {e}")

    def save_config(self):
        self.data_config['mode'] = 'learning' if self.chk_learning.isChecked() else 'enforcement'
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                json.dump(self.data_config, tmp, indent=2)
                tmp_path = tmp.name

            # Use single helper script to move, chmod, and signal daemon (only 1 password prompt)
            if not self._run_privileged(['pkexec', '/usr/bin/bastion-reload-config', tmp_path, str(self.config_path)],
                                        error_hint="Failed to save configuration."):
                return

            show_notification(self, "Success", "Configuration saved.")
        except Exception as e:
            show_notification(self, "Error", f"Failed to save config: {e}")

    def _run_privileged(self, cmd, success_message=None, error_hint="Operation failed. Check system logs."):
        """Run privileged commands with sanitized user feedback."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.SubprocessError as e:
            logger.error(f"Privileged command error: {cmd}: {e}")
            show_notification(self, "Error", error_hint or "Operation failed.")
            return False

        if result.returncode != 0:
            stderr_line = (result.stderr or "").strip().splitlines()
            sanitized = stderr_line[0][:200] if stderr_line else ""
            logger.error(f"Privileged command failed: {cmd} rc={result.returncode} stderr={sanitized}")
            if error_hint:
                show_notification(self, "Error", error_hint)
            return False

        if success_message:
            show_notification(self, "Success", success_message)
        return True


def run_dashboard():
    """Entry point for running the dashboard window."""
    app = QApplication(sys.argv)
    w = DashboardWindow()
    w.show()
    sys.exit(app.exec())

