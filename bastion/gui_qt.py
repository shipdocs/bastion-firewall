#!/usr/bin/env python3
"""
Bastion Firewall - Qt GUI
Modern interface using PyQt6.
Handles both the Decision Dialog (Popup) and the Control Panel (Dashboard).
"""

import sys
import os
import json
import socket
import logging
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QPushButton, QFrame, QStackedWidget,
                            QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
                            QSystemTrayIcon, QMenu, QMessageBox, QDialog, QCheckBox, 
                            QScrollArea, QAbstractItemView)
from .notification import show_notification
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QSize, QPoint
from PyQt6.QtGui import QIcon, QFont, QColor, QAction, QPixmap

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Modern Dark Theme Palette
COLORS = {
    "background": "#1e2227",      # Main window background
    "sidebar": "#282c34",         # Sidebar background
    "card": "#21252b",            # Card/Panel background
    "card_border": "#3e4451",     # Card border
    "text_primary": "#abb2bf",    # Main text
    "text_secondary": "#5c6370",  # Subtitles/muted text
    "accent": "#61afef",          # Blue accent
    "accent_hover": "#528bff",    # Blue hover
    "danger": "#e06c75",          # Red
    "success": "#98c379",         # Green
    "warning": "#e5c07b",         # Orange/Yellow
    "header": "#ffffff"           # Bright white header
}

STYLESHEET = f"""
QMainWindow {{
    background-color: {COLORS["background"]};
}}
QWidget {{
    font-family: 'Segoe UI', 'Ubuntu', 'Roboto', sans-serif;
    color: {COLORS["text_primary"]};
    font-size: 14px;
}}
/* Sidebar */
QFrame#sidebar {{
    background-color: {COLORS["sidebar"]};
    border-right: 1px solid #181a1f;
}}
QPushButton#nav_btn {{
    border: none;
    text-align: left;
    padding: 15px 25px;
    font-size: 15px;
    color: {COLORS["text_secondary"]};
    background: transparent;
    border-left: 3px solid transparent;
}}
QPushButton#nav_btn:hover {{
    color: {COLORS["text_primary"]};
    background-color: {COLORS["background"]};
}}
QPushButton#nav_btn:checked {{
    color: {COLORS["accent"]};
    background-color: {COLORS["background"]};
    border-left: 3px solid {COLORS["accent"]};
    font-weight: bold;
}}
/* Content Cards */
QFrame#card {{
    background-color: {COLORS["card"]};
    border: 1px solid {COLORS["card_border"]};
    border-radius: 8px;
}}
QLabel#page_title {{
    font-size: 28px;
    font-weight: 600;
    color: {COLORS["header"]};
    margin-bottom: 20px;
}}
QLabel#h2 {{
    font-size: 18px;
    font-weight: 600;
    color: {COLORS["header"]};
}}
QLabel#muted {{
    color: {COLORS["text_secondary"]};
}}
/* Buttons */
QPushButton#action_btn {{
    background-color: {COLORS["accent"]};
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: 600;
}}
QPushButton#action_btn:hover {{
    background-color: {COLORS["accent_hover"]};
}}
QPushButton#danger_btn {{
    background-color: {COLORS["card"]};
    color: {COLORS["danger"]};
    border: 1px solid {COLORS["danger"]};
    padding: 6px 12px;
    border-radius: 4px;
}}
QPushButton#danger_btn:hover {{
    background-color: {COLORS["danger"]};
    color: white;
}}
/* Table */
QTableWidget {{
    background-color: {COLORS["card"]};
    border: 1px solid {COLORS["card_border"]};
    gridline-color: {COLORS["card_border"]};
    border-radius: 6px;
}}
QHeaderView::section {{
    background-color: {COLORS["sidebar"]};
    padding: 8px;
    border: none;
    border-bottom: 1px solid {COLORS["card_border"]};
    font-weight: bold;
    color: {COLORS["text_primary"]};
}}
QTableWidget::item {{
    padding: 5px;
    border-bottom: 1px solid {COLORS["sidebar"]};
}}
QTableWidget::item:selected {{
    background-color: {COLORS["sidebar"]};
    color: {COLORS["accent"]};
}}
QScrollBar:vertical {{
    border: none;
    background: {COLORS["background"]};
    width: 10px;
    margin: 0px 0px 0px 0px;
}}
QScrollBar::handle:vertical {{
    background: {COLORS["card_border"]};
    min-height: 20px;
    border-radius: 5px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QCheckBox {{
    spacing: 10px;
    font-size: 15px;
}}
QCheckBox::indicator {{
    width: 20px;
    height: 20px;
    border-radius: 4px;
    border: 2px solid {COLORS["text_secondary"]};
    background: transparent;
}}
QCheckBox::indicator:checked {{
    background-color: {COLORS["accent"]};
    border-color: {COLORS["accent"]};
}}
"""

class FirewallDialog(QDialog):
    """
    Decision dialog for new connections.
    Always stays on top and grabs focus.
    """
    
    def __init__(self, conn_info, timeout=30, learning_mode=False):
        super().__init__()
        self.conn_info = conn_info
        self.timeout = timeout
        self.learning_mode = learning_mode
        self.decision = "deny"  # Default
        self.permanent = False
        self.time_remaining = timeout
        
        self.init_ui()
        self.start_timer()
        
    def init_ui(self):
        self.setWindowTitle("Bastion Firewall - Connection Request")
        self.setFixedSize(500, 450)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS["background"]};
                border: 1px solid {COLORS["accent"]};
            }}
            QLabel {{
                color: {COLORS["text_primary"]};
            }}
            QFrame#info_box {{
                background-color: {COLORS["card"]};
                border-radius: 6px;
                border: 1px solid {COLORS["card_border"]};
            }}
        """)
        
        self.setWindowFlags(
            Qt.WindowType.WindowStaysOnTopHint | 
            Qt.WindowType.FramelessWindowHint | 
            Qt.WindowType.Dialog
        )
        
        layout = QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        self.setLayout(layout)
        
        # Header
        header_layout = QHBoxLayout()
        icon = QLabel("🛡️")
        icon.setStyleSheet("font-size: 32px;")
        header_layout.addWidget(icon)
        
        title_text = "Connection Request"
        if self.learning_mode:
            title_text = "Learning Mode (Auto-Allow)"
        
        title = QLabel(title_text)
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['header']};")
        header_layout.addWidget(title)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Info Box
        info_frame = QFrame()
        info_frame.setObjectName("info_box")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(15, 15, 15, 15)
        info_layout.setSpacing(8)
        
        app_name = self.conn_info.get('app_name', 'Unknown Application')
        lbl_app = QLabel(app_name)
        lbl_app.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['accent']};")
        info_layout.addWidget(lbl_app)
        
        details_layout = QVBoxLayout()
        self.add_detail_row(details_layout, "Path", self.conn_info.get('app_path', 'Unknown'))
        self.add_detail_row(details_layout, "Destination", f"{self.conn_info.get('dest_ip')} : {self.conn_info.get('dest_port')}")
        self.add_detail_row(details_layout, "Protocol", self.conn_info.get('protocol', 'TCP'))
        info_layout.addLayout(details_layout)
        layout.addWidget(info_frame)
        
        # Buttons
        btn_grid = QVBoxLayout()
        btn_grid.setSpacing(10)
        
        row_allow = QHBoxLayout()
        btn_allow_once = self.create_button("Allow Once", COLORS['success'], outline=True)
        btn_allow_once.clicked.connect(self.allow_once)
        btn_allow_always = self.create_button("Allow Always", COLORS['success'])
        btn_allow_always.clicked.connect(self.allow_always)
        row_allow.addWidget(btn_allow_once)
        row_allow.addWidget(btn_allow_always)
        btn_grid.addLayout(row_allow)
        
        row_deny = QHBoxLayout()
        btn_deny_once = self.create_button("Deny Once", COLORS['danger'], outline=True)
        btn_deny_once.clicked.connect(self.deny_once)
        btn_deny_always = self.create_button("Deny Always", COLORS['danger'])
        btn_deny_always.clicked.connect(self.deny_always)
        row_deny.addWidget(btn_deny_once)
        row_deny.addWidget(btn_deny_always)
        btn_grid.addLayout(row_deny)
        
        layout.addLayout(btn_grid)
        
        # Timer
        if self.timeout > 0:
            self.progress = QProgressBar()
            self.progress.setFixedHeight(4)
            self.progress.setTextVisible(False)
            self.progress.setStyleSheet(f"""
                QProgressBar {{
                    border: none;
                    background-color: {COLORS['sidebar']};
                    border-radius: 2px;
                }}
                QProgressBar::chunk {{
                    background-color: {COLORS['text_secondary']};
                    border-radius: 2px;
                }}
            """)
            self.progress.setRange(0, self.timeout * 10)
            self.progress.setValue(self.timeout * 10)
            layout.addWidget(self.progress)
            
    def add_detail_row(self, layout, label, value):
        row = QHBoxLayout()
        lbl = QLabel(label + ":")
        lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; min-width: 80px;")
        val = QLabel(str(value))
        val.setWordWrap(True)
        row.addWidget(lbl)
        row.addWidget(val)
        layout.addLayout(row)

    def create_button(self, text, color, outline=False):
        btn = QPushButton(text)
        if outline:
            style = f"""
                QPushButton {{
                    background-color: transparent;
                    border: 2px solid {color};
                    color: {color};
                    padding: 8px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: {color}22;
                }}
            """
        else:
            style = f"""
                QPushButton {{
                    background-color: {color};
                    border: none;
                    color: #1e2227;
                    padding: 10px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: {color}dd;
                }}
            """
        btn.setStyleSheet(style)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        return btn

    def start_timer(self):
        if self.timeout <= 0: return
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)
        self.timer.start(100)
        
    def update_timer(self):
        current = self.progress.value()
        if current <= 0:
            self.timer.stop()
            self.deny_once()
            return
        self.progress.setValue(current - 1)
        
    def allow_once(self): self.decision = "allow"; self.permanent = False; self.accept()
    def allow_always(self): self.decision = "allow"; self.permanent = True; self.accept()
    def deny_once(self): self.decision = "deny"; self.permanent = False; self.reject()
    def deny_always(self): self.decision = "deny"; self.permanent = True; self.reject()
        
    def keyPressEvent(self, event):
        if event.key() in [Qt.Key.Key_Return, Qt.Key.Key_Enter]: self.allow_once()
        elif event.key() == Qt.Key.Key_Escape: self.deny_once()
        elif event.key() == Qt.Key.Key_A: self.allow_always()
        elif event.key() == Qt.Key.Key_D: self.deny_always()
        else: super().keyPressEvent(event)


from .inbound_firewall import InboundFirewallDetector

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

    # ... (rest of init/load methods same as before) ...
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
        except:
            pass

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
        from .icon_manager import IconManager
        logo_pixmap = IconManager.get_icon().pixmap(28, 28)
        logo.setPixmap(logo_pixmap)
        title = QLabel("Bastion")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {COLORS['header']}; margin-left: 10px;")
        brand_layout.addWidget(logo)
        brand_layout.addWidget(title)
        brand_layout.addStretch()
        sb_layout.addLayout(brand_layout)
        
        # Navigation with custom icons
        self.nav_btns = []
        self.add_nav_btn(sb_layout, "Status", "📊")
        self.add_nav_btn(sb_layout, "Rules", "📋")
        self.add_nav_btn(sb_layout, "USB", "🔌")
        self.add_nav_btn(sb_layout, "Logs", "📝")
        self.add_nav_btn(sb_layout, "Settings", "⚙️")

        sb_layout.addStretch()

        ver = QLabel("v1.5.0-dev")
        ver.setObjectName("muted")
        ver.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sb_layout.addWidget(ver)

        main_layout.addWidget(sidebar)

        # Content Stack
        self.stack = QStackedWidget()
        self.stack.setContentsMargins(30, 30, 30, 30)

        self.page_status = self.create_status_page()
        self.page_rules = self.create_rules_page()
        self.page_usb = self.create_usb_page()
        self.page_logs = self.create_logs_page()
        self.page_settings = self.create_settings_page()

        self.stack.addWidget(self.page_status)
        self.stack.addWidget(self.page_rules)
        self.stack.addWidget(self.page_usb)
        self.stack.addWidget(self.page_logs)
        self.stack.addWidget(self.page_settings)

        main_layout.addWidget(self.stack)
        self.nav_btns[0].setChecked(True)

    def add_nav_btn(self, layout, text, fallback_emoji):
        """Add navigation button with custom icon or emoji fallback."""
        from .icon_manager import IconManager

        btn = QPushButton()
        btn.setObjectName("nav_btn")
        btn.setCheckable(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)

        # Try to get custom nav icon
        icon = IconManager.get_nav_icon(text)
        if not icon.isNull():
            btn.setIcon(icon)
            btn.setIconSize(QSize(20, 20))
            btn.setText(f"  {text}")
        else:
            # Fallback to emoji
            btn.setText(f"  {fallback_emoji}   {text}")

        btn.clicked.connect(lambda: self.navigate(btn, text))
        layout.addWidget(btn)
        self.nav_btns.append(btn)

    def navigate(self, sender, page_name):
        for btn in self.nav_btns:
            btn.setChecked(False)
        sender.setChecked(True)
        if page_name == "Status": self.stack.setCurrentWidget(self.page_status); self.refresh_status()
        elif page_name == "Rules": self.stack.setCurrentWidget(self.page_rules); self.refresh_rules_table()
        elif page_name == "USB": self.stack.setCurrentWidget(self.page_usb); self.refresh_usb()
        elif page_name == "Logs": self.stack.setCurrentWidget(self.page_logs); self.refresh_logs()
        elif page_name == "Settings": self.stack.setCurrentWidget(self.page_settings)

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
        from .icon_manager import IconManager
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

        # 3. USB Device Control Card
        card_usb = QFrame(objectName="card")
        card_usb_layout = QVBoxLayout(card_usb)
        card_usb_layout.setContentsMargins(20, 20, 20, 20)

        # Card title
        card_usb_title_layout = QHBoxLayout()
        icon_usb = QLabel()
        usb_icon = IconManager.get_nav_icon('USB')
        if not usb_icon.isNull():
            icon_usb.setPixmap(usb_icon.pixmap(24, 24))
        else:
            icon_usb.setText("🔌")
        card_usb_title_layout.addWidget(icon_usb)
        lbl_usb_title = QLabel("USB Control")
        lbl_usb_title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['header']};")
        card_usb_title_layout.addWidget(lbl_usb_title)
        card_usb_title_layout.addStretch()
        card_usb_layout.addLayout(card_usb_title_layout)

        # Status - dynamic
        self.lbl_usb_title = QLabel("Checking...")
        self.lbl_usb_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['text_primary']}; margin-top: 8px;")
        card_usb_layout.addWidget(self.lbl_usb_title)

        self.lbl_usb_desc = QLabel("USB Device Control")
        self.lbl_usb_desc.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-bottom: 10px;")
        card_usb_layout.addWidget(self.lbl_usb_desc)

        self.btn_usb = QPushButton("Manage")
        self.btn_usb.setObjectName("action_btn")
        self.btn_usb.clicked.connect(lambda: self.navigate(self.nav_btns[2], "USB"))
        card_usb_layout.addWidget(self.btn_usb)

        status_cards.addWidget(card_usb)

        layout.addLayout(status_cards)
        
        # Stats
        layout.addSpacing(30)
        layout.addWidget(QLabel("Statistics (Live)", objectName="h2"))
        layout.addSpacing(15)
        
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(20)
        
        self.stat_connections = self.create_stat_card("Approx. Events", "0", COLORS["accent"])
        self.stat_blocked = self.create_stat_card("Deny Events", "0", COLORS["danger"])
        self.stat_rules = self.create_stat_card("Active Rules", "0", COLORS["warning"])
        
        stats_layout.addWidget(self.stat_connections)
        stats_layout.addWidget(self.stat_blocked)
        stats_layout.addWidget(self.stat_rules)
        
        layout.addLayout(stats_layout)
        layout.addStretch()
        return page

    # ... (create_stat_card, create_rules_page, create_logs_page remain same) ...

    def create_stat_card(self, title, value, accent_color):
        card = QFrame(objectName="card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(20, 20, 20, 20)
        lbl_title = QLabel(title); lbl_title.setObjectName("muted")
        lbl_val = QLabel(value); lbl_val.setStyleSheet(f"font-size: 32px; font-weight: bold; color: {accent_color};")
        layout.addWidget(lbl_title); layout.addWidget(lbl_val)
        return card

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

    def create_usb_page(self):
        """Create the USB Device Control page."""
        from .usb_gui import USBControlWidget
        self.usb_widget = USBControlWidget()
        return self.usb_widget

    def refresh_usb(self):
        """Refresh the USB device lists."""
        if hasattr(self, 'usb_widget'):
            self.usb_widget.refresh()

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

        # 2. Inbound Firewall (UFW)
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
        scroll_layout.addSpacing(20)

        # 3. Tray Icon Management
        card_tray = QFrame(objectName="card")
        cl_tray = QVBoxLayout(card_tray)
        cl_tray.setContentsMargins(30, 30, 30, 30)

        cl_tray.addWidget(QLabel("Tray Icon", objectName="h2"))

        lbl_tray_info = QLabel("The system tray icon provides quick access to firewall controls.")
        lbl_tray_info.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 13px; margin-bottom: 10px;")
        cl_tray.addWidget(lbl_tray_info)

        self.btn_start_tray = QPushButton("Start Tray Icon")
        self.btn_start_tray.setObjectName("action_btn")
        self.btn_start_tray.setFixedWidth(200)
        self.btn_start_tray.clicked.connect(self.start_tray_icon)
        cl_tray.addWidget(self.btn_start_tray)

        scroll_layout.addWidget(card_tray)

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
        except:
            self.lbl_status_title.setText("Error")

        # 2. Inbound (UFW)
        # Use cached status if possible or update occasionally? 
        # For now, quick check
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
        except:
            self.lbl_inbound_title.setText("Unknown")

        # 3. USB Device Control Status
        try:
            # Check if USB protection is enabled (authorized_default=0)
            usb_protected = False
            usb_controllers = 0
            for path in Path('/sys/bus/usb/devices').glob('usb*/authorized_default'):
                usb_controllers += 1
                try:
                    val = path.read_text().strip()
                    if val == '0':
                        usb_protected = True
                except:
                    pass

            # Get rule counts
            from .usb_rules import USBRuleManager
            usb_mgr = USBRuleManager()
            allowed = len(usb_mgr.get_allowed_devices())
            blocked = len(usb_mgr.get_blocked_devices())

            if usb_protected and usb_controllers > 0:
                self.lbl_usb_title.setText("Protected")
                self.lbl_usb_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['success']}; margin-top: 8px;")
                self.lbl_usb_desc.setText(f"{allowed} allowed, {blocked} blocked devices")
            else:
                self.lbl_usb_title.setText("Disabled")
                self.lbl_usb_title.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {COLORS['warning']}; margin-top: 8px;")
                self.lbl_usb_desc.setText("USB devices not monitored")
        except Exception as e:
            self.lbl_usb_title.setText("Unknown")
            self.lbl_usb_desc.setText("Could not check USB status")

        # 4. Update Stats (Approximate from rules and logs)
        self.stat_rules.findChild(QLabel, "").setText(str(len(self.data_rules)))
        
        try:
            if self.log_path.exists():
                # SECURITY FIX: Use list arguments instead of shell=True to prevent command injection
                res = subprocess.run(['wc', '-l', str(self.log_path)], capture_output=True, text=True)
                total = res.stdout.strip().split()[0] if res.returncode == 0 else "0"
                self.stat_connections.findChild(QLabel, "").setText(total)
                
                res = subprocess.run(['grep', '-c', 'decision: deny', str(self.log_path)], 
                                   capture_output=True, text=True)
                denied = res.stdout.strip() if res.returncode == 0 else "0"
                self.stat_blocked.findChild(QLabel, "").setText(denied)
        except Exception as e:
            # Log the error but don't crash the GUI
            import logging
            logging.getLogger(__name__).error(f"Error updating statistics: {e}")

    def toggle_autostart(self):
        should_enable = self.chk_autostart.isChecked()
        action = "enable" if should_enable else "disable"
        
        # SECURITY: Validate action parameter to prevent command injection
        ALLOWED_ACTIONS = ['enable', 'disable', 'start', 'stop', 'restart']
        if action not in ALLOWED_ACTIONS:
            logger.error(f"Invalid systemctl action: {action}")
            QMessageBox.critical(self, "Security Error", f"Invalid action: {action}")
            return
            
        try:
            # 1. System Service (Daemon)
            subprocess.run(['pkexec', 'systemctl', action, 'bastion-firewall'], check=True)
            
            # 2. User GUI (Tray) - Manage ~/.config/autostart
            self._manage_gui_autostart(should_enable)
            
            self.refresh_status() # Updates text
        except Exception as e:
            # Revert checkbox state
            self.chk_autostart.blockSignals(True)
            self.chk_autostart.setChecked(not should_enable)
            self.chk_autostart.blockSignals(False)
            # Modern error notification
            from .notification import show_notification
            show_notification(self, "Error", f"Failed to {action} autostart: {e}")

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
        from .notification import show_notification
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

        try:
            subprocess.run(['pkexec', 'ufw', 'disable'], check=True)
            from .notification import show_notification
            show_notification(self, "Success", "UFW disabled.")
        except Exception as e:
            from .notification import show_notification
            show_notification(self, "Error", f"Failed to disable UFW: {e}")
        self.refresh_ui()

    def start_tray_icon(self):
        """Start the system tray icon (bastion-gui)"""
        from .notification import show_notification

        try:
            # Try to start bastion-gui
            subprocess.Popen(
                ['/usr/bin/bastion-gui'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            show_notification(self, "Success", "Tray icon started. Look for it in your system tray.")
            logger.info("Tray icon started from control panel")
        except Exception as e:
            logger.error(f"Failed to start tray icon: {e}")
            show_notification(self, "Error", f"Failed to start tray icon: {e}")

    # ... (other methods remain) ...

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
            except:
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
        try:
            # Read last 50 lines
            cmd = ['tail', '-n', '50', str(self.log_path)]
            # If plain read fails, try pkexec (but pkexec for read is annoying in loop, assume readable or valid user group)
            # The daemon log should be readable by adm group or similar, but for now we try best effort
            if not os.access(self.log_path, os.R_OK):
                # Try pkexec only if we really can't read
                cmd = ['pkexec'] + cmd
                
            res = subprocess.run(cmd, capture_output=True, text=True)
            lines = res.stdout.strip().split('\n')
            
            self.table_logs.setRowCount(0)
            for line in reversed(lines): # Newest first
                if not line.strip(): continue
                row = self.table_logs.rowCount()
                self.table_logs.insertRow(row)
                self.table_logs.setItem(row, 0, QTableWidgetItem(line))
        except Exception as e:
            self.table_logs.setRowCount(1)
            self.table_logs.setItem(0, 0, QTableWidgetItem(f"Error reading logs: {e}"))

    def toggle_firewall(self):
        is_active = "Stop" in self.btn_toggle.text()
        
        # Use enable --now / disable --now for persistence across reboots
        if is_active:
            cmd = ['pkexec', 'systemctl', 'disable', '--now', 'bastion-firewall']
        else:
            cmd = ['pkexec', 'systemctl', 'enable', '--now', 'bastion-firewall']
            
        try:
            subprocess.run(cmd, check=True)
            state = "stopped" if is_active else "started"
            from .notification import show_notification
            show_notification(self, "Success", f"Firewall {state} successfully.")
        except Exception as e:
            from .notification import show_notification
            show_notification(self, "Error", f"Failed to toggle firewall: {e}")
        
        # Force immediate status refresh
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
            
            subprocess.run(['pkexec', 'mv', tmp_path, str(self.rules_path)], check=True)
            subprocess.run(['pkexec', 'chmod', '644', str(self.rules_path)])
            
            # signal daemon
            subprocess.run(['pkill', '-HUP', '-f', 'bastion-daemon'])
        except Exception as e:
            from .notification import show_notification
            show_notification(self, "Error", f"Failed to save rules: {e}")

    def save_config(self):
        self.data_config['mode'] = 'learning' if self.chk_learning.isChecked() else 'enforcement'
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
                json.dump(self.data_config, tmp, indent=2)
                tmp_path = tmp.name
                
            subprocess.run(['pkexec', 'mv', tmp_path, str(self.config_path)], check=True)
            subprocess.run(['pkexec', 'chmod', '644', str(self.config_path)])
            
            # signal daemon
            subprocess.run(['pkill', '-HUP', '-f', 'bastion-daemon'])
            from .notification import show_notification
            show_notification(self, "Success", "Configuration saved.")
        except Exception as e:
            from .notification import show_notification
            show_notification(self, "Error", f"Failed to save config: {e}")

def test_dialog():
    app = QApplication(sys.argv)
    conn = {'app_name': 'Firefox', 'app_path': '/usr/bin/firefox', 'dest_ip': '1.1.1.1', 'dest_port': 443, 'protocol': 'TCP'}
    d = FirewallDialog(conn, timeout=30)
    d.exec()
    sys.exit(0)

def run_dashboard():
    app = QApplication(sys.argv)
    w = DashboardWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--test-popup':
        test_dialog()
    else:
        run_dashboard()
