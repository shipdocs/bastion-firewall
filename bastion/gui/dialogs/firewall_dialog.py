#!/usr/bin/env python3
"""
Firewall Decision Dialog for Bastion Firewall.
Displays connection requests and allows user to allow/deny.
"""

import logging
import socket
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QFrame, QProgressBar, QCheckBox)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QGuiApplication

from ..platform import is_wayland
from ..theme import COLORS

logger = logging.getLogger(__name__)


class FirewallDialog(QDialog):
    """
    Decision dialog for new connections.
    Stays on top but doesn't steal focus or disappear on click-away.
    """

    def __init__(self, conn_info, timeout=60, learning_mode=False):
        super().__init__()
        self.conn_info = conn_info
        self.timeout = timeout
        self.learning_mode = learning_mode
        self.decision = "deny"  # Default
        self.permanent = False
        self.all_ports = False  # Wildcard port support (issue #13)
        self.time_remaining = timeout
        
        self.init_ui()
        self.start_timer()
        
    def init_ui(self):
        self.setWindowTitle("Bastion Firewall - Connection Request")
        self.setFixedSize(500, 650)  # Increased height for trust section
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

        # Platform-specific window flags to prevent focus stealing
        # On Wayland, WindowStaysOnTopHint is often ignored by compositors
        # We use different strategies based on the platform
        if is_wayland():
            # On Wayland: Use minimal flags
            # Many Wayland compositors (GNOME, KDE) ignore WindowStaysOnTopHint
            # We rely on WA_ShowWithoutActivating and compositor behavior
            logger.info("Using Wayland-compatible window flags")
            self.setWindowFlags(
                Qt.WindowType.Dialog |
                Qt.WindowType.FramelessWindowHint
            )
        else:
            # On X11: Use traditional flags that work reliably
            logger.info("Using X11 window flags")
            self.setWindowFlags(
                Qt.WindowType.WindowStaysOnTopHint |
                Qt.WindowType.FramelessWindowHint |
                Qt.WindowType.Tool  # Tool windows don't steal focus on X11
            )

        # Prevent focus stealing when window appears (works on both platforms)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)

        # Additional hint to stay above other windows without stealing focus
        self.setAttribute(Qt.WidgetAttribute.WA_X11DoNotAcceptFocus, True)

        # Position dialog in notification area (top-right corner)
        self.position_dialog()

        layout = QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        self.setLayout(layout)
        
        # Header
        header_layout = QHBoxLayout()
        icon = QLabel("Bastion")
        icon.setStyleSheet("font-size: 18px; font-weight: bold;")
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
        app_label = QLabel("Application:")
        app_label.setStyleSheet(f"font-size: 12px; color: {COLORS['text_secondary']};")
        info_layout.addWidget(app_label)

        lbl_app = QLabel(app_name)
        lbl_app.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['accent']}; margin-bottom: 8px;")
        info_layout.addWidget(lbl_app)

        details_layout = QVBoxLayout()
        app_path = self.conn_info.get('app_path', 'Unknown')
        self.add_detail_row(details_layout, "Path", app_path)
        
        # Enhanced Destination identification
        dest_ip = self.conn_info.get('dest_ip', '')
        dest_port = self.conn_info.get('dest_port', '')
        dest_display = f"{dest_ip}:{dest_port}"
        
        # 1. Try Reverse DNS (Fast, local cache usually)
        try:
            hostname = socket.gethostbyaddr(dest_ip)[0]
            dest_display = f"{hostname} ({dest_ip}):{dest_port}"
        except (socket.herror, socket.gaierror, OSError):
            # 2. Try Organization/ISP lookup (External, 1s timeout)
            try:
                import urllib.request
                import json
                # Fields: 16 (org), 512 (as) -> 528
                with urllib.request.urlopen(f"http://ip-api.com/json/{dest_ip}?fields=org,as", timeout=1.0) as response:
                    data = json.loads(response.read().decode())
                    org = data.get('org') or data.get('as', '').split(' ', 1)[-1]
                    if org:
                        dest_display = f"{org} - {dest_ip}:{dest_port}"
            except Exception as e:
                # Silently fall back to IP if lookup fails or times out
                logger.debug(f"IP info lookup failed for {dest_ip}: {e}")
                
        self.add_detail_row(details_layout, "Destination", dest_display)
        self.add_detail_row(details_layout, "Protocol", self.conn_info.get('protocol', 'TCP'))
        info_layout.addLayout(details_layout)

        # Show warning when path unavailable
        if not app_path or app_path in ('Unknown', 'unknown', ''):
            warning_label = QLabel("Warning: Path unavailable - rules will be based on application name only (less secure)")
            warning_label.setStyleSheet(f"font-size: 11px; color: {COLORS['warning']}; padding: 8px; background-color: rgba(229, 192, 123, 0.1); border-radius: 4px; margin-top: 8px;")
            warning_label.setWordWrap(True)
            info_layout.addWidget(warning_label)

        layout.addWidget(info_frame)

        # Trust Application Section (for Steam-like scenarios)
        trust_frame = QFrame()
        trust_frame.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(97, 175, 239, 0.1);
                border: 1px solid {COLORS['accent']};
                border-radius: 6px;
            }}
        """)
        trust_layout = QVBoxLayout(trust_frame)
        trust_layout.setContentsMargins(15, 12, 15, 12)
        trust_layout.setSpacing(8)

        trust_header = QLabel("Trust This Application")
        trust_header.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {COLORS['accent']};")
        trust_layout.addWidget(trust_header)

        trust_desc = QLabel(
            f"Allow <b>{app_name}</b> to connect to <b>any destination</b> on <b>any port</b>. "
            "No more popups for this application."
        )
        trust_desc.setWordWrap(True)
        trust_desc.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 12px;")
        trust_layout.addWidget(trust_desc)

        trust_warning = QLabel("Only use for applications you fully trust")
        trust_warning.setStyleSheet(f"color: {COLORS['warning']}; font-size: 11px; font-weight: bold;")
        trust_layout.addWidget(trust_warning)

        btn_trust = QPushButton("Trust & Allow All Connections")
        btn_trust.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['accent_hover']};
            }}
        """)
        btn_trust.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_trust.clicked.connect(self.trust_app)
        trust_layout.addWidget(btn_trust)

        layout.addWidget(trust_frame)
        layout.addSpacing(10)

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

        # "Apply to all ports" checkbox (issue #13)
        self.chk_all_ports = QCheckBox("Apply to all ports (less secure)")
        self.chk_all_ports.setToolTip(
            "When enabled, this rule will apply to ALL destination ports for this application, "
            f"not just port {self.conn_info.get('dest_port')}. Use for apps with dynamic ports (Zoom, games, etc)."
        )
        self.chk_all_ports.setStyleSheet(f"""
            QCheckBox {{
                color: {COLORS['text_secondary']};
                font-size: 12px;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
            }}
        """)
        layout.addWidget(self.chk_all_ports)

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

    def position_dialog(self):
        """Position dialog in notification area (top-right corner)"""
        try:
            # Get the primary screen
            screen = QGuiApplication.primaryScreen()
            if screen:
                screen_geometry = screen.availableGeometry()
                # Position in top-right corner with some margin
                x = screen_geometry.width() - self.width() - 20
                y = 20
                self.move(x, y)
                logger.debug(f"Positioned dialog at ({x}, {y})")
        except Exception as e:
            logger.warning(f"Failed to position dialog: {e}")

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

    def allow_once(self):
        self.decision = "allow"
        self.permanent = False
        self.all_ports = False
        self.accept()

    def allow_always(self):
        self.decision = "allow"
        self.permanent = True
        self.all_ports = self.chk_all_ports.isChecked()
        self.accept()

    def deny_once(self):
        self.decision = "deny"
        self.permanent = False
        self.all_ports = False
        self.reject()

    def deny_always(self):
        self.decision = "deny"
        self.permanent = True
        self.all_ports = self.chk_all_ports.isChecked()
        self.reject()

    def trust_app(self):
        """Trust this application completely - allow all destinations and ports"""
        self.decision = "allow"
        self.permanent = True
        self.all_ports = True  # Enable wildcard for all ports
        self.accept()

    def keyPressEvent(self, event):
        if event.key() in [Qt.Key.Key_Return, Qt.Key.Key_Enter]:
            self.allow_once()
        elif event.key() == Qt.Key.Key_Escape:
            self.deny_once()
        elif event.key() == Qt.Key.Key_A:
            self.allow_always()
        elif event.key() == Qt.Key.Key_D:
            self.deny_always()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        """Prevent accidental dismissal - only allow closing via buttons or timeout"""
        event.ignore()  # Ignore all close requests (clicking away, Alt+F4, etc.)

