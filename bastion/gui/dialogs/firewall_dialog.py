#!/usr/bin/env python3
"""
Firewall Decision Dialog for Bastion Firewall.
Displays connection requests and allows user to allow/deny.
"""

import logging
import socket
import threading
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                            QPushButton, QFrame, QProgressBar, QCheckBox, QComboBox)
from PyQt6.QtCore import Qt, QTimer, QMetaObject, Q_ARG
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
        self.duration = "once"  # Duration: "once", "session", "always"
        self.time_remaining = timeout
        
        self.init_ui()
        self.start_timer()
        
    def init_ui(self):
        self.setWindowTitle("Bastion Firewall - Connection Request")
        self.setFixedSize(500, 520)  # Reduced height after removing trust section
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

        # Enhanced Destination identification - non-blocking
        dest_ip = self.conn_info.get('dest_ip', '')
        dest_port = self.conn_info.get('dest_port', '')
        dest_display = f"{dest_ip}:{dest_port}"

        # Create destination label (will be updated async)
        self.dest_label = QLabel(dest_display)
        self.dest_label.setWordWrap(True)
        dest_row = QHBoxLayout()
        lbl_dest = QLabel("Destination:")
        lbl_dest.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; min-width: 80px;")
        dest_row.addWidget(lbl_dest)
        dest_row.addWidget(self.dest_label)
        details_layout.addLayout(dest_row)

        # Perform async lookup after dialog is shown
        QTimer.singleShot(50, lambda: self._lookup_dest_info_async(dest_ip, dest_port))
        self.add_detail_row(details_layout, "Protocol", self.conn_info.get('protocol', 'TCP'))
        info_layout.addLayout(details_layout)

        # Show warning when path unavailable
        if not app_path or app_path in ('Unknown', 'unknown', ''):
            warning_label = QLabel("Warning: Path unavailable - rules will be based on application name only (less secure)")
            warning_label.setStyleSheet(f"font-size: 11px; color: {COLORS['warning']}; padding: 8px; background-color: rgba(229, 192, 123, 0.1); border-radius: 4px; margin-top: 8px;")
            warning_label.setWordWrap(True)
            info_layout.addWidget(warning_label)

        layout.addWidget(info_frame)

        # Duration dropdown (OpenSnitch-style)
        duration_layout = QHBoxLayout()
        duration_label = QLabel("Duration:")
        duration_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold;")
        duration_layout.addWidget(duration_label)

        self.duration_combo = QComboBox()
        self.duration_combo.addItems(["This Time Only", "For This Session", "Always (Permanent)"])
        self.duration_combo.setCurrentIndex(0)  # Default to "This Time Only"
        self.duration_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS['card']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['card_border']};
                border-radius: 4px;
                padding: 8px 12px;
                font-size: 13px;
                min-width: 200px;
            }}
            QComboBox:hover {{
                border-color: {COLORS['accent']};
            }}
            QComboBox::drop-down {{
                border: none;
                padding-right: 10px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS['card']};
                color: {COLORS['text_primary']};
                selection-background-color: {COLORS['accent']};
                border: 1px solid {COLORS['card_border']};
            }}
        """)
        # Add tooltips to dropdown items
        self.duration_combo.setItemData(0, "Allow this single connection without saving a rule", Qt.ItemDataRole.ToolTipRole)
        self.duration_combo.setItemData(1, "Remember until daemon restart", Qt.ItemDataRole.ToolTipRole)
        self.duration_combo.setItemData(2, "Save permanently to /etc/bastion/rules.json", Qt.ItemDataRole.ToolTipRole)
        self.duration_combo.currentIndexChanged.connect(self._on_duration_changed)
        duration_layout.addWidget(self.duration_combo)
        duration_layout.addStretch()
        layout.addLayout(duration_layout)

        # Buttons (2x2 grid)
        btn_grid = QVBoxLayout()
        btn_grid.setSpacing(10)

        row_allow = QHBoxLayout()
        btn_allow_once = self.create_button("Allow Once", COLORS['success'], outline=True)
        btn_allow_once.clicked.connect(self.allow_once)
        btn_allow = self.create_button("Allow", COLORS['success'])
        btn_allow.clicked.connect(self.allow_with_duration)
        row_allow.addWidget(btn_allow_once)
        row_allow.addWidget(btn_allow)
        btn_grid.addLayout(row_allow)

        row_deny = QHBoxLayout()
        btn_deny_once = self.create_button("Deny Once", COLORS['danger'], outline=True)
        btn_deny_once.clicked.connect(self.deny_once)
        btn_deny = self.create_button("Deny", COLORS['danger'])
        btn_deny.clicked.connect(self.deny_with_duration)
        row_deny.addWidget(btn_deny_once)
        row_deny.addWidget(btn_deny)
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

    def _on_duration_changed(self, index):
        """Handle duration dropdown change - disable all_ports for 'once'"""
        durations = ["once", "session", "always"]
        self.duration = durations[index]
        # Disable "Apply to all ports" for one-time decisions (has no effect)
        self.chk_all_ports.setEnabled(index > 0)
        if index == 0:
            self.chk_all_ports.setChecked(False)

    def allow_once(self):
        self.decision = "allow"
        self.duration = "once"
        self.permanent = False
        self.all_ports = False
        self.accept()

    def allow_with_duration(self):
        """Allow using the selected duration from dropdown"""
        self.decision = "allow"
        self.permanent = (self.duration == "always")
        self.all_ports = self.chk_all_ports.isChecked() if self.duration != "once" else False
        self.accept()

    def deny_once(self):
        self.decision = "deny"
        self.duration = "once"
        self.permanent = False
        self.all_ports = False
        self.reject()

    def deny_with_duration(self):
        """Deny using the selected duration from dropdown"""
        self.decision = "deny"
        self.permanent = (self.duration == "always")
        self.all_ports = self.chk_all_ports.isChecked() if self.duration != "once" else False
        self.reject()

    def keyPressEvent(self, event):
        if event.key() in [Qt.Key.Key_Return, Qt.Key.Key_Enter]:
            self.allow_once()
        elif event.key() == Qt.Key.Key_Escape:
            self.deny_once()
        elif event.key() == Qt.Key.Key_A:
            self.allow_with_duration()
        elif event.key() == Qt.Key.Key_D:
            self.deny_with_duration()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        """Prevent accidental dismissal - only allow closing via buttons or timeout"""
        event.ignore()  # Ignore all close requests (clicking away, Alt+F4, etc.)

    def _lookup_dest_info_async(self, dest_ip, dest_port):
        """Perform DNS and IP info lookup in background thread to avoid blocking UI"""
        def lookup_worker():
            result = f"{dest_ip}:{dest_port}"
            try:
                # 1. Try Reverse DNS (Fast, local cache usually)
                hostname = socket.gethostbyaddr(dest_ip)[0]
                result = f"{hostname} ({dest_ip}):{dest_port}"
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
                            result = f"{org} - {dest_ip}:{dest_port}"
                except Exception as e:
                    # Silently fall back to IP if lookup fails or times out
                    logger.debug(f"IP info lookup failed for {dest_ip}: {e}")
            return result

        def on_lookup_complete():
            """Thread-safe UI update using QTimer"""
            # Start background thread
            def run_thread():
                result = lookup_worker()
                # Schedule UI update on main thread
                QTimer.singleShot(0, lambda: self._update_dest_label(result))

            thread = threading.Thread(target=run_thread, daemon=True)
            thread.start()

        on_lookup_complete()

    def _update_dest_label(self, text):
        """Thread-safe update of destination label"""
        if hasattr(self, 'dest_label') and self.dest_label:
            self.dest_label.setText(text)

