#!/usr/bin/env python3
"""
USB Device Control - GUI Components

Provides:
- USBPromptDialog: Popup for new device allow/block decision
- USBDeviceWidget: Control panel widget for USB device management
"""

import logging
from typing import Optional, Callable

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFrame, QRadioButton, QButtonGroup, QWidget, QScrollArea,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

from bastion.usb_device import USBDeviceInfo
from bastion.usb_rules import USBRuleManager, USBRule, Verdict, Scope

logger = logging.getLogger(__name__)

# Reuse colors from main GUI
COLORS = {
    "background": "#1e2227",
    "sidebar": "#282c34",
    "card": "#21252b",
    "card_border": "#3e4451",
    "text_primary": "#abb2bf",
    "text_secondary": "#5c6370",
    "accent": "#61afef",
    "danger": "#e06c75",
    "success": "#98c379",
    "warning": "#e5c07b",
    "header": "#ffffff"
}


class USBPromptDialog(QDialog):
    """
    Popup dialog for new USB device decisions.
    Matches FirewallDialog styling exactly.
    """

    def __init__(self, device: USBDeviceInfo, timeout: int = 30):
        super().__init__()
        self.device = device
        self.timeout = timeout
        self.time_remaining = timeout

        # Result
        self.verdict: Optional[Verdict] = None
        self.scope: Scope = 'device'

        self.init_ui()
        if timeout > 0:
            self.start_timer()

    def init_ui(self):
        self.setWindowTitle("Bastion - New USB Device")
        self.setFixedSize(500, 550)  # Slightly taller for scope options

        # Determine accent color based on risk
        accent_color = COLORS["danger"] if self.device.is_high_risk else COLORS["accent"]

        # EXACT same styling as FirewallDialog
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS["background"]};
                border: 1px solid {accent_color};
            }}
            QLabel {{
                color: {COLORS["text_primary"]};
            }}
            QFrame#info_box {{
                background-color: {COLORS["card"]};
                border-radius: 6px;
                border: 1px solid {COLORS["card_border"]};
            }}
            QRadioButton {{
                color: {COLORS["text_primary"]};
                spacing: 8px;
                font-size: 13px;
            }}
            QRadioButton::indicator {{
                width: 16px;
                height: 16px;
            }}
        """)

        # EXACT same window flags as FirewallDialog
        self.setWindowFlags(
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.Dialog
        )

        layout = QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)  # Same as FirewallDialog
        layout.setSpacing(20)  # Same as FirewallDialog
        self.setLayout(layout)

        # Header - EXACT same style as FirewallDialog
        header_layout = QHBoxLayout()
        icon = QLabel("⚠️" if self.device.is_high_risk else "🔌")
        icon.setStyleSheet("font-size: 32px;")
        header_layout.addWidget(icon)

        title = QLabel("New USB Device Detected")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['header']};")
        header_layout.addWidget(title)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Info Box - EXACT same style as FirewallDialog
        info_frame = QFrame()
        info_frame.setObjectName("info_box")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(20, 12, 20, 18)  # More bottom padding
        info_layout.setSpacing(4)  # Less space between title and details

        # Device name as title
        device_name = self.device.product_name or "Unknown Device"
        lbl_device = QLabel(device_name)
        lbl_device.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {accent_color};")
        info_layout.addWidget(lbl_device)

        # Details rows - same format as FirewallDialog
        details_layout = QVBoxLayout()
        details_layout.setSpacing(14)  # More space between rows
        details_layout.setContentsMargins(0, 0, 0, 0)  # No extra margins
        vendor_name = self.device.vendor_name or "Unknown"
        device_type = self.device.class_name
        device_id = f"{self.device.vendor_id}:{self.device.product_id}"

        self.add_detail_row(details_layout, "Vendor", vendor_name)
        self.add_detail_row(details_layout, "Type", device_type)
        self.add_detail_row(details_layout, "ID", device_id)

        if self.device.serial:
            serial_display = self.device.serial[:20] + "..." if len(self.device.serial) > 20 else self.device.serial
            self.add_detail_row(details_layout, "Serial", serial_display)

        info_layout.addLayout(details_layout)
        layout.addWidget(info_frame)

        # Warning for high-risk devices
        if self.device.is_high_risk:
            warning = QLabel(
                "⚠️  WARNING: This device can act as a keyboard and type commands "
                "automatically. Only allow if you trust this device."
            )
            warning.setStyleSheet(f"""
                background-color: rgba(229, 192, 123, 0.20);
                border: 1px solid {COLORS['warning']};
                border-radius: 6px;
                padding: 12px;
                color: {COLORS['warning']};
                font-size: 12px;
            """)
            warning.setWordWrap(True)
            layout.addWidget(warning)

        # Scope selection
        scope_label = QLabel("Apply decision to:")
        scope_label.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-top: 4px; font-size: 13px;")
        layout.addWidget(scope_label)

        self.scope_group = QButtonGroup(self)

        self.rb_device = QRadioButton(f"This device only")
        self.rb_model = QRadioButton(f"All {self.device.product_name} devices")
        self.rb_vendor = QRadioButton(f"All {self.device.vendor_name} devices")

        self.rb_device.setChecked(True)
        self.scope_group.addButton(self.rb_device, 0)
        self.scope_group.addButton(self.rb_model, 1)
        self.scope_group.addButton(self.rb_vendor, 2)

        layout.addWidget(self.rb_device)
        layout.addWidget(self.rb_model)
        layout.addWidget(self.rb_vendor)

        # Buttons - EXACT same style as FirewallDialog
        btn_grid = QVBoxLayout()
        btn_grid.setSpacing(10)

        row_allow = QHBoxLayout()
        btn_allow_once = self.create_button("Allow Once", COLORS['success'], outline=True)
        btn_allow_once.clicked.connect(self.allow_device)
        btn_allow_always = self.create_button("Allow Always", COLORS['success'])
        btn_allow_always.clicked.connect(self.allow_device)
        row_allow.addWidget(btn_allow_once)
        row_allow.addWidget(btn_allow_always)
        btn_grid.addLayout(row_allow)

        row_block = QHBoxLayout()
        btn_block_once = self.create_button("Block Once", COLORS['danger'], outline=True)
        btn_block_once.clicked.connect(self.block_device)
        btn_block_always = self.create_button("Block Always", COLORS['danger'])
        btn_block_always.clicked.connect(self.block_device)
        row_block.addWidget(btn_block_once)
        row_block.addWidget(btn_block_always)
        btn_grid.addLayout(row_block)

        layout.addLayout(btn_grid)

        # Timer - EXACT same style as FirewallDialog
        if self.timeout > 0:
            from PyQt6.QtWidgets import QProgressBar
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
        """Add a detail row - same format as FirewallDialog."""
        row = QHBoxLayout()
        row.setSpacing(10)
        lbl = QLabel(label + ":")
        lbl.setFixedHeight(24)
        lbl.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: bold; min-width: 80px;")
        val = QLabel(str(value))
        val.setFixedHeight(24)
        val.setStyleSheet(f"color: {COLORS['header']};")
        val.setWordWrap(True)
        row.addWidget(lbl)
        row.addWidget(val, 1)  # Give value more stretch
        layout.addLayout(row)

    def create_button(self, text, color, outline=False):
        """Create a styled button - same as FirewallDialog."""
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

    def _get_selected_scope(self) -> Scope:
        """Get the selected scope from radio buttons."""
        if self.rb_model.isChecked():
            return 'model'
        elif self.rb_vendor.isChecked():
            return 'vendor'
        return 'device'

    def start_timer(self):
        """Start countdown timer - same as FirewallDialog."""
        if self.timeout <= 0:
            return
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)
        self.timer.start(100)  # Update every 100ms like FirewallDialog

    def update_timer(self):
        """Update countdown timer - same as FirewallDialog."""
        current = self.progress.value()
        if current <= 0:
            self.timer.stop()
            self.block_device()
            return
        self.progress.setValue(current - 1)

    def allow_device(self):
        """User chose to allow the device."""
        self.verdict = 'allow'
        self.scope = self._get_selected_scope()
        logger.info(f"User allowed USB device: {self.device.product_name} (scope={self.scope})")
        self.accept()

    def block_device(self):
        """User chose to block the device."""
        self.verdict = 'block'
        self.scope = self._get_selected_scope()
        logger.info(f"User blocked USB device: {self.device.product_name} (scope={self.scope})")
        self.reject()

    def keyPressEvent(self, event):
        """Handle keyboard shortcuts."""
        key = event.key()
        if key == Qt.Key.Key_A:
            self.allow_device()
        elif key == Qt.Key.Key_B or key == Qt.Key.Key_Escape:
            self.block_device()
        else:
            super().keyPressEvent(event)


class USBControlWidget(QWidget):
    """
    Control Panel widget for USB device management.

    Shows:
    - Protection status (enabled/disabled)
    - Allowed devices list
    - Blocked devices list
    - Currently connected devices
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.rule_manager = USBRuleManager()
        self.init_ui()
        self.refresh()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(20)

        # Header
        header = QLabel("USB Device Control")
        header.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {COLORS['header']};
            margin-bottom: 10px;
        """)
        layout.addWidget(header)

        # Status card
        status_card = QFrame()
        status_card.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['card']};
                border-radius: 8px;
                border: 1px solid {COLORS['card_border']};
                padding: 16px;
            }}
        """)
        status_layout = QHBoxLayout(status_card)

        # Use PNG icon instead of emoji for better compatibility
        from .icon_manager import IconManager
        status_icon = QLabel()
        nav_icon = IconManager.get_nav_icon('USB')
        if not nav_icon.isNull():
            status_icon.setPixmap(nav_icon.pixmap(32, 32))
        else:
            status_icon.setText("🔌")
            status_icon.setFont(QFont("", 24))

        status_text = QVBoxLayout()
        self.lbl_status = QLabel("USB Protection Active")
        self.lbl_status.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['success']};")
        self.lbl_status_desc = QLabel("Monitoring for new devices")
        self.lbl_status_desc.setStyleSheet(f"color: {COLORS['text_secondary']};")
        status_text.addWidget(self.lbl_status)
        status_text.addWidget(self.lbl_status_desc)

        status_layout.addWidget(status_icon)
        status_layout.addLayout(status_text)
        status_layout.addStretch()

        # Enable/Disable toggle button
        self.btn_toggle = QPushButton("Disable")
        self.usb_enabled = True
        self.btn_toggle.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['danger']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #c0392b;
            }}
        """)
        self.btn_toggle.clicked.connect(self._toggle_usb_protection)
        status_layout.addWidget(self.btn_toggle)

        layout.addWidget(status_card)

        # Allowed devices section
        allowed_header = QHBoxLayout()
        allowed_icon = QLabel("●")
        allowed_icon.setStyleSheet(f"color: {COLORS['success']}; font-size: 12px;")
        allowed_label = QLabel("Allowed Devices")
        allowed_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['success']};")
        allowed_header.addWidget(allowed_icon)
        allowed_header.addWidget(allowed_label)
        allowed_header.addStretch()
        layout.addLayout(allowed_header)

        self.table_allowed = self._create_device_table()
        layout.addWidget(self.table_allowed)

        # Blocked devices section
        blocked_header = QHBoxLayout()
        blocked_icon = QLabel("●")
        blocked_icon.setStyleSheet(f"color: {COLORS['danger']}; font-size: 12px;")
        blocked_label = QLabel("Blocked Devices")
        blocked_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['danger']};")
        blocked_header.addWidget(blocked_icon)
        blocked_header.addWidget(blocked_label)
        blocked_header.addStretch()
        layout.addLayout(blocked_header)

        self.table_blocked = self._create_device_table()
        layout.addWidget(self.table_blocked)

        # Buttons
        btn_layout = QHBoxLayout()

        # Delete button
        btn_delete = QPushButton("Delete Selected")
        btn_delete.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['danger']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #c0392b;
            }}
        """)
        btn_delete.clicked.connect(self._delete_selected)
        btn_layout.addWidget(btn_delete)

        btn_layout.addStretch()

        btn_refresh = QPushButton("Refresh")
        btn_refresh.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['sidebar']};
                color: {COLORS['text_primary']};
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['card_border']};
            }}
        """)
        btn_refresh.clicked.connect(self.refresh)
        btn_layout.addWidget(btn_refresh)

        layout.addLayout(btn_layout)

    def _create_device_table(self) -> QTableWidget:
        """Create a styled device table."""
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(["Device", "Vendor", "Scope", "Added"])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setMaximumHeight(150)
        table.verticalHeader().setVisible(False)  # Hide row numbers
        table.setShowGrid(False)  # Hide grid lines for cleaner look
        table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['card']};
                border: 1px solid {COLORS['card_border']};
                border-radius: 6px;
                color: {COLORS['text_primary']};
            }}
            QTableWidget::item {{
                padding: 8px;
                color: {COLORS['text_primary']};
                background-color: {COLORS['card']};
                border-bottom: 1px solid {COLORS['card_border']};
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['sidebar']};
                color: {COLORS['text_primary']};
            }}
            QHeaderView::section {{
                background-color: {COLORS['sidebar']};
                color: {COLORS['text_secondary']};
                padding: 8px;
                border: none;
                border-bottom: 1px solid {COLORS['card_border']};
            }}
        """)
        return table

    def refresh(self):
        """Refresh the device lists from rules."""
        self.rule_manager = USBRuleManager()  # Reload from disk

        allowed = self.rule_manager.get_allowed_devices()
        blocked = self.rule_manager.get_blocked_devices()

        self._populate_table(self.table_allowed, allowed)
        self._populate_table(self.table_blocked, blocked)

        # Update status
        total = len(allowed) + len(blocked)
        self.lbl_status_desc.setText(f"Monitoring • {len(allowed)} allowed, {len(blocked)} blocked")

    def _populate_table(self, table: QTableWidget, rules: list[USBRule]):
        """Populate a table with rules."""
        table.setRowCount(len(rules))
        # Store rule keys for deletion
        table.rule_keys = []

        for i, rule in enumerate(rules):
            table.setItem(i, 0, QTableWidgetItem(rule.product_name))
            table.setItem(i, 1, QTableWidgetItem(rule.vendor_name))
            table.setItem(i, 2, QTableWidgetItem(rule.scope.capitalize()))
            # Format date nicely
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(rule.added)
                date_str = dt.strftime("%Y-%m-%d %H:%M")
            except:
                date_str = rule.added[:16] if rule.added else "Unknown"
            table.setItem(i, 3, QTableWidgetItem(date_str))
            # Store key for this row
            table.rule_keys.append(rule.key)

    def _toggle_usb_protection(self):
        """Toggle USB protection on/off."""
        import subprocess

        self.usb_enabled = not self.usb_enabled

        if self.usb_enabled:
            # Enable: set authorized_default=0 (block new devices)
            self.btn_toggle.setText("Disable")
            self.btn_toggle.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['danger']};
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: #c0392b;
                }}
            """)
            self.lbl_status.setText("USB Protection Active")
            self.lbl_status.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['success']};")
            # Set default to block
            try:
                subprocess.run(['pkexec', 'bash', '-c',
                    'for d in /sys/bus/usb/devices/usb*/authorized_default; do echo 0 > "$d"; done'],
                    check=True, capture_output=True)
            except Exception as e:
                logger.warning(f"Failed to enable USB protection: {e}")
        else:
            # Disable: set authorized_default=1 (allow new devices)
            self.btn_toggle.setText("Enable")
            self.btn_toggle.setStyleSheet(f"""
                QPushButton {{
                    background-color: {COLORS['success']};
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: #27ae60;
                }}
            """)
            self.lbl_status.setText("USB Protection Disabled")
            self.lbl_status.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['danger']};")
            # Set default to allow
            try:
                subprocess.run(['pkexec', 'bash', '-c',
                    'for d in /sys/bus/usb/devices/usb*/authorized_default; do echo 1 > "$d"; done'],
                    check=True, capture_output=True)
            except Exception as e:
                logger.warning(f"Failed to disable USB protection: {e}")

    def _delete_selected(self):
        """Delete selected rules from both tables."""
        deleted = False

        # Check allowed table
        for row in self.table_allowed.selectionModel().selectedRows():
            idx = row.row()
            if hasattr(self.table_allowed, 'rule_keys') and idx < len(self.table_allowed.rule_keys):
                key = self.table_allowed.rule_keys[idx]
                self.rule_manager.remove_rule(key)
                deleted = True

        # Check blocked table
        for row in self.table_blocked.selectionModel().selectedRows():
            idx = row.row()
            if hasattr(self.table_blocked, 'rule_keys') and idx < len(self.table_blocked.rule_keys):
                key = self.table_blocked.rule_keys[idx]
                self.rule_manager.remove_rule(key)
                deleted = True

        if deleted:
            self.refresh()


def test_usb_prompt():
    """Test the USB prompt dialog."""
    import sys
    from PyQt6.QtWidgets import QApplication

    app = QApplication(sys.argv)

    # Create test device
    device = USBDeviceInfo(
        vendor_id='046d',
        product_id='c52b',
        vendor_name='Logitech, Inc.',
        product_name='Unifying Receiver',
        device_class=0x03,  # HID - high risk
        serial='1234567890',
        bus_id='1-2.3'
    )

    dialog = USBPromptDialog(device, timeout=30)
    result = dialog.exec()

    print(f"Result: {'Accepted' if result else 'Rejected'}")
    print(f"Verdict: {dialog.verdict}")
    print(f"Scope: {dialog.scope}")

    sys.exit(0)


if __name__ == '__main__':
    test_usb_prompt()

