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
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, 
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
    
    Shows device info, warns about high-risk devices,
    and allows user to allow/block with scope selection.
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
        self.setFixedSize(480, 400)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS["background"]};
                border: 2px solid {COLORS["warning"] if self.device.is_high_risk else COLORS["accent"]};
            }}
            QLabel {{
                color: {COLORS["text_primary"]};
            }}
            QFrame#info_box {{
                background-color: {COLORS["card"]};
                border-radius: 8px;
                border: 1px solid {COLORS["card_border"]};
                padding: 12px;
            }}
            QRadioButton {{
                color: {COLORS["text_primary"]};
                spacing: 8px;
            }}
            QRadioButton::indicator {{
                width: 16px;
                height: 16px;
            }}
        """)
        
        self.setWindowFlags(
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.Dialog
        )
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)
        
        # Header
        header_layout = QHBoxLayout()
        
        icon = "⚠️" if self.device.is_high_risk else "🔌"
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("", 28))
        
        title = QLabel("New USB Device Detected")
        title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['header']};")
        
        header_layout.addWidget(icon_label)
        header_layout.addWidget(title)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Device Info Box
        info_box = QFrame()
        info_box.setObjectName("info_box")
        info_layout = QVBoxLayout(info_box)
        info_layout.setSpacing(8)
        
        self._add_info_row(info_layout, "Device:", self.device.product_name)
        self._add_info_row(info_layout, "Vendor:", self.device.vendor_name)
        self._add_info_row(info_layout, "Type:", self.device.class_name)
        self._add_info_row(info_layout, "ID:", f"{self.device.vendor_id}:{self.device.product_id}")
        if self.device.serial:
            self._add_info_row(info_layout, "Serial:", self.device.serial[:20] + "..." if len(self.device.serial) > 20 else self.device.serial)
        
        layout.addWidget(info_box)
        
        # Warning for high-risk devices
        if self.device.is_high_risk:
            warning = QLabel(
                "⚠️ This device can act as a keyboard.\n"
                "Malicious devices can type commands automatically."
            )
            warning.setStyleSheet(f"""
                background-color: {COLORS['warning']}22;
                border: 1px solid {COLORS['warning']};
                border-radius: 6px;
                padding: 10px;
                color: {COLORS['warning']};
            """)
            warning.setWordWrap(True)
            layout.addWidget(warning)
        
        # Scope selection
        scope_label = QLabel("Apply decision to:")
        scope_label.setStyleSheet(f"color: {COLORS['text_secondary']}; margin-top: 8px;")
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
        
        layout.addStretch()
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)
        
        self.btn_block = self._create_button("Block", COLORS["danger"])
        self.btn_allow = self._create_button("Allow", COLORS["success"])
        
        self.btn_block.clicked.connect(self.block_device)
        self.btn_allow.clicked.connect(self.allow_device)
        
        btn_layout.addWidget(self.btn_block)
        btn_layout.addWidget(self.btn_allow)
        layout.addLayout(btn_layout)
        
        # Timer label
        self.timer_label = QLabel(f"Auto-blocking in {self.timeout}s...")
        self.timer_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        self.timer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.timer_label)

    def _add_info_row(self, layout: QVBoxLayout, label: str, value: str):
        """Add a label: value row to the info box."""
        row = QHBoxLayout()
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; min-width: 60px;")
        val = QLabel(value)
        val.setStyleSheet(f"color: {COLORS['text_primary']}; font-weight: bold;")
        row.addWidget(lbl)
        row.addWidget(val)
        row.addStretch()
        layout.addLayout(row)

    def _create_button(self, text: str, color: str) -> QPushButton:
        """Create a styled button."""
        btn = QPushButton(text)
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                border: none;
                color: #1e2227;
                padding: 12px 32px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {color}dd;
            }}
        """)
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
        """Start auto-block countdown timer."""
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)
        self.timer.start(1000)

    def update_timer(self):
        """Update countdown and auto-block when expired."""
        self.time_remaining -= 1
        if self.time_remaining <= 0:
            self.timer.stop()
            self.block_device()
        else:
            self.timer_label.setText(f"Auto-blocking in {self.time_remaining}s...")

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

        status_icon = QLabel("🔌")
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

        layout.addWidget(status_card)

        # Allowed devices table
        allowed_label = QLabel("✅ Allowed Devices")
        allowed_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['success']};")
        layout.addWidget(allowed_label)

        self.table_allowed = self._create_device_table()
        layout.addWidget(self.table_allowed)

        # Blocked devices table
        blocked_label = QLabel("🚫 Blocked Devices")
        blocked_label.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['danger']};")
        layout.addWidget(blocked_label)

        self.table_blocked = self._create_device_table()
        layout.addWidget(self.table_blocked)

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
        table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['card']};
                border: 1px solid {COLORS['card_border']};
                border-radius: 6px;
                gridline-color: {COLORS['card_border']};
            }}
            QTableWidget::item {{
                padding: 8px;
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

