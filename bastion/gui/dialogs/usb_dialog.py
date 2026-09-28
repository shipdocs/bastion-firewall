#!/usr/bin/env python3
"""
USB device prompt for Bastion Firewall.
Shown when the daemon sees a new USB device with no matching rule.
"""

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                            QPushButton, QFrame, QComboBox)
from PyQt6.QtCore import Qt, QTimer

from ..theme import COLORS
from ...usb_client import sanitize_text, VALID_SCOPES

USB_CLASS_NAMES = {
    0x00: "Composite / per-interface",
    0x01: "Audio",
    0x02: "Communications (modem/network)",
    0x03: "Input device (keyboard/mouse)",
    0x06: "Camera / imaging",
    0x07: "Printer",
    0x08: "Storage",
    0x09: "Hub",
    0x0A: "Communications data",
    0x0E: "Video",
    0xE0: "Wireless adapter",
    0xFF: "Vendor specific",
}

SCOPE_LABELS = {
    "device": "This exact device (by serial)",
    "model": "All devices of this model",
    "vendor": "Everything from this vendor",
}


def plain_label(text, style=""):
    """QLabel that never interprets device-supplied text as rich text."""
    label = QLabel(sanitize_text(text, 256))
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(True)
    if style:
        label.setStyleSheet(style)
    return label


class USBPromptDialog(QDialog):
    """
    Decision dialog for a new USB device. Blocks the device if it times out
    or is closed without an answer.
    """

    def __init__(self, device, timeout=25):
        super().__init__()
        self.device = device
        self.allow = False
        self.permanent = False
        self.scope = "model"
        self.time_remaining = timeout
        self._answered = False
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(1000)

    def init_ui(self):
        self.setWindowTitle("Bastion Firewall - USB Device")
        self.setFixedWidth(480)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLORS["background"]}; border: 1px solid {COLORS["accent"]}; }}
            QLabel {{ color: {COLORS["text_primary"]}; }}
            QFrame#info_box {{ background-color: {COLORS["card"]}; border-radius: 6px;
                              border: 1px solid {COLORS["card_border"]}; }}
        """)
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.Dialog)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(14)

        layout.addWidget(plain_label(
            "New USB device connected",
            f"font-size: 18px; font-weight: bold; color: {COLORS['header']};"))

        if self.device.get("is_high_risk"):
            layout.addWidget(plain_label(
                "Warning: this device can act as a keyboard or network adapter. "
                "Only allow it if you connected it yourself.",
                f"color: {COLORS['danger']}; font-weight: bold;"))

        box = QFrame()
        box.setObjectName("info_box")
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(15, 15, 15, 15)
        box_layout.setSpacing(6)
        name = sanitize_text(self.device.get("product_name")) or "Unknown device"
        vendor = sanitize_text(self.device.get("vendor_name")) or "Unknown vendor"
        try:
            kind = USB_CLASS_NAMES.get(int(self.device.get("device_class", 0)), "Other")
        except (TypeError, ValueError):
            kind = "Other"
        box_layout.addWidget(plain_label(name, "font-size: 15px; font-weight: bold;"))
        box_layout.addWidget(plain_label(vendor, f"color: {COLORS['text_secondary']};"))
        box_layout.addWidget(plain_label(f"Type: {kind}"))
        box_layout.addWidget(plain_label(
            f"ID: {sanitize_text(self.device.get('vendor_id'), 8)}:"
            f"{sanitize_text(self.device.get('product_id'), 8)}"))
        serial = self.device.get("serial")
        if serial:
            box_layout.addWidget(plain_label(f"Serial: {sanitize_text(serial)}"))
        layout.addWidget(box)

        layout.addWidget(plain_label("Apply my choice to:"))
        self.scope_combo = QComboBox()
        for scope in VALID_SCOPES:
            if scope == "device" and not serial:
                continue  # can't identify one exact unit without a serial
            self.scope_combo.addItem(SCOPE_LABELS[scope], scope)
        self.scope_combo.setCurrentIndex(max(0, self.scope_combo.findData("model")))
        layout.addWidget(self.scope_combo)

        self.countdown = plain_label("", f"color: {COLORS['text_secondary']};")
        layout.addWidget(self.countdown)
        self._update_countdown()

        buttons = QHBoxLayout()
        for text, allow, permanent, color in (
            ("Allow once", True, False, COLORS["success"]),
            ("Always allow", True, True, COLORS["success"]),
            ("Block once", False, False, COLORS["danger"]),
            ("Always block", False, True, COLORS["danger"]),
        ):
            btn = QPushButton(text)
            btn.setStyleSheet(f"background-color: {color}; color: #1e2227; border: none; "
                              f"padding: 8px 10px; border-radius: 4px; font-weight: bold;")
            btn.clicked.connect(lambda _=False, a=allow, p=permanent: self._answer(a, p))
            buttons.addWidget(btn)
        layout.addLayout(buttons)

    def _update_countdown(self):
        self.countdown.setText(f"The device stays blocked if you don't answer in {self.time_remaining}s.")

    def _tick(self):
        self.time_remaining -= 1
        if self.time_remaining <= 0:
            self._answer(False, False)
        else:
            self._update_countdown()

    def _answer(self, allow, permanent):
        if self._answered:
            return
        self._answered = True
        self.timer.stop()
        self.allow = allow
        self.permanent = permanent
        self.scope = self.scope_combo.currentData() or "model"
        self.accept()

    def closeEvent(self, event):
        # Closing the window without choosing counts as "block once".
        if not self._answered:
            self._answer(False, False)
        super().closeEvent(event)
