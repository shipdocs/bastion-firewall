import sys
import os
import logging
from PyQt6.QtWidgets import QDialog, QLabel, QHBoxLayout, QVBoxLayout, QPushButton
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QRect
from PyQt6.QtGui import QIcon, QFont, QGuiApplication

logger = logging.getLogger(__name__)

def is_wayland():
    """Check if running on Wayland"""
    try:
        app = QGuiApplication.instance()
        if app:
            platform = app.platformName().lower()
            return platform == 'wayland'
    except Exception:
        pass

    # Fallback: check environment variables
    return bool(os.environ.get('WAYLAND_DISPLAY'))

class NotificationDialog(QDialog):
    """A modern, sleek notification dialog that auto‑closes.
    Designed to replace the old QMessageBox for simple info/warning messages.
    """
    def __init__(self, title: str, message: str, icon_path: str | None = None, timeout: int = 3000, parent=None):
        super().__init__(parent)

        # Platform-specific window flags
        if is_wayland():
            # On Wayland: minimal flags to avoid compositor issues
            self.setWindowFlags(
                Qt.WindowType.FramelessWindowHint |
                Qt.WindowType.Dialog
            )
        else:
            # On X11: traditional flags work well
            self.setWindowFlags(
                Qt.WindowType.FramelessWindowHint |
                Qt.WindowType.Tool |
                Qt.WindowType.WindowStaysOnTopHint
            )

        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.timeout = timeout

        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # Title
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 14px;")
        layout.addWidget(title_lbl)

        # Message
        msg_lbl = QLabel(message)
        msg_lbl.setWordWrap(True)
        msg_lbl.setStyleSheet("color: #dddddd; font-size: 13px;")
        layout.addWidget(msg_lbl)

        # Optional close button (for manual dismiss)
        btn = QPushButton("Close")
        btn.setStyleSheet(
            "QPushButton { background-color: #444444; color: #ffffff; border: none; padding: 5px 10px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #555555; }"
        )
        btn.clicked.connect(self.accept)
        layout.addWidget(btn, alignment=Qt.AlignmentFlag.AlignRight)

        # Styling – dark glassmorphism look
        self.setStyleSheet(
            "QDialog { background-color: rgba(30, 30, 30, 230); border-radius: 8px; }"
        )

        # Auto‑close timer
        QTimer.singleShot(self.timeout, self.accept)

        # Fade‑in animation
        self.setWindowOpacity(0.0)
        self.anim = QPropertyAnimation(self, b"windowOpacity")
        self.anim.setDuration(200)
        self.anim.setStartValue(0.0)
        self.anim.setEndValue(1.0)
        self.anim.start()

    # Optional: override reject to just close without animation
    def reject(self):
        self.accept()

def show_notification(parent, title: str, message: str, timeout: int = 3000):
    dlg = NotificationDialog(title, message, timeout=timeout, parent=parent)
    dlg.exec()
