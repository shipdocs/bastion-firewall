#!/usr/bin/env python3
"""
Allow Rule Dialog for Bastion Firewall.
Allows creating allow rules from blocked log entries.
"""

import logging
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                            QPushButton, QFrame, QCheckBox, QComboBox, QRadioButton, QButtonGroup)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor

from ..theme import COLORS

logger = logging.getLogger(__name__)


class AllowRuleDialog(QDialog):
    """
    Dialog for creating allow rules from blocked log entries.
    Shows what was blocked and why, and allows converting to allow rule.
    """

    def __init__(self, log_entry, parent=None):
        super().__init__(parent)
        self.log_entry = log_entry
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Create Allow Rule")
        self.setMinimumWidth(500)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS["background"]};
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

        layout = QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        self.setLayout(layout)

        # Header
        header = QLabel("Create Allow Rule")
        header.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {COLORS['header']};")
        layout.addWidget(header)

        # Info Box - Connection Details
        info_frame = QFrame()
        info_frame.setObjectName("info_box")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(15, 15, 15, 15)
        info_layout.setSpacing(8)

        # Application
        app_label = QLabel("Application:")
        app_label.setStyleSheet(f"font-size: 12px; color: {COLORS['text_secondary']};")
        info_layout.addWidget(app_label)

        lbl_app = QLabel(self.log_entry.app_name)
        lbl_app.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {COLORS['accent']}; margin-bottom: 8px;")
        info_layout.addWidget(lbl_app)

        # Path (if available)
        if self.log_entry.app_path and self.log_entry.app_path != '-':
            path_row = QHBoxLayout()
            lbl_path_label = QLabel("Path:")
            lbl_path_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; min-width: 80px;")
            lbl_path = QLabel(self.log_entry.app_path)
            lbl_path.setWordWrap(True)
            path_row.addWidget(lbl_path_label)
            path_row.addWidget(lbl_path)
            info_layout.addLayout(path_row)

        # Destination
        dest_display = f"{self.log_entry.dest_ip}:{self.log_entry.dest_port}"
        dest_row = QHBoxLayout()
        lbl_dest_label = QLabel("Destination:")
        lbl_dest_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; min-width: 80px;")
        lbl_dest = QLabel(dest_display)
        lbl_dest.setWordWrap(True)
        dest_row.addWidget(lbl_dest_label)
        dest_row.addWidget(lbl_dest)
        info_layout.addLayout(dest_row)

        # Block Reason
        reason_display = self._get_block_reason_display()
        reason_row = QHBoxLayout()
        lbl_reason_label = QLabel("Blocked by:")
        lbl_reason_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold; min-width: 80px;")
        lbl_reason = QLabel(reason_display)
        lbl_reason.setWordWrap(True)
        lbl_reason.setStyleSheet(f"color: {COLORS['danger']};")
        reason_row.addWidget(lbl_reason_label)
        reason_row.addWidget(lbl_reason)
        info_layout.addLayout(reason_row)

        layout.addWidget(info_frame)

        # Rule Type Selection
        rule_type_layout = QVBoxLayout()
        rule_type_label = QLabel("Rule Type:")
        rule_type_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold;")
        rule_type_layout.addWidget(rule_type_label)

        self.rule_type_group = QButtonGroup(self)

        # Determine which rule types to show based on available info
        has_path = self.log_entry.app_path and self.log_entry.app_path != '-'
        has_name = self.log_entry.app_name and self.log_entry.app_name != 'unknown'

        if has_path:
            # Path-based rule (most specific)
            radio_path = QRadioButton(f"Path-based: Allow {self.log_entry.app_path} to {self.log_entry.dest_port}")
            radio_path.setChecked(True)
            radio_path.setToolTip("Most secure - only allows this specific executable")
            self.rule_type_group.addButton(radio_path, 0)
            rule_type_layout.addWidget(radio_path)

        if has_name:
            # Name-based rule
            radio_name = QRadioButton(f"Name-based: Allow {self.log_entry.app_name} to {self.log_entry.dest_port}")
            if not has_path:
                radio_name.setChecked(True)
            radio_name.setToolTip("Allows any app with this name (less secure)")
            self.rule_type_group.addButton(radio_name, 1)
            rule_type_layout.addWidget(radio_name)

        # Destination-based rule (for unknown apps)
        radio_dest = QRadioButton(f"Destination-based: Allow {self.log_entry.dest_ip}:{self.log_entry.dest_port}")
        if not has_path and not has_name:
            radio_dest.setChecked(True)
        radio_dest.setToolTip("Allows any app to this destination (least secure)")
        self.rule_type_group.addButton(radio_dest, 2)
        rule_type_layout.addWidget(radio_dest)

        layout.addLayout(rule_type_layout)

        # Duration selection
        duration_layout = QHBoxLayout()
        duration_label = QLabel("Duration:")
        duration_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold;")
        duration_layout.addWidget(duration_label)

        self.duration_combo = QComboBox()
        self.duration_combo.addItems(["Always (Permanent)", "For This Session"])
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
        """)
        self.duration_combo.setItemData(0, "Save permanently to /etc/bastion/rules.json", Qt.ItemDataRole.ToolTipRole)
        self.duration_combo.setItemData(1, "Remember until daemon restart", Qt.ItemDataRole.ToolTipRole)
        duration_layout.addWidget(self.duration_combo)
        duration_layout.addStretch()
        layout.addLayout(duration_layout)

        # "Apply to all ports" checkbox
        self.chk_all_ports = QCheckBox("Apply to all ports (less secure)")
        self.chk_all_ports.setToolTip(
            "When enabled, this rule will apply to ALL destination ports, "
            f"not just port {self.log_entry.dest_port}."
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

        # Session cache clear option
        self.chk_clear_cache = QCheckBox("Clear session cache and retry immediately")
        self.chk_clear_cache.setChecked(True)
        self.chk_clear_cache.setToolTip(
            "If this connection was blocked by a cached session decision, "
            "clearing the cache will allow the connection to retry immediately."
        )
        self.chk_clear_cache.setStyleSheet(f"""
            QCheckBox {{
                color: {COLORS['success']};
                font-size: 12px;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
            }}
        """)
        layout.addWidget(self.chk_clear_cache)

        layout.addStretch()

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        btn_cancel = QPushButton("Cancel")
        btn_cancel.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['sidebar']};
                color: {COLORS['text_primary']};
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['card_border']};
            }}
        """)
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_cancel)

        btn_create = QPushButton("Create Rule")
        btn_create.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['success']};
                color: #1e2227;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLORS['success']}dd;
            }}
        """)
        btn_create.clicked.connect(self.accept)
        btn_layout.addWidget(btn_create)

        layout.addLayout(btn_layout)

    def _get_block_reason_display(self):
        """Get user-friendly display of why the connection was blocked"""
        event_type = self.log_entry.event_type
        action = self.log_entry.action

        if action == 'ALLOW':
            return "N/A (Connection was allowed)"

        reason_map = {
            'RULE': 'Firewall rule',
            'USER': 'User decision',
            'SESSION': 'Session cache',
            'CACHED': 'Cached decision',
            'BLOCK': 'Blocked',
        }
        return reason_map.get(event_type, event_type)

    def get_rule_config(self):
        """Get the rule configuration based on user selections"""
        # Get selected rule type
        selected_id = self.rule_type_group.checkedId()

        # Determine rule key based on selection
        if selected_id == 0 and self.log_entry.app_path and self.log_entry.app_path != '-':
            # Path-based
            rule_type = 'path'
            rule_key = self.log_entry.app_path
        elif selected_id == 1 and self.log_entry.app_name and self.log_entry.app_name != 'unknown':
            # Name-based
            rule_type = 'name'
            rule_key = f"@name:{self.log_entry.app_name}"
        else:
            # Destination-based
            rule_type = 'dest'
            rule_key = f"@dest:{self.log_entry.dest_ip}"

        # Duration
        duration_idx = self.duration_combo.currentIndex()
        duration = "always" if duration_idx == 0 else "session"

        return {
            'rule_type': rule_type,
            'rule_key': rule_key,
            'dest_ip': self.log_entry.dest_ip,
            'dest_port': int(self.log_entry.dest_port) if self.log_entry.dest_port.isdigit() else 0,
            'app_name': self.log_entry.app_name,
            'app_path': self.log_entry.app_path,
            'duration': duration,
            'all_ports': self.chk_all_ports.isChecked(),
            'clear_cache': self.chk_clear_cache.isChecked(),
            'allow': True,
        }
