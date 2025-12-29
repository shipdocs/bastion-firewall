#!/usr/bin/env python3
"""
Theme and styling constants for Bastion Firewall GUI.
Modern dark theme with consistent color palette.
"""

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

