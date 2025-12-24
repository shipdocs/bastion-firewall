"""
GUI Theme Configuration

Centralized color scheme and styling for all GUI components.
Ensures consistent theming across the application.
"""

# One Dark Pro inspired color scheme
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

# GUI String Constants
STRINGS = {
    "usb_device_title": "Bastion - New USB Device",
    "usb_protection_active": "USB Protection Active",
    "usb_protection_disabled": "USB Protection Disabled",
    "usb_protection_enable": "Enable",
    "usb_protection_disable": "Disable",
    "usb_device_widget_title": "USB Device Control",
    "usb_allowed_devices": "Allowed Devices",
    "usb_blocked_devices": "Blocked Devices",
    "usb_allow_button": "Allow",
    "usb_block_button": "Block",
    "usb_delete_button": "Delete",
}


def get_color(name: str, default: str = "#ffffff") -> str:
    """Get color by name with fallback."""
    return COLORS.get(name, default)


def get_string(key: str, default: str = "") -> str:
    """Get localized string by key with fallback."""
    return STRINGS.get(key, default)

