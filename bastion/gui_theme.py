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
    """
    Retrieve a color hex string from the theme palette.
    
    Parameters:
        name (str): Key identifying the desired color in the module-level COLORS mapping.
        default (str): Hex color string to return if `name` is not present in COLORS.
    
    Returns:
        str: The hex color string associated with `name`, or `default` if not found.
    """
    return COLORS.get(name, default)


def get_string(key: str, default: str = "") -> str:
    """
    Retrieve a UI text string by key from the module's STRINGS dictionary.
    
    Parameters:
        key (str): The lookup key for the desired localized string.
        default (str): Fallback string returned when the key is not present in STRINGS.
    
    Returns:
        str: The string associated with `key`, or `default` if the key is not found.
    """
    return STRINGS.get(key, default)
