"""
Bastion Firewall GUI Package
Modern Qt6-based interface for firewall management.
"""

from .platform import get_platform_name, is_wayland
from .theme import COLORS, STYLESHEET

__all__ = [
    'get_platform_name',
    'is_wayland',
    'COLORS',
    'STYLESHEET',
]

