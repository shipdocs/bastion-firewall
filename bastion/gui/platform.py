#!/usr/bin/env python3
"""
Platform detection utilities for Bastion Firewall GUI.
Detects windowing system (Wayland vs X11) for platform-specific behavior.
"""

import os
import logging

logger = logging.getLogger(__name__)

# Cache platform detection result
_platform_cache = None


def get_platform_name():
    """
    Detect the current windowing platform (Wayland, X11, etc.)
    
    Returns:
        str: 'wayland', 'xcb' (X11), or 'unknown'
    """
    try:
        from PyQt6.QtGui import QGuiApplication
        app = QGuiApplication.instance()
        if app:
            platform = app.platformName().lower()
            logger.info(f"Detected Qt platform: {platform}")
            return platform
    except Exception as e:
        logger.warning(f"Failed to detect platform: {e}")

    # Fallback: check environment variables
    if os.environ.get('WAYLAND_DISPLAY'):
        logger.info("Detected Wayland via WAYLAND_DISPLAY environment variable")
        return 'wayland'
    elif os.environ.get('DISPLAY'):
        logger.info("Detected X11 via DISPLAY environment variable")
        return 'xcb'

    return 'unknown'


def is_wayland():
    """
    Check if running on Wayland.
    
    Returns:
        bool: True if running on Wayland, False otherwise
    """
    global _platform_cache
    if _platform_cache is None:
        _platform_cache = get_platform_name()
    return _platform_cache == 'wayland'

