#!/usr/bin/env python3
"""
Icon Manager - Handles tray icon loading and status updates

Provides professional icons for different firewall states:
- Connected (green checkmark)
- Disconnected (gray)
- Error (red)
- Learning mode (blue)
"""

import logging
from pathlib import Path
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor
from PyQt6.QtCore import Qt

logger = logging.getLogger(__name__)


class IconManager:
    """Manages application icons"""

    # Icon paths
    ICON_DIR = Path(__file__).parent / 'resources'

    # Status-specific icon files
    STATUS_ICONS = {
        'connected': ICON_DIR / 'bastion-icon-connected.svg',
        'disconnected': ICON_DIR / 'bastion-icon-disconnected.svg',
        'error': ICON_DIR / 'bastion-icon-error.svg',
        'learning': ICON_DIR / 'bastion-icon-learning.svg',
        'warning': ICON_DIR / 'bastion-icon-warning.svg',
    }

    # Fallback icons (legacy)
    BASTION_ICON_PNG = ICON_DIR / 'bastion-icon.png'
    BASTION_ICON_SVG = ICON_DIR / 'bastion-icon.svg'

    # Status colors (for reference/fallback)
    COLORS = {
        'connected': '#98c379',    # Green
        'disconnected': '#5c6370', # Gray
        'error': '#e06c75',        # Red
        'learning': '#61afef',     # Blue
        'warning': '#e5c07b'       # Orange
    }
    
    @classmethod
    def get_icon(cls, status='connected'):
        """
        Get icon for given status

        Args:
            status: 'connected', 'disconnected', 'error', 'learning', 'warning'

        Returns:
            QIcon object
        """
        # Try to load status-specific icon first
        if status in cls.STATUS_ICONS:
            icon_path = cls.STATUS_ICONS[status]
            if icon_path.exists():
                try:
                    icon = QIcon(str(icon_path))
                    if not icon.isNull():
                        logger.debug(f"Loaded status-specific icon from {icon_path}")
                        return icon
                    else:
                        logger.warning(f"Status icon loaded but is null: {icon_path}")
                except Exception as e:
                    logger.warning(f"Failed to load status icon {icon_path}: {e}")
            else:
                logger.debug(f"Status icon not found: {icon_path}")

        # Fallback to generic custom icon (PNG preferred, then SVG)
        for icon_path in [cls.BASTION_ICON_PNG, cls.BASTION_ICON_SVG]:
            if icon_path.exists():
                try:
                    icon = QIcon(str(icon_path))
                    if not icon.isNull():
                        logger.debug(f"Loaded generic custom icon from {icon_path}")
                        return icon
                    else:
                        logger.warning(f"Custom icon loaded but is null: {icon_path}")
                except Exception as e:
                    logger.warning(f"Failed to load custom icon {icon_path}: {e}")

        logger.warning(f"Custom icon files not found: {cls.BASTION_ICON_SVG}, {cls.BASTION_ICON_PNG}")

        # Fallback to theme icons with status-specific colors
        fallback_icons = {
            'connected': 'security-high',
            'disconnected': 'security-low',
            'error': 'dialog-error',
            'learning': 'dialog-information',
            'warning': 'dialog-warning'
        }

        icon_name = fallback_icons.get(status, 'security-high')
        logger.debug(f"Using fallback icon: {icon_name} for status: {status}")

        # Try theme icon
        icon = QIcon.fromTheme(icon_name)
        if not icon.isNull():
            return icon

        # If theme icon fails, try other fallbacks
        fallback_chain = [
            'security-high',
            'security-medium',
            'system-lock-screen',
            'emblem-locked',
            'network-wired'
        ]

        for fallback in fallback_chain:
            icon = QIcon.fromTheme(fallback)
            if not icon.isNull():
                logger.debug(f"Using fallback icon: {fallback}")
                return icon

        # Last resort: return empty icon
        logger.warning("No suitable icon found, returning empty icon")
        return QIcon()
    
    @classmethod
    def get_status_icon(cls, connected=True, learning_mode=False, error=False):
        """
        Get appropriate icon based on firewall state
        
        Args:
            connected: Is daemon connected?
            learning_mode: Is firewall in learning mode?
            error: Is there an error?
            
        Returns:
            QIcon object
        """
        if error:
            return cls.get_icon('error')
        elif not connected:
            return cls.get_icon('disconnected')
        elif learning_mode:
            return cls.get_icon('learning')
        else:
            return cls.get_icon('connected')
    
    @classmethod
    def create_status_pixmap(cls, status='connected', size=64):
        """
        Create a pixmap with status indicator
        
        Args:
            status: Status string
            size: Icon size in pixels
            
        Returns:
            QPixmap object
        """
        # Create base pixmap
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        # Draw icon
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        
        icon = cls.get_icon(status)
        icon.paint(painter, 0, 0, size, size)
        
        # Draw status indicator circle
        color = QColor(cls.COLORS.get(status, cls.COLORS['disconnected']))
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        
        indicator_size = size // 4
        painter.drawEllipse(size - indicator_size - 4, size - indicator_size - 4, 
                           indicator_size, indicator_size)
        
        painter.end()
        return pixmap

