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
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtSvg import QSvgRenderer

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
    def _render_svg_to_icon(cls, svg_path, sizes=[16, 22, 24, 32, 48, 64, 128]):
        """
        Render SVG to QIcon with multiple sizes for proper tray display.
        Qt6 system tray often has issues with raw SVG files.
        """
        try:
            renderer = QSvgRenderer(str(svg_path))
            if not renderer.isValid():
                logger.warning(f"Invalid SVG file: {svg_path}")
                return None

            icon = QIcon()
            for size in sizes:
                pixmap = QPixmap(QSize(size, size))
                pixmap.fill(Qt.GlobalColor.transparent)
                painter = QPainter(pixmap)
                renderer.render(painter)
                painter.end()
                icon.addPixmap(pixmap)

            logger.debug(f"Rendered SVG to icon with sizes: {sizes}")
            return icon
        except Exception as e:
            logger.warning(f"Failed to render SVG {svg_path}: {e}")
            return None

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
                # Render SVG to pixmap for reliable tray display
                icon = cls._render_svg_to_icon(icon_path)
                if icon and not icon.isNull():
                    logger.debug(f"Loaded status-specific icon from {icon_path}")
                    return icon
                else:
                    logger.warning(f"Status icon render failed: {icon_path}")
            else:
                logger.debug(f"Status icon not found: {icon_path}")

        # Fallback to generic custom icon (PNG preferred for reliability)
        if cls.BASTION_ICON_PNG.exists():
            try:
                icon = QIcon(str(cls.BASTION_ICON_PNG))
                if not icon.isNull():
                    logger.debug(f"Loaded PNG icon from {cls.BASTION_ICON_PNG}")
                    return icon
            except Exception as e:
                logger.warning(f"Failed to load PNG icon: {e}")

        # Try SVG fallback
        if cls.BASTION_ICON_SVG.exists():
            icon = cls._render_svg_to_icon(cls.BASTION_ICON_SVG)
            if icon and not icon.isNull():
                logger.debug(f"Loaded SVG icon from {cls.BASTION_ICON_SVG}")
                return icon

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

