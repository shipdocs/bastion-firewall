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
    BASTION_ICON = ICON_DIR / 'bastion-icon.svg'
    
    # Status colors
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
        # Try to load custom icon first
        if cls.BASTION_ICON.exists():
            try:
                icon = QIcon(str(cls.BASTION_ICON))
                if not icon.isNull():
                    return icon
            except Exception as e:
                logger.warning(f"Failed to load custom icon: {e}")
        
        # Fallback to theme icons
        fallback_icons = {
            'connected': 'security-high',
            'disconnected': 'security-low',
            'error': 'dialog-error',
            'learning': 'dialog-information',
            'warning': 'dialog-warning'
        }
        
        icon_name = fallback_icons.get(status, 'security-high')
        return QIcon.fromTheme(icon_name)
    
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

