#!/usr/bin/env python3
"""
Service Whitelist - Smart auto-allow for known services on standard ports

This module defines which applications should be automatically allowed
for specific ports without prompting the user.
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# Port -> List of allowed application names (case-insensitive partial match)
# RESTRICTIVE: Only essential system services, like on a server
SERVICE_WHITELIST = {
    # DNS - Essential for name resolution
    53: ['systemd-resolved', 'dnsmasq'],

    # NTP - Essential for time sync
    123: ['systemd-timesyncd', 'ntpd', 'chronyd'],

    # DHCP - Essential for network configuration
    67: ['dhclient', 'dhcpcd', 'NetworkManager'],
    68: ['dhclient', 'dhcpcd', 'NetworkManager'],

    # Package managers - Only for system updates (apt, snap)
    80: ['apt', 'apt-get', 'aptitude', 'unattended-upgrade'],
    443: ['apt', 'apt-get', 'aptitude', 'unattended-upgrade'],
}


# Always allow these applications regardless of port
TRUSTED_APPLICATIONS = [
    'systemd-resolved',  # DNS resolver
    'systemd-timesyncd',  # Time sync
    'NetworkManager',     # Network management
    'dhclient',          # DHCP client
    'avahi-daemon',      # mDNS/Zeroconf
]


def should_auto_allow(app_name: str, app_path: str, dest_port: int, dest_ip: str) -> tuple[bool, str]:
    """
    Check if an application should be automatically allowed.

    Args:
        app_name: Application name (e.g., 'firefox')
        app_path: Full path to application
        dest_port: Destination port
        dest_ip: Destination IP

    Returns:
        (should_allow, reason) tuple
    """
    # Check localhost connections FIRST (always allow, even for unknown apps)
    if dest_ip.startswith('127.') or dest_ip == 'localhost':
        logger.debug(f"Auto-allowing localhost connection: {app_name or 'unknown'}")
        return (True, "Localhost connection")

    if not app_name:
        return (False, "")

    app_name_lower = app_name.lower()

    # Check trusted applications (always allow)
    for trusted in TRUSTED_APPLICATIONS:
        if trusted.lower() in app_name_lower:
            logger.info(f"Auto-allowing trusted application: {app_name}")
            return (True, f"Trusted system service: {app_name}")
    
    # Check service whitelist for specific ports
    if dest_port in SERVICE_WHITELIST:
        allowed_apps = SERVICE_WHITELIST[dest_port]
        for allowed in allowed_apps:
            if allowed.lower() in app_name_lower:
                logger.info(f"Auto-allowing {app_name} on port {dest_port} (known service)")
                return (True, f"Known service on port {dest_port}")
    
    return (False, "")


def is_system_service(app_path: str) -> bool:
    """
    Check if an application is a system service.
    
    System services are typically in /usr/bin, /usr/sbin, /bin, /sbin
    """
    if not app_path:
        return False
    
    path = Path(app_path)
    system_dirs = ['/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/lib', '/lib']
    
    for sys_dir in system_dirs:
        if str(path).startswith(sys_dir):
            return True
    
    return False


def get_app_category(app_name: str, app_path: str) -> str:
    """
    Get a human-readable category for an application.
    
    Returns:
        Category string like "Web Browser", "System Service", etc.
    """
    if not app_name:
        return "Unknown"
    
    app_name_lower = app_name.lower()
    
    # Browsers
    if any(browser in app_name_lower for browser in ['firefox', 'chrome', 'chromium', 'safari', 'edge']):
        return "Web Browser"
    
    # Email clients
    if any(mail in app_name_lower for mail in ['thunderbird', 'evolution', 'outlook', 'mail']):
        return "Email Client"
    
    # Development tools
    if any(dev in app_name_lower for dev in ['code', 'vscode', 'git', 'python', 'node', 'npm']):
        return "Development Tool"
    
    # System services
    if any(sys in app_name_lower for sys in ['systemd', 'networkmanager', 'dhcp', 'avahi']):
        return "System Service"
    
    # Package managers
    if any(pkg in app_name_lower for pkg in ['apt', 'snap', 'flatpak', 'dpkg', 'packagekit']):
        return "Package Manager"
    
    # Check if it's in system directories
    if is_system_service(app_path):
        return "System Application"
    
    return "Application"

