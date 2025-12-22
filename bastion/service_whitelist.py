#!/usr/bin/env python3
"""
Service Whitelist - Smart auto-allow for known services on standard ports

This module defines which applications should be automatically allowed
for specific ports without prompting the user.

SECURITY MODEL:
- Standaard Linux: 100% open (alles toegestaan)
- Douane zonder whitelist: Vraagt gebruiker voor ALLES (inclusief DNS, DHCP)
- Douane met whitelist: Auto-allow alleen bekende system services op verwachte poorten

DESIGN PRINCIPLES:
1. Exacte naam matching (geen substring) + path validatie
2. Port restrictions voor trusted apps (defense-in-depth)
3. Localhost: alleen bekende services, rest vraagt gebruiker
4. DHCP: alleen bekende clients naar broadcast/link-local
5. Onbekende apps: altijd blokkeren (gebruiker beslist)
"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# Port -> List of allowed application names (EXACT match required)
# RESTRICTIVE: Only essential system services
SERVICE_WHITELIST = {
    # DNS - Essential for name resolution
    53: ['systemd-resolved', 'dnsmasq'],

    # NTP - Essential for time sync
    123: ['systemd-timesyncd', 'ntpd', 'chronyd'],

    # DHCP - Essential for network configuration
    67: ['dhclient', 'dhcpcd', 'NetworkManager', 'systemd-networkd'],
    68: ['dhclient', 'dhcpcd', 'NetworkManager', 'systemd-networkd'],

    # Package managers - Only for system updates (apt, snap)
    80: ['apt', 'apt-get', 'aptitude', 'unattended-upgrade', 'snapd'],
    443: ['apt', 'apt-get', 'aptitude', 'unattended-upgrade', 'snapd'],
}


# Trusted applications with their allowed ports (port restriction for security)
# Format: app_name -> [allowed_ports]
TRUSTED_APP_PORTS = {
    'systemd-resolved': [53],                    # DNS only
    'systemd-timesyncd': [123],                  # NTP only
    'NetworkManager': [53, 67, 68, 123, 5353],  # DNS, DHCP, NTP, mDNS
    'systemd-networkd': [53, 67, 68, 123],      # DNS, DHCP, NTP
    'dhclient': [67, 68],                        # DHCP only
    'dhcpcd': [67, 68],                          # DHCP only
    'avahi-daemon': [5353],                      # mDNS only
}


# Known DHCP clients (for validation)
KNOWN_DHCP_CLIENTS = ['dhclient', 'dhcpcd', 'NetworkManager', 'systemd-networkd']


# Legitimate DHCP destinations
DHCP_BROADCAST_IPS = ['255.255.255.255', '0.0.0.0']


# Localhost services that are auto-allowed (service_name, port, ip)
# All other localhost connections will prompt the user
LOCALHOST_WHITELIST = {
    ('systemd-resolved', 53, '127.0.0.53'),  # systemd DNS stub resolver
    ('dnsmasq', 53, '127.0.0.1'),            # dnsmasq DNS
}


def should_auto_allow(app_name: str, app_path: str, dest_port: int, dest_ip: str) -> tuple[bool, str]:
    """
    Check if an application should be automatically allowed.

    SECURITY HARDENING (v2.0.18):
    - Localhost: Only whitelisted services (prevents tunnel bypass)
    - DHCP: Only known clients to broadcast IPs (prevents exfiltration)
    - Trusted apps: Port-restricted + path validation (defense-in-depth)
    - String matching: Exact match + system path check (prevents spoofing)

    Args:
        app_name: Application name (e.g., 'firefox') - CAN BE None
        app_path: Full path to application - CAN BE None
        dest_port: Destination port
        dest_ip: Destination IP

    Returns:
        (should_allow, reason) tuple
    """

    # ============================================================================
    # PHASE 1: LOCALHOST CONNECTIONS (HARDENED)
    # ============================================================================
    # Only allow specific known services on localhost
    # All other localhost connections will be prompted to user

    if dest_ip.startswith('127.') or dest_ip == 'localhost':
        # EXCEPTION: DNS queries to localhost resolver (127.0.0.53) are ALWAYS allowed
        # This is systemd-resolved, and blocking it breaks ALL network connectivity
        # ANY application should be able to resolve DNS
        if dest_port == 53 and dest_ip in ['127.0.0.53', '127.0.0.1', '127.0.1.1']:
            logger.debug(f"Auto-allowing DNS query to localhost resolver: {app_name or 'unknown'} -> {dest_ip}:53")
            return (True, "DNS to localhost resolver")

        if app_name and app_path:
            # Check if this is a whitelisted localhost service
            for service_name, service_port, service_ip in LOCALHOST_WHITELIST:
                if (service_name.lower() == app_name.lower() and
                    dest_port == service_port and
                    is_system_service(app_path)):
                    logger.info(f"Auto-allowing localhost service: {app_name}:{dest_port}")
                    return (True, f"Localhost service: {service_name}")

        if dest_port > 1024:
            # Ephemeral/High ports on localhost are typically IPC (Inter-Process Communication)
            # Blocking them for "unknown" apps (short-lived processes) causes excessive popups
            # for unlikely threats. Auto-allow to improve UX.
            logger.info(f"Auto-allowing anonymous localhost IPC: {app_name or 'unidentified'} -> {dest_ip}:{dest_port}")
            return (True, "Anonymous Localhost IPC")

        # Unknown localhost connection on privileged port - ask user (prevents tunnel bypass)
        logger.warning(f"Unknown localhost connection: {app_name or 'unidentified'} -> {dest_ip}:{dest_port}")
        return (False, "")

    # ============================================================================
    # PHASE 2: DHCP HARDENING
    # ============================================================================
    # Only allow known DHCP clients to broadcast/link-local addresses
    if dest_port in [67, 68]:
        # Check if destination is a valid DHCP target
        is_broadcast = dest_ip in DHCP_BROADCAST_IPS
        is_link_local = dest_ip.startswith('169.254.')

        if is_broadcast or is_link_local:
            # Check if it's a known DHCP client
            if app_name:
                for dhcp_client in KNOWN_DHCP_CLIENTS:
                    if dhcp_client.lower() == app_name.lower():
                        if is_system_service(app_path):
                            logger.info(f"Auto-allowing DHCP client: {app_name} -> {dest_ip}")
                            return (True, f"DHCP client: {app_name}")
                        else:
                            logger.warning(f"DHCP client name matches but not in system path: {app_path}")
                            return (False, "")

            # Unknown DHCP client - ask user
            logger.warning(f"Unknown DHCP client: {app_name or 'unidentified'} -> {dest_ip}:{dest_port}")
            return (False, "")
        else:
            # DHCP to non-broadcast IP - suspicious!
            logger.warning(f"Suspicious DHCP to {dest_ip}: {app_name or 'unidentified'}")
            return (False, "")

    # ============================================================================
    # PHASE 3: APPLICATION IDENTIFICATION
    # ============================================================================
    # If app cannot be identified, block it (security-first approach)
    if not app_name or not app_path:
        logger.warning(f"Could not identify application for {dest_ip}:{dest_port}")
        return (False, "")

    app_name_lower = app_name.lower()

    # ============================================================================
    # PHASE 4 & 5: TRUSTED APPLICATIONS (HARDENED)
    # ============================================================================
    # Check trusted applications with port restrictions and path validation
    if app_name_lower in TRUSTED_APP_PORTS:
        # Check if port is allowed for this app
        if dest_port in TRUSTED_APP_PORTS[app_name_lower]:
            # Validate it's actually a system service
            if is_system_service(app_path):
                logger.info(f"Auto-allowing trusted app: {app_name} on port {dest_port}")
                return (True, f"Trusted service: {app_name}")
            else:
                logger.warning(f"App name '{app_name}' matches trusted app but not in system path: {app_path}")
                return (False, "")
        else:
            # Trusted app on unexpected port - ask user
            logger.warning(f"Trusted app '{app_name}' on unexpected port {dest_port}")
            return (False, "")

    # ============================================================================
    # SERVICE WHITELIST (HARDENED)
    # ============================================================================
    # Check service whitelist for specific ports with exact matching
    if dest_port in SERVICE_WHITELIST:
        allowed_apps = SERVICE_WHITELIST[dest_port]
        for allowed in allowed_apps:
            # EXACT match (not substring) to prevent spoofing
            if allowed.lower() == app_name_lower:
                # Validate system path
                if is_system_service(app_path):
                    logger.info(f"Auto-allowing {app_name} on port {dest_port} (known service)")
                    return (True, f"Known service on port {dest_port}")
                else:
                    logger.warning(f"Service name '{app_name}' matches but not in system path: {app_path}")
                    return (False, "")

    # No whitelist match - ask user
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


def is_critical_system_service(app_name: str, app_path: str, dest_port: int, dest_ip: str) -> bool:
    """
    Check if this is a CRITICAL system service that must work even without GUI.

    These are services that if blocked, would break the system or network connectivity.
    This is used as a fallback when GUI is not connected in enforcement mode.

    Args:
        app_name: Application name (can be None)
        app_path: Application path (can be None)
        dest_port: Destination port
        dest_ip: Destination IP

    Returns:
        True if this is a critical system service that should always be allowed
    """
    # CRITICAL: DNS queries to localhost resolver (systemd-resolved)
    # ANY app can query DNS, this is essential for network to work
    if dest_port == 53 and (dest_ip.startswith('127.') or dest_ip == 'localhost'):
        logger.debug(f"Auto-allowing DNS query to localhost resolver: {app_name or 'unknown'} -> {dest_ip}:53")
        return True

    if not app_name or not app_path:
        return False

    app_name_lower = app_name.lower()

    # CRITICAL: DNS resolution services themselves
    if dest_port == 53:
        if app_name_lower in ['systemd-resolved', 'dnsmasq']:
            if is_system_service(app_path):
                return True

    # CRITICAL: DHCP (without this, no network configuration)
    if dest_port in [67, 68]:
        if app_name_lower in ['dhclient', 'dhcpcd', 'networkmanager', 'systemd-networkd']:
            if is_system_service(app_path):
                return True

    # CRITICAL: NTP (time sync - needed for SSL/TLS)
    if dest_port == 123:
        if app_name_lower in ['systemd-timesyncd', 'ntpd', 'chronyd']:
            if is_system_service(app_path):
                return True

    # NOT critical: Package managers (can wait for GUI)
    # NOT critical: Browsers (can wait for GUI)
    # NOT critical: mDNS/Avahi (nice to have, not critical)

    return False

