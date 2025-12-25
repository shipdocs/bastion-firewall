"""
Bastion Firewall - Shared Utility Functions
"""

import os
import sys
import logging

logger = logging.getLogger(__name__)


def require_root(allow_dev_mode: bool = False) -> None:
    """Exit the program if not running as root.

    Keeping the privilege check in a dedicated function prevents import-time
    failures, which improves testability and avoids surprises when the module
    is used as a library while still enforcing root for runtime execution.

    Args:
        allow_dev_mode: If True and --dev-mode is in sys.argv, skip root check.
                       This must be explicitly enabled by the caller.
    
    SECURITY NOTE: Root checking cannot be bypassed via environment variables
    for security reasons. Dev mode must be explicitly enabled via CLI flag.
    """
    # Check for explicit dev mode flag (must be in argv AND explicitly allowed)
    if allow_dev_mode and '--dev-mode' in sys.argv:
        logger.warning(f"⚠️  ROOT CHECK BYPASSED via --dev-mode flag")
        logger.warning(f"   PID: {os.getpid()}, UID: {os.getuid()}, EUID: {os.geteuid() if hasattr(os, 'geteuid') else 'N/A'}")
        logger.warning(f"   This mode is for development only and should never be used in production!")
        print("⚠️  WARNING: Running in development mode without root privileges", file=sys.stderr)
        print("   Firewall operations will likely fail. This is for testing only.", file=sys.stderr)
        return

    # Check if geteuid is available (Linux/Unix only)
    if not hasattr(os, 'geteuid'):
        logger.warning("os.geteuid() not available on this platform, skipping root check")
        return

    if os.geteuid() != 0:
        logger.error("This application must be run as root (use sudo)")
        print("ERROR: This application must be run as root (use sudo)", file=sys.stderr)
        print("       For development/testing, use: --dev-mode flag", file=sys.stderr)
        sys.exit(1)

