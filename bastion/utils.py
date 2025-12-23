"""
Bastion Firewall - Shared Utility Functions
"""

import os
import sys
import logging

logger = logging.getLogger(__name__)


def require_root() -> None:
    """Exit the program if not running as root.

    Keeping the privilege check in a dedicated function prevents import-time
    failures, which improves testability and avoids surprises when the module
    is used as a library while still enforcing root for runtime execution.

    Set BASTION_SKIP_ROOT_CHECK=1 to bypass for testing environments.
    """
    # Allow bypass for test environments
    if os.environ.get('BASTION_SKIP_ROOT_CHECK') == '1':
        logger.warning("Root check bypassed via BASTION_SKIP_ROOT_CHECK")
        return

    # Check if geteuid is available (Linux/Unix only)
    if not hasattr(os, 'geteuid'):
        logger.warning("os.geteuid() not available on this platform, skipping root check")
        return

    if os.geteuid() != 0:
        logger.error("This application must be run as root (use sudo)")
        print("ERROR: This application must be run as root (use sudo)", file=sys.stderr)
        sys.exit(1)

