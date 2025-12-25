"""
Bastion Firewall - Shared Utility Functions
"""

import os
import sys
import logging

logger = logging.getLogger(__name__)


def require_root(build_mode: bool = False) -> None:
    """Exit program if not running as root.

    SECURITY: Root privileges are required for firewall operations.
    This function prevents privilege escalation and ensures proper security boundaries.
    
    Args:
        build_mode: If True, allows running without root ONLY during build/package testing
    
    SECURITY NOTE: 
    - Dev mode bypass has been removed for production security
    - Only build_mode is allowed for package testing scenarios
    - Environment variable bypasses are explicitly blocked
    """
    # SECURITY: Explicitly block any environment variable bypass attempts
    if os.environ.get('BASTION_SKIP_ROOT_CHECK'):
        logger.critical("SECURITY ALERT: BASTION_SKIP_ROOT_CHECK environment variable detected")
        logger.critical("This bypass mechanism has been removed for security reasons")
        print("CRITICAL: Environment variable bypass detected and blocked", file=sys.stderr)
        sys.exit(1)
    
    # Allow build mode ONLY for package testing (not runtime)
    if build_mode and '--build-mode' in sys.argv:
        logger.warning("BUILD MODE: Running without root for package testing only")
        print("WARNING: Build mode active - firewall operations will be simulated", file=sys.stderr)
        return

    # Check if geteuid is available (Linux/Unix only)
    if not hasattr(os, 'geteuid'):
        logger.error("Platform does not support privilege checking")
        print("ERROR: This platform is not supported for security operations", file=sys.stderr)
        sys.exit(1)

    if os.geteuid() != 0:
        logger.error("SECURITY: Application must be run as root (use sudo)")
        print("ERROR: This application must be run as root (use sudo)", file=sys.stderr)
        print("       Root privileges are required for firewall operations", file=sys.stderr)
        sys.exit(1)
