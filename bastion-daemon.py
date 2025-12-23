#!/usr/bin/env python3
"""
Bastion Firewall Daemon - Entry Point
"""

import sys
import os
import logging
import atexit
import signal

# Ensure we can import the package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup basic logging before daemon starts
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/bastion-daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("bastion-daemon")


def _require_root() -> None:
    """Exit the program if not running as root.

    Set BASTION_SKIP_ROOT_CHECK=1 to bypass for testing environments.
    """
    if os.environ.get('BASTION_SKIP_ROOT_CHECK') == '1':
        logger.warning("Root check bypassed via BASTION_SKIP_ROOT_CHECK")
        return

    if not hasattr(os, 'geteuid'):
        logger.warning("os.geteuid() not available on this platform")
        return

    if os.geteuid() != 0:
        logger.error("Daemon must be run as root (use sudo)")
        print("ERROR: Daemon must be run as root (use sudo)", file=sys.stderr)
        sys.exit(1)


try:
    from bastion.daemon import BastionDaemon
except ImportError as e:
    logger.error(f"Failed to import bastion package: {e}")
    # Fallback to local import if installed differently
    try:
        sys.path.append('/usr/lib/python3/dist-packages')
        from bastion.daemon import BastionDaemon
    except ImportError:
        logger.critical("Could not load Bastion modules")
        sys.exit(1)


def main():
    _require_root()

    daemon = BastionDaemon()

    # Register cleanup
    def cleanup(signum=None, frame=None):
        logger.info("Stopping...")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    atexit.register(daemon.stop)

    try:
        daemon.start()
    except Exception as e:
        logger.critical(f"Daemon crashed: {e}")
        daemon.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()

