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


try:
    from bastion.daemon import BastionDaemon
    from bastion.utils import require_root
except ImportError as e:
    logger.error(f"Failed to import bastion package: {e}")
    # Fallback to local import if installed differently
    try:
        sys.path.append('/usr/lib/python3/dist-packages')
        from bastion.daemon import BastionDaemon
        from bastion.utils import require_root
    except ImportError:
        logger.critical("Could not load Bastion modules")
        sys.exit(1)


def main():
    require_root()

    daemon = BastionDaemon()

    # Register cleanup - prefix unused params with _ to indicate intentional
    def cleanup(_signum=None, _frame=None):
        logger.info("Stopping...")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    atexit.register(daemon.stop)

    try:
        daemon.start()
    except Exception:
        # Use logging.exception for automatic traceback inclusion
        logger.exception("Daemon crashed")
        daemon.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()

