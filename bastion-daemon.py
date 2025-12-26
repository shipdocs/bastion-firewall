#!/usr/bin/env python3
"""
Bastion Firewall Daemon - Entry Point
"""

import argparse
import sys
import os
import logging
import atexit
import signal

# Ensure we can import the package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup basic logging before daemon starts
log_file = '/var/log/bastion-daemon.log'

# Ensure log directory exists with proper permissions
os.makedirs(os.path.dirname(log_file), mode=0o755, exist_ok=True)

# Create a custom FileHandler to set proper permissions
class PermissionFileHandler(logging.FileHandler):
    def __init__(self, filename, mode='a', encoding=None, delay=False):
        super().__init__(filename, mode, encoding, delay)
    
    def _open(self):
        # Call parent's _open to create the file
        super()._open()
        # Set proper permissions (640 = rw-r-----)
        try:
            import grp
            os.chmod(self.baseFilename, 0o640)
            # Try to set group to bastion if the group exists
            try:
                bastion_gid = grp.getgrnam('bastion').gr_gid
                os.chown(self.baseFilename, 0, bastion_gid)  # root:bastion
            except KeyError:
                # Group doesn't exist, just keep default
                pass
        except (OSError, ImportError):
            # Fail silently if we can't set permissions
            pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        PermissionFileHandler(log_file),
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
    parser = argparse.ArgumentParser(description="Bastion Firewall daemon")
    parser.add_argument('--health-check', action='store_true', help="Report daemon GUI connectivity and headless policy")
    parser.add_argument('--health-port', type=int, help="Override health endpoint port when querying")
    args = parser.parse_args()

    if args.health_check:
        daemon = BastionDaemon()
        port = args.health_port or daemon.config.get('health_port', 8676)
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as resp:
                print(resp.read().decode())
                return
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            print(f"Health check failed: {e}")
            sys.exit(1)

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
