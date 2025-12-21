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

# Check root privileges
if os.geteuid() != 0:
    print("ERROR: Daemon must be run as root (use sudo)")
    sys.exit(1)

# Setup basic logging before daemon starts
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/bastion-daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("douane-entry")

try:
    from bastion.daemon import DouaneDaemon
except ImportError as e:
    logger.error(f"Failed to import bastion package: {e}")
    # Fallback to local import if installed differently
    try:
        sys.path.append('/usr/local/lib/python3/dist-packages')
        from bastion.daemon import DouaneDaemon
    except ImportError:
        logger.critical("Could not load Douane modules")
        sys.exit(1)

def main():
    daemon = DouaneDaemon()
    
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

