#!/usr/bin/env python3
"""
Bastion Firewall Control Panel - Main GUI window
"""
import sys
import os
import fcntl

# Support private module install (RPM/Fedora)
if os.path.exists("/usr/share/bastion-firewall"):
    sys.path.insert(0, "/usr/share/bastion-firewall")

from bastion.gui_qt import run_dashboard

# Lock file to prevent multiple control panel instances
LOCK_FILE = f'/tmp/bastion-control-panel-{os.getuid()}.lock'

def acquire_lock():
    """Try to acquire a lock file. Returns file handle if successful, None if already running."""
    try:
        # Check if stale lock (process died without cleanup)
        if os.path.exists(LOCK_FILE):
            try:
                with open(LOCK_FILE, 'r') as f:
                    old_pid = int(f.read().strip())
                # Check if process is still running
                os.kill(old_pid, 0)  # Raises OSError if not running
            except (ValueError, OSError):
                # Stale lock or invalid PID - remove it
                os.remove(LOCK_FILE)

        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.write(str(os.getpid()))
        lock_fd.flush()
        return lock_fd
    except (IOError, OSError):
        return None

if __name__ == '__main__':
    # Check for already running instance
    lock = acquire_lock()
    if lock is None:
        print("Bastion Control Panel is already running.")
        sys.exit(1)

    try:
        run_dashboard()
    finally:
        # Clean up lock file on exit
        try:
            os.remove(LOCK_FILE)
        except OSError:
            pass
        lock.close()
