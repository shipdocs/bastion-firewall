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
    """Try to acquire a lock file. Returns file handle if successful, None if already running.

    The flock is taken first and is released by the kernel when the process
    dies, so no separate stale-PID check (and its TOCTOU window) is needed.
    """
    try:
        fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        lock_fd = os.fdopen(fd, 'r+')
    except OSError:
        return None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_fd.close()
        return None
    lock_fd.truncate(0)
    lock_fd.write(str(os.getpid()))
    lock_fd.flush()
    return lock_fd

if __name__ == '__main__':
    # Check for already running instance
    lock = acquire_lock()
    if lock is None:
        print("Bastion Control Panel is already running.")
        sys.exit(1)

    try:
        run_dashboard()
    finally:
        # Keep the lock file (removing it would race a new instance); closing releases the flock
        lock.close()
