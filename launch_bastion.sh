#!/bin/bash
# Wrapper to start Douane.
# If daemon not running, start client (which starts daemon).
# If running, open control panel.

# Debug logging
exec 1> >(tee -a "/tmp/bastion-launch.log") 2>&1
echo "--- Launching Bastion at $(date) ---"
echo "User: $(whoami)"
echo "Environment: $(env)"

if pgrep -f "bastion-daemon" > /dev/null; then
    echo "Daemon found, opening control panel..."
    /usr/bin/bastion-control-panel
else
    echo "Daemon not found, starting GUI client..."
    # Not running, start client (Start in background to release terminal if needed)
    /usr/bin/bastion-gui &
    
    # Wait a bit and open control panel so user sees something
    sleep 2
    echo "Opening control panel..."
    /usr/bin/bastion-control-panel
fi
