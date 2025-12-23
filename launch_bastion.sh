#!/bin/bash
# Wrapper to start Douane.
# If daemon not running, start client (which starts daemon).
# If running, open control panel.

# Debug logging
exec 1> >(tee -a "/tmp/bastion-launch.log") 2>&1
echo "--- Launching Bastion at $(date) ---"
echo "User: $(whoami)"
echo "Environment: $(env)"

# Check if GUI (Tray) is running
if ! pgrep -f "/usr/bin/bastion-gui" > /dev/null; then
    echo "Tray icon not running, starting..."
    /usr/bin/bastion-gui &
    sleep 1
else
    echo "Tray icon already running."
fi

# Always open control panel when launching from menu
echo "Opening control panel..."
/usr/bin/bastion-control-panel
