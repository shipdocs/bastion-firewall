#!/bin/bash
# Wrapper to start Douane.
# If daemon not running, start client (which starts daemon).
# If running, open control panel.

if pgrep -f "douane-daemon" > /dev/null; then
    # Daemon running, open control panel
    /usr/local/bin/douane-control-panel
else
    # Not running, start client (Start in background to release terminal if needed)
    /usr/local/bin/douane-gui-client &
    
    # Wait a bit and open control panel so user sees something
    sleep 2
    /usr/local/bin/douane-control-panel
fi
