#!/bin/bash
# Start Douane Firewall cleanly

echo "============================================================"
echo "Starting Douane Firewall"
echo "============================================================"

# First, ensure everything is stopped
echo "Ensuring clean state..."
pkill -f douane-gui-client 2>/dev/null
sudo pkill -f douane-daemon 2>/dev/null
sudo rm -f /tmp/douane-daemon.sock
sleep 1

# Remove any leftover iptables rules
while sudo iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null; do
    echo "  Removed leftover NFQUEUE rule"
done

# Ensure UFW allows outbound (learning mode)
echo "Configuring UFW for learning mode..."
sudo ufw default allow outgoing >/dev/null 2>&1
sudo ufw reload >/dev/null 2>&1

# Test connectivity before starting
echo "Testing connectivity..."
if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "⚠️  WARNING: No internet connection before starting!"
    echo "   Fix your connection first, then try again."
    exit 1
fi
echo "✓ Internet working"

# Start the GUI client (which will start the daemon)
echo ""
echo "Starting Douane Firewall GUI..."
echo "(This will ask for your sudo password)"
echo ""

python3 /usr/local/bin/douane-gui-client &
GUI_PID=$!

sleep 3

# Check if it's running
if ps -p $GUI_PID > /dev/null 2>&1; then
    echo ""
    echo "============================================================"
    echo "✓ Douane Firewall started!"
    echo "============================================================"
    echo ""
    echo "GUI Client PID: $GUI_PID"
    echo ""
    echo "Try opening a browser or running: curl https://example.com"
    echo "You should see a popup asking for permission."
    echo ""
    echo "To stop: ./douane-stop.sh"
    echo ""
else
    echo ""
    echo "⚠️  Failed to start GUI client"
    echo "Check the logs for errors"
    exit 1
fi

