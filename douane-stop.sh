#!/bin/bash
# Stop Douane Firewall cleanly

echo "============================================================"
echo "Stopping Douane Firewall"
echo "============================================================"

# Stop GUI client
echo "Stopping GUI client..."
pkill -f douane-gui-client 2>/dev/null
sleep 1

# Stop daemon
echo "Stopping daemon..."
sudo pkill -f douane-daemon 2>/dev/null
sleep 1

# Remove socket
echo "Removing socket..."
sudo rm -f /tmp/douane-daemon.sock

# Remove iptables NFQUEUE rules (all of them)
echo "Removing iptables rules..."
while sudo iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null; do
    echo "  Removed NFQUEUE rule"
done

# Verify no NFQUEUE rules remain
NFQUEUE_COUNT=$(sudo iptables -L OUTPUT -n | grep -c NFQUEUE || true)
if [ "$NFQUEUE_COUNT" -gt 0 ]; then
    echo "⚠️  WARNING: $NFQUEUE_COUNT NFQUEUE rules still present!"
    echo "Trying to remove all NFQUEUE rules..."
    sudo iptables -S OUTPUT | grep NFQUEUE | cut -d' ' -f2- | while read rule; do
        sudo iptables -D OUTPUT $rule
    done
fi

# Ensure UFW allows outbound
echo "Ensuring UFW allows outbound..."
sudo ufw default allow outgoing >/dev/null 2>&1
sudo ufw reload >/dev/null 2>&1

# Test connectivity
echo ""
echo "Testing connectivity..."
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "✓ Internet connection working"
else
    echo "⚠️  WARNING: No internet connection!"
    echo "   Try: sudo ufw disable && sudo ufw enable"
fi

echo ""
echo "============================================================"
echo "✓ Douane Firewall stopped"
echo "============================================================"
echo ""
echo "To verify:"
echo "  sudo iptables -L OUTPUT -n | grep NFQUEUE"
echo "  (should show nothing)"
echo ""
echo "If connection still broken:"
echo "  sudo iptables -F OUTPUT"
echo "  sudo ufw reload"

