#!/bin/bash
# Safe test script with automatic cleanup

SUDO_PASS="Texel21"

cleanup() {
    echo ""
    echo ">>> Cleaning up..."
    echo "$SUDO_PASS" | sudo -S pkill -9 bastion-daemon 2>/dev/null
    echo "$SUDO_PASS" | sudo -S iptables -F OUTPUT 2>/dev/null
    echo "✅ Cleanup complete - Internet restored"
}

# Setup cleanup on exit
trap cleanup EXIT INT TERM

echo ">>> Setting up test environment..."
# Clear any existing rules
echo "$SUDO_PASS" | sudo -S iptables -F OUTPUT

# Start daemon in background
echo ">>> Starting daemon..."
echo "$SUDO_PASS" | sudo -S RUST_LOG=info ./target/release/bastion-daemon &
DAEMON_PID=$!

# Wait for daemon to initialize
sleep 2

# Check if daemon is still running
if ! ps -p $DAEMON_PID > /dev/null; then
    echo "❌ Daemon failed to start"
    exit 1
fi

echo "✅ Daemon started (PID: $DAEMON_PID)"

# Add iptables rule AFTER daemon is ready
echo ">>> Adding iptables rule..."
echo "$SUDO_PASS" | sudo -S iptables -I OUTPUT 1 -j NFQUEUE --queue-num 1

echo ""
echo ">>> Testing basic connectivity..."
echo ">>> Trying DNS lookup..."
timeout 2 nslookup google.com 8.8.8.8 && echo "✅ DNS works" || echo "❌ DNS failed"

echo ""
echo ">>> Trying HTTP request..."
timeout 5 curl -I https://example.com && echo "✅ HTTP works" || echo "❌ HTTP failed"

echo ""
echo ">>> Daemon will run for 10 more seconds..."
echo ">>> Check logs above for eBPF activity"
sleep 10

echo ""
echo ">>> Test complete!"