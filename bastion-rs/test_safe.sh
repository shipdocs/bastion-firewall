#!/bin/bash
# Safe test script for Rust interceptor
# Uses --queue-bypass so traffic flows if daemon isn't running

set -e

cleanup() {
    echo ">>> Cleaning up iptables..."
    sudo iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || true
    sudo pkill -9 bastion-rs 2>/dev/null || true
}

# Always cleanup on exit
trap cleanup EXIT

echo ">>> Building..."
cargo build

echo ">>> Starting Rust Daemon in background..."
sudo ./target/debug/bastion-rs &
DAEMON_PID=$!
sleep 1

echo ">>> Adding iptables rule (with --queue-bypass for safety)..."
sudo iptables -I OUTPUT 1 -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass

echo ">>> Generating test traffic..."
ping -c 2 1.1.1.1 || echo "Ping failed"
curl -s --max-time 3 https://example.com > /dev/null && echo "HTTPS works!" || echo "HTTPS failed"

echo ">>> Stopping daemon..."
sudo kill $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true

echo ">>> Done!"
