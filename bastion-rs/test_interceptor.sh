#!/bin/bash
set -e

echo ">>> Setting up iptables..."
# Ensure we don't duplicate
sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1 2>/dev/null || true
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1

echo ">>> Starting Bastion-RS..."
# Redirect stderr to stdout to capture logs
sudo ./target/debug/bastion-rs > rust_log.txt 2>&1 &
PID=$!
echo "Rust Daemon PID: $PID"

sleep 3

echo ">>> Generaring traffic (ping 1.1.1.1)..."
# We expect this to work if the Rust daemon is accepting packets
ping -c 2 1.1.1.1 || echo "Ping failed!"

echo ">>> Stopping Bastion-RS..."
sudo kill $PID
wait $PID 2>/dev/null || true

echo ">>> Cleaning up iptables..."
sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1

echo ">>> Done. Rust Output:"
cat rust_log.txt
