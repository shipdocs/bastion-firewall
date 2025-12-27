#!/bin/bash
# Quick test script for eBPF-enabled daemon

echo ">>> Setting up iptables rules..."
echo 'Texel21' | sudo -S iptables -I OUTPUT 1 -j NFQUEUE --queue-num 1

echo ""
echo ">>> Starting daemon with eBPF support..."
echo ">>> (Press Ctrl+C to stop)"
echo ""

# Run daemon with debug logging
echo 'Texel21' | sudo -S RUST_LOG=debug ./target/release/bastion-daemon
