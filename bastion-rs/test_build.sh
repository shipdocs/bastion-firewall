#!/bin/bash
set -e

echo ">>> Building Rust daemon (without eBPF for now)..."

# Build the daemon
cd /home/martin/Ontwikkel/bastion-firewall/bastion-rs
cargo build

if [ $? -eq 0 ]; then
    echo "✅ Build successful"
    echo ">>> Testing with safe script..."
    ./test_safe.sh
else
    echo "❌ Build failed"
    exit 1
fi