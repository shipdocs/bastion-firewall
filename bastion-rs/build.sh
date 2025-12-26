#!/bin/bash
set -e

echo "╔══════════════════════════════════════════╗"
echo "║  Building Bastion Daemon (Rust)          ║"
echo "╚══════════════════════════════════════════╝"

cd "$(dirname "$0")"

# Build release binary
echo ">>> Building release binary..."
cargo build --release

# Check binary size
ls -lh target/release/bastion-daemon

echo ""
echo "Build complete!"
echo ""
echo "To install manually:"
echo "  sudo cp target/release/bastion-daemon /usr/bin/"
echo "  sudo cp bastion-daemon.service /etc/systemd/system/"
echo "  sudo mkdir -p /etc/bastion /var/run/bastion"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable bastion-firewall"
echo "  sudo systemctl start bastion-firewall"
