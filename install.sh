#!/bin/bash
# Bastion Firewall Installer
# Handles dependency installation automatically

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./install.sh"
    exit 1
fi

DEB_FILE="bastion-firewall_2.0.0_all.deb"

if [ ! -f "$DEB_FILE" ]; then
    echo "ERROR: $DEB_FILE not found in current directory"
    exit 1
fi

echo "Installing Bastion Firewall v2.0.0..."
echo ""

# Install the package and dependencies
apt-get install -y ./"$DEB_FILE"

echo ""
echo "✅ Bastion Firewall installed successfully!"
echo ""
echo "To start: Search for 'Bastion Firewall' in your application menu"
