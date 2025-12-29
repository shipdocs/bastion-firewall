#!/bin/bash
# Bastion Firewall Installer
# Handles dependency installation automatically

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./install.sh"
    exit 1
fi

DEB_FILE="bastion-firewall_2.0.0_all.deb"

# Optional: Verify package integrity (recommended for security)
# Uncomment and set the expected SHA256 hash to enable verification
# Generate hash with: sha256sum bastion-firewall_2.0.0_all.deb
# EXPECTED_SHA256="your_sha256_hash_here"

if [ ! -f "$DEB_FILE" ]; then
    echo "ERROR: $DEB_FILE not found in current directory"
    exit 1
fi

# Verify package integrity if hash is set
if [ -n "${EXPECTED_SHA256:-}" ]; then
    echo "Verifying package integrity..."
    ACTUAL_SHA256=$(sha256sum "$DEB_FILE" | awk '{print $1}')

    if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
        echo "❌ ERROR: Package integrity verification failed!"
        echo "   Expected: $EXPECTED_SHA256"
        echo "   Actual:   $ACTUAL_SHA256"
        echo ""
        echo "The .deb file may be corrupted or tampered with."
        exit 1
    fi
    echo "✅ Package integrity verified"
    echo ""
else
    echo "⚠️  Warning: Package integrity verification is disabled"
    echo "   To enable, set EXPECTED_SHA256 in this script"
    echo "   Generate with: sha256sum $DEB_FILE"
    echo ""
fi

echo "Installing Bastion Firewall v2.0.0..."
echo ""

# Install the package and dependencies
apt-get install -y ./"$DEB_FILE"

echo ""
echo "✅ Bastion Firewall installed successfully!"
echo ""
echo "To start: Search for 'Bastion Firewall' in your application menu"
