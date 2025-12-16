#!/bin/bash
#
# Build Debian package for Douane Firewall
#

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "============================================================"
echo "Building Douane Firewall Debian Package"
echo "============================================================"
echo ""

# Check if running in project directory
if [ ! -f "douane_firewall.py" ]; then
    print_error "Must run from project root directory"
    exit 1
fi

# Clean previous build
print_step "Cleaning previous build..."
rm -rf debian/usr/local/bin/*
rm -rf debian/usr/lib/python3/dist-packages/douane/*.py
rm -rf debian/usr/share/doc/douane-firewall/*
rm -f douane-firewall_*.deb

# Ensure directory structure exists
print_step "Creating directory structure..."
mkdir -p debian/usr/local/bin
mkdir -p debian/usr/lib/python3/dist-packages/douane
mkdir -p debian/usr/share/doc/douane-firewall
mkdir -p debian/usr/share/applications
mkdir -p debian/lib/systemd/system
mkdir -p debian/DEBIAN

# Copy executables
print_step "Copying executables..."
cp douane_firewall.py debian/usr/local/bin/douane-firewall
cp setup_firewall.sh debian/usr/local/bin/douane-setup-firewall
cp douane-daemon.py debian/usr/local/bin/douane-daemon
cp douane-gui-client.py debian/usr/local/bin/douane-gui-client
cp douane_control_panel.py debian/usr/local/bin/douane-control-panel
chmod +x debian/usr/local/bin/douane-firewall
chmod +x debian/usr/local/bin/douane-setup-firewall
chmod +x debian/usr/local/bin/douane-daemon
chmod +x debian/usr/local/bin/douane-gui-client
chmod +x debian/usr/local/bin/douane-control-panel

# Copy Python modules
print_step "Copying Python modules..."
cp firewall_core.py debian/usr/lib/python3/dist-packages/douane/
cp douane_gui_improved.py debian/usr/lib/python3/dist-packages/douane/gui_improved.py
cp ufw_firewall_gui.py debian/usr/lib/python3/dist-packages/douane/ufw_manager.py
cp service_whitelist.py debian/usr/lib/python3/dist-packages/douane/service_whitelist.py

# Make modules importable
cat > debian/usr/lib/python3/dist-packages/douane/__main__.py << 'EOF'
"""
Main entry point for Douane Firewall when run as module
"""
import sys
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--rules':
        from gui_improved import RuleManagerGUI
        manager = RuleManagerGUI()
        manager.show()
    elif len(sys.argv) > 1 and sys.argv[1] == '--test':
        from gui_improved import test_dialog
        test_dialog()
    else:
        print("Usage:")
        print("  python3 -m douane --test   # Test GUI")
        print("  python3 -m douane --rules  # Manage rules")
EOF

# Copy systemd service file
print_step "Copying systemd service..."
if [ -f "debian/lib/systemd/system/douane-firewall.service" ]; then
    # Service file already exists in debian directory
    echo "  Using existing service file"
else
    # Create service file
    cat > debian/lib/systemd/system/douane-firewall.service << 'EOF'
[Unit]
Description=Douane Firewall - Outbound Connection Control
Documentation=https://github.com/shipdocs/Douane
After=network.target ufw.service graphical.target

[Service]
Type=simple
ExecStart=/usr/local/bin/douane-firewall
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# GUI access - needed for popup dialogs
Environment="DISPLAY=:0"
Environment="WAYLAND_DISPLAY=wayland-0"
Environment="XDG_RUNTIME_DIR=/run/user/1000"

# Security settings
NoNewPrivileges=false
PrivateTmp=false

[Install]
WantedBy=graphical.target
EOF
fi

# Copy configuration
print_step "Copying configuration..."
cp config.json debian/etc/douane/config.json

# Copy desktop entry
print_step "Copying desktop entry..."
cp douane-firewall.desktop debian/usr/share/applications/douane-firewall.desktop
chmod 644 debian/usr/share/applications/douane-firewall.desktop

# Copy documentation
print_step "Copying documentation..."
cp README.md debian/usr/share/doc/douane-firewall/
cp PRODUCTION_GUIDE.md debian/usr/share/doc/douane-firewall/
cp FAQ.md debian/usr/share/doc/douane-firewall/
cp IMPLEMENTATION.md debian/usr/share/doc/douane-firewall/
cp config.json debian/usr/share/doc/douane-firewall/config.json.example

# Create copyright file
cat > debian/usr/share/doc/douane-firewall/copyright << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: douane-firewall
Upstream-Contact: Martin <shipdocs@users.noreply.github.com>
Source: https://github.com/shipdocs/Douane

Files: *
Copyright: 2024 Martin
License: See LICENSE file in source repository
EOF

# Create changelog
cat > debian/usr/share/doc/douane-firewall/changelog << 'EOF'
douane-firewall (2.0.0) stable; urgency=medium

  * Production-ready release with real packet interception
  * NetfilterQueue integration for packet capture
  * Enhanced GUI with timeout protection
  * UFW integration for persistent rules
  * Decision caching for performance
  * Safe installation with rollback capability
  * Systemd service integration
  * Comprehensive documentation

 -- Martin <shipdocs@users.noreply.github.com>  Sun, 15 Dec 2024 12:00:00 +0000

douane-firewall (1.0.0) stable; urgency=low

  * Initial release with demo mode
  * Basic GUI and UFW integration

 -- Martin <shipdocs@users.noreply.github.com>  Sat, 01 Dec 2024 12:00:00 +0000
EOF

gzip -9 debian/usr/share/doc/douane-firewall/changelog

# Set permissions
print_step "Setting permissions..."
find debian/usr -type f -exec chmod 644 {} \;
find debian/usr -type d -exec chmod 755 {} \;
chmod +x debian/usr/local/bin/*
chmod +x debian/DEBIAN/postinst
chmod +x debian/DEBIAN/prerm
chmod +x debian/DEBIAN/postrm

# Build package
print_step "Building package..."
dpkg-deb --build debian douane-firewall_2.0.0_all.deb

# Check package
print_step "Checking package..."
dpkg-deb --info douane-firewall_2.0.0_all.deb
echo ""
dpkg-deb --contents douane-firewall_2.0.0_all.deb

echo ""
print_info "Package built successfully: douane-firewall_2.0.0_all.deb"
echo ""
print_info "To install:"
echo "  sudo dpkg -i douane-firewall_2.0.0_all.deb"
echo "  sudo apt-get install -f  # Install dependencies if needed"
echo ""
print_info "To test:"
echo "  dpkg-deb --contents douane-firewall_2.0.0_all.deb"
echo "  dpkg-deb --info douane-firewall_2.0.0_all.deb"
echo ""

