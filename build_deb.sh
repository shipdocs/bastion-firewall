#!/bin/bash
#
# Build Debian package for Douane Firewall
#

set -e

VERSION="2.0.10"

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
rm -rf debian/etc
rm -f douane-firewall_*.deb

# Ensure directory structure exists
print_step "Creating directory structure..."
mkdir -p debian/usr/local/bin
mkdir -p debian/usr/lib/python3/dist-packages/douane
mkdir -p debian/usr/share/doc/douane-firewall
mkdir -p debian/usr/share/applications
mkdir -p debian/usr/share/metainfo
mkdir -p debian/lib/systemd/system
mkdir -p debian/usr/share/polkit-1/actions
mkdir -p debian/DEBIAN
# Note: /etc/douane is created by postinst, not in package

# Copy executables
print_step "Copying executables..."
cp douane_firewall.py debian/usr/local/bin/douane-firewall
cp setup_firewall.sh debian/usr/local/bin/douane-setup-firewall
cp douane-daemon.py debian/usr/local/bin/douane-daemon
cp douane-gui-client.py debian/usr/local/bin/douane-gui-client
cp douane_control_panel.py debian/usr/local/bin/douane-control-panel
cp launch_douane.sh debian/usr/local/bin/douane-launch
chmod +x debian/usr/local/bin/douane-firewall
chmod +x debian/usr/local/bin/douane-setup-firewall
chmod +x debian/usr/local/bin/douane-daemon
chmod +x debian/usr/local/bin/douane-gui-client
chmod +x debian/usr/local/bin/douane-control-panel
chmod +x debian/usr/local/bin/douane-launch

# Copy Python modules
print_step "Copying Python modules..."
cp -r douane/* debian/usr/lib/python3/dist-packages/douane/

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

# Copy systemd service
print_step "Copying systemd service..."
cp douane-firewall.service debian/lib/systemd/system/

# Note: config.json is NOT copied to /etc/douane/ in the package
# It will be created by postinst script during installation with user prompts

# Copy desktop entries
print_step "Copying desktop entries..."
cp douane-firewall.desktop debian/usr/share/applications/douane-firewall.desktop
chmod 644 debian/usr/share/applications/douane-firewall.desktop
# Control panel desktop file already exists in debian/usr/share/applications/
chmod 644 debian/usr/share/applications/douane-control-panel.desktop

# Create AppStream metadata for Software Center
print_step "Creating AppStream metadata..."
cat > debian/usr/share/metainfo/com.douane.firewall.metainfo.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.douane.firewall</id>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-3.0+</project_license>
  <name>Douane Application Firewall</name>
  <summary>Control which applications can access the network</summary>
  <description>
    <p>
      Douane is an outbound application firewall for Linux that gives you control over which
      applications can access the network. Similar to Little Snitch on macOS or Windows Firewall,
      Douane shows a popup whenever an application tries to make a network connection, allowing
      you to allow or deny it.
    </p>
    <p>Features:</p>
    <ul>
      <li>Real-time packet interception using NetfilterQueue</li>
      <li>Learning mode for safe testing (shows popups but allows all connections)</li>
      <li>Enforcement mode for actual blocking</li>
      <li>Per-application, per-port rules</li>
      <li>Automatic rule persistence</li>
      <li>UFW integration - rules visible in system firewall manager</li>
      <li>Control panel for managing settings and rules</li>
      <li>System tray integration</li>
    </ul>
  </description>
  <launchable type="desktop-id">douane-firewall.desktop</launchable>
  <url type="homepage">https://shipdocs.github.io/Douane-Application-firewall-for-Linux/</url>
  <url type="bugtracker">https://github.com/shipdocs/Douane-Application-firewall-for-Linux/issues</url>
  <url type="help">https://github.com/shipdocs/Douane-Application-firewall-for-Linux/blob/master/FAQ.md</url>
  <developer id="com.douane">
    <name>Martin</name>
  </developer>
  <update_contact>shipdocs@users.noreply.github.com</update_contact>
  <content_rating type="oars-1.1" />
  <categories>
    <category>System</category>
    <category>Security</category>
    <category>Network</category>
  </categories>
  <keywords>
    <keyword>firewall</keyword>
    <keyword>security</keyword>
    <keyword>network</keyword>
    <keyword>outbound</keyword>
    <keyword>application</keyword>
  </keywords>
  <releases>
    <release version="2.0.0" date="2024-12-15">
      <description>
        <p>Production-ready release with real packet interception</p>
        <ul>
          <li>NetfilterQueue integration for packet capture</li>
          <li>Enhanced GUI with timeout protection</li>
          <li>UFW integration for persistent rules</li>
          <li>Decision caching for performance</li>
          <li>Control panel for managing settings</li>
          <li>Automatic rule persistence in learning mode</li>
        </ul>
      </description>
    </release>
  </releases>
</component>
EOF
chmod 644 debian/usr/share/metainfo/com.douane.firewall.metainfo.xml

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
License: GPL-3.0+
EOF

# Create changelog
cat > debian/usr/share/doc/douane-firewall/changelog << 'EOF'
douane-firewall (2.0.10) stable; urgency=high

  * Fix: Improved startup logic to prevent password prompt on boot
  * Fix: Cleaner process shutdown logic
  * Change: Updated to version 2.0.10

 -- Martin <shipdocs@users.noreply.github.com>  Sat, 21 Dec 2024 10:00:00 +0000

douane-firewall (2.0.9) stable; urgency=high

  * Fix: Decoupled UFW logic (Douane now manages filtering internally)
  * Fix: Daemon now reloads configuration instantly on mode switch
  * Change: UFW set to "Allow Outgoing" (Pass-through mode)

 -- Martin <shipdocs@users.noreply.github.com>  Sat, 20 Dec 2024 13:00:00 +0000

douane-firewall (2.0.8) stable; urgency=high

douane-firewall (2.0.7) stable; urgency=medium

  * Systemd Integration: Migrated daemon management to strict systemd service
  * Fix: Resolves issue with multiple daemon instances preventing Stop
  * Fix: Improved Control Panel responsiveness and status accuracy
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

# Calculate installed size (in KB)
INSTALLED_SIZE=$(du -s debian/usr | cut -f1)
# Add Installed-Size to control file (insert after Architecture)
if grep -q "^Installed-Size:" debian/DEBIAN/control; then
    sed -i "s/^Installed-Size: .*/Installed-Size: $INSTALLED_SIZE/" debian/DEBIAN/control
else
    sed -i "/^Architecture:/a Installed-Size: $INSTALLED_SIZE" debian/DEBIAN/control
fi

# Build package
print_step "Building package..."
dpkg-deb --build debian "douane-firewall_${VERSION}_all.deb"

# Check package
print_step "Checking package..."
dpkg-deb --info "douane-firewall_${VERSION}_all.deb"
echo ""
dpkg-deb --contents "douane-firewall_${VERSION}_all.deb"

echo ""
print_info "Package built successfully: douane-firewall_${VERSION}_all.deb"
echo ""
print_info "To install:"
echo "  sudo dpkg -i douane-firewall_${VERSION}_all.deb"
echo "  sudo apt-get install -f  # Install dependencies if needed"
echo ""
print_info "To test:"
echo "  dpkg-deb --contents douane-firewall_${VERSION}_all.deb"
echo "  dpkg-deb --info douane-firewall_${VERSION}_all.deb"
echo ""

