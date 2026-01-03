#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ ! -d "bastion-rs" ]; then
    print_error "Must run from project root directory"
    exit 1
fi

# Read version from single source of truth
if [ ! -f "VERSION" ]; then
    print_error "VERSION file not found"
    exit 1
fi
VERSION=$(cat VERSION | tr -d '[:space:]')

print_step "Syncing version ${VERSION} across all files..."

# Update bastion/__init__.py
sed -i "s/__version__ = .*/__version__ = '${VERSION}'/" bastion/__init__.py

# Update setup.py
sed -i "s/version=\"[^\"]*\"/version=\"${VERSION}\"/" setup.py

# Update debian/DEBIAN/control
sed -i "s/^Version: .*/Version: ${VERSION}/" debian/DEBIAN/control

# Update bastion-rs/Cargo.toml (keep in sync)
sed -i "0,/^version = /s/^version = .*/version = \"${VERSION}\"/" bastion-rs/Cargo.toml

print_info "Version synced to ${VERSION}"
echo ""

echo "Building Bastion Firewall v${VERSION}..."
echo ""

print_step "Cleaning previous build..."
rm -rf debian/usr/bin/*
rm -rf debian/usr/lib/python3/dist-packages/douane
rm -rf debian/usr/lib/python3/dist-packages/bastion
rm -rf debian/usr/share/doc/douane-firewall
rm -rf debian/usr/share/doc/bastion-firewall
rm -rf debian/usr/share/applications/*
rm -rf debian/usr/share/metainfo/*
rm -rf debian/etc
rm -f bastion-firewall_*.deb

print_step "Creating directory structure..."
mkdir -p debian/usr/bin
mkdir -p debian/usr/lib/python3/dist-packages/bastion
mkdir -p debian/usr/share/doc/bastion-firewall
mkdir -p debian/usr/share/applications
mkdir -p debian/usr/share/metainfo
mkdir -p debian/lib/systemd/system
mkdir -p debian/usr/share/polkit-1/actions
mkdir -p debian/usr/share/bastion-firewall
mkdir -p debian/DEBIAN

print_step "Building Rust daemon and eBPF..."
cd bastion-rs

./build_ebpf.sh || { print_error "eBPF build failed"; cd ..; exit 1; }

print_info "Building Rust daemon..."
cargo build --release || { print_error "Rust daemon build failed"; cd ..; exit 1; }

cd ..

print_step "Copying binaries..."
cp bastion-rs/target/release/bastion-daemon debian/usr/bin/bastion-daemon
cp bastion-rs/ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o debian/usr/share/bastion-firewall/
cp bastion-gui.py debian/usr/bin/bastion-gui
cp bastion_control_panel.py debian/usr/bin/bastion-control-panel
cp bastion-launch-gui.sh debian/usr/bin/bastion-launch
cp bastion-reload-rules debian/usr/bin/bastion-reload-rules
cp bastion-reload-config debian/usr/bin/bastion-reload-config
cp bastion-setup-inbound debian/usr/bin/bastion-setup-inbound
cp bastion-cleanup-inbound debian/usr/bin/bastion-cleanup-inbound
chmod +x debian/usr/bin/*

print_step "Copying Python modules..."
cp -r bastion/* debian/usr/lib/python3/dist-packages/bastion/

# Ensure resources directory exists in package
mkdir -p debian/usr/lib/python3/dist-packages/bastion/resources

# Make modules importable
cat > debian/usr/lib/python3/dist-packages/bastion/__main__.py << 'EOF'
"""
Main entry point for Bastion Firewall when run as module
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
        print("  python3 -m bastion --test   # Test GUI")
        print("  python3 -m bastion --rules  # Manage rules")
EOF

# Copy systemd service
print_step "Copying systemd service..."
cp bastion-firewall.service debian/lib/systemd/system/

# Note: config.json is NOT copied to /etc/bastion/ in package
# It will be created by postinst script during installation with user prompts

# Copy desktop entries
print_step "Copying desktop entries..."
cp com.bastion.firewall.desktop debian/usr/share/applications/com.bastion.firewall.desktop
chmod 644 debian/usr/share/applications/com.bastion.firewall.desktop
# Control panel desktop file (hidden from launcher to avoid redundancy with main app)
cp bastion-control-panel.desktop debian/usr/share/applications/bastion-control-panel.desktop
echo "NoDisplay=true" >> debian/usr/share/applications/bastion-control-panel.desktop
chmod 644 debian/usr/share/applications/bastion-control-panel.desktop
# Tray icon autostart entry (ONLY in autostart, NOT in applications menu)
# This prevents Software Center from picking it up as main app
mkdir -p debian/etc/xdg/autostart
cp bastion-tray.desktop debian/etc/xdg/autostart/bastion-tray.desktop
chmod 644 debian/etc/xdg/autostart/bastion-tray.desktop

# Install application icon to system hicolor icon theme using reverse-DNS name
print_step "Installing application icon..."
mkdir -p debian/usr/share/icons/hicolor/scalable/apps
cp bastion/resources/bastion-icon.svg debian/usr/share/icons/hicolor/scalable/apps/com.bastion.firewall.svg
chmod 644 debian/usr/share/icons/hicolor/scalable/apps/com.bastion.firewall.svg

# Also install 128x128 PNG for better compatibility
mkdir -p debian/usr/share/icons/hicolor/128x128/apps
if [ -f bastion/resources/bastion-icon.png ]; then
    cp bastion/resources/bastion-icon.png debian/usr/share/icons/hicolor/128x128/apps/com.bastion.firewall.png
    chmod 644 debian/usr/share/icons/hicolor/128x128/apps/com.bastion.firewall.png
fi

# Copy polkit policy file for software center authentication
print_step "Copying polkit policy..."
cp com.bastion.firewall.policy debian/usr/share/polkit-1/actions/
chmod 644 debian/usr/share/polkit-1/actions/com.bastion.firewall.policy

# Create AppStream metadata for Software Center
print_step "Creating AppStream metadata..."
cat > debian/usr/share/metainfo/com.bastion.firewall.metainfo.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.bastion.firewall</id>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-3.0+</project_license>
  <name>Bastion Firewall</name>
  <summary>Application Firewall - Control which applications can access the network</summary>
  <description>
    <p>
      🏰 Bastion Firewall is an outbound application firewall built specifically for Zorin OS 18
      (and compatible with all Debian-based distributions). Like a medieval bastion protecting a
      fortress, Bastion stands guard over your system's network connections, giving you control
      over which applications can access the network.
    </p>
    <p>Features:</p>
    <ul>
      <li>Real-time packet interception using NetfilterQueue</li>
      <li>Beautiful GUI dialogs for permission requests</li>
      <li>Independent tray icon with visual status indicators</li>
      <li>Security hardened (5-phase implementation, score: 2/10 LOW RISK)</li>
      <li>Per-application, per-port rules</li>
      <li>UFW integration for complete firewall coverage</li>
      <li>Control panel for managing settings and rules</li>
      <li>Auto-start support with systemctl controls</li>
    </ul>
  </description>
  <launchable type="desktop-id">com.bastion.firewall.desktop</launchable>
  <icon type="stock">com.bastion.firewall</icon>
  <url type="homepage">https://github.com/shipdocs/bastion-firewall</url>
  <url type="bugtracker">https://github.com/shipdocs/bastion-firewall/issues</url>
  <url type="help">https://github.com/shipdocs/bastion-firewall/blob/master/README.md</url>
  <developer id="com.bastion">
    <name>Martin</name>
  </developer>
  <update_contact>shipdocs@users.noreply.github.com</update_contact>
  <content_rating type="oars-1.1" />
  <pkgname>bastion-firewall</pkgname>
  <provides>
    <binary>bastion-daemon</binary>
    <binary>bastion-gui</binary>
    <binary>bastion-control-panel</binary>
    <binary>bastion-firewall</binary>
  </provides>
  <recommends>
    <control>pointing</control>
    <control>keyboard</control>
  </recommends>
  <requires>
    <display_length compare="ge">768</display_length>
  </requires>
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
    <release version="${VERSION}" date="$(date +%Y-%m-%d)">
      <description>
        <p>🏰 Update to v${VERSION}</p>
        <ul>
          <li>Non-blocking learning mode popups (zero latency)</li>
          <li>Asynchronous rule creation from popups</li>
          <li>Improved path identification for Flatpak/ containerized apps</li>
          <li>Codebase cleanup and security hardening</li>
        </ul>
      </description>
    </release>
    <release version="2.0.25" date="2024-12-31" />
    <release version="1.0.0" date="2024-12-21" />
  </releases>
</component>
EOF
chmod 644 debian/usr/share/metainfo/com.bastion.firewall.metainfo.xml

# Copy documentation
print_step "Copying documentation..."
cp README.md debian/usr/share/doc/bastion-firewall/
cp CONTRIBUTING.md debian/usr/share/doc/bastion-firewall/
cp SECURITY.md debian/usr/share/doc/bastion-firewall/
cp config.json debian/usr/share/doc/bastion-firewall/config.json.example

# Copy logrotate configuration
cp debian/bastion-firewall.logrotate debian/usr/share/doc/bastion-firewall/

# Create copyright file
cat > debian/usr/share/doc/bastion-firewall/copyright << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: bastion-firewall
Upstream-Contact: Martin <shipdocs@users.noreply.github.com>
Source: https://github.com/bastion-firewall/bastion-firewall

Files: *
Copyright: 2024 Martin
License: GPL-3.0+
EOF

# Create changelog
cat > debian/usr/share/doc/bastion-firewall/changelog << 'EOF'
bastion-firewall (${VERSION}) stable; urgency=medium

  * 🏰 Release v${VERSION}
  * Non-blocking learning mode popups
  * Asynchronous rule creation
  * Cleaned codebase and removed verbose comments

 -- Martin <shipdocs@users.noreply.github.com>  $(date -R)

bastion-firewall (1.0.0) stable; urgency=medium
  * Safe installation with rollback capability
  * Systemd service integration
  * Comprehensive documentation

EOF

gzip -9 debian/usr/share/doc/bastion-firewall/changelog

# Copy maintainer scripts (use existing files instead of generating inline)
print_step "Copying maintainer scripts..."
if [ -f "debian/DEBIAN/postinst" ]; then
    chmod +x debian/DEBIAN/postinst
else
    print_error "ERROR: debian/DEBIAN/postinst not found!"
    exit 1
fi

if [ -f "debian/DEBIAN/prerm" ]; then
    chmod +x debian/DEBIAN/prerm
else
    print_error "ERROR: debian/DEBIAN/prerm not found!"
    exit 1
fi

if [ -f "debian/DEBIAN/postrm" ]; then
    chmod +x debian/DEBIAN/postrm
else
    print_error "ERROR: debian/DEBIAN/postrm not found!"
    exit 1
fi

if [ -f "debian/DEBIAN/preinst" ]; then
    chmod +x debian/DEBIAN/preinst
fi

# Set permissions
print_step "Setting permissions..."
find debian/usr -type f -exec chmod 644 {} \;
find debian/usr -type d -exec chmod 755 {} \;
chmod +x debian/usr/bin/*
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
dpkg-deb --root-owner-group --build debian "bastion-firewall_${VERSION}_all.deb"

# Check package
print_step "Checking package..."
dpkg-deb --info "bastion-firewall_${VERSION}_all.deb"
echo ""
dpkg-deb --contents "bastion-firewall_${VERSION}_all.deb"

echo ""
print_info "Package built successfully: bastion-firewall_${VERSION}_all.deb"
echo ""
print_info "To install:"
echo "  sudo dpkg -i bastion-firewall_${VERSION}_all.deb"
echo "  sudo apt-get install -f  # Install dependencies if needed"
echo ""
print_info "To test:"
echo "  dpkg-deb --contents bastion-firewall_${VERSION}_all.deb"
echo "  dpkg-deb --info bastion-firewall_${VERSION}_all.deb"
echo ""
