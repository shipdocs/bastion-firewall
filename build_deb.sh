#!/bin/bash
#
# Build Debian package for Bastion Firewall
#

set -e

VERSION="1.0.5"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "============================================================"
echo "🏰 Building Bastion Firewall Debian Package"
echo "============================================================"
echo ""

# Check if running in project directory
if [ ! -f "bastion_firewall.py" ]; then
    print_error "Must run from project root directory"
    exit 1
fi

# Clean previous build
print_step "Cleaning previous build..."
# Clean previous build
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

# Ensure directory structure exists
print_step "Creating directory structure..."
mkdir -p debian/usr/bin
mkdir -p debian/usr/lib/python3/dist-packages/bastion
mkdir -p debian/usr/share/doc/bastion-firewall
mkdir -p debian/usr/share/applications
mkdir -p debian/usr/share/metainfo
mkdir -p debian/lib/systemd/system
mkdir -p debian/usr/share/polkit-1/actions
mkdir -p debian/DEBIAN
# Note: /etc/bastion is created by postinst, not in package

# Copy executables
print_step "Copying executables..."
cp bastion_firewall.py debian/usr/bin/bastion-firewall
cp setup_firewall.sh debian/usr/bin/bastion-setup-firewall
cp bastion-daemon.py debian/usr/bin/bastion-daemon
cp bastion-gui.py debian/usr/bin/bastion-gui
cp bastion_control_panel.py debian/usr/bin/bastion-control-panel
cp launch_bastion.sh debian/usr/bin/bastion-launch
chmod +x debian/usr/bin/bastion-firewall
chmod +x debian/usr/bin/bastion-setup-firewall
chmod +x debian/usr/bin/bastion-daemon
chmod +x debian/usr/bin/bastion-gui
chmod +x debian/usr/bin/bastion-control-panel
chmod +x debian/usr/bin/bastion-launch

# Copy Python modules
print_step "Copying Python modules..."
cp -r bastion/* debian/usr/lib/python3/dist-packages/bastion/

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

# Note: config.json is NOT copied to /etc/bastion/ in the package
# It will be created by postinst script during installation with user prompts

# Copy desktop entries
print_step "Copying desktop entries..."
cp com.bastion.firewall.desktop debian/usr/share/applications/com.bastion.firewall.desktop
chmod 644 debian/usr/share/applications/com.bastion.firewall.desktop
# Control panel desktop file
cp bastion-control-panel.desktop debian/usr/share/applications/bastion-control-panel.desktop
chmod 644 debian/usr/share/applications/bastion-control-panel.desktop
# Tray icon autostart entry (ONLY in autostart, NOT in applications menu)
# This prevents Software Center from picking it up as the main app
mkdir -p debian/etc/xdg/autostart
cp bastion-tray.desktop debian/etc/xdg/autostart/bastion-tray.desktop
chmod 644 debian/etc/xdg/autostart/bastion-tray.desktop

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
  <icon type="stock">security-high</icon>
  <url type="homepage">https://github.com/shipdocs/bastion-firewall</url>
  <url type="bugtracker">https://github.com/shipdocs/bastion-firewall/issues</url>
  <url type="help">https://github.com/shipdocs/bastion-firewall/blob/master/FAQ.md</url>
  <developer id="com.bastion">
    <name>Martin</name>
  </developer>
  <update_contact>shipdocs@users.noreply.github.com</update_contact>
  <content_rating type="oars-1.1" />
  <provides>
    <binary>bastion-daemon</binary>
    <binary>bastion-gui</binary>
    <binary>bastion-control-panel</binary>
    <binary>bastion-firewall</binary>
    <id>com.bastion.firewall.desktop</id>
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
    <release version="1.0.0" date="2024-12-21">
      <description>
        <p>🏰 Initial release of Bastion Firewall - Your Last Line of Defense</p>
        <ul>
          <li>Rebranded from Douane to Bastion Firewall</li>
          <li>Built specifically for Zorin OS 18</li>
          <li>Independent tray icon with auto-connect</li>
          <li>Visual status indicators (green/red/orange)</li>
          <li>Security hardened (5-phase implementation)</li>
          <li>UFW integration for complete protection</li>
          <li>Production-ready and stable</li>
        </ul>
      </description>
    </release>
  </releases>
</component>
EOF
chmod 644 debian/usr/share/metainfo/com.bastion.firewall.metainfo.xml

# Copy documentation
print_step "Copying documentation..."
cp README.md debian/usr/share/doc/bastion-firewall/
cp PRODUCTION_GUIDE.md debian/usr/share/doc/bastion-firewall/
cp FAQ.md debian/usr/share/doc/bastion-firewall/
cp IMPLEMENTATION.md debian/usr/share/doc/bastion-firewall/
cp config.json debian/usr/share/doc/bastion-firewall/config.json.example

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
bastion-firewall (1.0.0) stable; urgency=medium

  * 🏰 Initial release of Bastion Firewall
  * Rebranded from Douane to Bastion Firewall
  * Professional branding: "Your Last Line of Defense"
  * Built specifically for Zorin OS 18
  * Independent tray icon with auto-connect
  * Visual status indicators (green/red/orange)
  * Security hardened (5-phase implementation, score: 2/10 LOW RISK)
  * UFW integration for complete firewall coverage
  * Production-ready and stable

 -- Martin <shipdocs@users.noreply.github.com>  Sat, 21 Dec 2024 14:00:00 +0000
  * Safe installation with rollback capability
  * Systemd service integration
  * Comprehensive documentation

EOF

gzip -9 debian/usr/share/doc/bastion-firewall/changelog

# Create postinst
print_step "Creating postinst script..."
cat > debian/DEBIAN/postinst << 'EOF'
#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }

# Create bastion user/group if they don't exist
if ! getent group bastion >/dev/null; then
    groupadd -r bastion
fi
if ! getent passwd bastion >/dev/null; then
    useradd -r -g bastion -d /var/lib/bastion -s /usr/sbin/nologin -c "Bastion Firewall User" bastion
fi

# Set up configuration directory
mkdir -p /etc/bastion
if [ ! -f /etc/bastion/config.json ]; then
    if [ -f /usr/share/doc/bastion-firewall/config.json.example ]; then
        cp /usr/share/doc/bastion-firewall/config.json.example /etc/bastion/config.json
    else
        echo '{"log_level": "INFO", "rules_file": "/etc/bastion/rules.json"}' > /etc/bastion/config.json
    fi
    chmod 644 /etc/bastion/config.json
fi

# Set up rules file
if [ ! -f /etc/bastion/rules.json ]; then
    echo '{"applications": {}, "services": {}}' > /etc/bastion/rules.json
    chmod 644 /etc/bastion/rules.json
fi

# Set permissions for logs
mkdir -p /var/log/bastion
chown -R bastion:bastion /var/log/bastion
chmod 750 /var/log/bastion

# Reload systemd
systemctl daemon-reload
if systemctl is-enabled bastion-firewall >/dev/null 2>&1; then
    systemctl enable bastion-firewall
fi

# Update desktop database
update-desktop-database || true

# Autostart helpers
if [ -d /home ]; then
    for user_dir in /home/*; do
        if [ -d "$user_dir/.config/autostart" ]; then
            chown -R $(basename "$user_dir"):$(basename "$user_dir") "$user_dir/.config/autostart" 2>/dev/null || true
        fi
    done
fi
EOF

# Create prerm
print_step "Creating prerm script..."
cat > debian/DEBIAN/prerm << 'EOF'
#!/bin/bash
set -e
systemctl stop bastion-firewall || true
systemctl disable bastion-firewall || true
pkill -f bastion-gui || true
pkill -f bastion-control-panel || true
EOF

# Create postrm
print_step "Creating postrm script..."
cat > debian/DEBIAN/postrm << 'EOF'
#!/bin/bash
set -e
if [ "$1" = "purge" ]; then
    rm -rf /etc/bastion
    rm -rf /var/log/bastion
    rm -rf /var/lib/bastion
fi
update-desktop-database || true
EOF

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

