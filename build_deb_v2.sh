#!/bin/bash
#
# Build Debian package for Bastion Firewall v2.0 (Rust Daemon)
#

set -e

VERSION="2.0.0"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# print_info prints an informational message prefixed with a green "[INFO]" tag.
print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
# print_step prints a blue "[STEP]" prefix followed by the provided message to stdout, using color codes and resetting the color.
print_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
# print_error prints an error message prefixed with `[ERROR]` in red; the message is provided as the first argument.
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
# print_warning prints a yellow "[WARNING]" prefix followed by the given message to stdout.
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

echo "============================================================"
echo "Building Bastion Firewall v2.0 Debian Package"
echo "============================================================"
echo ""

# Check if Rust daemon is built
if [ ! -f "bastion-rs/target/release/bastion-daemon" ]; then
    print_error "Rust daemon not built. Please run:"
    echo "  cd bastion-rs && cargo build --release"
    exit 1
fi

# Check if eBPF program is built
if [ ! -f "bastion-rs/ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o" ]; then
    print_warning "eBPF program not found. Building..."
    cd bastion-rs
    ./build_ebpf.sh
    cd ..
fi

# Clean previous build
print_step "Cleaning previous build..."
rm -rf debian/usr/bin/*
rm -rf debian/usr/lib/python3/dist-packages/bastion
rm -rf debian/usr/share/doc/bastion-firewall
rm -rf debian/usr/share/applications/*
rm -rf debian/usr/share/metainfo/*
rm -rf debian/usr/share/bastion-firewall
rm -rf debian/lib/systemd/system/*
rm -f bastion-firewall_*.deb

# Create directory structure
print_step "Creating directory structure..."
mkdir -p debian/usr/bin
mkdir -p debian/usr/lib/python3/dist-packages/bastion
mkdir -p debian/usr/share/doc/bastion-firewall
mkdir -p debian/usr/share/applications
mkdir -p debian/usr/share/metainfo
mkdir -p debian/usr/share/bastion-firewall
mkdir -p debian/lib/systemd/system
mkdir -p debian/DEBIAN

# Copy Rust daemon
print_step "Copying Rust daemon..."
cp bastion-rs/target/release/bastion-daemon debian/usr/bin/
chmod +x debian/usr/bin/bastion-daemon

# Copy eBPF program
print_step "Copying eBPF program..."
cp bastion-rs/ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o debian/usr/share/bastion-firewall/
print_info "eBPF program will be embedded in binary for production, but included as fallback"

# Copy Python GUI
print_step "Copying Python GUI..."
cp bastion-gui.py debian/usr/bin/bastion-gui
cp bastion_control_panel.py debian/usr/bin/bastion-control-panel
cp bastion-launch-gui.sh debian/usr/bin/bastion-launch-gui
chmod +x debian/usr/bin/bastion-gui
chmod +x debian/usr/bin/bastion-control-panel
chmod +x debian/usr/bin/bastion-launch-gui

# Copy Python modules
print_step "Copying Python modules..."
cp -r bastion/* debian/usr/lib/python3/dist-packages/bastion/

# Copy systemd service
print_step "Copying systemd service..."
cp bastion-firewall.service debian/lib/systemd/system/

# Copy desktop files
print_step "Copying desktop entries..."
if [ -f "com.bastion.firewall.desktop" ]; then
    cp com.bastion.firewall.desktop debian/usr/share/applications/
fi
if [ -f "bastion-control-panel.desktop" ]; then
    cp bastion-control-panel.desktop debian/usr/share/applications/
fi

# Copy autostart entry
print_step "Copying autostart entry..."
mkdir -p debian/etc/xdg/autostart
cp bastion-tray.desktop debian/etc/xdg/autostart/

# Create AppStream metadata for Software Centre
print_step "Creating AppStream metadata..."
cat > debian/usr/share/metainfo/com.bastion.firewall.metainfo.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.bastion.firewall</id>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-3.0+</project_license>
  <name>Bastion Firewall</name>
  <summary>High-Performance Application Firewall with eBPF</summary>
  <description>
    <p>
      🏰 Bastion Firewall v2.0 is an advanced outbound application firewall with
      a high-performance Rust daemon and kernel-level eBPF process tracking.
    </p>
    <p>Features:</p>
    <ul>
      <li>Rust daemon for memory-safe packet processing</li>
      <li>eBPF process tracking with less than 1 microsecond latency</li>
      <li>Solves timing issues with short-lived connections (curl, wget)</li>
      <li>Beautiful Qt6 GUI for connection permissions</li>
      <li>Per-application rules with persistent storage</li>
      <li>Learning mode for easy setup</li>
      <li>System bypass rules for stability</li>
      <li>UFW integration for inbound protection</li>
    </ul>
  </description>
  <launchable type="desktop-id">com.bastion.firewall.desktop</launchable>
  <icon type="stock">security-high</icon>
  <url type="homepage">https://github.com/shipdocs/bastion-firewall</url>
  <url type="bugtracker">https://github.com/shipdocs/bastion-firewall/issues</url>
  <developer id="com.bastion">
    <name>Martin</name>
  </developer>
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
    <keyword>ebpf</keyword>
    <keyword>rust</keyword>
  </keywords>
  <releases>
    <release version="2.0.0" date="2025-12-27">
      <description>
        <p>🚀 Major update with Rust daemon and eBPF</p>
        <ul>
          <li>Complete rewrite in Rust for performance and safety</li>
          <li>eBPF kernel hooks for process tracking</li>
          <li>Less than 1 microsecond identification latency</li>
          <li>Correctly identifies short-lived connections</li>
          <li>System bypass rules for stability</li>
          <li>/proc scanning fallback for compatibility</li>
        </ul>
      </description>
    </release>
  </releases>
</component>
EOF

# Copy documentation
print_step "Copying documentation..."
cp README.md debian/usr/share/doc/bastion-firewall/
cp REQUIREMENTS.md debian/usr/share/doc/bastion-firewall/
cp bastion-rs/README.md debian/usr/share/doc/bastion-firewall/RUST_README.md

# Create copyright file
cat > debian/usr/share/doc/bastion-firewall/copyright << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: bastion-firewall
Upstream-Contact: Martin <shipdocs@users.noreply.github.com>
Source: https://github.com/shipdocs/bastion-firewall

Files: *
Copyright: 2024-2025 Martin
License: GPL-3.0+
EOF

# Set permissions
print_step "Setting permissions..."
if [ -f "debian/DEBIAN/postinst" ]; then chmod +x debian/DEBIAN/postinst; fi
if [ -f "debian/DEBIAN/prerm" ]; then chmod +x debian/DEBIAN/prerm; fi
if [ -f "debian/DEBIAN/postrm" ]; then chmod +x debian/DEBIAN/postrm; fi
# FIX #16: Check if control file exists before editing
if [ -f "debian/DEBIAN/control" ]; then
    chmod 644 debian/DEBIAN/control

    # Calculate installed size
    INSTALLED_SIZE=$(du -sk debian/usr debian/lib 2>/dev/null | awk '{s+=$1} END {print s}')
    sed -i "s/^Installed-Size:.*/Installed-Size: $INSTALLED_SIZE/" debian/DEBIAN/control
else
    print_error "debian/DEBIAN/control file not found. Cannot build package."
    exit 1
fi

# Build package
print_step "Building package..."
dpkg-deb --root-owner-group --build debian "bastion-firewall_${VERSION}_amd64.deb"

# Check package
print_step "Package contents:"
dpkg-deb --info "bastion-firewall_${VERSION}_amd64.deb"
echo ""
dpkg-deb --contents "bastion-firewall_${VERSION}_amd64.deb" | head -20

echo ""
print_info "Package built successfully: bastion-firewall_${VERSION}_amd64.deb"
echo ""
print_info "To install:"
echo "  sudo dpkg -i bastion-firewall_${VERSION}_amd64.deb"
echo "  sudo apt-get install -f  # Install dependencies if needed"
echo ""
print_info "To test:"
echo "  sudo systemctl status bastion-daemon"
echo "  bastion-gui  # Launch GUI"
echo ""