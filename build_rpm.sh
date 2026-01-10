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

# Check for rpmbuild
if ! command -v rpmbuild &> /dev/null; then
    print_error "rpmbuild not found. Install with:"
    echo "  sudo apt install rpm"
    exit 1
fi

NAME="bastion-firewall"
BUILD_DIR="rpmbuild"

print_step "Building RPM package v${VERSION}..."
echo ""

# Check if Rust daemon is built
if [ ! -f "bastion-rs/target/release/bastion-daemon" ]; then
    print_step "Building Rust daemon..."
    cd bastion-rs
    ./build_ebpf.sh || { print_error "eBPF build failed"; cd ..; exit 1; }
    cargo build --release || { print_error "Rust daemon build failed"; cd ..; exit 1; }
    cd ..
fi

# Check for eBPF binary
if [ ! -f "bastion-rs/ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o" ]; then
    print_error "eBPF binary not found. Run ./build_ebpf.sh in bastion-rs/"
    exit 1
fi

# Clean previous build
print_step "Cleaning previous build..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball
print_step "Creating source tarball..."
TEMP_DIR="${NAME}-${VERSION}"
mkdir -p "$TEMP_DIR"

# Copy Rust daemon binary
cp bastion-rs/target/release/bastion-daemon "$TEMP_DIR/"

# Copy eBPF binary
cp bastion-rs/ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o "$TEMP_DIR/"

# Copy Python GUI files
cp bastion-gui.py "$TEMP_DIR/bastion-gui"
cp bastion_control_panel.py "$TEMP_DIR/bastion-control-panel"
cp bastion-launch-gui.sh "$TEMP_DIR/bastion-launch"
cp bastion-reload-rules "$TEMP_DIR/bastion-reload-rules"
cp bastion-reload-config "$TEMP_DIR/bastion-reload-config"
cp bastion-setup-inbound "$TEMP_DIR/bastion-setup-inbound"
cp bastion-cleanup-inbound "$TEMP_DIR/bastion-cleanup-inbound"

# Copy Python modules
cp -r bastion "$TEMP_DIR/"

# Copy systemd service
cp bastion-firewall.service "$TEMP_DIR/"

# Copy desktop files
cp com.bastion.firewall.desktop "$TEMP_DIR/"
cp bastion-control-panel.desktop "$TEMP_DIR/"
cp bastion-tray.desktop "$TEMP_DIR/"

# Copy polkit policy
cp com.bastion.firewall.policy "$TEMP_DIR/"

# Copy documentation
cp README.md "$TEMP_DIR/"
cp LICENSE "$TEMP_DIR/"
cp CONTRIBUTING.md "$TEMP_DIR/" 2>/dev/null || true
cp SECURITY.md "$TEMP_DIR/" 2>/dev/null || true

# Copy icon
mkdir -p "$TEMP_DIR/resources"
cp bastion/resources/bastion-icon.svg "$TEMP_DIR/resources/" 2>/dev/null || true
cp bastion/resources/bastion-icon.png "$TEMP_DIR/resources/" 2>/dev/null || true

# Create AppStream metadata
cat > "$TEMP_DIR/com.bastion.firewall.metainfo.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>com.bastion.firewall</id>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>GPL-3.0+</project_license>
  <name>Bastion Firewall</name>
  <summary>Application Firewall - Control which applications can access the network</summary>
  <description>
    <p>
      🏰 Bastion Firewall is a high-performance outbound application firewall with eBPF support.
      Like a medieval bastion protecting a fortress, Bastion stands guard over your system's
      network connections, giving you control over which applications can access the network.
    </p>
    <p>Features:</p>
    <ul>
      <li>eBPF kernel hooks for microsecond-latency process identification</li>
      <li>Real-time packet interception using NetfilterQueue</li>
      <li>Beautiful GUI dialogs for permission requests</li>
      <li>System tray with visual status indicators</li>
      <li>Per-application, per-port firewall rules</li>
      <li>Control panel for managing settings and rules</li>
      <li>Auto-start support with systemctl controls</li>
    </ul>
  </description>
  <launchable type="desktop-id">com.bastion.firewall.desktop</launchable>
  <icon type="stock">com.bastion.firewall</icon>
  <url type="homepage">https://github.com/shipdocs/bastion-firewall</url>
  <url type="bugtracker">https://github.com/shipdocs/bastion-firewall/issues</url>
  <developer id="com.bastion">
    <name>Martin</name>
  </developer>
  <content_rating type="oars-1.1" />
  <releases>
    <release version="${VERSION}" date="$(date +%Y-%m-%d)">
      <description>
        <p>🏰 Release v${VERSION}</p>
      </description>
    </release>
  </releases>
</component>
EOF

tar -czf "$BUILD_DIR/SOURCES/${NAME}-${VERSION}.tar.gz" "$TEMP_DIR"
rm -rf "$TEMP_DIR"

# Create spec file
print_step "Creating RPM spec file..."
cat > "$BUILD_DIR/SPECS/bastion.spec" << 'SPECEOF'
Name:           bastion-firewall
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        🏰 Application Firewall with eBPF - Your Last Line of Defense

License:        GPLv3+
URL:            https://github.com/shipdocs/bastion-firewall
Source0:        %{name}-%{version}.tar.gz

BuildArch:      x86_64

# Don't strip eBPF binaries (they're not regular ELF)
%global __os_install_post %{nil}
%define debug_package %{nil}

Requires:       python3
Requires:       python3-gobject
Requires:       python3-pillow
Requires:       python3-psutil
Requires:       iptables
Requires:       polkit
Requires:       gtk3
Requires:       libayatana-appindicator-gtk3

%description
🏰 Bastion Firewall - Your Last Line of Defense

Bastion Firewall is a high-performance outbound application firewall with eBPF
support. It provides Windows-like outbound connection control for Linux, 
intercepting all outbound traffic and showing GUI dialogs to let users decide
which applications can access the network.

Features:
 - eBPF kernel hooks for microsecond-latency process identification
 - Real-time packet interception using netfilter
 - Beautiful GUI dialogs for user decisions
 - System tray with visual status indicators
 - Per-application, per-port firewall rules
 - Control panel for managing settings and rules
 - Auto-start support with systemctl controls

%prep
%setup -q

%build
# Binary is pre-built

%install
rm -rf $RPM_BUILD_ROOT

# Create directories
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/lib/python3/dist-packages/bastion
mkdir -p $RPM_BUILD_ROOT/usr/share/bastion-firewall
mkdir -p $RPM_BUILD_ROOT/usr/share/applications
mkdir -p $RPM_BUILD_ROOT/usr/share/metainfo
mkdir -p $RPM_BUILD_ROOT/usr/share/polkit-1/actions
mkdir -p $RPM_BUILD_ROOT/usr/share/icons/hicolor/scalable/apps
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/bastion-firewall
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system
mkdir -p $RPM_BUILD_ROOT/etc/xdg/autostart

# Install binaries
install -m 755 bastion-daemon $RPM_BUILD_ROOT/usr/bin/
install -m 755 bastion-gui $RPM_BUILD_ROOT/usr/bin/
install -m 755 bastion-control-panel $RPM_BUILD_ROOT/usr/bin/
install -m 755 bastion-launch $RPM_BUILD_ROOT/usr/bin/
install -m 755 bastion-reload-rules $RPM_BUILD_ROOT/usr/bin/
install -m 755 bastion-reload-config $RPM_BUILD_ROOT/usr/bin/
install -m 755 bastion-setup-inbound $RPM_BUILD_ROOT/usr/bin/
install -m 755 bastion-cleanup-inbound $RPM_BUILD_ROOT/usr/bin/

# Install eBPF binary
install -m 644 bastion-ebpf.o $RPM_BUILD_ROOT/usr/share/bastion-firewall/

# Install Python modules
cp -r bastion/* $RPM_BUILD_ROOT/usr/lib/python3/dist-packages/bastion/

# Install systemd service
install -m 644 bastion-firewall.service $RPM_BUILD_ROOT/lib/systemd/system/

# Install desktop files
install -m 644 com.bastion.firewall.desktop $RPM_BUILD_ROOT/usr/share/applications/
install -m 644 bastion-control-panel.desktop $RPM_BUILD_ROOT/usr/share/applications/
install -m 644 bastion-tray.desktop $RPM_BUILD_ROOT/etc/xdg/autostart/

# Install polkit policy
install -m 644 com.bastion.firewall.policy $RPM_BUILD_ROOT/usr/share/polkit-1/actions/

# Install AppStream metadata
install -m 644 com.bastion.firewall.metainfo.xml $RPM_BUILD_ROOT/usr/share/metainfo/

# Install icon
if [ -f resources/bastion-icon.svg ]; then
    install -m 644 resources/bastion-icon.svg $RPM_BUILD_ROOT/usr/share/icons/hicolor/scalable/apps/com.bastion.firewall.svg
fi

# Install documentation
install -m 644 README.md $RPM_BUILD_ROOT/usr/share/doc/bastion-firewall/
install -m 644 LICENSE $RPM_BUILD_ROOT/usr/share/doc/bastion-firewall/

%files
/usr/bin/bastion-daemon
/usr/bin/bastion-gui
/usr/bin/bastion-control-panel
/usr/bin/bastion-launch
/usr/bin/bastion-reload-rules
/usr/bin/bastion-reload-config
/usr/bin/bastion-setup-inbound
/usr/bin/bastion-cleanup-inbound
/usr/share/bastion-firewall/bastion-ebpf.o
/usr/lib/python3/dist-packages/bastion/
/lib/systemd/system/bastion-firewall.service
/usr/share/applications/com.bastion.firewall.desktop
/usr/share/applications/bastion-control-panel.desktop
/etc/xdg/autostart/bastion-tray.desktop
/usr/share/polkit-1/actions/com.bastion.firewall.policy
/usr/share/metainfo/com.bastion.firewall.metainfo.xml
/usr/share/icons/hicolor/scalable/apps/com.bastion.firewall.svg
%doc /usr/share/doc/bastion-firewall/

%pre
# Pre-installation script
if [ $1 -eq 2 ]; then
    # Upgrade - stop existing service
    systemctl stop bastion-firewall 2>/dev/null || true
fi

%post
# Post-installation script
echo ""
echo "============================================================"
echo "🏰 Bastion Firewall - Post Installation"
echo "============================================================"
echo ""

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install --quiet psutil tabulate pystray pillow 2>/dev/null || true

# Reload systemd
systemctl daemon-reload

# Update icon cache
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
fi

# Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q 2>/dev/null || true
fi

echo ""
echo "✓ Bastion Firewall installed successfully!"
echo ""
echo "To start the firewall:"
echo "  sudo systemctl start bastion-firewall"
echo "  sudo systemctl enable bastion-firewall"
echo ""
echo "Or launch from the application menu."
echo ""

%preun
# Pre-uninstallation script
if [ $1 -eq 0 ]; then
    # Complete removal (not upgrade)
    echo ""
    echo "============================================================"
    echo "🏰 Bastion Firewall - Pre-Removal"
    echo "============================================================"
    echo ""

    # Stop and disable service
    if systemctl is-active --quiet bastion-firewall 2>/dev/null; then
        echo "Stopping bastion-firewall service..."
        systemctl stop bastion-firewall 2>/dev/null || true
    fi

    if systemctl is-enabled --quiet bastion-firewall 2>/dev/null; then
        systemctl disable bastion-firewall 2>/dev/null || true
    fi

    # Kill all processes
    pkill -f bastion-daemon 2>/dev/null || true
    pkill -f bastion-gui 2>/dev/null || true

    # Remove iptables rules
    iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null || true
    ip6tables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null || true

    echo "✓ Bastion Firewall stopped"
fi

%postun
# Post-uninstallation script
if [ $1 -eq 0 ]; then
    # Complete removal
    systemctl daemon-reload 2>/dev/null || true
    
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q 2>/dev/null || true
    fi
    
    echo ""
    echo "✓ Bastion Firewall removed"
    echo "Configuration files remain in /etc/bastion"
    echo "To completely remove: sudo rm -rf /etc/bastion"
    echo ""
fi

%changelog
* $(date "+%a %b %d %Y") Martin <shipdocs@users.noreply.github.com> - ${VERSION}-1
- 🏰 Release v${VERSION}
- Rust daemon with eBPF kernel hooks
- High-performance process identification (~1µs latency)
- Non-blocking learning mode popups
- Asynchronous rule creation

* Sat Dec 21 2024 Martin <shipdocs@users.noreply.github.com> - 1.0.0-1
- 🏰 Initial release of Bastion Firewall
SPECEOF

# Replace VERSION placeholder in spec file
sed -i "s/\${VERSION}/$VERSION/g" "$BUILD_DIR/SPECS/bastion.spec"
# Fix the date in changelog - force English locale for RPM compatibility
CHANGELOG_DATE=$(LC_ALL=C date "+%a %b %d %Y")
sed -i "s/\$(date \"+%a %b %d %Y\")/$CHANGELOG_DATE/g" "$BUILD_DIR/SPECS/bastion.spec"

# Build RPM
print_step "Running rpmbuild..."
rpmbuild --define "_topdir $(pwd)/$BUILD_DIR" -bb "$BUILD_DIR/SPECS/bastion.spec"

# Move artifact to project root
find "$BUILD_DIR/RPMS" -name "*.rpm" -exec mv {} . \;

echo ""
print_info "============================================================"
print_info "RPM package built successfully!"
print_info "============================================================"
echo ""
ls -la *.rpm 2>/dev/null || true
echo ""
print_info "To install on Fedora/RHEL/openSUSE:"
echo "  sudo dnf install bastion-firewall-${VERSION}-1.*.rpm"
echo ""
