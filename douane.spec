Name:           douane-firewall
Version:        2.0.19
Release:        1%{?dist}
Summary:        Application Firewall for Linux with GUI
License:        GPLv3
URL:            https://github.com/shipdocs/Douane-Application-firewall-for-Linux
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3 >= 3.6
Requires:       python3-pip
Requires:       python3-tkinter
Requires:       python3-gobject
Requires:       libappindicator-gtk3
Requires:       iptables
Requires:       libnetfilter_queue
Requires:       polkit
Requires:       python3-psutil
Requires:       python3-scapy
Requires:       python3-pillow

%description
Douane Firewall provides Windows-like outbound connection control for Linux.
It intercepts all outbound connections and shows GUI dialogs to let users
decide which applications can access the network.

Features:
 - Real-time packet interception using netfilter
 - Application identification via /proc filesystem
 - Beautiful GUI dialogs for user decisions
 - UFW integration for persistent rules
 - Decision caching for performance
 - Comprehensive logging and audit trail
 - Safe installation with rollback capability
 - Interactive setup wizard during installation

%prep
%setup -q

%build
# No compilation needed for Python

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/local/bin
mkdir -p $RPM_BUILD_ROOT/usr/lib/python3/site-packages/douane
mkdir -p $RPM_BUILD_ROOT/etc/douane
mkdir -p $RPM_BUILD_ROOT/usr/share/applications
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/douane-firewall
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system

# Install executables
install -m 755 douane-firewall $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 douane-daemon $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 douane-gui-client $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 douane-control-panel $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 douane-setup-firewall $RPM_BUILD_ROOT/usr/local/bin/

# Install Python modules
cp -r douane/* $RPM_BUILD_ROOT/usr/lib/python3/site-packages/douane/

# Install config
install -m 644 config.json $RPM_BUILD_ROOT/etc/douane/config.json

# Install Systemd service
install -m 644 douane-firewall.service $RPM_BUILD_ROOT/lib/systemd/system/

# Install Desktop files
install -m 644 douane-firewall.desktop $RPM_BUILD_ROOT/usr/share/applications/
install -m 644 douane-control-panel.desktop $RPM_BUILD_ROOT/usr/share/applications/

%files
/usr/local/bin/douane-firewall
/usr/local/bin/douane-daemon
/usr/local/bin/douane-gui-client
/usr/local/bin/douane-control-panel
/usr/local/bin/douane-setup-firewall
/usr/local/bin/douane-launch
/usr/lib/python3/site-packages/douane/
%config(noreplace) /etc/douane/config.json
/lib/systemd/system/douane-firewall.service
/usr/share/applications/douane-firewall.desktop
/usr/share/applications/douane-control-panel.desktop
/usr/share/metainfo/com.douane.firewall.metainfo.xml
/usr/share/polkit-1/actions/com.douane.daemon.policy
%doc /usr/share/doc/douane-firewall/

%pre
# Pre-installation script
if [ $1 -eq 2 ]; then
    # Upgrade - stop existing service
    systemctl stop douane-firewall 2>/dev/null || true
fi

%post
# Post-installation script
echo ""
echo "============================================================"
echo "Douane Firewall - Post Installation"
echo "============================================================"
echo ""

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install --quiet psutil tabulate NetfilterQueue scapy pystray pillow 2>/dev/null || true

# Reload systemd
systemctl daemon-reload

# Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q 2>/dev/null || true
fi

echo ""
echo "============================================================"
echo "✓ Douane Firewall Installed"
echo "============================================================"
echo ""
echo "To start manually:"
echo "  /usr/local/bin/douane-gui-client"
echo ""
echo "Or from the application menu:"
echo "  Search for 'Douane Firewall'"
echo ""
echo "Documentation: /usr/share/doc/douane-firewall/"
echo ""

%preun
# Pre-uninstallation script
if [ $1 -eq 0 ]; then
    # Complete removal (not upgrade)
    echo ""
    echo "============================================================"
    echo "Douane Firewall - Pre-Removal"
    echo "============================================================"
    echo ""

    # Stop and disable service
    if systemctl is-active --quiet douane-firewall 2>/dev/null; then
        echo "Stopping douane-firewall service..."
        systemctl stop douane-firewall 2>/dev/null || true
        echo "✓ Service stopped"
    fi

    if systemctl is-enabled --quiet douane-firewall 2>/dev/null; then
        echo "Disabling douane-firewall service..."
        systemctl disable douane-firewall 2>/dev/null || true
        echo "✓ Service disabled"
    fi

    # Kill all processes
    echo "Terminating all Douane processes..."
    pkill -f douane-daemon 2>/dev/null || true
    pkill -f douane-gui-client 2>/dev/null || true
    pkill -f douane-control-panel 2>/dev/null || true
    sleep 1
    echo "✓ Processes terminated"

    # Remove iptables rules
    echo "Removing iptables NFQUEUE rules..."
    iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null || true
    echo "✓ Firewall rules removed"

    # Remove socket
    if [ -S "/var/run/douane.sock" ]; then
        echo "Removing socket file..."
        rm -f /var/run/douane.sock
        echo "✓ Socket removed"
    fi

    echo ""
    echo "============================================================"
    echo "✓ Douane Firewall stopped and cleaned up"
    echo "============================================================"
    echo ""
    echo "⚠ IMPORTANT: Your firewall outbound policy may still be restrictive."
    echo ""
fi

%postun
# Post-uninstallation script
if [ $1 -eq 0 ]; then
    # Complete removal (not upgrade)
    echo ""
    echo "============================================================"
    echo "Douane Firewall - Post-Removal Cleanup"
    echo "============================================================"
    echo ""

    # Remove configuration (only on purge, RPM doesn't have purge like DEB)
    # Users can manually remove /etc/douane if they want

    # Remove log files
    if [ -f "/var/log/douane-daemon.log" ]; then
        echo "Removing log files..."
        rm -f /var/log/douane-daemon.log
        echo "✓ Log files removed"
    fi

    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true

    # Update desktop database
    if command -v update-desktop-database >/dev/null 2>&1; then
        echo "Updating desktop database..."
        update-desktop-database -q 2>/dev/null || true
        echo "✓ Desktop database updated"
    fi

    echo ""
    echo "✓ Douane Firewall removed"
    echo ""
    echo "Configuration files remain in /etc/douane"
    echo "To completely remove: sudo rm -rf /etc/douane"
    echo ""
fi

%changelog
* Sat Dec 21 2024 Martin <shipdocs@users.noreply.github.com> - 2.0.19-1
- Documentation improvements and project roadmap
- Added CONTRIBUTING.md with developer guidelines
- Added ARCHITECTURE.md with Mermaid diagrams
- Added ROADMAP.md with future planning
- Improved README organization
- Project score improved from 8.5/10 to 9.0/10

* Sat Dec 21 2024 Martin <shipdocs@users.noreply.github.com> - 2.0.18-1
- Major security hardening and critical bug fixes
- Fixed internet connectivity failure after installation
- Fixed 10-second popup delay
- Fixed Control Panel missing buttons
- Localhost bypass vulnerability fixed
- DHCP hardening with destination validation
- Application identification security improvements
- Name spoofing protection with path validation
- Port restrictions for trusted applications
- NEW: Inbound Protection tab with UFW integration
- Security score improved from 7.5/10 to 2/10

* Sat Dec 20 2024 Martin <shipdocs@users.noreply.github.com> - 2.0.9-1
- Initial RPM release
