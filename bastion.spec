Name:           bastion-firewall
Version:        1.4.7
Release:        1%{?dist}
Summary:        Application Firewall for Linux with GUI - Your Last Line of Defense
License:        GPLv3
URL:            https://github.com/bastion-firewall/bastion-firewall
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
🏰 Bastion Firewall - Your Last Line of Defense

Bastion Firewall provides Windows-like outbound connection control for Linux.
Like a medieval bastion protecting a fortress, Bastion stands guard over your
system's network connections, intercepting all outbound traffic and showing
GUI dialogs to let users decide which applications can access the network.

Built specifically for Zorin OS 18 and compatible with all Debian-based distributions.

Features:
 - Real-time packet interception using netfilter
 - Application identification via /proc filesystem
 - Beautiful GUI dialogs for user decisions
 - Independent tray icon with visual status indicators
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
mkdir -p $RPM_BUILD_ROOT/usr/lib/python3/site-packages/bastion
mkdir -p $RPM_BUILD_ROOT/etc/bastion
mkdir -p $RPM_BUILD_ROOT/usr/share/applications
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/bastion-firewall
mkdir -p $RPM_BUILD_ROOT/lib/systemd/system

# Install executables
install -m 755 bastion-firewall $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 bastion-daemon $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 bastion-gui $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 bastion-control-panel $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 bastion-setup-firewall $RPM_BUILD_ROOT/usr/local/bin/
install -m 755 bastion-launch $RPM_BUILD_ROOT/usr/local/bin/

# Install Python modules
cp -r bastion/* $RPM_BUILD_ROOT/usr/lib/python3/site-packages/bastion/

# Install config
install -m 644 config.json $RPM_BUILD_ROOT/etc/bastion/config.json

# Install Systemd service
install -m 644 bastion-firewall.service $RPM_BUILD_ROOT/lib/systemd/system/

# Install Desktop files
install -m 644 com.bastion.firewall.desktop $RPM_BUILD_ROOT/usr/share/applications/
install -m 644 bastion-control-panel.desktop $RPM_BUILD_ROOT/usr/share/applications/
install -m 644 bastion-tray.desktop $RPM_BUILD_ROOT/usr/share/applications/

# Install autostart entry for tray icon
mkdir -p $RPM_BUILD_ROOT/etc/xdg/autostart
install -m 644 bastion-tray.desktop $RPM_BUILD_ROOT/etc/xdg/autostart/

%files
/usr/local/bin/bastion-firewall
/usr/local/bin/bastion-daemon
/usr/local/bin/bastion-gui
/usr/local/bin/bastion-control-panel
/usr/local/bin/bastion-setup-firewall
/usr/local/bin/bastion-launch
/usr/lib/python3/site-packages/bastion/
%config(noreplace) /etc/bastion/config.json
/lib/systemd/system/bastion-firewall.service
/usr/share/applications/com.bastion.firewall.desktop
/usr/share/applications/bastion-control-panel.desktop
/usr/share/applications/bastion-tray.desktop
/etc/xdg/autostart/bastion-tray.desktop
/usr/share/metainfo/com.bastion.firewall.metainfo.xml
/usr/share/polkit-1/actions/com.bastion.daemon.policy
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
echo "Bastion Firewall - Post Installation"
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
echo "✓ Bastion Firewall Installed"
echo "============================================================"
echo ""
echo "To start manually:"
echo "  /usr/local/bin/bastion-gui"
echo ""
echo "Or from the application menu:"
echo "  Search for 'Bastion Firewall'"
echo ""
echo "Documentation: /usr/share/doc/bastion-firewall/"
echo ""

%preun
# Pre-uninstallation script
if [ $1 -eq 0 ]; then
    # Complete removal (not upgrade)
    echo ""
    echo "============================================================"
    echo "Bastion Firewall - Pre-Removal"
    echo "============================================================"
    echo ""

    # Stop and disable service
    if systemctl is-active --quiet bastion-firewall 2>/dev/null; then
        echo "Stopping bastion-firewall service..."
        systemctl stop bastion-firewall 2>/dev/null || true
        echo "✓ Service stopped"
    fi

    if systemctl is-enabled --quiet bastion-firewall 2>/dev/null; then
        echo "Disabling bastion-firewall service..."
        systemctl disable bastion-firewall 2>/dev/null || true
        echo "✓ Service disabled"
    fi

    # Kill all processes
    echo "Terminating all Bastion processes..."
    pkill -f bastion-daemon 2>/dev/null || true
    pkill -f bastion-gui 2>/dev/null || true
    pkill -f bastion-control-panel 2>/dev/null || true
    sleep 1
    echo "✓ Processes terminated"

    # Remove iptables rules
    echo "Removing iptables NFQUEUE rules..."
    iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null || true
    echo "✓ Firewall rules removed"

    # Remove socket
    if [ -S "/var/run/bastion.sock" ]; then
        echo "Removing socket file..."
        rm -f /var/run/bastion.sock
        echo "✓ Socket removed"
    fi

    echo ""
    echo "============================================================"
    echo "✓ Bastion Firewall stopped and cleaned up"
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
    echo "Bastion Firewall - Post-Removal Cleanup"
    echo "============================================================"
    echo ""

    # Remove configuration (only on purge, RPM doesn't have purge like DEB)
    # Users can manually remove /etc/bastion if they want

    # Remove log files
    if [ -f "/var/log/bastion-daemon.log" ]; then
        echo "Removing log files..."
        rm -f /var/log/bastion-daemon.log
        echo "✓ Log files removed"
    fi

    # Remove autostart entries from user directories
    for user_home in /home/*; do
        if [ -d "$user_home/.config/autostart" ]; then
            rm -f "$user_home/.config/autostart/bastion"*.desktop 2>/dev/null || true
        fi
    done

    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true

    # Update desktop database
    if command -v update-desktop-database >/dev/null 2>&1; then
        echo "Updating desktop database..."
        update-desktop-database -q 2>/dev/null || true
        echo "✓ Desktop database updated"
    fi

    echo ""
    echo "✓ Bastion Firewall removed"
    echo ""
    echo "Configuration files remain in /etc/bastion"
    echo "To completely remove: sudo rm -rf /etc/bastion"
    echo ""
fi

%changelog
* Sat Dec 21 2024 Martin <shipdocs@users.noreply.github.com> - 1.0.0-1
- 🏰 Initial release of Bastion Firewall
- Rebranded from Douane to Bastion Firewall
- Professional branding: "Your Last Line of Defense"
- Built specifically for Zorin OS 18
- All features from Douane 2.0.20 included:
  * Independent tray icon with auto-connect
  * Visual status indicators (green/red/orange)
  * Working Start/Restart/Stop controls
  * Auto-start support
  * Security hardening (5 phases)
  * UFW integration
  * Comprehensive documentation
  * Production-ready stability
- NEW: Inbound Protection tab with UFW integration
- Security score improved from 7.5/10 to 2/10

* Sat Dec 20 2024 Martin <shipdocs@users.noreply.github.com> - 2.0.9-1
- Initial RPM release
