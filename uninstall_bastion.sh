#!/bin/bash

#############################################################
# Bastion Firewall - Universal Uninstaller
# Version: 2.0.19
# Description: Completely removes Bastion Firewall from system
# Supports: Debian, Ubuntu, Fedora, RHEL, CentOS, Arch, Generic
#############################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    else
        DISTRO="unknown"
    fi
    echo "$DISTRO"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root"
    echo "Please run: sudo $0"
    exit 1
fi

DISTRO=$(detect_distro)

print_header "Bastion Firewall - Universal Uninstaller"
print_info "Detected distribution: $DISTRO"
echo ""

# Confirmation
echo -e "${YELLOW}This will completely remove Bastion Firewall from your system.${NC}"
echo ""
echo "The following will be removed:"
echo "  • Bastion Firewall package"
echo "  • Configuration files (/etc/bastion)"
echo "  • Log files (/var/log/bastion-daemon.log)"
echo "  • Binaries (/usr/bin/bastion-*)"
echo "  • Root helper and polkit policies"
echo "  • Python modules"
echo "  • Systemd service"
echo "  • Desktop entries"
echo "  • All runtime files"
echo ""
read -p "Are you sure you want to continue? (yes/no): " -r
echo ""

if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    print_info "Uninstall cancelled"
    exit 0
fi

print_header "Step 1: Stopping Bastion Firewall"

# Stop the service if running
if systemctl is-active --quiet bastion-firewall 2>/dev/null; then
    print_info "Stopping bastion-firewall service..."
    systemctl stop bastion-firewall || true
    print_success "Service stopped"
else
    print_info "Service not running"
fi

# Disable service
if systemctl is-enabled --quiet bastion-firewall 2>/dev/null; then
    print_info "Disabling bastion-firewall service..."
    systemctl disable bastion-firewall || true
    print_success "Service disabled"
fi

# Kill any running processes
print_info "Terminating all Bastion processes..."
pkill -f bastion-daemon 2>/dev/null || true
pkill -f bastion-gui 2>/dev/null || true
pkill -f bastion-control-panel 2>/dev/null || true
pkill -f bastion-root-helper 2>/dev/null || true
sleep 1
print_success "Processes terminated"

# Remove iptables rules
print_info "Removing iptables NFQUEUE rules..."
iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null || true
print_success "Firewall rules removed"

print_header "Step 2: Removing Package"

case "$DISTRO" in
    debian|ubuntu|linuxmint|pop)
        # Debian-based systems
        if dpkg -l | grep -q bastion-firewall 2>/dev/null; then
            print_info "Removing bastion-firewall package (Debian/Ubuntu)..."
            dpkg --purge bastion-firewall 2>/dev/null || true
            print_success "Package removed"

            print_info "Removing unused dependencies..."
            apt-get autoremove -y >/dev/null 2>&1 || true
            print_success "Dependencies cleaned"
        else
            print_info "Package not installed"
        fi
        ;;

    fedora|rhel|centos|rocky|almalinux)
        # RPM-based systems
        if rpm -q bastion-firewall >/dev/null 2>&1; then
            print_info "Removing bastion-firewall package (Fedora/RHEL)..."
            dnf remove -y bastion-firewall 2>/dev/null || yum remove -y bastion-firewall 2>/dev/null || true
            print_success "Package removed"

            print_info "Removing unused dependencies..."
            dnf autoremove -y >/dev/null 2>&1 || yum autoremove -y >/dev/null 2>&1 || true
            print_success "Dependencies cleaned"
        else
            print_info "Package not installed"
        fi
        ;;

    arch|manjaro)
        # Arch-based systems
        if pacman -Q bastion-firewall >/dev/null 2>&1; then
            print_info "Removing bastion-firewall package (Arch)..."
            pacman -Rns --noconfirm bastion-firewall 2>/dev/null || true
            print_success "Package removed"
        else
            print_info "Package not installed"
        fi
        ;;

    *)
        print_warning "Unknown distribution - skipping package removal"
        print_info "Manual files will still be removed"
        ;;
esac

print_header "Step 3: Removing Files and Directories"

# Remove configuration
if [ -d "/etc/bastion" ]; then
    print_info "Removing /etc/bastion..."
    rm -rf /etc/bastion
    print_success "Configuration removed"
fi

# Remove log files
if [ -f "/var/log/bastion-daemon.log" ]; then
    print_info "Removing /var/log/bastion-daemon.log..."
    rm -f /var/log/bastion-daemon.log
    print_success "Log file removed"
fi

if [ -d "/var/log/bastion" ]; then
    print_info "Removing /var/log/bastion..."
    rm -rf /var/log/bastion
    print_success "Log directory removed"
fi

# Remove socket
if [ -S "/var/run/bastion.sock" ]; then
    print_info "Removing /var/run/bastion.sock..."
    rm -f /var/run/bastion.sock
    print_success "Socket removed"
fi

# Remove binaries (both old douane and new bastion)
print_info "Removing binaries from /usr/bin..."
rm -f /usr/bin/douane* 2>/dev/null || true
rm -f /usr/bin/bastion-daemon 2>/dev/null || true
rm -f /usr/bin/bastion-gui 2>/dev/null || true
rm -f /usr/bin/bastion-control-panel 2>/dev/null || true
rm -f /usr/bin/bastion-firewall 2>/dev/null || true
rm -f /usr/bin/bastion-launch 2>/dev/null || true
rm -f /usr/bin/bastion-setup-firewall 2>/dev/null || true
rm -f /usr/bin/bastion-root-helper 2>/dev/null || true
print_success "Binaries removed"

# Remove Python modules (try both Debian and RPM paths)
if [ -d "/usr/lib/python3/dist-packages/douane" ]; then
    print_info "Removing Python modules (Debian path - douane)..."
    rm -rf /usr/lib/python3/dist-packages/douane
    print_success "Python modules removed"
fi

if [ -d "/usr/lib/python3/dist-packages/bastion" ]; then
    print_info "Removing Python modules (Debian path - bastion)..."
    rm -rf /usr/lib/python3/dist-packages/bastion
    print_success "Python modules removed"
fi

if [ -d "/usr/lib/python3/site-packages/douane" ]; then
    print_info "Removing Python modules (RPM path - douane)..."
    rm -rf /usr/lib/python3/site-packages/douane
    print_success "Python modules removed"
fi

if [ -d "/usr/lib/python3/site-packages/bastion" ]; then
    print_info "Removing Python modules (RPM path - bastion)..."
    rm -rf /usr/lib/python3/site-packages/bastion
    print_success "Python modules removed"
fi

# Remove systemd service
if [ -f "/lib/systemd/system/bastion-firewall.service" ]; then
    print_info "Removing systemd service..."
    rm -f /lib/systemd/system/bastion-firewall.service
    systemctl daemon-reload
    print_success "Systemd service removed"
fi

if [ -f "/usr/lib/systemd/system/bastion-firewall.service" ]; then
    print_info "Removing systemd service (alternate path)..."
    rm -f /usr/lib/systemd/system/bastion-firewall.service
    systemctl daemon-reload
    print_success "Systemd service removed"
fi

# Remove tmpfiles.d configuration
if [ -f "/usr/lib/tmpfiles.d/bastion.conf" ]; then
    print_info "Removing tmpfiles.d config..."
    rm -f /usr/lib/tmpfiles.d/bastion.conf
    print_success "Tmpfiles config removed"
fi

# Remove runtime directory
if [ -d "/run/bastion" ]; then
    print_info "Removing runtime directory..."
    rm -rf /run/bastion
    print_success "Runtime directory removed"
fi

# Remove desktop entries
print_info "Removing desktop entries..."
rm -f /usr/share/applications/douane*.desktop 2>/dev/null || true
rm -f /usr/share/applications/bastion-firewall.desktop 2>/dev/null || true
rm -f /usr/share/applications/com.bastion.firewall.desktop 2>/dev/null || true
rm -f /usr/share/applications/bastion-control-panel.desktop 2>/dev/null || true
rm -f /usr/share/applications/bastion-tray.desktop 2>/dev/null || true
print_success "Desktop entries removed"

# Remove autostart entries
if ls /etc/xdg/autostart/douane*.desktop >/dev/null 2>&1 || ls /etc/xdg/autostart/bastion*.desktop >/dev/null 2>&1; then
    print_info "Removing autostart entries..."
    rm -f /etc/xdg/autostart/douane*.desktop
    rm -f /etc/xdg/autostart/bastion*.desktop
    print_success "Autostart entries removed"
fi

# Also remove user-specific autostart entries
for user_home in /home/*; do
    if [ -d "$user_home/.config/autostart" ]; then
        rm -f "$user_home/.config/autostart/douane"*.desktop 2>/dev/null || true
        rm -f "$user_home/.config/autostart/bastion"*.desktop 2>/dev/null || true
    fi
done
print_success "User autostart entries removed"

# Remove AppStream metadata
if [ -f "/usr/share/metainfo/com.bastion.firewall.metainfo.xml" ]; then
    print_info "Removing AppStream metadata..."
    rm -f /usr/share/metainfo/com.bastion.firewall.metainfo.xml
    print_success "AppStream metadata removed"
fi


# Remove PolicyKit actions
print_info "Removing PolicyKit actions..."
rm -f /usr/share/polkit-1/actions/com.bastion.daemon.policy 2>/dev/null || true
rm -f /usr/share/polkit-1/actions/com.bastion.root-helper.policy 2>/dev/null || true
rm -f /usr/share/polkit-1/actions/com.bastion.firewall.policy 2>/dev/null || true
print_success "PolicyKit actions removed"

# Remove documentation
if [ -d "/usr/share/doc/bastion-firewall" ]; then
    print_info "Removing documentation..."
    rm -rf /usr/share/doc/bastion-firewall
    print_success "Documentation removed"
fi

# Remove user configurations
print_info "Removing user configurations..."
rm -rf /root/.config/douane 2>/dev/null || true
rm -rf /root/.config/bastion 2>/dev/null || true

for user_home in /home/*; do
    rm -rf "$user_home/.config/douane" 2>/dev/null || true
    rm -rf "$user_home/.config/bastion" 2>/dev/null || true
done
print_success "User configurations removed"

# Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    print_info "Updating desktop database..."
    update-desktop-database -q 2>/dev/null || true
    print_success "Desktop database updated"
fi

# Reload systemd
print_info "Reloading systemd daemon..."
systemctl daemon-reload 2>/dev/null || true
print_success "Systemd reloaded"

print_header "Uninstallation Complete"

echo -e "${GREEN}✓ Bastion Firewall has been completely removed from your system${NC}"
echo ""
echo "Removed:"
echo "  ✓ All packages and dependencies"
echo "  ✓ Configuration files"
echo "  ✓ Log files"
echo "  ✓ Binaries and Python modules"
echo "  ✓ Root helper and PolicyKit policies"
echo "  ✓ Systemd service"
echo "  ✓ Desktop entries and metadata"
echo "  ✓ User configurations"
echo ""
echo -e "${YELLOW}⚠ IMPORTANT:${NC}"
echo "  Your firewall outbound policy may still be restrictive."
echo ""
echo "  To restore normal outbound access:"
echo "    • For UFW users:"
echo "        sudo ufw default allow outgoing"
echo "        sudo ufw reload"
echo ""
echo "    • For firewalld users:"
echo "        sudo firewall-cmd --permanent --set-default-zone=public"
echo "        sudo firewall-cmd --reload"
echo ""
echo "Thank you for using Bastion Firewall!"
echo ""


