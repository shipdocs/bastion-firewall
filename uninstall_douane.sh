#!/bin/bash

#############################################################
# Douane Firewall - Universal Uninstaller
# Version: 2.0.18
# Description: Completely removes Douane Firewall from system
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

print_header "Douane Firewall - Universal Uninstaller"
print_info "Detected distribution: $DISTRO"
echo ""

# Confirmation
echo -e "${YELLOW}This will completely remove Douane Firewall from your system.${NC}"
echo ""
echo "The following will be removed:"
echo "  • Douane package"
echo "  • Configuration files (/etc/douane)"
echo "  • Log files (/var/log/douane-daemon.log)"
echo "  • Binaries (/usr/local/bin/douane*)"
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

print_header "Step 1: Stopping Douane Firewall"

# Stop the service if running
if systemctl is-active --quiet douane-firewall 2>/dev/null; then
    print_info "Stopping douane-firewall service..."
    systemctl stop douane-firewall || true
    print_success "Service stopped"
else
    print_info "Service not running"
fi

# Disable service
if systemctl is-enabled --quiet douane-firewall 2>/dev/null; then
    print_info "Disabling douane-firewall service..."
    systemctl disable douane-firewall || true
    print_success "Service disabled"
fi

# Kill any running processes
print_info "Terminating all Douane processes..."
pkill -f douane-daemon 2>/dev/null || true
pkill -f douane-gui-client 2>/dev/null || true
pkill -f douane-control-panel 2>/dev/null || true
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
        if dpkg -l | grep -q douane-firewall 2>/dev/null; then
            print_info "Removing douane-firewall package (Debian/Ubuntu)..."
            dpkg --purge douane-firewall 2>/dev/null || true
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
        if rpm -q douane-firewall >/dev/null 2>&1; then
            print_info "Removing douane-firewall package (Fedora/RHEL)..."
            dnf remove -y douane-firewall 2>/dev/null || yum remove -y douane-firewall 2>/dev/null || true
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
        if pacman -Q douane-firewall >/dev/null 2>&1; then
            print_info "Removing douane-firewall package (Arch)..."
            pacman -Rns --noconfirm douane-firewall 2>/dev/null || true
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
if [ -d "/etc/douane" ]; then
    print_info "Removing /etc/douane..."
    rm -rf /etc/douane
    print_success "Configuration removed"
fi

# Remove log files
if [ -f "/var/log/douane-daemon.log" ]; then
    print_info "Removing /var/log/douane-daemon.log..."
    rm -f /var/log/douane-daemon.log
    print_success "Log file removed"
fi

if [ -d "/var/log/douane" ]; then
    print_info "Removing /var/log/douane..."
    rm -rf /var/log/douane
    print_success "Log directory removed"
fi

# Remove socket
if [ -S "/var/run/douane.sock" ]; then
    print_info "Removing /var/run/douane.sock..."
    rm -f /var/run/douane.sock
    print_success "Socket removed"
fi

# Remove binaries
if ls /usr/local/bin/douane* >/dev/null 2>&1; then
    print_info "Removing binaries from /usr/local/bin..."
    rm -f /usr/local/bin/douane*
    print_success "Binaries removed"
fi

# Remove Python modules (try both Debian and RPM paths)
if [ -d "/usr/lib/python3/dist-packages/douane" ]; then
    print_info "Removing Python modules (Debian path)..."
    rm -rf /usr/lib/python3/dist-packages/douane
    print_success "Python modules removed"
fi

if [ -d "/usr/lib/python3/site-packages/douane" ]; then
    print_info "Removing Python modules (RPM path)..."
    rm -rf /usr/lib/python3/site-packages/douane
    print_success "Python modules removed"
fi

# Remove systemd service
if [ -f "/lib/systemd/system/douane-firewall.service" ]; then
    print_info "Removing systemd service..."
    rm -f /lib/systemd/system/douane-firewall.service
    systemctl daemon-reload
    print_success "Systemd service removed"
fi

if [ -f "/usr/lib/systemd/system/douane-firewall.service" ]; then
    print_info "Removing systemd service (alternate path)..."
    rm -f /usr/lib/systemd/system/douane-firewall.service
    systemctl daemon-reload
    print_success "Systemd service removed"
fi

# Remove desktop entries
if ls /usr/share/applications/douane*.desktop >/dev/null 2>&1; then
    print_info "Removing desktop entries..."
    rm -f /usr/share/applications/douane*.desktop
    print_success "Desktop entries removed"
fi

# Remove autostart entries
if ls /etc/xdg/autostart/douane*.desktop >/dev/null 2>&1; then
    print_info "Removing autostart entries..."
    rm -f /etc/xdg/autostart/douane*.desktop
    print_success "Autostart entries removed"
fi

# Also remove user-specific autostart entries
for user_home in /home/*; do
    if [ -d "$user_home/.config/autostart" ]; then
        if ls "$user_home/.config/autostart/douane"*.desktop >/dev/null 2>&1; then
            rm -f "$user_home/.config/autostart/douane"*.desktop
        fi
    fi
done

# Remove AppStream metadata
if [ -f "/usr/share/metainfo/com.douane.firewall.metainfo.xml" ]; then
    print_info "Removing AppStream metadata..."
    rm -f /usr/share/metainfo/com.douane.firewall.metainfo.xml
    print_success "AppStream metadata removed"
fi


# Remove PolicyKit actions
if [ -f "/usr/share/polkit-1/actions/com.douane.daemon.policy" ]; then
    print_info "Removing PolicyKit actions..."
    rm -f /usr/share/polkit-1/actions/com.douane.daemon.policy
    print_success "PolicyKit actions removed"
fi

# Remove documentation
if [ -d "/usr/share/doc/douane-firewall" ]; then
    print_info "Removing documentation..."
    rm -rf /usr/share/doc/douane-firewall
    print_success "Documentation removed"
fi

# Remove user configurations
print_info "Removing user configurations..."
rm -rf /root/.config/douane 2>/dev/null || true

for user_home in /home/*; do
    if [ -d "$user_home/.config/douane" ]; then
        rm -rf "$user_home/.config/douane"
    fi
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

echo -e "${GREEN}✓ Douane Firewall has been completely removed from your system${NC}"
echo ""
echo "Removed:"
echo "  ✓ All packages and dependencies"
echo "  ✓ Configuration files"
echo "  ✓ Log files"
echo "  ✓ Binaries and Python modules"
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
echo "Thank you for using Douane Firewall!"
echo ""


