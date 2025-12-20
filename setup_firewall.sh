#!/bin/bash
#
# Douane Firewall Setup Script
#
# This script safely configures UFW and the system for outbound firewall control.
# It includes safety checks and rollback capabilities.
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for --auto flag
AUTO_MODE=false
if [ "$1" = "--auto" ]; then
    AUTO_MODE=true
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root (use pkexec or sudo)${NC}"
    exit 1
fi

if [ "$AUTO_MODE" = false ]; then
    echo "============================================================"
    echo "Douane Firewall - Setup Script"
    echo "============================================================"
    echo ""
fi

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if UFW is installed
print_info "Checking for UFW..."
if ! command -v ufw &> /dev/null; then
    print_error "UFW is not installed!"
    echo "Install with: sudo apt-get install ufw"
    exit 1
fi
print_info "UFW found"

# Check if iptables is installed
print_info "Checking for iptables..."
if ! command -v iptables &> /dev/null; then
    print_error "iptables is not installed!"
    exit 1
fi
print_info "iptables found"

# Backup current UFW configuration
print_info "Backing up current UFW configuration..."
BACKUP_DIR="/var/backups/douane_firewall_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /etc/ufw "$BACKUP_DIR/" 2>/dev/null || true
ufw status verbose > "$BACKUP_DIR/ufw_status.txt" 2>/dev/null || true
print_info "Backup saved to: $BACKUP_DIR"

# Warning message
if [ "$AUTO_MODE" = false ]; then
    echo ""
    print_warning "IMPORTANT: This script will configure UFW to ALLOW outbound connections by default."
    print_warning "The Douane Firewall daemon will intercept traffic and block unapproved apps."
    echo ""
    echo "This means:"
    echo "  - UFW will act as pass-through for outbound traffic"
    echo "  - Douane provides the actual filtering"
    echo "  - Inbound traffic is still blocked by UFW (except SSH/basics)"
    echo ""
    read -p "Do you want to continue? (yes/no): " -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        print_info "Setup cancelled by user"
        exit 0
    fi
else
    print_info "Running in automatic mode..."
fi

# Enable UFW if not already enabled
print_info "Checking UFW status..."
if ! ufw status | grep -q "Status: active"; then
    print_warning "UFW is not active. Enabling UFW..."
    
    # Add essential rules before enabling
    print_info "Adding essential rules..."
    
    # Allow SSH (important!)
    ufw allow 22/tcp comment 'SSH access'
    
    # Allow established connections
    ufw allow out to any port 53 comment 'DNS'
    
    # Enable UFW
    echo "y" | ufw enable
    print_info "UFW enabled"
else
    print_info "UFW is already active"
fi

# Add safety rules BEFORE changing default policy
print_info "Adding safety rules..."

# Allow DNS (critical for name resolution)
ufw allow out 53 comment 'DNS - Douane Firewall'

# Allow DHCP client
ufw allow out 67:68/udp comment 'DHCP - Douane Firewall'

# Allow NTP (time synchronization)
ufw allow out 123/udp comment 'NTP - Douane Firewall'

# Allow established connections (important!)
# Note: UFW handles this automatically, but we make it explicit
print_info "Established connections will be allowed automatically by UFW"

# Show current default policies
print_info "Current UFW default policies:"
ufw status verbose | grep "Default:" || true

# In Learning Mode, we keep outbound as ALLOW
# In Enforcement Mode, Douane intercepts via NFQUEUE, so we still set UFW default to ALLOW.
# Douane is an Application Firewall that sits on top.
print_info "Setting default outbound policy as ALLOW (Pass-through for Douane)"
ufw default allow outgoing

# Keep default inbound as deny
ufw default deny incoming

# Allow loopback
ufw allow in on lo
ufw allow out on lo

# Ensure NFQUEUE rule exists for Douane interception
# This is usually done by the daemon, but good to check here or ensure dependencies
print_info "Ensuring iptables NFQUEUE support..."
if ! iptables -C OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null; then
    print_info "Note: NFQUEUE iptables rule will be managed by the Douane daemon."
fi

# Show new status
echo ""
print_info "New UFW status:"
ufw status verbose

# Create rollback script
ROLLBACK_SCRIPT="$BACKUP_DIR/rollback.sh"
cat > "$ROLLBACK_SCRIPT" << 'EOF'
#!/bin/bash
# Rollback script - restores UFW to allow outbound
echo "Rolling back UFW configuration..."
ufw default allow outgoing
ufw reload
echo "Rollback complete. Outbound connections are now allowed by default."
EOF
chmod +x "$ROLLBACK_SCRIPT"

echo ""
print_info "Setup complete!"
echo ""
print_warning "IMPORTANT NEXT STEPS:"
echo "  1. Start the Douane Firewall: /usr/local/bin/douane-gui-client"
echo "  2. Test your connection by opening a web browser"
echo "  3. You should see popup dialogs for each connection"
echo ""
print_info "If something goes wrong, run the rollback script:"
echo "  pkexec $ROLLBACK_SCRIPT"
echo ""
print_info "Backup location: $BACKUP_DIR"
echo ""

exit 0
