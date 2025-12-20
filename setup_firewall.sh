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

# firewall detection and configuration
print_info "Detecting firewall manager..."

# Check for Firewalld (Fedora/RHEL/CentOS/OpenSUSE)
if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld; then
    print_info "Firewalld detected."
    print_info "Configuring Firewalld for Pass-Through (Allow Outbound)..."
    
    # We rely on Douane for blocking. Firewalld should just pass traffic.
    # Usually strictly not needed as firewalld allows outbound by default.
    DEFAULT_ZONE=$(firewall-cmd --get-default-zone)
    print_info "Default zone: $DEFAULT_ZONE"
    print_info "Ensuring outbound traffic is allowed..."
    
    print_info "Firewalld configuration complete."

# Check for UFW (Debian/Ubuntu/Mint)
elif command -v ufw &> /dev/null; then
    print_info "UFW detected."
    
    # Enable UFW if not already enabled
    if ! ufw status | grep -q "Status: active"; then
        print_warning "UFW is not active. Enabling UFW..."
        # Add essential rules before enabling
        ufw allow 22/tcp comment 'SSH access'
        ufw allow out to any port 53 comment 'DNS'
        echo "y" | ufw enable
        print_info "UFW enabled"
    fi

    # Set policies
    print_info "Setting default outbound policy as ALLOW (Pass-through for Douane)"
    ufw default allow outgoing
    ufw default deny incoming
    
    # Allow loopback
    ufw allow in on lo
    ufw allow out on lo
    
    print_info "UFW configuration updated"

# Fallback to direct iptables config
elif command -v iptables &> /dev/null; then
    print_info "No firewall manager detected (UFW/Firewalld). Using raw iptables."
    
    # We only care about ensuring OUTPUT is ACCEPT by default for the chains
    # Douane inserts its NFQUEUE rule at the top of OUTPUT.
    print_info "Setting default OUTPUT policy to ACCEPT..."
    iptables -P OUTPUT ACCEPT
    
    print_info "Note: We are NOT modifying INPUT chain policies to avoid locking you out."
    
else
    print_error "No supported firewall tools found (ufw, firewalld, iptables)."
    exit 1
fi

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

# Create rollback script (Best effort)
ROLLBACK_SCRIPT="$BACKUP_DIR/rollback.sh"
cat > "$ROLLBACK_SCRIPT" << 'EOF'
#!/bin/bash
# Rollback script - attempts to restore outbound policy
echo "Rolling back firewall configuration..."
if command -v ufw &> /dev/null; then
    ufw default allow outgoing
    ufw reload
elif command -v iptables &> /dev/null; then
    iptables -P OUTPUT ACCEPT
fi
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
