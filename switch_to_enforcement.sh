#!/bin/bash
#
# Switch Douane Firewall to Enforcement Mode
#
# This script:
# 1. Changes UFW default outbound policy to DENY
# 2. Ensures Douane daemon is running (adds NFQUEUE rule)
# 3. Updates config to enforcement mode
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run with pkexec or sudo"
    exit 1
fi

echo "============================================================"
echo "Douane Firewall - Switch to Enforcement Mode"
echo "============================================================"
echo ""

print_warning "This will change UFW to DENY outbound connections by default!"
print_warning "Douane daemon MUST be running for internet to work!"
echo ""
read -p "Continue? (yes/no): " -r
echo ""

if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    print_info "Cancelled"
    exit 0
fi

# Step 1: Change UFW default outbound policy to DENY
print_info "Changing UFW default outbound policy to DENY..."
ufw default deny outgoing

# Step 2: Reload UFW
print_info "Reloading UFW..."
ufw reload

# Step 3: Update Douane config to enforcement mode
print_info "Updating Douane config to enforcement mode..."
if [ -f /etc/bastion/config.json ]; then
    # Use Python to update JSON properly
    python3 << 'PYTHON_EOF'
import json
config_file = '/etc/bastion/config.json'
with open(config_file, 'r') as f:
    config = json.load(f)
config['mode'] = 'enforcement'
with open(config_file, 'w') as f:
    json.dump(config, f, indent=2)
print("✓ Config updated to enforcement mode")
PYTHON_EOF
else
    print_warning "Config file not found at /etc/bastion/config.json"
fi

# Step 4: Show current status
echo ""
print_info "Current UFW status:"
ufw status verbose | grep -E "Default:|Status:"

echo ""
print_info "Current iptables OUTPUT chain (first 10 rules):"
iptables -L OUTPUT -n -v --line-numbers | head -12

echo ""
print_warning "IMPORTANT: Make sure Douane daemon is running!"
print_info "The NFQUEUE rule should be at position 1 in OUTPUT chain"
print_info "If not, start Douane: /usr/local/bin/bastion-gui"

echo ""
print_info "Setup complete!"
echo ""

