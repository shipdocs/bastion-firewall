#!/bin/bash
#
# Rebrand Douane to Bastion Firewall
# This script systematically replaces all references
#

set -e

echo "🏰 ============================================================"
echo "🏰 REBRANDING TO BASTION FIREWALL"
echo "🏰 ============================================================"
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_done() {
    echo -e "${GREEN}  ✓${NC} $1"
}

# Step 1: Python imports
print_step "Updating Python imports..."
find . -type f -name "*.py" -exec sed -i 's/from douane/from bastion/g' {} +
find . -type f -name "*.py" -exec sed -i 's/import douane/import bastion/g' {} +
print_done "Python imports updated"

# Step 2: Module references
print_step "Updating module references..."
find . -type f -name "*.py" -exec sed -i 's/douane\./bastion./g' {} +
print_done "Module references updated"

# Step 3: File paths - /etc/bastion
print_step "Updating /etc/bastion paths..."
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.spec" \) \
  -exec sed -i 's|/etc/bastion|/etc/bastion|g' {} +
print_done "/etc/bastion → /etc/bastion"

# Step 4: File paths - /var/log/bastion
print_step "Updating /var/log/bastion paths..."
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.spec" \) \
  -exec sed -i 's|/var/log/bastion|/var/log/bastion|g' {} +
print_done "/var/log/bastion → /var/log/bastion"

# Step 5: Socket paths
print_step "Updating socket paths..."
find . -type f \( -name "*.py" -o -name "*.sh" \) \
  -exec sed -i 's|/tmp/bastion-daemon.sock|/tmp/bastion-daemon.sock|g' {} +
find . -type f \( -name "*.py" -o -name "*.sh" \) \
  -exec sed -i 's|/var/run/bastion.sock|/var/run/bastion.sock|g' {} +
print_done "Socket paths updated"

# Step 6: Binary names
print_step "Updating binary names..."
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.desktop" -o -name "*.spec" -o -name "control" \) \
  -exec sed -i 's|bastion-daemon|bastion-daemon|g' {} +
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.desktop" -o -name "*.spec" -o -name "control" \) \
  -exec sed -i 's|bastion-gui|bastion-gui|g' {} +
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.desktop" -o -name "*.spec" -o -name "control" \) \
  -exec sed -i 's|bastion_control_panel|bastion_control_panel|g' {} +
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.desktop" -o -name "*.spec" -o -name "control" \) \
  -exec sed -i 's|bastion-control-panel|bastion-control-panel|g' {} +
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.desktop" -o -name "*.spec" -o -name "control" \) \
  -exec sed -i 's|bastion_firewall|bastion_firewall|g' {} +
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.desktop" -o -name "*.spec" -o -name "control" \) \
  -exec sed -i 's|bastion-firewall|bastion-firewall|g' {} +
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.desktop" -o -name "*.spec" -o -name "control" \) \
  -exec sed -i 's|bastion-setup-firewall|bastion-setup-firewall|g' {} +
find . -type f \( -name "*.py" -o -name "*.sh" -o -name "*.service" -o -name "*.desktop" -o -name "*.spec" -o -name "control" \) \
  -exec sed -i 's|bastion-launch|bastion-launch|g' {} +
print_done "Binary names updated"

# Step 7: Package names
print_step "Updating package names..."
find . -type f \( -name "*.spec" -o -name "control" -o -name "*.desktop" -o -name "*.sh" -o -name "*.xml" \) \
  -exec sed -i 's/bastion-firewall/bastion-firewall/g' {} +
print_done "Package names updated"

# Step 8: Display names
print_step "Updating display names..."
find . -type f -name "*.py" -exec sed -i 's/Douane Firewall/Bastion Firewall/g' {} +
find . -type f -name "*.desktop" -exec sed -i 's/Douane Firewall/Bastion Firewall/g' {} +
find . -type f -name "*.desktop" -exec sed -i 's/Douane/Bastion/g' {} +
find . -type f -name "*.xml" -exec sed -i 's/Douane Firewall/Bastion Firewall/g' {} +
find . -type f -name "*.xml" -exec sed -i 's/Douane/Bastion/g' {} +
find . -type f -name "*.md" -exec sed -i 's/Douane Firewall/Bastion Firewall/g' {} +
find . -type f -name "*.md" -exec sed -i 's/Douane/Bastion/g' {} +
print_done "Display names updated"

# Step 9: PolicyKit actions
print_step "Updating PolicyKit actions..."
find . -type f -name "*.policy" -exec sed -i 's/com.douane/com.bastion/g' {} +
find . -type f \( -name "*.spec" -o -name "control" -o -name "*.sh" \) \
  -exec sed -i 's/com.bastion.daemon.policy/com.bastion.daemon.policy/g' {} +
print_done "PolicyKit actions updated"

# Step 10: AppStream metadata
print_step "Updating AppStream metadata..."
find . -type f \( -name "*.xml" -o -name "*.spec" -o -name "control" -o -name "*.sh" \) \
  -exec sed -i 's/com.bastion.firewall/com.bastion.firewall/g' {} +
print_done "AppStream metadata updated"

# Step 11: Documentation paths
print_step "Updating documentation paths..."
find . -type f \( -name "*.spec" -o -name "control" -o -name "*.sh" \) \
  -exec sed -i 's|/usr/share/doc/bastion-firewall|/usr/share/doc/bastion-firewall|g' {} +
print_done "Documentation paths updated"

echo ""
echo -e "${GREEN}✅ REBRANDING COMPLETE!${NC}"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Test build: ./build_deb.sh"
echo "  3. Commit: git add -A && git commit -m 'rebrand: Douane → Bastion Firewall'"
echo ""

