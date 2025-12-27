#!/bin/bash
# Start daemon with bypass rules for system traffic

SUDO_PASS="Texel21"

echo ">>> Setting up bypass rules for system traffic..."

# 1. Root bypass (UID 0)
echo "$SUDO_PASS" | sudo -S iptables -I OUTPUT 1 -m owner --uid-owner 0 -m comment --comment "BASTION_BYPASS" -j ACCEPT

# 2. systemd-network bypass (if available)
echo "$SUDO_PASS" | sudo -S iptables -I OUTPUT 1 -m owner --gid-owner systemd-network -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || true

# 3. NFQUEUE rule (goes after bypass rules, so it's checked last)
echo "$SUDO_PASS" | sudo -S iptables -I OUTPUT 3 -m state --state NEW -j NFQUEUE --queue-num 1

echo "✅ Iptables rules configured"
echo ""
echo "$SUDO_PASS" | sudo -S iptables -L OUTPUT -n --line-numbers | head -10
echo ""

echo ">>> Starting Rust daemon..."
cd "$(dirname "$0")"
echo "$SUDO_PASS" | sudo -S RUST_LOG=info ./target/release/bastion-daemon
