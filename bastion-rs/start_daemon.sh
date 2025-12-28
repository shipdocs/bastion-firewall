#!/bin/bash
# Start daemon with bypass rules for system traffic

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo."
  exit 1
fi

echo ">>> Setting up bypass rules for system traffic..."

# 1. Root bypass (UID 0)
iptables -C OUTPUT -m owner --uid-owner 0 -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || \
iptables -I OUTPUT 1 -m owner --uid-owner 0 -m comment --comment "BASTION_BYPASS" -j ACCEPT

# 2. systemd-network bypass (if available)
iptables -C OUTPUT -m owner --gid-owner systemd-network -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || \
iptables -I OUTPUT 1 -m owner --gid-owner systemd-network -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || true

# 3. NFQUEUE rule (goes after bypass rules, so it's checked last)
# Use --queue-bypass to prevent network lockouts if daemon crashes/is not running
iptables -C OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || \
iptables -I OUTPUT 3 -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass

echo "✅ Iptables rules configured"
echo ""
iptables -L OUTPUT -n --line-numbers | head -10
echo ""

echo ">>> Starting Rust daemon..."
cd "$(dirname "$0")" || { echo "Failed to change directory"; exit 1; }
RUST_LOG=info ./target/release/bastion-daemon
