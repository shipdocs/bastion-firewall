#!/bin/bash
# Start daemon with bypass rules for system traffic and optional inbound protection

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
# Append to end of chain instead of hardcoded position to handle variable bypass rules
iptables -C OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || \
iptables -A OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass

echo "✅ OUTPUT chain rules configured"
echo ""

# ============================================================================
# INBOUND PROTECTION (INPUT chain)
# Only add rules if no other firewall is detected and config allows it
# ============================================================================

setup_inbound_protection() {
    echo ">>> Checking inbound protection..."

    # Check if inbound protection is disabled in config
    CONFIG_FILE="/etc/bastion/config.json"
    if [ -f "$CONFIG_FILE" ]; then
        INBOUND_ENABLED=$(grep -o '"inbound_protection"[[:space:]]*:[[:space:]]*\(true\|false\)' "$CONFIG_FILE" | grep -o '\(true\|false\)' || echo "true")
        if [ "$INBOUND_ENABLED" = "false" ]; then
            echo "ℹ️  Inbound protection disabled in config"
            return 0
        fi
    fi

    # Check for existing firewalls - if any are active, skip our rules

    # 1. Check UFW
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            echo "✅ UFW is active - skipping Bastion inbound rules"
            return 0
        fi
    fi

    # 2. Check firewalld
    if systemctl is-active firewalld &>/dev/null; then
        echo "✅ firewalld is active - skipping Bastion inbound rules"
        return 0
    fi

    # 3. Check nftables (look for input chain)
    if command -v nft &>/dev/null; then
        if nft list ruleset 2>/dev/null | grep -qi "chain input"; then
            echo "✅ nftables input chain detected - skipping Bastion inbound rules"
            return 0
        fi
    fi

    # 4. Check for existing iptables INPUT rules (non-Bastion)
    INPUT_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -v "^Chain\|^target\|^$\|BASTION_INBOUND" | wc -l)
    if [ "$INPUT_RULES" -gt 0 ]; then
        echo "✅ Existing iptables INPUT rules detected ($INPUT_RULES rules) - skipping"
        return 0
    fi

    # 5. Check if our rules are already in place
    if iptables -L INPUT -n 2>/dev/null | grep -q "BASTION_INBOUND"; then
        echo "✅ Bastion inbound rules already configured"
        return 0
    fi

    # No firewall detected - set up minimal INPUT rules
    echo ">>> Setting up minimal inbound protection..."

    # IPv4 rules
    iptables -A INPUT -i lo -m comment --comment "BASTION_INBOUND" -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -m comment --comment "BASTION_INBOUND" -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -m comment --comment "BASTION_INBOUND" -j ACCEPT
    iptables -A INPUT -m comment --comment "BASTION_INBOUND" -j DROP

    # IPv6 rules (if ip6tables available)
    if command -v ip6tables &>/dev/null; then
        ip6tables -A INPUT -i lo -m comment --comment "BASTION_INBOUND" -j ACCEPT 2>/dev/null
        ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -m comment --comment "BASTION_INBOUND" -j ACCEPT 2>/dev/null
        ip6tables -A INPUT -p icmpv6 -m comment --comment "BASTION_INBOUND" -j ACCEPT 2>/dev/null
        ip6tables -A INPUT -m comment --comment "BASTION_INBOUND" -j DROP 2>/dev/null
    fi

    echo "✅ Bastion inbound protection enabled"
    echo "   Allowing: localhost, established connections, ICMP ping"
    echo "   Blocking: all other unsolicited inbound connections"
}

# Run inbound protection setup
setup_inbound_protection

echo ""
echo "=== Current iptables rules ==="
echo "OUTPUT chain:"
iptables -L OUTPUT -n --line-numbers | head -10
echo ""
echo "INPUT chain:"
iptables -L INPUT -n --line-numbers | head -10
echo ""

echo ">>> Starting Rust daemon..."
cd "$(dirname "$0")" || { echo "Failed to change directory"; exit 1; }
RUST_LOG=info ./target/release/bastion-daemon
