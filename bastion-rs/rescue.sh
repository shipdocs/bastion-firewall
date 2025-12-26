#!/bin/bash
# RESCUE SCRIPT - Run this if firewall blocks everything
# This script requires NO network access

echo "=== Bastion Firewall Emergency Rescue ==="
echo ""

# Method 1: Stop the service
echo "[1] Stopping bastion-firewall service..."
systemctl stop bastion-firewall 2>/dev/null

# Method 2: Kill the daemon directly  
echo "[2] Killing bastion-daemon process..."
pkill -9 bastion-daemon 2>/dev/null
pkill -9 bastion-rs 2>/dev/null

# Method 3: Flush iptables (doesn't need DNS)
echo "[3] Flushing OUTPUT chain..."
/usr/sbin/iptables -F OUTPUT 2>/dev/null

# Method 4: Remove specific NFQUEUE rule
echo "[4] Removing NFQUEUE rule..."
/usr/sbin/iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null
/usr/sbin/iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null

# Method 5: Set default policy to ACCEPT
echo "[5] Setting OUTPUT policy to ACCEPT..."
/usr/sbin/iptables -P OUTPUT ACCEPT 2>/dev/null

echo ""
echo "=== Rescue complete ==="
echo "Network should now be restored."
echo ""
echo "To verify: ping 8.8.8.8"
