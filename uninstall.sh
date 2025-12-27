#!/bin/bash
# Bastion Firewall - Complete Uninstaller
# Removes Rust daemon, Python GUI, and all configuration

set -e

echo "=== Bastion Firewall Uninstaller ==="
echo ""
echo "This will remove:"
echo "  - Rust daemon (bastion-daemon)"
echo "  - Python GUI (bastion-gui)"  
echo "  - iptables rules"
echo "  - systemd service"
echo "  - Configuration files (optional)"
echo ""

read -p "Continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Stop services
echo "==> Stopping services..."
sudo systemctl stop bastion-daemon 2>/dev/null || true
sudo systemctl disable bastion-daemon 2>/dev/null || true
# Try graceful shutdown first
sudo pkill bastion-daemon 2>/dev/null || true
pkill -f bastion-gui 2>/dev/null || true
sleep 2
# Force kill if still running
sudo pkill -9 bastion-daemon 2>/dev/null || true
pkill -9 -f bastion-gui 2>/dev/null || true
echo "✅ Services stopped"

# Remove iptables rules
echo "==> Cleaning up iptables rules..."
sudo iptables -F OUTPUT 2>/dev/null || true

# Remove NFQUEUE rules
for i in {1..20}; do
    sudo iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null || break
done

# Remove BASTION_BYPASS rules
for i in {1..20}; do
    RULE=$(sudo iptables -S OUTPUT | grep "BASTION_BYPASS" | head -n1)
    if [ -z "$RULE" ]; then
        break
    fi
    sudo iptables -D OUTPUT $(echo $RULE | cut -d' ' -f3-) 2>/dev/null || break
done

echo "✅ iptables rules removed"

# Remove binaries
echo "==> Removing binaries..."
sudo rm -f /usr/bin/bastion-daemon
sudo rm -f /usr/bin/bastion-gui
sudo rm -f /usr/local/bin/bastion-gui
echo "✅ Binaries removed"

# Remove systemd service
echo "==> Removing systemd service..."
sudo rm -f /etc/systemd/system/bastion-daemon.service
sudo rm -f /etc/systemd/system/bastion-firewall.service
sudo systemctl daemon-reload
echo "✅ Systemd service removed"

# Remove socket
echo "==> Removing socket..."
sudo rm -f /var/run/bastion/bastion-daemon.sock
sudo rmdir /var/run/bastion 2>/dev/null || true
echo "✅ Socket removed"

# Ask about configuration
echo ""
read -p "Remove configuration files? (/etc/bastion/*, /var/log/bastion-daemon.log) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo rm -rf /etc/bastion
    sudo rm -f /var/log/bastion-daemon.log
    echo "✅ Configuration removed"
else
    echo "ℹ️  Configuration preserved in /etc/bastion/"
fi

# Remove desktop entry
rm -f ~/.local/share/applications/bastion-firewall.desktop 2>/dev/null || true

echo ""
echo "=== Uninstall Complete ==="
echo ""
echo "Bastion Firewall has been removed from your system."
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Your rules are still in /etc/bastion/rules.json"
    echo "To completely remove: sudo rm -rf /etc/bastion"
fi
