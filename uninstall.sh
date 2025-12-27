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
systemctl stop bastion-daemon 2>/dev/null || true
if systemctl is-active bastion-firewall 2>/dev/null; then
    systemctl stop bastion-firewall 2>/dev/null || true
fi
systemctl disable bastion-daemon 2>/dev/null || true
if systemctl is-enabled bastion-firewall 2>/dev/null; then
    systemctl disable bastion-firewall 2>/dev/null || true
fi

# FIX #7: Use more precise matching for GUI processes
# Kill only bastion-gui processes by exact binary path
if [ -n "$SUDO_USER" ]; then
    # Running under sudo - kill processes for real user
    su - "$SUDO_USER" -c 'pkill -x bastion-gui' 2>/dev/null || true
else
    # Running as root directly - try to find and kill GUI processes
    # Get list of user sessions and kill GUI processes for each user
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            user=$(basename "$user_home")
            su - "$user" -c 'pkill -x bastion-gui' 2>/dev/null || true
        fi
    done
fi

# Try graceful shutdown first
sleep 2

# Force kill if still running
if [ -n "$SUDO_USER" ]; then
    su - "$SUDO_USER" -c 'pkill -9 -x bastion-gui' 2>/dev/null || true
else
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            user=$(basename "$user_home")
            su - "$user" -c 'pkill -9 -x bastion-gui' 2>/dev/null || true
        fi
    done
fi

echo "✅ Services stopped"

# FIX #9, #11: Clean up iptables rules with explicit presence checks
echo "==> Cleaning up iptables rules..."

# Remove NFQUEUE rules with --queue-bypass
while iptables -C OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null; do
    iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass 2>/dev/null || break
done

# Also remove any old NFQUEUE rules without --queue-bypass
while iptables -C OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null; do
    iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1 2>/dev/null || break
done

# FIX #8, #21: Remove BASTION_BYPASS rules with full rule specification
while iptables -C OUTPUT -m owner --gid-owner systemd-network -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null; do
    iptables -D OUTPUT -m owner --gid-owner systemd-network -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || break
done

while iptables -C OUTPUT -m owner --uid-owner 0 -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null; do
    iptables -D OUTPUT -m owner --uid-owner 0 -m comment --comment "BASTION_BYPASS" -j ACCEPT 2>/dev/null || break
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
systemctl daemon-reload
echo "✅ Systemd service removed"

# Remove socket
echo "==> Removing socket..."
sudo rm -f /var/run/bastion/bastion-daemon.sock
sudo rmdir /var/run/bastion 2>/dev/null || true
echo "✅ Socket removed"

# FIX #19: Remove desktop file from real user's home directory
echo "==> Removing desktop entry..."
if [ -n "$SUDO_USER" ]; then
    # Use SUDO_USER to find real user's home
    REAL_HOME="/home/$SUDO_USER"
    rm -f "$REAL_HOME/.local/share/applications/bastion-firewall.desktop" 2>/dev/null || true
    rm -f "$REAL_HOME/.config/autostart/bastion-tray.desktop" 2>/dev/null || true
else
    # Fallback: try common home directories
    for user_home in /home/*; do
        if [ -d "$user_home" ]; then
            rm -f "$user_home/.local/share/applications/bastion-firewall.desktop" 2>/dev/null || true
            rm -f "$user_home/.config/autostart/bastion-tray.desktop" 2>/dev/null || true
        fi
    done
fi

# Ask about configuration
echo ""
read -p "Remove configuration files? (/etc/bastion/*, /var/log/bastion-daemon.log) [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo rm -rf /etc/bastion
    sudo rm -f /var/log/bastion-daemon.log
    sudo rm -rf /var/log/bastion
    echo "✅ Configuration removed"
else
    echo "ℹ️  Configuration preserved in /etc/bastion/"
fi

echo ""
echo "=== Uninstall Complete ==="
echo ""
echo "Bastion Firewall has been removed from your system."
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Your rules are still in /etc/bastion/rules.json"
    echo "To completely remove: sudo rm -rf /etc/bastion"
fi
