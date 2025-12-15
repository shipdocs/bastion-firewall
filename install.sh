#!/bin/bash
# Installation script for Douane firewall

set -e

echo "=== Douane Firewall Installation ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Install system dependencies
echo "Installing system dependencies..."
apt-get update
apt-get install -y python3 python3-pip python3-gi gir1.2-gtk-3.0

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Make scripts executable
chmod +x douane_daemon.py
chmod +x douane_gui.py

# Create symlinks in /usr/local/bin
echo "Creating symlinks..."
ln -sf "$(pwd)/douane_daemon.py" /usr/local/bin/douane-daemon
ln -sf "$(pwd)/douane_gui.py" /usr/local/bin/douane-gui

# Create systemd service (optional)
if [ -d /etc/systemd/system ]; then
    echo "Creating systemd service..."
    cat > /etc/systemd/system/douane.service <<EOF
[Unit]
Description=Douane Application Firewall
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/douane-daemon
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "Systemd service created. Enable with: sudo systemctl enable douane"
    echo "Start with: sudo systemctl start douane"
fi

echo
echo "=== Installation Complete ==="
echo
echo "Douane has been installed successfully!"
echo
echo "Usage:"
echo "  - Start daemon: sudo douane-daemon"
echo "  - Test GUI: douane-gui --test"
echo
echo "Note: The daemon requires root privileges to monitor network connections."
