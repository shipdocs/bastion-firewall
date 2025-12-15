# Installation Guide - UFW Firewall GUI

## Quick Install (Ubuntu/Debian)

```bash
# 1. Update system
sudo apt-get update

# 2. Install system dependencies
sudo apt-get install -y python3 python3-pip python3-tk ufw iptables

# 3. Clone or download the repository
cd /opt
sudo git clone https://github.com/shipdocs/Douane.git
cd Douane

# 4. Install Python dependencies
sudo pip3 install -r requirements.txt

# 5. Enable UFW
sudo ufw enable
sudo ufw status

# 6. Run the application
sudo python3 ufw_firewall_gui.py
```

## Detailed Installation Steps

### Step 1: System Requirements

Ensure your system meets these requirements:
- Ubuntu 20.04+ or Debian 10+ (or compatible distribution)
- Kernel 3.0 or higher
- X11 or Wayland display server
- At least 512 MB RAM
- Root/sudo access

Check kernel version:
```bash
uname -r
```

### Step 2: Install Dependencies

#### Python and Tkinter
```bash
sudo apt-get install python3 python3-pip python3-tk
```

Verify Python installation:
```bash
python3 --version  # Should be 3.6 or higher
python3 -c "import tkinter"  # Should not error
```

#### UFW (Uncomplicated Firewall)
```bash
sudo apt-get install ufw
```

Verify UFW installation:
```bash
which ufw
ufw version
```

#### Optional: Development Tools
For packet inspection features (optional, for advanced use):
```bash
sudo apt-get install libnetfilter-queue-dev build-essential python3-dev
```

### Step 3: Download the Application

#### Option A: Git Clone (Recommended)
```bash
cd /opt
sudo git clone https://github.com/shipdocs/Douane.git
cd Douane
```

#### Option B: Download ZIP
```bash
wget https://github.com/shipdocs/Douane/archive/main.zip
unzip main.zip
cd Douane-main
```

### Step 4: Install Python Dependencies

```bash
sudo pip3 install -r requirements.txt
```

If you want to install for the current user only:
```bash
pip3 install --user -r requirements.txt
```

### Step 5: Configure UFW

Enable UFW if not already enabled:
```bash
sudo ufw enable
```

Check status:
```bash
sudo ufw status verbose
```

Set default policies (recommended):
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

### Step 6: Configure the Application

Edit `config.json` to customize settings:
```bash
nano config.json
```

Default configuration works for most users. Key settings:
- `log_decisions`: Enable/disable decision logging
- `cache_decisions`: Remember previous decisions
- `timeout_seconds`: Dialog auto-close timeout

### Step 7: Test the Installation

Run in demo mode to verify everything works:
```bash
sudo python3 ufw_firewall_gui.py
```

You should see demo connection attempts with GUI dialogs.

### Step 8: Production Use

For actual packet filtering (advanced), you would need to:

1. Set up iptables NFQUEUE rules
2. Install NetfilterQueue Python library
3. Run the application as a service

This is documented in IMPLEMENTATION.md for advanced users.

## Installation on Other Distributions

### Fedora/RHEL/CentOS
```bash
# Install dependencies
sudo dnf install python3 python3-pip python3-tkinter firewalld

# Note: This implementation uses UFW, not firewalld
# You may need to install UFW separately or adapt the code
sudo dnf install ufw
```

### Arch Linux
```bash
# Install dependencies
sudo pacman -S python python-pip tk ufw

# Enable UFW
sudo systemctl enable ufw
sudo systemctl start ufw
```

## Post-Installation

### Verify Installation

1. Check UFW is running:
```bash
sudo systemctl status ufw
```

2. Verify Python can import required modules:
```bash
python3 -c "import tkinter; import json; import logging"
```

3. Check log directory is writable:
```bash
sudo touch /var/log/ufw_firewall_gui.log
sudo chmod 644 /var/log/ufw_firewall_gui.log
```

### First Run

```bash
sudo python3 /opt/Douane/ufw_firewall_gui.py
```

### Common Installation Issues

#### Issue: "tkinter not found"
**Solution:**
```bash
sudo apt-get install python3-tk
```

#### Issue: "Permission denied" on log file
**Solution:**
```bash
sudo mkdir -p /var/log
sudo touch /var/log/ufw_firewall_gui.log
sudo chmod 666 /var/log/ufw_firewall_gui.log
```

#### Issue: UFW not enabled
**Solution:**
```bash
sudo ufw enable
sudo ufw status
```

#### Issue: "Must be run as root"
**Solution:**
Always use `sudo` when running:
```bash
sudo python3 ufw_firewall_gui.py
```

## Updating

To update to the latest version:

```bash
cd /opt/Douane
sudo git pull
sudo pip3 install -r requirements.txt --upgrade
```

## Uninstallation

To remove the application:

```bash
# Stop the application if running
sudo pkill -f ufw_firewall_gui.py

# Remove files
sudo rm -rf /opt/Douane

# Optionally remove log files
sudo rm /var/log/ufw_firewall_gui.log

# Python packages remain installed for potential other uses
```

To also remove UFW rules created by the application:
```bash
# List all rules
sudo ufw status numbered

# Delete specific rules (note the numbers may change)
sudo ufw delete [number]

# Or reset UFW entirely (WARNING: removes all rules)
sudo ufw --force reset
sudo ufw enable
```

## Setting Up as a Service (Advanced)

For users who want the application to run automatically at startup, see the systemd setup guide in IMPLEMENTATION.md.

Note: Running GUI applications as services requires special X11/Wayland configuration.

## Support

If you encounter issues during installation:
1. Check FAQ.md for common problems
2. Review logs: `sudo tail -f /var/log/ufw_firewall_gui.log`
3. Open an issue on GitHub with system details

## Next Steps

After installation:
1. Read FAQ.md for usage questions
2. Review IMPLEMENTATION.md for technical details
3. Customize config.json for your needs
4. Start the application and test with a few connections
