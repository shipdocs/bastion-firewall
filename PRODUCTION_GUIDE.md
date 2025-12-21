# Douane Firewall - Production Deployment Guide

## Overview

Douane Firewall is a production-ready outbound firewall for Linux that provides Windows-like network control. It intercepts all outbound connections and prompts users with GUI dialogs to allow or deny each connection.

## What This Does

**Before Douane:**
- Linux allows ALL outbound connections by default
- Applications can connect to any server without your knowledge
- No visibility into what's connecting where

**After Douane:**
- UFW configuration set to "Allow Outbound" (Pass-through)
- Douane blocks unauthorized traffic internally
- Every new outbound connection triggers a popup dialog
- You decide which applications can access the network
- Decisions are cached and can be made permanent
- Full audit trail of all connection attempts

## Architecture

```
Application → Outbound Connection Attempt
                    ↓
            Linux Network Stack
                    ↓
            iptables NFQUEUE
                    ↓
        Douane Firewall (Python)
                    ↓
        Identify Application
                    ↓
        Check Cached Rules
                    ↓
    [No Rule] → Show GUI Dialog → User Decision
                    ↓
            Accept or Drop Packet
                    ↓
    [Optional] Store in Internal Rules (rules.json)
```

## Components

1. **firewall_core.py** - Packet interception and processing
   - Uses NetfilterQueue to intercept packets
   - Identifies applications via /proc filesystem
   - Manages packet accept/drop decisions

2. **douane_firewall.py** - Main application
   - Decision engine with caching
   - Internal Rule Engine (Decoupled from UFW)
   - Coordinates packet processing and GUI

3. **douane-gui-client** - User interface
   - Enhanced GUI dialogs
   - Rule management interface
   - Timeout handling

4. **setup_firewall.sh** - UFW configuration
   - Safely sets UFW to deny outbound
   - Adds essential rules (DNS, DHCP, etc.)
   - Creates rollback script

5. **install_douane.sh** - Complete installation
   - Installs all dependencies
   - Sets up systemd service
   - Configures system

## Installation

### Quick Install (Ubuntu/Debian)

```bash
# Clone the repository
git clone https://github.com/shipdocs/Douane.git
cd Douane

# Run installation script
sudo ./install_douane.sh

# Configure UFW
sudo ./setup_firewall.sh

# Start the firewall
sudo systemctl start douane-firewall

# Check status
sudo systemctl status douane-firewall
```

### Manual Installation

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-dev python3-tk \
    build-essential libnetfilter-queue-dev \
    iptables ufw

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Test the GUI
douane-gui-client --test

# 4. Configure UFW (IMPORTANT: Read warnings!)
sudo ./setup_firewall.sh

# 5. Run the firewall
sudo douane-daemon
```

## Configuration

Edit `/etc/douane/config.json` (or `config.json` in the project directory):

```json
{
  "cache_decisions": true,
  "default_action": "deny",
  "timeout_seconds": 30,
  "allow_localhost": true,
  "allow_lan": false,
  "log_decisions": true
}
```

### Configuration Options

- **cache_decisions**: Cache user decisions to avoid repeated prompts
- **default_action**: Default action when timeout occurs ("allow" or "deny")
- **timeout_seconds**: Seconds before auto-deny (0 = no timeout)
- **allow_localhost**: Automatically allow connections to 127.0.0.1
- **allow_lan**: Automatically allow connections to private LAN IPs
- **log_decisions**: Log all decisions to file

## Usage

### Starting the Firewall

```bash
# Start manually
sudo douane-daemon

# Or use systemd
sudo systemctl start douane-firewall

# Enable on boot
sudo systemctl enable douane-firewall

# View logs
sudo journalctl -u douane-firewall -f
```

### Using the GUI

When an application tries to connect:

1. A popup dialog appears showing:
   - Application name and path
   - Destination IP and port
   - Protocol (TCP/UDP)
   - Timestamp

2. You can:
   - **Allow** - Permit this connection
   - **Deny** - Block this connection
   - **Remember** - Make decision permanent for this app

3. Keyboard shortcuts:
   - `Enter` - Allow
   - `Escape` - Deny

### Managing Rules

```bash
# View rule manager GUI
douane-control-panel

# View UFW rules
sudo ufw status verbose

# Delete a specific rule
sudo ufw delete [rule_number]
```

## Safety Features

### Rollback Capability

If something goes wrong, use the rollback script created during setup:

```bash
sudo /var/backups/douane_firewall_*/rollback.sh
```

This restores UFW to allow outbound connections.

### Essential Services Protected

The setup script automatically allows:
- DNS (port 53) - Required for name resolution
- DHCP (ports 67-68) - Required for network configuration
- NTP (port 123) - Time synchronization
- Loopback (lo) - Local connections
- Established connections - Existing connections continue working

### Safe Defaults

- Localhost (127.0.0.1) allowed by default
- Unknown applications denied by default
- Timeout auto-denies after 30 seconds
- Errors fail closed (deny)

## Troubleshooting

### No Internet After Setup

1. Check if firewall is running:
   ```bash
   sudo systemctl status douane-firewall
   ```

2. Check UFW status:
   ```bash
   sudo ufw status verbose
   ```

3. Check logs:
   ```bash
   tail -f ~/.config/douane/douane_firewall.log
   ```

4. If stuck, use rollback:
   ```bash
   sudo /var/backups/douane_firewall_*/rollback.sh
   ```

### GUI Not Appearing

1. Check if running in graphical session:
   ```bash
   echo $DISPLAY
   ```

2. Test GUI manually:
   ```bash
   douane-gui-client --test
   ```

3. Check for tkinter:
   ```bash
   python3 -c "import tkinter"
   ```

### Application Not Identified

Some applications may not be identified correctly. This can happen with:
- Very short-lived connections
- Kernel threads
- System services

These are denied by default for security.

## Performance Considerations

- Each packet is inspected, adding ~1-5ms latency
- GUI dialogs pause packet processing
- Cached decisions are fast (no GUI shown)
- Recommended for desktop/workstation use
- Not recommended for high-throughput servers

## Security Notes

### What This Protects Against

✅ Unauthorized outbound connections
✅ Malware calling home
✅ Applications phoning home without permission
✅ Unexpected network activity

### What This Does NOT Protect Against

❌ Root malware (can disable the firewall)
❌ Kernel exploits
❌ Physical access attacks
❌ Inbound attacks (use UFW inbound rules)

### Best Practices

1. **Review decisions carefully** - Don't just click "Allow" on everything
2. **Use permanent rules wisely** - Only for trusted applications
3. **Monitor logs regularly** - Check for suspicious activity
4. **Keep system updated** - Security patches are critical
5. **Layer security** - Use with SELinux/AppArmor, antivirus, etc.

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop douane-firewall
sudo systemctl disable douane-firewall

# Remove iptables rules
sudo iptables -D OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1

# Restore UFW default
sudo ufw default allow outgoing

# Remove files
sudo rm /usr/local/bin/douane-firewall
sudo rm /etc/systemd/system/douane-firewall.service
sudo systemctl daemon-reload
```

## Support

- GitHub Issues: https://github.com/shipdocs/Douane/issues
- Documentation: See README.md, FAQ.md, IMPLEMENTATION.md

## License

See LICENSE file for details.

