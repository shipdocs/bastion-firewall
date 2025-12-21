# Bastion Application Firewall for Linux - Frequently Asked Questions

## General Questions

### What is this tool?

Bastion Application Firewall is a production-ready outbound firewall for Linux that gives you Windows-like control over which applications can access the network. It monitors all outbound network connections and shows GUI popups allowing you to interactively allow or deny them. It uses a robust internal rule engine to store your decisions reliably.

### How is this different from the original Bastion?

The original Bastion project has moved to GitLab (https://gitlab.com/douaneapp/Bastion). This is a modernized implementation with:
- Internal persistent rule storage (Decoupled from UFW)
- Enhanced GUI with control panel
- Automatic rule persistence (even in learning mode)
- Better privilege separation (daemon + GUI client)
- Production-ready packet interception
- Comprehensive logging and management features

### Do I need this if I already have UFW?

UFW is excellent for managing inbound firewall rules, but by default, Linux allows all outbound connections. This tool adds interactive control over outbound connections, letting you decide which applications can access the network.

## Installation and Setup

### What are the prerequisites?

- Linux with kernel 3.0 or higher
- Python 3.6 or higher
- UFW installed and configured
- Root/sudo privileges
- X11 or Wayland display server (for GUI)

### How do I install it?

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk ufw

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Enable UFW if not already enabled
sudo ufw enable

# 4. Run the application
/usr/local/bin/douane-gui-client
```

### Why does it need root privileges?

Root access is required to:
- Monitor network packets using netfilter
- Modify firewall rules through UFW
- Read process information to identify applications
- Access system network stack

### Can I run this on a headless server?

No, this tool requires a display server (X11 or Wayland) because it shows GUI dialogs. For headless servers, consider using UFW command-line rules directly.

## Usage

### How do I start the application?

**From Application Menu (Recommended):**
1. Search for "Bastion Firewall" in your application menu
2. Click to launch
3. Enter password when prompted (uses pkexec for GUI password dialog)
4. System tray icon appears - firewall is active!

**From Command Line:**
```bash
/usr/local/bin/douane-gui-client
```

The application runs in the background with a system tray icon and shows popups when applications attempt new outbound connections.

### How do I open the Control Panel?

**From Application Menu:**
- Search for "Bastion Control Panel"

**From System Tray:**
- Right-click the tray icon → "Control Panel"

**From Command Line:**
```bash
/usr/local/bin/douane-control-panel
```

### What can I do in the Control Panel?

The Control Panel provides complete firewall management:

- **Status Tab**: View firewall status, statistics, current mode
- **Settings Tab**: Switch between Learning/Enforcement modes, adjust timeout
- **Rules Tab**: View all rules, delete individual rules, clear all rules
- **Logs Tab**: View daemon logs, see all connection attempts
- **Control Buttons**: Start, Stop, or Restart the firewall

**Important**: The Control Panel stays open when you stop or restart the firewall, so you can manage it easily!

### What's the difference between Learning Mode and Enforcement Mode?

**Learning Mode (Default):**
- Shows popups for new connections
- **Always allows** the connection (won't break your internet)
- Saves your decisions to rules.json automatically
- Safe for initial setup and testing
- Perfect for building your rule set without risk

**Enforcement Mode:**
- Shows popups for new connections
- **Actually blocks** connections you deny
- Saves decisions to rules.json
- Use after you've built your initial rule set
- Production mode for real security

**Important**: In both modes, rules are saved automatically! You won't lose your decisions when restarting.

### What happens when I click "Allow Once"?

The specific connection is permitted, but the decision is cached only for this session. If the same application tries to connect to the same port again during this session, it's allowed automatically. After restart, you'll be prompted again.

### What happens when I click "Allow Always"?

The decision is saved permanently to `/etc/douane/rules.json`. The application can always connect to this port. You won't be prompted for this app+port combination again.

### What happens when I click "Deny"?

In Learning Mode: Connection is allowed anyway (learning mode never blocks), but you see the popup.
In Enforcement Mode: Connection is blocked immediately.

### Can I see what rules have been added?

**Via Control Panel (Easiest):**
1. Open Control Panel
2. Go to "Rules" tab
3. See all saved rules with application names and ports

**Via Command Line:**
```bash
# View Bastion rules
cat /etc/douane/rules.json
```

### How do I remove a rule?

**Via Control Panel (Recommended):**
1. Open Control Panel → Rules tab
2. Select the rule you want to delete
3. Click "Delete Selected" or "Clear All Rules"

**Via Command Line:**
```bash
# Remove from Bastion
# Edit /etc/douane/rules.json and remove the line

# Remove from UFW (if in Enforcement mode)
sudo ufw status numbered
sudo ufw delete [number]
```

### Do my rules persist after restarting?

**Yes!** All rules are automatically saved to `/etc/douane/rules.json` immediately when you make a decision, even in Learning Mode. When you restart the firewall or reboot your computer, all your rules are loaded automatically.

## Troubleshooting

### The GUI dialogs don't appear

1. Check that you're running in a graphical session
2. Verify tkinter is installed: `python3 -c "import tkinter"`
3. Check X11 DISPLAY variable: `echo $DISPLAY`
4. Try running with: `douane-gui-client`

### UFW commands fail

1. Check UFW is installed: `which ufw`
2. Verify UFW service is running: `sudo systemctl status ufw`
3. Enable UFW: `sudo ufw enable`

### Too many popup dialogs

This is expected during initial use. Options:
1. Use "Allow Always" for trusted applications
2. Set up initial rules manually with UFW
3. Adjust the `cache_decisions` setting in `config.json`

### Application names show as "unknown"

Some applications may be hard to identify. The tool shows the full path to help you determine what's making the connection.

### Performance impact

Inspecting every packet does add overhead. For high-throughput systems, consider:
1. Adding rules for known-good applications
2. Using the cache feature
3. Limiting monitoring to specific protocols

### Existing connections aren't blocked

The tool only monitors NEW connection attempts. Existing connections continue to work. To block existing connections, you'd need to terminate them manually.

## Advanced Topics

### Can I whitelist certain applications?

Yes, you can pre-configure UFW rules:

```bash
sudo ufw allow out to any port 443 proto tcp comment 'HTTPS'
sudo ufw allow out to any port 80 proto tcp comment 'HTTP'
```

### How do I see the logs?

```bash
sudo tail -f /var/log/douane-daemon.log
```

### Can I customize the GUI?

Edit `config.json` to adjust:
- Window timeout
- Theme settings
- Dialog behavior

### How do I run this at startup?

Create a systemd service (advanced users):

```bash
# Note: This requires additional configuration for GUI in systemd
sudo systemctl enable ufw-firewall-gui
sudo systemctl start ufw-firewall-gui
```

Note: Running GUI applications via systemd requires special setup for X11 access.

### What about Docker containers?

Docker manages its own iptables rules. This tool focuses on host-level application monitoring, not container traffic.

## Security

### Is this tool secure?

The tool requires root privileges, which always carries risk. Review the source code before running. All actions are logged for audit purposes.

### What if malware tries to bypass it?

The tool uses netfilter queuing, which catches packets before they leave. However:
- Root malware could disable the tool
- Kernel-level exploits could bypass userspace filtering
- This is one layer of defense, not a complete solution

### Should I trust third-party applications?

Always be cautious. This tool helps you control network access, but:
- Review what you install
- Keep systems updated
- Use additional security layers (SELinux, AppArmor)

## Contributing

### How can I contribute?

1. Test the application and report issues
2. Submit patches or improvements
3. Improve documentation
4. Share your configuration and use cases

### Where do I report bugs?

Open an issue on the GitHub repository with:
- System information (OS, Python version)
- Steps to reproduce
- Log output
- Expected vs actual behavior

## License and Legal

### What license is this under?

See the LICENSE file in the repository.

### Is this production-ready?

This is an educational/community tool. Use at your own risk and test thoroughly before relying on it for security.
