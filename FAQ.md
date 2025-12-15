# UFW Firewall GUI - Frequently Asked Questions

## General Questions

### What is this tool?

UFW Firewall GUI is a graphical application that monitors outbound network connections on Linux and allows you to interactively allow or deny them. It integrates with UFW (Uncomplicated Firewall) to store your decisions as persistent firewall rules.

### How is this different from the original Douane?

The original Douane project has moved to GitLab (https://gitlab.com/douaneapp/Douane). This is a new implementation specifically designed to work with UFW, making it easier to integrate with Ubuntu and other Debian-based systems that use UFW by default.

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
sudo python3 ufw_firewall_gui.py
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

```bash
sudo python3 ufw_firewall_gui.py
```

The application runs in the background and shows popups when applications attempt new outbound connections.

### What happens when I click "Allow Once"?

The specific connection is permitted, but no UFW rule is added. If the same application tries to connect to the same destination again, you'll be prompted again.

### What happens when I click "Allow Always"?

An UFW rule is added to permanently allow connections matching this pattern (destination IP and port). You won't be prompted for similar connections in the future.

### What happens when I click "Deny Once"?

The connection is blocked this time, but you'll be prompted again for similar future connections.

### What happens when I click "Deny Always"?

An UFW rule is added to permanently block connections to this destination IP and port.

### Can I see what rules have been added?

Yes, use standard UFW commands:

```bash
sudo ufw status verbose
sudo ufw status numbered
```

### How do I remove a rule?

```bash
# List rules with numbers
sudo ufw status numbered

# Delete by number
sudo ufw delete [number]
```

## Troubleshooting

### The GUI dialogs don't appear

1. Check that you're running in a graphical session
2. Verify tkinter is installed: `python3 -c "import tkinter"`
3. Check X11 DISPLAY variable: `echo $DISPLAY`
4. Try running with: `sudo -E python3 ufw_firewall_gui.py` (preserves environment)

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
sudo tail -f /var/log/ufw_firewall_gui.log
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
