<p align="center">
  <a href="http://blog.zedroot.org/" target="_blank">
    <img src="https://gitlab.com/zedtux/gpair/raw/master/media/developpeur_breton_logo.png" alt="Je suis un developpeyr Breton!"/>
  </a>
</p>

# Douane Firewall - Production Outbound Firewall for Linux

**🔒 Take Control of Your Outbound Connections**

Douane is a **production-ready** application firewall that gives Linux users the same outbound connection control they had on Windows. It intercepts **every** outbound connection attempt and lets you decide which applications can access the network.

## 🎯 The Problem

Linux by default **allows ALL outbound connections**. Any application can connect to any server without your knowledge or permission. This is a security risk.

## ✅ The Solution

Douane Firewall:
- **Blocks all outbound connections by default** (via UFW)
- **Intercepts packets in real-time** using netfilter/iptables
- **Shows GUI popups** for each new connection attempt
- **Identifies the application** making the connection
- **Lets you decide** - Allow or Deny, Once or Always
- **Integrates with UFW** to persist your rules

## ✨ Features

### Production-Ready Packet Interception
- **Real netfilter integration** - Intercepts actual packets using iptables NFQUEUE
- **Application identification** - Matches packets to processes via /proc filesystem
- **Fast decision engine** - Cached rules for instant decisions
- **Safe defaults** - Fails closed (deny) on errors

### Beautiful, Informative GUI
- **Enhanced dialogs** - Shows hostname, port description, process info, risk level
- **System tray icon** - Statistics and quick access menu
- **Timeout protection** - Auto-deny after 30 seconds
- **Keyboard shortcuts** - Enter to allow, Escape to deny
- **Rule management** - GUI to view and delete existing rules

### Smart Rule Management
- **Per-application rules** - Allow/deny all connections from an app
- **Per-connection rules** - Allow/deny specific destinations
- **UFW integration** - Permanent rules stored in UFW
- **Decision caching** - Avoid repeated prompts for known connections

### Safety First
- **Rollback capability** - Easy restore if something goes wrong
- **Essential services protected** - DNS, DHCP, NTP automatically allowed
- **Localhost allowed** - Local connections work by default
- **Comprehensive logging** - Full audit trail of all decisions

## 🏗️ Architecture

```
Application → Outbound Connection
                ↓
        Linux Network Stack
                ↓
        iptables NFQUEUE ← [UFW: Default DENY outbound]
                ↓
    Douane Firewall (Python)
                ↓
    Identify Application (/proc)
                ↓
        Check Cached Rules
                ↓
    [No Rule] → GUI Dialog → User Decision
                ↓
        Accept or Drop Packet
                ↓
    [Optional] Store in UFW
```

### Core Components

1. **firewall_core.py** - Packet interception engine
   - NetfilterQueue integration for packet capture
   - Application identification via /proc filesystem
   - Packet accept/drop logic

2. **douane_firewall.py** - Main application
   - Decision engine with intelligent caching
   - UFW rule management
   - Coordinates packet processing and GUI

3. **douane_gui_improved.py** - Enhanced user interface
   - Beautiful, informative dialogs
   - Rule management interface
   - Timeout handling with countdown

4. **setup_firewall.sh** - Safe UFW configuration
   - Sets UFW to deny outbound by default
   - Adds essential service rules
   - Creates rollback script for safety

## 📦 Installation

### Method 1: Install from Package (Recommended)

Download and install the pre-built package for your distribution:

#### Debian/Ubuntu/Linux Mint

```bash
# Download the .deb package from releases
wget https://github.com/shipdocs/Douane/releases/download/v2.0.0/douane-firewall_2.0.0_all.deb

# Install
sudo dpkg -i douane-firewall_2.0.0_all.deb

# Install dependencies if needed
sudo apt-get install -f
```

#### Fedora/RHEL/CentOS

```bash
# Download the .rpm package from releases
wget https://github.com/shipdocs/Douane/releases/download/v2.0.0/douane-firewall-2.0.0-1.noarch.rpm

# Install
sudo dnf install douane-firewall-2.0.0-1.noarch.rpm

# Or with rpm
sudo rpm -ivh douane-firewall-2.0.0-1.noarch.rpm
```

After installation:

```bash
# Configure UFW (IMPORTANT!)
sudo douane-setup-firewall

# Start the firewall
sudo systemctl start douane-firewall

# Enable on boot
sudo systemctl enable douane-firewall
```

### Method 2: Quick Install from Source

```bash
# Clone the repository
git clone https://github.com/shipdocs/Douane.git
cd Douane

# Run the complete installation script
sudo ./install_douane.sh

# Configure UFW (IMPORTANT: Read the warnings!)
sudo ./setup_firewall.sh

# Start the firewall
sudo systemctl start douane-firewall

# Check status
sudo systemctl status douane-firewall
```

### Method 3: Build Your Own Package

```bash
# Clone the repository
git clone https://github.com/shipdocs/Douane.git
cd Douane

# Build packages (interactive menu)
./build_packages.sh

# Or build specific package
./build_deb.sh    # For Debian/Ubuntu
./build_rpm.sh    # For Fedora/RHEL

# Install the built package
sudo dpkg -i douane-firewall_2.0.0_all.deb  # Debian
# Or
sudo dnf install douane-firewall-2.0.0-1.noarch.rpm  # Fedora
```

See [PACKAGING.md](PACKAGING.md) for detailed packaging documentation.

### Method 4: Manual Installation

```bash
# 1. Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-dev python3-tk \
    build-essential libnetfilter-queue-dev \
    iptables ufw

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Test the system
python3 test_production.py

# 4. Configure UFW
sudo ./setup_firewall.sh

# 5. Run the firewall
sudo python3 douane_firewall.py
```

### Requirements

**System:**
- Linux with kernel 3.0+ (netfilter support)
- Python 3.6 or higher
- X11 or Wayland (for GUI)
- Root/sudo privileges

**Dependencies:**
- python3-tk - GUI framework
- NetfilterQueue - Packet interception
- scapy - Packet parsing
- psutil - Process identification
- iptables - Packet filtering
- ufw - Firewall management

## 🚀 Usage

### Starting the Firewall

```bash
# Start manually (foreground)
sudo python3 douane_firewall.py

# Or use systemd (background)
sudo systemctl start douane-firewall

# Enable on boot
sudo systemctl enable douane-firewall

# View logs
sudo journalctl -u douane-firewall -f
# Or
tail -f ~/.config/douane/douane_firewall.log
```

### Using the GUI

When an application tries to connect to the internet:

1. **A popup appears** showing:
   - Application name and full path
   - Destination IP address and port
   - Protocol (TCP/UDP)
   - Timestamp

2. **You decide**:
   - Click **"Allow"** or press `Enter` to permit
   - Click **"Deny"** or press `Escape` to block
   - Check **"Remember this decision"** to make it permanent

3. **What happens**:
   - **Once**: Decision applies to this connection only
   - **Always**: Decision stored for this application
   - **Timeout**: Auto-deny after 30 seconds

### Managing Rules

```bash
# View rule manager GUI
python3 douane_gui_improved.py --rules

# View UFW rules
sudo ufw status verbose

# Delete a specific UFW rule
sudo ufw delete [rule_number]

# View logs
tail -f ~/.config/douane/douane_firewall.log
```

### Testing

```bash
# Test all components
python3 test_production.py

# Test GUI dialog
python3 douane_gui_improved.py --test

# Test rule manager
python3 douane_gui_improved.py --rules
```

## 🔧 How It Works

### The Flow

1. **Application tries to connect** → Creates outbound packet
2. **Linux network stack** → Packet enters OUTPUT chain
3. **iptables NFQUEUE** → Packet queued to userspace (queue #1)
4. **Douane Firewall receives packet** → Via NetfilterQueue
5. **Parse packet** → Extract IP, port, protocol using scapy
6. **Identify application** → Match socket to process via /proc
7. **Check rules**:
   - Localhost? → Auto-allow
   - Cached decision? → Apply it
   - Application rule? → Apply it
   - No rule? → Show GUI dialog
8. **User decides** → Allow or Deny, Once or Always
9. **Apply decision** → Accept or drop the packet
10. **Store rule** (if permanent) → Add to UFW

### Technical Details

- **Packet Interception**: Uses `iptables -j NFQUEUE` to send packets to userspace
- **Application ID**: Reads `/proc/net/tcp` and matches to `/proc/<pid>/exe`
- **Thread Safety**: Decision cache protected by locks
- **Performance**: Cached decisions are instant, new decisions pause packet
- **Safety**: Errors fail closed (deny), timeout auto-denies

## ⚙️ Configuration

Edit `/etc/douane/config.json` or `config.json`:

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
- **default_action**: What to do on timeout ("allow" or "deny")
- **timeout_seconds**: Seconds before auto-deny (0 = no timeout)
- **allow_localhost**: Auto-allow connections to 127.0.0.1
- **allow_lan**: Auto-allow connections to private LAN IPs
- **log_decisions**: Log all decisions to file

### Files and Logs

- `/etc/douane/config.json` - Configuration file
- `~/.config/douane/douane_firewall.log` - Application logs
- `/var/log/ufw_firewall_gui.log` - Legacy logs
- `/var/backups/douane_firewall_*/` - Backup and rollback scripts

## 📖 Examples

### Example 1: First Time Running Firefox

```
🔒 Network Connection Request

Application:
  Name: firefox
  Path: /usr/bin/firefox

Connection Details:
  Destination: 93.184.216.34:443
  Protocol: TCP
  Time: 2024-01-15 14:30:22

⚠️ This application wants to connect to the internet.
   Do you want to allow this connection?

☑ Remember this decision for this application

[✓ Allow]  [✗ Deny]
```

**What to do**: Click "Allow" and check "Remember" so Firefox can access any website.

### Example 2: Suspicious Unknown Application

```
🔒 Network Connection Request

Application:
  Name: unknown_app
  Path: /tmp/suspicious_binary

Connection Details:
  Destination: 192.0.2.123:8080
  Protocol: TCP

⚠️ This application wants to connect to the internet.
```

**What to do**:
- Unknown app from /tmp? Suspicious!
- Click "Deny" and check "Remember" to permanently block it
- Investigate the application

### Example 3: System Update

```
Application: apt
Path: /usr/bin/apt
Destination: archive.ubuntu.com:80
```

**What to do**: Click "Allow" and "Remember" for system updates.

## 🚨 Important Safety Information

### Rollback

If something goes wrong and you lose internet connectivity:

```bash
# Use the rollback script created during setup
sudo /var/backups/douane_firewall_*/rollback.sh

# Or manually restore UFW
sudo ufw default allow outgoing
sudo ufw reload
```

### What This Protects Against

✅ Unauthorized outbound connections
✅ Malware calling home
✅ Applications phoning home without permission
✅ Unexpected network activity
✅ Data exfiltration attempts

### What This Does NOT Protect Against

❌ Root malware (can disable the firewall)
❌ Kernel exploits
❌ Physical access attacks
❌ Inbound attacks (use UFW inbound rules)
❌ DNS-based attacks (DNS is auto-allowed)

### Best Practices

1. **Review decisions carefully** - Don't blindly click "Allow"
2. **Use permanent rules wisely** - Only for applications you trust
3. **Monitor logs regularly** - Check for suspicious activity
4. **Keep system updated** - Security patches are critical
5. **Layer your security** - Use with SELinux/AppArmor, antivirus, etc.

## 📊 Status

### Production Ready ✅

This is a **production-ready** implementation with:

✅ Real packet interception via NetfilterQueue
✅ Application identification via /proc
✅ Enhanced GUI with timeout protection
✅ UFW integration for persistent rules
✅ Decision caching for performance
✅ Comprehensive logging
✅ Safe installation with rollback
✅ Systemd service integration

### Tested On

- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- Linux Mint 21
- Other systemd-based distributions

### Known Limitations

- Requires GUI (X11/Wayland) - not suitable for headless servers
- Adds 1-5ms latency per new connection
- May not identify all applications (kernel threads, etc.)
- DNS must be allowed for name resolution

## 🤝 Contributing

Contributions are welcome! Areas where help is needed:

- Testing on different Linux distributions
- Performance optimizations
- Additional GUI features (application icons, etc.)
- Better application identification
- Documentation improvements
- Translation to other languages

Please feel free to submit a Pull Request or open an Issue.

## 📚 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Get started in 5 minutes ⚡
- **[PACKAGING.md](PACKAGING.md)** - Build and distribute packages 📦
- **[PRODUCTION_GUIDE.md](PRODUCTION_GUIDE.md)** - Complete production deployment guide 🚀
- **[IMPLEMENTATION.md](IMPLEMENTATION.md)** - Technical implementation details 🔧
- **[FAQ.md](FAQ.md)** - Frequently asked questions ❓
- **[RELEASE_NOTES.md](RELEASE_NOTES.md)** - What's new in v2.0.0 🎉

## 🐛 Troubleshooting

### No Internet After Setup

```bash
# Check firewall status
sudo systemctl status douane-firewall

# Check UFW
sudo ufw status verbose

# View logs
tail -f ~/.config/douane/douane_firewall.log

# Rollback if needed
sudo /var/backups/douane_firewall_*/rollback.sh
```

### GUI Not Appearing

```bash
# Test GUI
python3 douane_gui_improved.py --test

# Check DISPLAY
echo $DISPLAY

# Check tkinter
python3 -c "import tkinter"
```

See [PRODUCTION_GUIDE.md](PRODUCTION_GUIDE.md) for more troubleshooting.

## 📄 License

See LICENSE file for details.

## 🔗 Links

- **GitHub**: https://github.com/shipdocs/Douane
- **Original project**: [GitLab](https://gitlab.com/douaneapp/Douane)
- **Issues**: https://github.com/shipdocs/Douane/issues

## ⭐ Star This Project

If you find Douane Firewall useful, please star this repository to help others discover it!

---

**Made with ❤️ for Linux users who want control over their outbound connections**
