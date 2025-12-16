<p align="center">
  <a href="http://blog.zedroot.org/" target="_blank">
    <img src="https://gitlab.com/zedtux/gpair/raw/master/media/developpeur_breton_logo.png" alt="Je suis un developpeyr Breton!"/>
  </a>
</p>

# Douane Application Firewall for Linux

**🔒 Take Control of Your Outbound Connections**

Douane is a **production-ready** application firewall that gives Linux users the same outbound connection control they had on Windows. It intercepts **every** outbound connection attempt and lets you decide which applications can access the network.

> **Latest Updates (v2.0.0):**
> - ✅ **Interactive installation** - Choose learning/enforcement mode, autostart, and start now
> - ✅ **Beautiful progress dialogs** - Visual feedback for start/stop/restart operations
> - ✅ **Automatic rule reload** - Delete rules and they take effect immediately (SIGHUP)
> - ✅ **pkexec integration** - Proper permission handling for editing rules and settings
> - ✅ **AppStream metadata** - Shows up in Software Center and Settings > Apps
> - ✅ Rules persist automatically in learning mode
> - ✅ Control panel stays open when stopping/restarting firewall
> - ✅ Real-time mode updates in status display

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
- **Two-process architecture** - Daemon (root) + GUI client (user) for proper privilege separation

### Beautiful, Informative GUI
- **Enhanced dialogs** - Shows hostname, port description, process info, risk level
- **Control Panel** - Full-featured GUI to manage settings, rules, and view logs
  - Real-time status monitoring
  - Rule management (view, delete, clear all) with pkexec for proper permissions
  - Mode switching (Learning ↔ Enforcement)
  - Live log viewing
  - Beautiful progress dialogs for start/stop/restart operations
  - Automatic rule reload (no restart needed when deleting rules)
- **System tray icon** - Statistics and quick access menu
- **Timeout protection** - Auto-deny after 30 seconds (configurable)
- **Interactive installation** - Guided setup with whiptail dialogs
- **Keyboard shortcuts** - Enter to allow, Escape to deny

### Smart Rule Management
- **Per-application + port rules** - Firefox:443 allows all HTTPS, Firefox:80 separate for HTTP
- **Persistent storage** - Rules automatically saved to /etc/douane/rules.json (even in learning mode!)
- **UFW integration** - Permanent rules stored in UFW
- **Decision caching** - Avoid repeated prompts for known connections
- **Learning mode** - Shows popups but always allows (safe for testing, rules are saved)
- **Enforcement mode** - Actually blocks based on decisions
- **Automatic rule persistence** - All decisions are saved immediately, no data loss on restart

### Safety First
- **Learning mode default** - Won't break your internet while you configure
- **Essential services protected** - DNS, DHCP, NTP, apt automatically allowed
- **Localhost allowed** - Local connections work by default
- **Graceful shutdown** - Automatic iptables cleanup on exit
- **Comprehensive logging** - Full audit trail at /var/log/douane-daemon.log

## 🏗️ Architecture

### Two-Process Design

```
┌─────────────────────────────────────────────────────────────┐
│  Application → Outbound Connection                          │
│                      ↓                                       │
│              Linux Network Stack                            │
│                      ↓                                       │
│              iptables NFQUEUE (queue 1)                     │
│                      ↓                                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  DOUANE DAEMON (runs as root)                        │  │
│  │  - Intercepts packets via NetfilterQueue             │  │
│  │  - Identifies application via /proc                  │  │
│  │  - Checks whitelist & cached rules                   │  │
│  │  - Sends request to GUI via Unix socket              │  │
│  │  - Accepts/drops packet based on decision            │  │
│  └──────────────────────────────────────────────────────┘  │
│                      ↕ (Unix socket)                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  GUI CLIENT (runs as user)                           │  │
│  │  - Shows popup dialogs (has DISPLAY access)          │  │
│  │  - System tray icon with menu                        │  │
│  │  - Sends decisions back to daemon                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                      ↓                                       │
│              User Decision (Allow/Deny)                     │
│                      ↓                                       │
│          Save to /etc/douane/rules.json                     │
│          Add to UFW (if permanent)                          │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

1. **douane-daemon.py** - Root daemon process
   - NetfilterQueue packet interception
   - Application identification via /proc and psutil
   - Decision caching and rule persistence
   - UFW integration for permanent rules
   - Unix socket server for GUI communication

2. **douane-gui-client.py** - User GUI client
   - Enhanced popup dialogs with detailed information
   - System tray icon (pystray + AppIndicator3)
   - Unix socket client to communicate with daemon
   - Starts daemon with pkexec (GUI password prompt)

3. **douane_control_panel.py** - Control panel application
   - Settings management (mode, timeout)
   - Rule viewer and editor
   - Log viewer with pkexec for privileged access
   - Firewall start/stop/restart controls

4. **firewall_core.py** - Packet processing engine
   - NetfilterQueue bindings
   - Packet parsing with scapy
   - Application identification logic

5. **service_whitelist.py** - Smart whitelist
   - Auto-allows essential services (DNS, NTP, DHCP, apt)
   - Localhost connections always allowed
   - Configurable trusted applications

## 📦 Installation

### Prerequisites

```bash
# Ubuntu/Debian - Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip iptables gir1.2-ayatanaappindicator3-0.1
```

### Method 1: Install from .deb Package (Recommended)

```bash
# Clone the repository
git clone https://github.com/shipdocs/Douane.git
cd Douane

# Build the package
./build_deb.sh

# Install
sudo dpkg -i douane-firewall_2.0.0_all.deb

# If there are dependency issues, fix them:
sudo apt-get install -f
```

The package installs:
- `/usr/local/bin/douane-daemon` - Root daemon
- `/usr/local/bin/douane-gui-client` - GUI client
- `/usr/local/bin/douane-control-panel` - Control panel
- `/etc/douane/config.json` - Configuration
- `/usr/share/applications/douane-firewall.desktop` - Application menu entry
- `/usr/share/applications/douane-control-panel.desktop` - Control panel menu entry

### Method 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/shipdocs/Douane.git
cd Douane

# Build the Debian package
./build_deb.sh

# Install the package
sudo dpkg -i douane-firewall_2.0.0_all.deb
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

**From Application Menu:**
1. Search for "Douane Firewall" in your application menu
2. Click to launch
3. Enter your password when prompted (pkexec)
4. System tray icon appears (green shield)
5. Firewall is now active!

**From Command Line:**
```bash
# Start the GUI client (recommended)
/usr/local/bin/douane-gui-client
```

**Open Control Panel:**
1. Search for "Douane Control Panel" in application menu, OR
2. Right-click system tray icon → "Control Panel"

### Using the Control Panel

The Control Panel provides complete management of the firewall:

**Status Tab:**
- View firewall running status (Running/Stopped)
- See statistics: total rules, allowed/denied counts
- Current operating mode (Learning/Enforcement)
- Popup timeout setting
- Refresh button to update all information

**Settings Tab:**
- Switch between Learning and Enforcement modes
- Adjust popup timeout (seconds)
- Save settings (automatically updates status display)

**Rules Tab:**
- View all saved rules (application:port → Allow/Deny)
- Delete individual rules
- Clear all rules
- Refresh rules list

**Logs Tab:**
- View real-time daemon logs
- See all connection attempts and decisions
- Clear logs
- Refresh to see latest entries

**Control Buttons:**
- Start Firewall - Launch the daemon and GUI client
- Stop Firewall - Stop daemon and GUI (Control Panel stays open!)
- Restart Firewall - Stop and restart (Control Panel stays open!)

### Using the Popup Dialogs

When an application tries to connect to the internet, a popup appears showing:

**Information Displayed:**
- Application name and full path
- Destination hostname (reverse DNS lookup)
- Destination IP and port with description
- Process information (PID, user, CPU%, memory%)
- Risk assessment (Low/Medium/High)

**Your Options:**
- **Allow Once** - Allow this connection, ask again next time
- **Allow Always** - Allow all connections from this app on this port (saved permanently)
- **Deny** - Block this connection
- **Auto-deny** - If you don't respond within timeout (default 30s), connection is denied

**Keyboard Shortcuts:**
- `Enter` or `A` - Allow Once
- `Escape` - Deny

### Managing Rules

**Via Control Panel:**
1. Open Control Panel (from app menu or tray icon)
2. Go to "Rules" tab
3. View all saved rules (application:port → action)
4. Delete individual rules or clear all

**Via Command Line:**
```bash
# View saved rules
cat /etc/douane/rules.json

# View UFW rules
sudo ufw status numbered

# View logs
sudo tail -f /var/log/douane-daemon.log
```

### Stopping the Firewall

**From Control Panel (Recommended):**
- Click "Stop Firewall" button
- Control Panel stays open for management
- Can restart anytime with "Start Firewall" button

**From System Tray:**
- Right-click tray icon → "Stop Firewall"

**From Command Line:**
```bash
# Stop daemon and GUI client
pkill -TERM -f douane-daemon
pkill -TERM -f douane-gui-client
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

### No Popups Appearing

If the firewall is running but you're not seeing popups:

```bash
# Check if NFQUEUE rule is active
sudo iptables -S OUTPUT | grep NFQUEUE

# If missing, restart the firewall
# Use the Control Panel: Firewall > Restart
# Or manually:
sudo pkill -TERM -f douane-daemon
sudo pkill -TERM -f douane-gui-client
/usr/local/bin/douane-gui-client

# Check daemon logs
sudo tail -f /var/log/douane-daemon.log
```

**Note:** The NFQUEUE rule can be removed if UFW is reloaded. If this happens frequently, restart the Douane firewall after any UFW changes.

### Permission Errors in Control Panel

If you get permission errors when deleting rules or changing settings:

```bash
# Make sure pkexec is installed
which pkexec

# The control panel uses pkexec to modify root-owned files
# You'll be prompted for your password - this is normal
```

See [PRODUCTION_GUIDE.md](PRODUCTION_GUIDE.md) for more troubleshooting.

## 🗑️ Uninstallation

### Complete Uninstallation

```bash
# Stop the firewall
pkill -TERM -f douane
sudo rm -f /tmp/douane-daemon.sock

# Uninstall the package
sudo dpkg --purge douane-firewall

# Remove configuration and rules (optional)
sudo rm -rf /etc/douane
sudo rm -f /var/log/douane-daemon.log

# Verify iptables rules are cleaned up
sudo iptables -L OUTPUT -v -n | grep NFQUEUE
# Should return nothing

# Check UFW rules (optional cleanup)
sudo ufw status numbered
# Delete any Douane-related rules if needed
```

The package's `postrm` script automatically:
- Removes iptables NFQUEUE rules
- Cleans up the Unix socket
- Removes installed files

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
