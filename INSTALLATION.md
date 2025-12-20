# Douane Firewall - Clean Installation Guide

## ✅ Package Installed Successfully

The Douane Firewall package has been installed cleanly without breaking your internet connection!

## What Was Installed

### Executables (`/usr/local/bin/`)
- `douane-daemon` - Root daemon (packet interception)
- `douane-gui-client` - User GUI client (shows popups)
- `douane-firewall` - Main executable
- `douane-setup-firewall` - UFW configuration script

### Python Modules (`/usr/lib/python3/dist-packages/douane/`)
- `firewall_core.py` - Packet processing with clean shutdown
- `gui_improved.py` - Modern GUI dialogs
- `service_whitelist.py` - Restrictive whitelist (server-like)
- `service_whitelist.py` - Restrictive whitelist (server-like)

### Configuration
- `/etc/douane/config.json` - Learning mode by default
- `/var/log/douane-daemon.log` - Daemon log file

### Desktop Entry
- `/usr/share/applications/douane-firewall.desktop` - Application menu entry

## Starting the Firewall

### Option 1: From Application Menu
1. Open your application menu
2. Search for "Douane Firewall"
3. Click to launch

### Option 2: From Command Line
```bash
/usr/local/bin/douane-gui-client
```

This will:
1. Ask for your sudo password (to start the daemon)
2. Start the daemon as root
3. Connect the GUI client
4. Create system tray icon
5. Show popups for connection requests

## Stopping the Firewall

### Option 1: Use the Stop Script
```bash
./douane-stop.sh
```

This safely:
- Stops GUI client
- Stops daemon
- Removes iptables rules
- Ensures internet still works

### Option 2: Kill Processes
```bash
pkill -f douane-gui-client
sudo pkill -f douane-daemon
sudo iptables -F OUTPUT
sudo ufw reload
```

## Testing

### 1. Start the Firewall
```bash
/usr/local/bin/douane-gui-client
```

### 2. Test with curl (should show popup)
```bash
curl https://example.com
```

You should see:
- System tray icon (green shield)
- Popup with connection details (hostname, port description, risk level)
- 3 buttons: **Allow Once** (Blue), **Allow Always** (Green), **Deny** (Red)

### 3. Stop the Firewall
```bash
./douane-stop.sh
```

### 4. Verify Internet Still Works
```bash
ping google.com
```

## Configuration

Edit `/etc/douane/config.json`:

```json
{
  "mode": "learning",           // "learning" or "enforcement"
  "cache_decisions": true,      // Remember decisions
  "timeout_seconds": 30,        // Popup timeout
  "allow_localhost": true       // Auto-allow localhost
}
```

**Modes:**
- **learning** - Shows popups but NEVER blocks (safe for testing)
- **enforcement** - Actually blocks based on decisions

## Whitelist (Restrictive - Server-Like)

Only these are auto-allowed:
- DNS (systemd-resolved)
- NTP (systemd-timesyncd)
- DHCP (NetworkManager)
- Package managers (apt only)

Everything else requires a popup:
- ❌ Browsers (Firefox, Chrome)
- ❌ curl, wget
- ❌ VSCode, development tools
- ❌ Email clients
- ❌ Any user application

## Troubleshooting

### Internet Stopped Working
```bash
sudo iptables -F OUTPUT
sudo ufw default allow outgoing
sudo ufw reload
ping google.com
```

### Firewall Won't Start
```bash
# Check if daemon is running
ps aux | grep douane-daemon

# Check logs
tail -20 /var/log/douane-daemon.log

# Remove socket and try again
sudo rm -f /tmp/douane-daemon.sock
/usr/local/bin/douane-gui-client
```

### No Popups Appearing
1. Check if GUI client is running: `ps aux | grep douane-gui-client`
2. Check if daemon is running: `ps aux | grep douane-daemon`
3. Check logs: `tail -20 /var/log/douane-daemon.log`
4. Restart both: `./douane-stop.sh && /usr/local/bin/douane-gui-client`

## Uninstallation

```bash
# Stop the firewall
./douane-stop.sh

# Remove package
sudo dpkg -r douane-firewall

# Restore UFW
sudo ufw default allow outgoing
sudo ufw reload

# Verify internet works
ping google.com
```

## Files Cleaned Up

Removed old/duplicate files:
- Old daemon (`douane_daemon.py`)
- Old GUI (`douane_gui.py`)
- Test files
- Duplicate documentation

Current clean structure:
- Core files only
- No duplicates
- Clean build process

