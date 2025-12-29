# Testing the .deb Package

**Package:** bastion-firewall_2.0.0_amd64.deb (1.2 MB)  
**Date:** December 27, 2025

## Pre-Installation

### 1. Remove Old Version (if installed)
```bash
sudo apt remove bastion-firewall
# Or for complete removal:
sudo apt purge bastion-firewall
```

### 2. Check System Requirements
```bash
# Check kernel version (need 6.0+, have 6.14)
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux
```

## Installation

### Install the Package
```bash
sudo dpkg -i bastion-firewall_2.0.0_amd64.deb
sudo apt-get install -f  # Install any missing dependencies
```

Expected output:
- Creates /etc/bastion/ directory
- Creates /var/run/bastion/ socket directory
- Starts bastion-daemon service
- Installs desktop entries

## Verification

### 1. Check Service Status
```bash
sudo systemctl status bastion-daemon
```

Should show: `active (running)`

### 2. Check Logs
```bash
sudo journalctl -u bastion-daemon -f
```

Look for:
- "eBPF process tracking loaded successfully"
- "Process identifier initialized (eBPF enabled: true)"
- "Listening on NFQUEUE 1"

### 3. Check iptables Rules
```bash
sudo iptables -L OUTPUT -n --line-numbers
```

Should show (in order):
1. ACCEPT for systemd-network
2. ACCEPT for root (UID 0)
3. NFQUEUE for NEW connections

### 4. Launch GUI
```bash
bastion-gui
# Or from Applications menu: "Bastion Firewall"
```

### 5. Test Connection
```bash
curl https://httpbin.org/ip
```

Should see:
- GUI popup asking to allow/deny curl
- Daemon logs showing process identification

## Testing Checklist

- [ ] Package installs without errors
- [ ] Service starts automatically
- [ ] eBPF loads successfully (check logs)
- [ ] GUI launches and connects to daemon
- [ ] Popup appears for new connections
- [ ] Process is correctly identified (not "unknown")
- [ ] Rules are saved in /etc/bastion/rules.json
- [ ] Internet works with daemon running

## What to Look For

### eBPF Working
```
[INFO] eBPF process tracking loaded successfully
[INFO] Process identifier initialized (eBPF enabled: true)
```

### Process Identified (Good)
```
[POPUP] curl (/usr/bin/curl) -> 54.204.39.132:443
```

### Process Not Identified (Bad)
```
[POPUP] unknown (unknown) -> 54.204.39.132:443
```

If you see "unknown", eBPF may not be working. Check:
```bash
# Check if BTF exists
ls /sys/kernel/btf/vmlinux

# Check daemon logs for errors
sudo journalctl -u bastion-daemon | grep -i ebpf
```

## Uninstallation

### Keep Config
```bash
sudo apt remove bastion-firewall
```

### Remove Everything
```bash
sudo apt purge bastion-firewall
```

Or use:
```bash
./uninstall.sh
```

## Troubleshooting

### Service Won't Start
```bash
# Check logs
sudo journalctl -u bastion-daemon -n 50

# Try manual start
sudo /usr/bin/bastion-daemon
```

### GUI Won't Connect
```bash
# Check socket
ls -la /var/run/bastion/

# Check if daemon is listening
sudo netstat -an | grep bastion
```

### Internet Blocked
```bash
# Emergency: Remove rules
sudo iptables -F OUTPUT

# Stop daemon
sudo systemctl stop bastion-daemon
```

## Files Installed

- `/usr/bin/bastion-daemon` - Rust daemon (3.4 MB)
- `/usr/bin/bastion-gui` - Python GUI
- `/usr/share/bastion-firewall/bastion-ebpf.o` - eBPF program (14.6 KB)
- `/lib/systemd/system/bastion-daemon.service` - Systemd unit
- `/etc/bastion/config.json` - Configuration
- `/etc/bastion/rules.json` - Firewall rules
- Various desktop entries and documentation

---

**Ready to test!** Install and verify eBPF is working correctly.
