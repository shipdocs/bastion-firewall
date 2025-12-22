# Release Notes

## v1.3.0 - Major Feature: eBPF Core
**Release Date:** 2025-12-22

### 🔒 Security & Performance
- **eBPF Traffic identification**: Implemented kernel-level traffic monitoring using eBPF (Extended Berkeley Packet Filter).
  - Eliminates "race conditions" where short-lived processes (like curl or build tools) would disappear before identification.
  - Significantly reduces "Unknown Application" popups.
  - **Zero Overhead**: Captures process info directly in the kernel without expensive /proc scanning.
- **Kernel Compatibility**: Includes fixes for **Linux Kernel 6.9+** (struct bpf_wq definition).

### ✨ Improvements
- **Modern Notifications**: Replaced old `QMessageBox` popups with sleek, dark-themed, auto-closing notification dialogs for better UX.
- **Crash Fixes**: Resolved `AttributeError` in Control Panel when enabling/disabling UFW.
- **Dependency Update**: Added `python3-bpfcc` and `linux-headers-generic` dependencies.

---

## v2.0.18 - Major Security Hardening & Critical Bug Fixes
**Release Date:** 2025-12-21

### 🐛 Critical Bug Fixes

**Bug #1: Complete Internet Connectivity Failure (CRITICAL)**
- **Problem**: After installation, all internet connectivity was blocked - ping, curl, browsers all failed
- **Root Cause**: Daemon was designed to wait for GUI connection before processing packets, but systemd service only starts daemon (as root), not GUI client (runs as user)
- **Impact**: During wait period, packets queued in NFQUEUE but never processed, causing complete network failure
- **Fix**: Restructured daemon startup:
  - ✅ Packet processor starts **immediately** in background thread
                    <img src="https://img.shields.io/badge/Version-1.2.1-brightgreen" alt="Version 1.2.1"> - ✅ GUI connection acceptor runs in separate background thread
  - ✅ Intelligent fallback for system services when GUI not connected
  - ✅ DNS to localhost resolver (127.0.0.53) **always allowed** for all applications
- **Result**: Internet works perfectly without GUI, ping/curl/wget all functional

**Bug #2: 10-Second Popup Delay (HIGH)**
- **Problem**: Popup window appeared immediately but was blank for ~10 seconds before showing connection details
- **Root Cause**: GUI was performing synchronous reverse DNS lookup on destination IP before displaying dialog
- **Impact**: Poor user experience - users had to wait 10 seconds before making a decision
- **Fix**: Removed reverse DNS lookup entirely - popup now shows IP address directly
- **Result**: Popup appears **instantly** with all data - "supersnel!" (super fast)

**Bug #3: Control Panel Missing Buttons (MEDIUM)**
- **Problem**: Start/Stop/Restart buttons were not visible in Control Panel
- **Root Cause**: Notebook widget expanded to fill entire window, covering bottom button frame
- **Fix**:
  - ✅ Adjusted layout to ensure buttons always visible at bottom
  - ✅ Increased window size from 800x600 to 1000x750
  - ✅ Added minimum window size (900x650)
  - ✅ Added proper padding and styling to buttons
- **Result**: All control buttons clearly visible and functional

### 🔒 Critical Security Fixes

**PHASE 1: Localhost Bypass Fixed (CRITICAL)**
- **Fixed**: Removed blanket localhost whitelist that allowed ANY application to bypass firewall via localhost tunnels
- **New**: Only specific known services (systemd-resolved, dnsmasq) on specific ports are auto-allowed on localhost
- **Exception**: DNS queries to localhost resolver (127.0.0.53) are **always allowed** from any application (required for network connectivity)
- **Impact**: Prevents malware from using SSH tunnels, SOCKS proxies, or port forwarding to bypass firewall
- **User Impact**: May see 1-2 prompts for legitimate localhost IPC (IDE's, development tools) - click "Allow Always"

**PHASE 2: DHCP Hardening (HIGH)**
- **Fixed**: DHCP whitelist now validates destination IP addresses (must be broadcast or link-local)
- **Fixed**: Only known DHCP clients (dhclient, NetworkManager, systemd-networkd) are auto-allowed
- **Impact**: Prevents data exfiltration via fake DHCP packets to attacker-controlled servers
- **User Impact**: None - legitimate DHCP continues to work

**PHASE 3: Application Identification (HIGH)**
- **Fixed**: Unidentified applications no longer bypass security checks via "Unknown Application" string
- **Fixed**: app_name and app_path are now properly None when identification fails
- **Impact**: Closes security hole where short-lived malicious processes could bypass whitelists
- **User Impact**: None - properly identified apps work as before

**PHASE 4: String Matching Hardening (MEDIUM)**
- **Fixed**: Changed from substring matching to exact name matching for trusted applications
- **Fixed**: Added path validation - apps must be in system directories (/usr/bin, /usr/sbin, etc.)
- **Impact**: Prevents malware from spoofing trusted names (e.g., /tmp/systemd-resolved-evil)
- **User Impact**: None - legitimate system services continue to work

**PHASE 5: Trusted Application Port Restrictions (MEDIUM)**
- **New**: Trusted applications are now restricted to their expected ports
- **Example**: systemd-resolved only allowed on port 53 (DNS), not arbitrary ports
- **Impact**: Defense-in-depth - if a trusted service is compromised, it can't make arbitrary connections
- **User Impact**: None under normal operation

### 🛡️ New Feature: Inbound Firewall Protection

**Inbound Protection Tab in Control Panel**
- **New**: Detects if user has inbound firewall protection (UFW, firewalld, iptables, nftables)
- **New**: Offers to install and configure UFW if no protection is detected
- **Configuration**: Sets up stateful firewall rules:
  - ✅ DENY all NEW inbound connections (blocks port scans, attacks)
  - ✅ ALLOW ESTABLISHED/RELATED (responses to your outbound requests)
  - ✅ ALLOW all outbound (Bastion controls this)
- **User Impact**: Optional - only activated if user clicks "Install & Configure UFW"

### 📊 Security Improvement Summary

| Vulnerability | Before v2.0.18 | After v2.0.18 |
|---------------|----------------|---------------|
| Localhost Bypass | 🔴 Critical (9/10) | 🟢 Fixed (2/10) |
| DHCP Exfiltration | 🟠 High (7/10) | 🟢 Fixed (2/10) |
| App ID Bypass | 🟠 High (7/10) | 🟢 Fixed (2/10) |
| Name Spoofing | 🟡 Medium (6/10) | 🟢 Fixed (2/10) |
| Trusted App Abuse | 🟡 Medium (5/10) | 🟢 Fixed (2/10) |
| **Overall Risk** | 🔴 **High (7.5/10)** | 🟢 **Low (2/10)** |

### 🎯 Comparison with Standard Linux

- **Standard Linux (UFW default)**: 100% open outbound, basic inbound rules
- **Bastion v2.0.17**: Outbound filtering with some security holes
- **Bastion v2.0.18**: Hardened outbound filtering + optional inbound protection = **Complete firewall solution**

### ✅ Test Results

All critical functionality verified working:
- ✅ ping google.com - works without GUI (DNS auto-allowed)
- ✅ curl - works, got instant popup
- ✅ wget - works, got instant popup
- ✅ python3 script - works, got instant popup
- ✅ Internet connectivity - works perfectly
- ✅ Control Panel - all buttons visible and functional
- ✅ Popup performance - instant display ("supersnel!")

### ⚠️ Breaking Changes

**None** - All changes are backwards compatible. Existing rules continue to work.

### 📝 Technical Details

See `douane/service_whitelist.py` for detailed implementation of all security phases.
See `douane/daemon.py` for daemon startup architecture changes.
See `douane/gui.py` for popup performance improvements.

---

## v2.0.17 - Security Hardening
**Release Date:** 2025-12-21

### 🔒 Security Improvements
- **Restricted Infrastructure Whitelist**: Only auto-allow DHCP (Ports 67/68) for unidentified applications to ensure devices can obtain IP addresses. DNS (53), NTP (123), and mDNS (5353) are now BLOCKED for unidentified applications to prevent potential data exfiltration. If the application cannot be identified, it cannot send DNS queries.

---

## v2.0.16 - Connectivity Fixes
**Release Date:** 2025-12-21

### 🐛 Bug Fixes
- **Fix "No Internet" Detection**: Automatically allow essential infrastructure traffic (DNS, DHCP, NTP, mDNS) even if the application cannot be identified. This prevents the OS from erroneously reporting "No Internet Connection" due to blocked connectivity checks from short-lived system processes.

---

## v2.0.15 - Deadlock Fix
**Release Date:** 2025-12-21

### 🐛 Bug Fixes
- **Fix Release Hang**: Addressed a deadlock condition where the daemon would hang on stop/restart because the packet processing thread was waiting for socket I/O, while the stop sequence waited for the thread to finish. Sockets are now closed immediately on stop to unblock all threads.

---

## v2.0.14 - Restart Fix
**Release Date:** 2025-12-21

### 🐛 Bug Fixes
- **Fix Restart Hang**: Fixed an issue where restarting the firewall (especially after changing modes) could hang due to the daemon waiting for a GUI response. The shutdown process is now much more robust.

---

## v2.0.13 - Real-time Statistics
**Release Date:** 2025-12-21

### ✨ New Features
- **Real-time Statistics**: The system tray icon now shows live connection statistics (Total, Allowed, Blocked) when hovering or clicking "Show Statistics".
- **Live Updates**: Statistics in the GUI update automatically every 2 seconds without reopening the window.

---

## v2.0.12 - Tray Icon Persistence
**Release Date:** 2025-12-21

### ✨ Improvements
- **Persistent Tray Icon**: The system tray icon now remains visible even when the firewall service is stopped. It will switch to a "Disconnected" state (red icon) but won't crash or disappear. This makes it easier to restart the firewall from the tray menu.
- **Smarter Control Panel**: The Control Panel no longer kills the GUI client when stopping the firewall, ensuring your monitoring context is preserved.

---

## v2.0.11 - Control Panel Polish
**Release Date:** 2025-12-21

### 🐛 Bug Fixes
- **Control Panel Status Sync**: Fixed an issue where the Control Panel would display an incorrect "Stopped" or "Unknown" status when toggling the firewall. It now accurately reflects the systemd service state (Running, Starting, Stopping, Stopped).

---

## v2.0.10 - Startup & Polish
**Release Date:** 2025-12-21

### 🐛 Bug Fixes
- **Startup Race Condition Fix**: `douane-gui-client` now robustly waits for the systemd daemon to initialize on boot. This prevents the "Password Required" prompt that occurred when the GUI started before the daemon. 
- **Process Cleanup**: Improved signal handling for cleaner shutdowns during system restart or service stops.

---

## v2.0.9 - Universal Support & Decoupled Architecture
**Release Date:** 2025-12-20

### 🌍 Universal Linux Support
- **Decoupled Architecture**: Bastion no longer messes with your system firewall rules.
- **Pass-Through Logic**: UFW/Firewalld are set to "Allow Outbound", and Bastion handles filtering internally via NFQUEUE.
- **Multi-Distro Support**: Added installation scripts and docs for Fedora, RHEL, CentOS, and Arch Linux.
- **RPM Packaging**: Added `build_rpm.sh` and `douane.spec` used by CI/CD.

### 🐛 Improvements & Fixes
- **Instant Reload**: Daemon now reloads configuration instantly on SIGHUP (no restart).
- **Tray Icon**: Fixed tray icon support for modern GNOME/Zorin OS (AppIndicator3).
- **Setup Script**: `setup_firewall.sh` now auto-detects UFW, Firewalld, or raw iptables.

---


## Version 2.0.0 (2025-12-16)

### 🎉 Major Features

#### Interactive Installation
- **Guided setup with whiptail dialogs** during package installation
- Choose between **Learning Mode** (recommended) or **Enforcement Mode** (advanced)
- Configure **autostart** behavior (enable/manual)
- Option to **start firewall immediately** after installation
- Clear, descriptive button labels (no more confusing Yes/No)

#### Beautiful Progress Dialogs
- **Visual feedback** for all firewall operations
- **Start Firewall Dialog** (350x150):
  - Animated progress bar
  - "Starting Bastion Firewall..." message
  - Verifies daemon is running
  - Shows "✓ Firewall started successfully!"
  - Auto-closes after 1.5 seconds
- **Stop Firewall Dialog** (350x150):
  - Warning: "Your system will be unprotected"
  - Animated progress bar
  - "Stopping Bastion Firewall..." message
  - Shows "✓ Firewall stopped"
  - Auto-closes after 1.5 seconds
- **Restart Firewall Dialog** (400x200):
  - Detailed step-by-step progress
  - Scrollable log showing each operation
  - Steps: Stop daemon → Stop GUI → Wait → Clean socket → Start → Verify
  - Shows "✓ Firewall restarted successfully!"
  - Manual close button

#### Automatic Rule Reload (SIGHUP)
- **Instant rule updates** without restarting the daemon
- Delete rules from control panel → **takes effect immediately**
- Daemon reloads rules from disk when receiving SIGHUP signal
- Control panel automatically sends SIGHUP after:
  - Deleting a rule
  - Clearing all rules
  - Saving configuration changes
- Logs show: "Reloading rules from disk..." and "Rules reloaded: X → Y rules"

#### pkexec Integration
- **Proper permission handling** for editing root-owned files
- Control panel uses **pkexec** (GUI password dialog) instead of sudo
- Secure temporary file approach:
  1. Write changes to temp file
  2. Use `pkexec cp` to copy to `/etc/douane/`
  3. Clean up temp file
- Applies to:
  - Deleting rules
  - Clearing all rules
  - Saving configuration (mode, timeout)
- User sees familiar GUI password prompt (not terminal)

#### AppStream Metadata
- **Shows up in Software Center** (GNOME Software, KDE Discover)
- **Visible in Settings > Apps** on modern Linux desktops
- Metadata file: `/usr/share/metainfo/com.douane.firewall.metainfo.xml`
- Includes:
  - Application description
  - Feature list
  - Developer information
  - Categories (System, Security, Network)
  - Content rating (OARS 1.1)
- Searchable with: `appstreamcli search douane`

### 🔧 Improvements

#### Control Panel Enhancements
- **Stays open** when stopping/restarting firewall (no more closing)
- **Real-time status updates** after operations
- **Better error handling** with informative messages
- **Centered dialogs** for better UX
- **Modal dialogs** with `grab_set()` for focus management

#### Installation Experience
- **No more silent installs** - interactive prompts guide users
- **Clear mode explanations** with bullet points
- **Recommended options** clearly marked
- **Fresh install detection** - only prompts on new installations
- **config.json created during install** with user choices

#### Daemon Improvements
- **Signal handlers** for graceful shutdown and reload:
  - SIGHUP: Reload rules from disk
  - SIGTERM: Graceful shutdown
  - SIGINT: Graceful shutdown
- **NFQUEUE watchdog** - Monitors and auto-recovers NFQUEUE rule:
  - Checks every 30 seconds if NFQUEUE rule exists
  - Automatically re-adds rule if missing (e.g., after UFW reload)
  - Logs warnings and recovery actions
- **Better logging** for rule reload operations
- **Rule count tracking** in logs (old count → new count)

### 🐛 Bug Fixes

- Fixed permission errors when deleting rules (now uses pkexec)
- Fixed control panel closing when stopping firewall
- Fixed rules not taking effect after deletion (now sends SIGHUP)
- Fixed confusing installation dialog buttons (now descriptive)
- Fixed missing AppStream metadata (now shows in Software Center)
- Fixed config.json being included in package (now created by postinst)

### 📚 Documentation Updates

- Updated README.md with new features
- Updated index.html (GitHub Pages) with latest updates
- Added troubleshooting section for:
  - No popups appearing (NFQUEUE rule missing)
  - Permission errors in control panel
  - UFW reload removing NFQUEUE rule
- Updated feature descriptions in all docs

### 🔄 Migration Notes

If upgrading from v1.x:

1. **Backup your rules**: `sudo cp /etc/douane/rules.json ~/rules.json.backup`
2. **Uninstall old version**: `sudo dpkg -r douane-firewall`
3. **Install new version**: `sudo dpkg -i douane-firewall_2.0.0_all.deb`
4. **Restore rules if needed**: `sudo cp ~/rules.json.backup /etc/douane/rules.json`
5. **Restart firewall**: Use control panel or `pkill -HUP -f douane-daemon`

### ⚠️ Known Issues

- ~~**NFQUEUE rule can disappear** if UFW is reloaded~~ **FIXED**
  - ✅ **Watchdog added**: Daemon now checks NFQUEUE rule every 30 seconds
  - ✅ **Auto-recovery**: Rule is automatically re-added if missing
  - ✅ **Logging**: Warns when rule is missing, confirms when re-added

### 🙏 Credits

- Original Bastion project by Guillaume Hain
- Modernization and v2.0 features by Martin (shipdocs)
- Community feedback and testing

--> - 🎯- **Version**: 1.3.0 (Initial Release)

- Basic packet interception with netfilter/iptables
- GUI popups for connection requests
- Learning mode and enforcement mode
- Rule persistence in JSON format
- UFW integration
- System tray icon
- Control panel for rule management

