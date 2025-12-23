# 🏰 Bastion Firewall v1.4.1 - Unified GUI/Daemon Integration Release

**Release Date**: December 23, 2025  
**Status**: ✅ Production Ready

---

## 🎯 Major Improvements

### 1. **Critical Bug Fixes** 🔧
- ✅ Fixed default learning mode not being applied on fresh install
- ✅ Increased GUI connection timeout from 10s to 30s (allows user login time)
- ✅ Fixed fallback logic for learning mode when GUI not connected
- ✅ Ensured config persistence: learning mode on install, keep config on upgrade/reboot

### 2. **Unified GUI/Daemon Integration** 🔗
- ✅ Created `GUIManager` class for centralized GUI lifecycle management
- ✅ Daemon now automatically starts and monitors GUI process
- ✅ GUI automatically restarts if it crashes (health check every 10 seconds)
- ✅ Daemon and GUI work as one cohesive application
- ✅ GUI autostart configured for all users on installation

### 3. **Professional Tray Icon System** 🎨
- ✅ Created `IconManager` for consistent icon management
- ✅ Beautiful SVG shield icon with status indicators
- ✅ Status-aware icons: connected (green), disconnected (gray), error (red), learning (blue)
- ✅ Integrated with system theme fallbacks for compatibility
- ✅ Professional appearance across all desktop environments

### 4. **Installation & Configuration** 📦
- ✅ Fresh install: Automatically starts in learning mode (safe default)
- ✅ Upgrade: Preserves existing configuration
- ✅ Reboot: Maintains configured mode
- ✅ GUI autostart: Automatically configured for all users
- ✅ Systemd integration: Daemon manages GUI lifecycle

---

## 📋 Technical Changes

### New Modules
- `bastion/gui_manager.py` - GUI lifecycle management
- `bastion/icon_manager.py` - Icon loading and status management
- `bastion/resources/bastion-icon.svg` - Professional tray icon

### Modified Files
- `bastion/daemon.py` - Added GUIManager, improved health monitoring
- `bastion/config.py` - Already had learning mode as default
- `bastion-gui.py` - Integrated IconManager for professional icons
- `debian/DEBIAN/postinst` - Enhanced installation with GUI autostart setup
- `debian/DEBIAN/control` - Version bumped to 1.4.1

### Key Features
1. **Config Persistence Logic**
   - On install: Creates config.json with learning mode
   - On upgrade: Preserves existing config.json
   - On reboot: Loads config from disk

2. **GUI Lifecycle Management**
   - Daemon starts GUI automatically
   - Health monitor checks GUI every 10 seconds
   - Automatically restarts GUI if it crashes
   - Graceful shutdown of GUI on daemon stop

3. **Icon System**
   - Custom SVG icon with gradient and checkmark
   - Status indicators (green/gray/red/blue)
   - Fallback to system theme icons
   - Professional appearance

---

## ✅ Testing Checklist

- [x] Fresh install starts in learning mode
- [x] GUI connects within 30 seconds
- [x] Unknown connections are allowed in learning mode
- [x] Tray icon displays correctly
- [x] GUI restarts if killed
- [x] Config persists across reboots
- [x] Upgrade preserves configuration
- [x] All critical system services work (DNS, DHCP, NTP)
- [x] Rate limiting prevents popup spam
- [x] eBPF integration works with fallback

---

## 🚀 Installation

```bash
sudo dpkg -i bastion-firewall_1.4.1_all.deb
sudo apt-get install -f  # Install dependencies if needed
```

The daemon will start automatically and GUI will launch on user login.

---

## 📊 Version History

- **v1.4.1** (Dec 23, 2025) - Unified GUI/Daemon, critical bug fixes
- **v1.4.0** (Dec 21, 2025) - Security audit release
- **v1.3.2** (Dec 15, 2025) - Tray icon and startup fixes

