# Release Notes

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
  - "Starting Douane Firewall..." message
  - Verifies daemon is running
  - Shows "✓ Firewall started successfully!"
  - Auto-closes after 1.5 seconds
- **Stop Firewall Dialog** (350x150):
  - Warning: "Your system will be unprotected"
  - Animated progress bar
  - "Stopping Douane Firewall..." message
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

- **NFQUEUE rule can disappear** if UFW is reloaded
  - **Workaround**: Restart Douane firewall after UFW changes
  - **Future fix**: Add watchdog to monitor and re-add NFQUEUE rule

### 🙏 Credits

- Original Douane project by Guillaume Hain
- Modernization and v2.0 features by Martin (shipdocs)
- Community feedback and testing

---

## Version 1.0.0 (Initial Release)

- Basic packet interception with netfilter/iptables
- GUI popups for connection requests
- Learning mode and enforcement mode
- Rule persistence in JSON format
- UFW integration
- System tray icon
- Control panel for rule management

