# Changelog

All notable changes to Bastion Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.28] - 2026-01-10

### Features
- **DNS Cache Integration**: Full userspace DNS snooping integrated with eBPF process tracking.
- **Smart Resolver Attribution**: Correctly attributes network connections to the originating application even when DNS queries are handled by `systemd-resolved` or other local resolvers.
- **LAN Broadcast Auto-Allow**: Automatically allows all broadcast traffic (addresses ending in `.255` or `255.255.255.255`).
  - Fixes repeated popups for Steam LAN discovery, DLNA, printers, and gaming protocols.

### Improvements
- **GUI Robustness**: Fixed `AttributeError` crashes in the Control Panel when filtering empty log or rule tables.
- **Codebase Sanitization**: Removed decorative symbols and AI-style comments for a more professional development environment.
- **Startup Experience**: Simplified and updated the daemon startup banner with accurate versioning.

## [2.0.26] - 2026-01-03

### Features
- **Perfect Learning Mode**: Non-blocking popups for zero-latency traffic while in learning mode.
- **Asynchronous Rule Creation**: Rules created from popups are now saved in the background.

### Improvements
- **Robust Path Identification**: Improved cleaning for containerized app paths (Flatpak/Brave).
- **Codebase Sanitization**: Removed verbose AI-generated comments and redundant artifacts.
- **Security**: Hardened daemon IPC with peer credential verification.

## [2.0.25] - 2025-12-31

### Features
- **DNS Hostname Tracking** (Issues #25, #26): eBPF-based DNS query tracking for hostname correlation
  - Shows destination hostname in firewall popups (e.g., "google.com" instead of just IP)
  - Tracks DNS queries at kernel level to correlate IPs with hostnames
  - Helps identify what unknown processes are connecting to
- **mDNS Auto-Allow**: Automatically allows mDNS multicast traffic (224.0.0.251:5353) for `.local` hostname resolution
  - No more popups for Avahi/mDNS discovery
  - Improves out-of-box experience for local network browsing

### Improvements
- **Learning Mode Indicator**: Stats logging now shows "(learning)" suffix when in learning mode
- **GUI Stats Display**: Control panel shows learning mode state with stats updates
- **Branch Cleanup**: Consolidated all feature branches into master
- **Version Management**: All components now use single-source VERSION file

## [2.0.24] - 2025-12-31

### Features
- **Hybrid Inbound Firewall Protection** (Issue #27): Automatic inbound protection
  - Detects existing firewalls: UFW, firewalld, nftables, iptables
  - Adds minimal INPUT rules if no other firewall is detected
  - Allows: localhost, established connections, ICMP ping
  - Blocks: all other unsolicited inbound connections
  - GUI shows accurate inbound status (Protected/Exposed) with firewall type
  - New `inbound_protection` config option (default: true)
  - Rules tagged with `BASTION_INBOUND` for easy identification
  - Automatic cleanup on uninstall (removes only Bastion's rules)
  - Docker detection with appropriate warnings

## [2.0.23] - 2025-12-31

### Features
- **Wildcard Port Rules** (Issue #13): Allow/deny an application on ALL ports with a single rule
  - New "Apply to all ports" checkbox in firewall popup dialog
  - Support for `*` port in manual rule entry
  - Rules stored as `app_path:*` in JSON format
  - Specific port rules take precedence over wildcard rules (security-first design)
  - Ideal for applications like Zoom, Slack, Teams that use multiple ports

### Tests
- Added 10 comprehensive tests for wildcard rule functionality
  - Core wildcard matching
  - Precedence (specific overrides wildcard)
  - JSON serialization/deserialization
  - Persistence across restarts

## [2.0.22] - 2025-12-31

### Build System
- **Single-Source Version Management**: Added `VERSION` file as single source of truth
  - `build_deb.sh` now auto-syncs version to all files (setup.py, Cargo.toml, control, __init__.py)
  - `release_tool.sh` simplified to just update VERSION file
  - No more manual version updates in multiple files

## [2.0.19] - 2025-12-30

### Code Quality & Repository Cleanup
- **Repository Cleanup**: Removed all AI attribution footers and references from commit history
- **Code Refactoring**: Split monolithic `gui_qt.py` (1,265 lines) into modular package structure
  - Created `bastion/gui/` package with separate modules for dialogs, dashboard, platform, and theme
  - Improved maintainability and testability
- **Documentation**: Updated all version numbers to 2.0.19 for consistency
- **GitHub Pages**: Updated website to reflect v2.0.19 release

### Bug Fixes
- **Logs Display**: Fixed control panel logs to read from journalctl instead of empty log file
- **UI Threading**: Fixed QTimer callback using functools.partial instead of lambda
- **IPC Connection**: Added proper IPC connection to dashboard for real-time stats

### Improvements
- **Focus Management**: Improved popup behavior on Wayland/GNOME to prevent focus stealing
- **Process Identification**: Enhanced process tracking with eBPF for better reliability
- **Stats Display**: Added live stats updates in control panel dashboard

## [1.4.7] - 2025-12-26

### Critical Fixes
- **Robust Installation (Zorin 18 / Ubuntu 24.04)**: Installer now automatically handles missing `python3-netfilterqueue` by compiling it via pip, including all necessary build dependencies.
- **Service Stability**: Fixed Daemon startup failure caused by `sys.path` not including `/usr/local` packages on modern Ubuntu versions.
- **UX Fix**: Fixed annoying "Authentication Required" popup spam by ensuring log file permissions are correct (644) on fresh installs.
- **Production Readiness**: Synced mismatched version numbers across all package files.
- **License**: Added missing GPL-3.0 LICENSE file to repository root.
- **Bug Fix**: Fixed case-sensitivity issue in `service_whitelist.py` that caused `NetworkManager` to be blocked incorrectly.

### Improvements
- **Testing**: Added comprehensive "smart" test suite using parametrized inputs. Coverage increased significantly for core modules.
- **CI/CD**: Updated GitHub Actions to trigger correctly on `master` branch.
- **Cleanup**: Removed build artifacts (`.deb`) from git tracking.

## [1.4.5] - 2025-12-25

### Security Hardening
- **Root Bypass Removal**: Removed `BASTION_SKIP_ROOT_CHECK` environment variable bypass from production code. Now requires explicit `--dev-mode` CLI flag with audit logging.
- **Config Validation**: Implemented strict validation for `config.json` loading. Detects type mismatches, invalid values (e.g. timeouts > 600s), and unknown keys.
- **Decision Cache TTL**: Added Time-To-Live caching (5m for connections, 24h for app rules) to prevent stale cache entries and potential port reuse attacks.

### UX Improvements
- **Smart GUI Launch**: Daemon now automatically detects active graphical sessions (X11/Wayland) and launches the tray icon for all logged-in users.
- **Learning Mode Visibility**: Added prominent "Graduate" banner to connection dialogs when in Learning Mode, clearly indicating that connections are auto-allowed.
- **Dynamic Version Display**: Replaced hardcoded version strings with dynamic lookups, ensuring the dashboard correctly identifies as v1.4.5.

### Documentation
- Added `SECURITY_UX_ASSESSMENT_2025-12-25.md` with deep-dive analysis.

## [1.4.4] - 2025-12-25

### Security
- **CRITICAL**: Fixed rollback script path vulnerability in `setup_firewall.sh` (CVE-BASTION-2025-002)
  - Uninitialized `$BACKUP_DIR` variable caused script to write to root directory
  - Added proper initialization to `/var/backups/bastion` with secure permissions (700)
  - Added symlink detection to prevent symlink attacks
  - Added writability validation before script generation
  - Prevents file clobbering and local privilege escalation
- **Enhanced**: Added Unix socket peer authentication using `SO_PEERCRED`
  - Daemon now verifies UID/GID of connecting GUI process
  - Rejects connections from root (GUI should run as normal user)
  - Logs all connection attempts for security audit
  - Hardens against misconfigured permissions or group memberships

### Bug Fixes
- **Fixed**: Global socket timeout side effect in `bastion/gui.py`
  - Removed process-wide `socket.setdefaulttimeout()` call
  - Now saves and restores previous timeout around DNS lookups
  - Prevents unexpected timeout behavior in daemon communication
- **Improved**: Process lookup performance in GUI dialogs
  - Now prefers `psutil` library when available (more accurate and faster)
  - Falls back to targeted `ps aux` parsing if psutil unavailable
  - Stops searching immediately after finding first match
  - Guards against "unknown" app paths to skip unnecessary work
  - Reduces CPU usage and latency on popup dialogs

### Enhancements
- **UX**: Responsive dialog sizing for smaller laptops
  - Changed from fixed 900×750 to dynamic sizing (70% of screen)
  - Reduced minimum size to 700×550 (fits 1366×768 displays)
  - Topmost attribute now auto-releases after 500ms to avoid being intrusive
  - Better experience on budget Zorin/Ubuntu laptops
- **Docs**: Added comprehensive implementation report (`IMPLEMENTATION_REPORT_2025-12-25.md`)

### Notes
- All Python files verified to compile without errors
- Shell script syntax validated with bash -n
- Recommended for all users as a security patch

## [1.4.3] - 2025-12-25

### Previous releases
- See git history for earlier versions

---

**Full Changelog**: https://github.com/shipdocs/bastion-firewall/compare/v1.4.3...v1.4.4
