# Changelog

All notable changes to Bastion Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.7] - 2025-12-26

### Critical Fixes
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
