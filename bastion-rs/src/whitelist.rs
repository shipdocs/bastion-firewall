//! Service whitelist - auto-allow essential system services

use std::collections::HashSet;
use once_cell::sync::Lazy;

/// Ports that should always be allowed for system operation
static ESSENTIAL_PORTS: Lazy<HashSet<u16>> = Lazy::new(|| {
    let mut s = HashSet::new();
    s.insert(53);   // DNS
    s.insert(67);   // DHCP client
    s.insert(68);   // DHCP server
    s.insert(123);  // NTP
    s.insert(323);  // Chrony NTP
    s
});

/// System binaries that should always be allowed
static SYSTEM_PATHS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s = HashSet::new();
    // Core system
    s.insert("/usr/lib/systemd/systemd");
    s.insert("/usr/lib/systemd/systemd-resolved");
    s.insert("/usr/lib/systemd/systemd-networkd");
    s.insert("/usr/lib/systemd/systemd-timesyncd");
    s.insert("/usr/sbin/NetworkManager");
    s.insert("/usr/sbin/dhclient");
    s.insert("/usr/sbin/chronyd");
    s.insert("/usr/sbin/ntpd");
    // Package managers
    s.insert("/usr/bin/apt");
    s.insert("/usr/bin/apt-get");
    s.insert("/usr/lib/apt/apt-helper");
    s.insert("/usr/lib/apt/methods/http");
    s.insert("/usr/lib/apt/methods/https");
    s.insert("/usr/bin/snap");
    s.insert("/usr/bin/flatpak");
    // Update services
    s.insert("/usr/bin/gnome-software");
    s.insert("/usr/libexec/packagekitd");
    s
});

/// Category of an application
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppCategory {
    System,
    Browser,
    Development,
    Communication,
    Unknown,
}

/// Decides whether a connection should be automatically allowed and returns a short reason label.
///
/// This grants trusted system binaries access to essential service ports and loopback addresses,
/// and treats known system paths (and systemd services) as allowed sources.
/// The decision follows the file's whitelist policy: essential ports and localhost are only
/// auto-allowed for trusted binaries; known system binaries and `/usr/lib/systemd/` paths are allowed.
///
/// # Returns
///
/// A tuple where the first element is `true` if the connection should be auto-allowed, `false` otherwise;
/// the second element is a short static reason string when allowed, or an empty string when denied.
///
/// # Examples
///
/// ```
/// let (allowed, reason) = should_auto_allow("/usr/sbin/NetworkManager", 53, "8.8.8.8");
/// assert_eq!((allowed, reason), (true, "Essential port (trusted)"));
///
/// let (allowed, reason) = should_auto_allow("/home/user/myapp", 80, "127.0.0.1");
/// assert_eq!((allowed, reason), (false, ""));
/// ```
pub fn should_auto_allow(app_path: &str, dest_port: u16, dest_ip: &str) -> (bool, &'static str) {
    // 1. Localhost connections - auto-allow all (low risk, internal traffic)
    if let Ok(ip) = dest_ip.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return (true, "Localhost");
        }
    }
    // Also check string patterns for systemd-resolved
    if dest_ip == "127.0.0.53" || dest_ip.starts_with("127.") {
        return (true, "Localhost");
    }
    
    // 2. DNS traffic - auto-allow (needed for everything to work)
    if dest_port == 53 {
        return (true, "DNS");
    }
    
    // 3. Other essential ports (DHCP, NTP) - only for trusted binaries
    if ESSENTIAL_PORTS.contains(&dest_port) && dest_port != 53 {
        if SYSTEM_PATHS.contains(app_path) || app_path.starts_with("/usr/lib/systemd/") {
            return (true, "Essential port (trusted)");
        }
    }
    
    // 4. System binaries
    if SYSTEM_PATHS.contains(app_path) {
        return (true, "System service");
    }
    
    // 5. Check path prefixes
    if app_path.starts_with("/usr/lib/systemd/") {
        return (true, "Systemd service");
    }
    
    (false, "")
}

/// Get category for an application (for GUI display)
// FIX #24: Use case-insensitive matching for executable names
/// Infers a display category for an application from its filesystem path.
///
/// The function classifies the application into one of `AppCategory` variants
/// based on the path or executable name (case-insensitive).
///
/// - `app_path`: filesystem path to the application binary or service unit.
///
/// # Returns
///
/// `AppCategory::System` when the path is a known system binary or is under
/// `/usr/lib/systemd/` or `/usr/sbin/`. `AppCategory::Browser` when the
/// executable name indicates a web browser. `AppCategory::Development` when the
/// executable name indicates a development tool. `AppCategory::Communication`
/// when the executable name indicates a communication app. Otherwise
/// `AppCategory::Unknown`.
///
/// # Examples
///
/// ```
/// let cat = get_app_category("/usr/bin/firefox");
/// assert_eq!(cat, AppCategory::Browser);
///
/// let sys = get_app_category("/usr/lib/systemd/systemd");
/// assert_eq!(sys, AppCategory::System);
/// ```
pub fn get_app_category(app_path: &str) -> AppCategory {
    if app_path.starts_with("/usr/lib/systemd/") ||
       app_path.starts_with("/usr/sbin/") ||
       SYSTEM_PATHS.contains(app_path) {
        return AppCategory::System;
    }
    
    let name = app_path.split('/').last().unwrap_or("");
    let name_lower = name.to_lowercase();
    
    // Browsers (case-insensitive)
    if ["firefox", "firefox-esr", "chromium", "chrome", "brave", "vivaldi", "opera"]
        .iter().any(|&b| name_lower.contains(b)) {
        return AppCategory::Browser;
    }

    // Dev tools (case-insensitive)
    if ["code", "vim", "nvim", "cargo", "rustc", "python", "node", "npm", "git"]
        .iter().any(|&t| name_lower.contains(t)) {
        return AppCategory::Development;
    }

    // Communication (case-insensitive)
    if ["discord", "slack", "telegram", "signal", "teams", "zoom", "skype"]
        .iter().any(|&c| name_lower.contains(c)) {
        return AppCategory::Communication;
    }
    
    AppCategory::Unknown
}