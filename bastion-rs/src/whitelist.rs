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

/// Check if this connection should be auto-allowed
pub fn should_auto_allow(app_path: &str, dest_port: u16, dest_ip: &str) -> (bool, &'static str) {
    // 1. Essential ports (DNS, DHCP, NTP) - only for trusted binaries
    if ESSENTIAL_PORTS.contains(&dest_port) {
        // SECURITY: Only allow essential ports for trusted system binaries
        // This prevents malicious processes from bypassing the firewall via DNS/DHCP/NTP
        if SYSTEM_PATHS.contains(app_path) || app_path.starts_with("/usr/lib/systemd/") {
            return (true, "Essential port (trusted)");
        }
        // Don't auto-allow unknown processes on essential ports
        return (false, "");
    }
    
    // 2. Localhost connections - only for trusted binaries
    if let Ok(ip) = dest_ip.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            // SECURITY: Only auto-allow localhost for trusted system binaries
            // This prevents malicious processes from bypassing firewall via loopback tunnels
            if SYSTEM_PATHS.contains(app_path) || app_path.starts_with("/usr/lib/systemd/") {
                return (true, "Localhost (trusted)");
            }
            // Don't auto-allow unknown processes on localhost
            return (false, "");
        }
    }
    
    // 3. System binaries
    if SYSTEM_PATHS.contains(app_path) {
        return (true, "System service");
    }
    
    // 4. Check path prefixes
    if app_path.starts_with("/usr/lib/systemd/") {
        return (true, "Systemd service");
    }
    
    (false, "")
}

/// Get category for an application (for GUI display)
pub fn get_app_category(app_path: &str) -> AppCategory {
    if app_path.starts_with("/usr/lib/systemd/") || 
       app_path.starts_with("/usr/sbin/") ||
       SYSTEM_PATHS.contains(app_path) {
        return AppCategory::System;
    }
    
    let name = app_path.split('/').last().unwrap_or("");
    
    // Browsers
    if ["firefox", "firefox-esr", "chromium", "chrome", "brave", "vivaldi", "opera"]
        .iter().any(|b| name.contains(b)) {
        return AppCategory::Browser;
    }
    
    // Dev tools
    if ["code", "vim", "nvim", "cargo", "rustc", "python", "node", "npm", "git"]
        .iter().any(|t| name.contains(t)) {
        return AppCategory::Development;
    }
    
    // Communication
    if ["discord", "slack", "telegram", "signal", "teams", "zoom", "skype"]
        .iter().any(|c| name.contains(c)) {
        return AppCategory::Communication;
    }
    
    AppCategory::Unknown
}
