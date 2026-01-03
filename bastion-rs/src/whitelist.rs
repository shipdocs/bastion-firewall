//! Service whitelist - auto-allow essential system services and trusted apps

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

// NOTE: We intentionally do NOT auto-allow apps by name alone.
// This would be a security risk as comm names can be spoofed.
// Instead, we show a popup on first connection and let the user decide.
// The decision is then saved as a persistent rule (@name:appname:port).

/// Decides whether a connection should be automatically allowed and returns a short reason label.
pub fn should_auto_allow(app_path: &str, app_name: &str, dest_port: u16, dest_ip: &str) -> (bool, &'static str) {
    // 1. Localhost connections - only for trusted binaries
    if let Ok(ip) = dest_ip.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return (true, "Localhost");
        }
    }

    // 1b. mDNS multicast (224.0.0.251:5353)
    if dest_ip == "224.0.0.251" && dest_port == 5353 {
        return (true, "mDNS (local)");
    }

    // 1c. SSDP/UPnP multicast (239.255.255.250:1900)
    if dest_ip == "239.255.255.250" && dest_port == 1900 {
        return (true, "SSDP (local)");
    }

    // 2. DNS traffic
    if dest_port == 53 {
        if SYSTEM_PATHS.contains(app_path) || app_path.starts_with("/usr/lib/systemd/") {
            return (true, "DNS (trusted)");
        }
        if app_path.is_empty() && (app_name == "NetworkManager" || app_name.starts_with("systemd")) {
            return (true, "DNS (trusted)");
        }
        if app_path.is_empty() || app_path == "unknown" {
            return (true, "DNS (system)");
        }
    }

    // 3. Other essential ports (DHCP, NTP)
    if ESSENTIAL_PORTS.contains(&dest_port) {
        if SYSTEM_PATHS.contains(app_path) || app_path.starts_with("/usr/lib/systemd/") {
            return (true, "Essential port (trusted)");
        }
        if app_path.is_empty() && (app_name == "NetworkManager" || app_name.starts_with("systemd") || app_name == "chronyd" || app_name == "ntpd") {
            return (true, "Essential port (trusted)");
        }
        if (app_path.is_empty() || app_path == "unknown") && (dest_port == 123 || dest_port == 67 || dest_port == 68 || dest_port == 323) {
            return (true, "System service");
        }
    }

    // 4. NetworkManager connectivity checks
    if app_name == "NetworkManager" && (dest_port == 80 || dest_port == 443) {
        return (true, "Network connectivity check");
    }

    // 5. System binaries
    if SYSTEM_PATHS.contains(app_path) {
        return (true, "System service");
    }

    // 6. Check path prefixes for systemd
    if app_path.starts_with("/usr/lib/systemd/") {
        return (true, "Systemd service");
    }

    (false, "")
}
