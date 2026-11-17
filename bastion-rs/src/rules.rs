//! Rules management module
//! Loads and matches firewall rules from JSON
//!
//! Python format: {"path:port": true/false, ...}
//! Also supports: {"applications": {}, "services": {}, "path:port": bool}

// Removed unused serde imports

use log::{debug, error, info, warn};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const RULES_PATH: &str = "/etc/bastion/rules.json";

/// Strip a DNS domain hint that leaked into a name-based rule key.
///
/// Popups show "<name> (<domain>.)" when the daemon knows the destination's domain.
/// Older GUIs sent that display text back as the app name, which produced keys like
/// `@name:Socket Thread (start.thunderbird.net.)` that never match, because lookups
/// use the bare process name. Domain hints from the DNS cache always end in a dot,
/// so only a trailing " (<something>.)" is removed; names such as
/// `next-server (v1` (a truncated comm) are left alone.
pub fn normalize_rule_app(app: &str) -> String {
    if let Some(name) = app.strip_prefix("@name:") {
        if name.ends_with(".)") {
            if let Some(pos) = name.rfind(" (") {
                let base = &name[..pos];
                if !base.is_empty() {
                    return format!("@name:{}", base);
                }
            }
        }
    }
    app.to_string()
}

pub struct RuleManager {
    path: PathBuf,
    // Key: (app_path, port) -> allow
    rules: RwLock<HashMap<(String, u16), bool>>,
}

impl RuleManager {
    pub fn new() -> Self {
        Self::with_path(RULES_PATH)
    }

    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        let manager = Self {
            path: path.as_ref().to_path_buf(),
            rules: RwLock::new(HashMap::new()),
        };
        manager.load_rules();
        manager
    }

    pub fn reload(&self) {
        self.load_rules();
    }

    pub fn load_rules(&self) {
        let path = self.path.as_path();
        if !path.exists() {
            info!("No rules file at {}, starting with empty rules", path.display());
            let mut rules = self.rules.write();
            rules.clear();
            return;
        }

        // Security: Reject symlinks to prevent symlink attacks
        if path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            error!("Rules file is a symlink, refusing to load: {}", path.display());
            let mut rules = self.rules.write();
            rules.clear();
            return;
        }

        match fs::read_to_string(path) {
            Ok(content) => {
                // Parse as generic JSON object
                match serde_json::from_str::<serde_json::Value>(&content) {
                    Ok(json) => {
                        let mut rules = self.rules.write();
                        rules.clear();
                        // Keys with a leaked domain hint: (fixed key, port, allow).
                        let mut migrated: Vec<(String, String, u16, bool)> = Vec::new();

                        if let serde_json::Value::Object(map) = json {
                            for (key, value) in map {
                                // Skip meta fields
                                if key == "applications" || key == "services" {
                                    continue;
                                }

                                // Parse "path:port" format (port can be * for wildcard)
                                if let Some(colon_pos) = key.rfind(':') {
                                    let app_path = &key[..colon_pos];
                                    let port_str = &key[colon_pos + 1..];

                                    // Handle wildcard port (stored as 0 internally)
                                    let port = if port_str == "*" {
                                        0u16 // Wildcard marker
                                    } else if let Ok(p) = port_str.parse::<u16>() {
                                        p
                                    } else {
                                        continue; // Invalid port format
                                    };

                                    if let serde_json::Value::Bool(allow) = value {
                                        let fixed = normalize_rule_app(app_path);
                                        if fixed != app_path {
                                            migrated.push((key.clone(), fixed, port, allow));
                                            continue;
                                        }
                                        rules.insert((app_path.to_string(), port), allow);
                                        let port_display = if port == 0 {
                                            "*".to_string()
                                        } else {
                                            port.to_string()
                                        };
                                        debug!(
                                            "Loaded rule: {} port {} -> {}",
                                            app_path,
                                            port_display,
                                            if allow { "allow" } else { "deny" }
                                        );
                                    }
                                }
                            }
                        }

                        // Apply fixed keys after the clean ones, so an explicit rule
                        // without a domain wins over a repaired one.
                        let needs_save = !migrated.is_empty();
                        for (old_key, fixed, port, allow) in migrated {
                            if rules.contains_key(&(fixed.clone(), port)) {
                                info!("Removed unmatchable rule {} (already covered)", old_key);
                            } else {
                                info!("Repaired unmatchable rule {} -> {}", old_key, fixed);
                                rules.insert((fixed, port), allow);
                            }
                        }

                        info!("Loaded {} rules from {}", rules.len(), path.display());
                        drop(rules);
                        if needs_save {
                            self.save_rules();
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse rules file: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read rules file: {}", e);
            }
        }
    }

    pub fn get_decision(&self, app_path: &str, port: u16) -> Option<bool> {
        let rules = self.rules.read();

        // 1. Try exact match (app + specific port) - highest priority
        if let Some(&allow) = rules.get(&(app_path.to_string(), port)) {
            return Some(allow);
        }

        // 2. Try wildcard match (app + any port, stored as port 0)
        if let Some(&allow) = rules.get(&(app_path.to_string(), 0)) {
            return Some(allow);
        }

        None
    }

    pub fn add_rule(&self, app_path: &str, port: Option<u16>, allow: bool, all_ports: bool) {
        let stored_port = if all_ports {
            0 // Wildcard marker for "All ports" checkbox
        } else if let Some(p) = port {
            p
        } else {
            0 // Default to 0 for @dest rules where port is already in the app_path
        };

        let app_path = normalize_rule_app(app_path);
        {
            let mut rules = self.rules.write();
            rules.insert((app_path, stored_port), allow);
        }
        self.save_rules();
    }

    pub fn delete_rule(&self, key: &str) -> bool {
        // Parse "path:port" format (port can be * for wildcard)
        if let Some(colon_pos) = key.rfind(':') {
            let app_path = &key[..colon_pos];
            let port_str = &key[colon_pos + 1..];

            // Handle wildcard port (stored as 0 internally)
            let port = if port_str == "*" {
                Some(0u16)
            } else {
                port_str.parse::<u16>().ok()
            };

            let mut rules = self.rules.write();
            let removed = if let Some(p) = port {
                rules.remove(&(app_path.to_string(), p)).is_some()
            } else {
                // Delete all rules for this app path (for @dest:IP:PORT format)
                let initial_len = rules.len();
                rules.retain(|(path, _), _| path != app_path);
                rules.len() < initial_len
            };

            if removed {
                drop(rules); // Release write lock before save
                self.save_rules();
                info!("Deleted rule: {}", key);
                true
            } else {
                warn!("Rule not found for deletion: {}", key);
                false
            }
        } else {
            warn!("Invalid rule key format for deletion: {}", key);
            false
        }
    }

    pub fn get_all_rules(&self) -> serde_json::Value {
        let rules = self.rules.read();
        let mut map = serde_json::Map::new();
        map.insert("applications".to_string(), serde_json::json!({}));
        map.insert("services".to_string(), serde_json::json!({}));

        for ((path, port), &allow) in rules.iter() {
            let port_str = if *port == 0 {
                "*".to_string()
            } else {
                port.to_string()
            };
            let key = format!("{}:{}", path, port_str);
            map.insert(key, serde_json::Value::Bool(allow));
        }

        serde_json::Value::Object(map)
    }

    fn save_rules(&self) {
        let rules = self.rules.read();
        let path = self.path.as_path();

        // Security: Reject symlinks
        if path.exists()
            && path
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            error!("Rules file is a symlink, refusing to save: {}", path.display());
            return;
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                error!("Failed to create rules directory: {}", e);
                return;
            }
        }

        // Build Python-compatible format
        let mut map = serde_json::Map::new();
        map.insert("applications".to_string(), serde_json::json!({}));
        map.insert("services".to_string(), serde_json::json!({}));

        for ((path, port), &allow) in rules.iter() {
            // Convert port 0 back to * for JSON serialization (issue #13)
            let port_str = if *port == 0 {
                "*".to_string()
            } else {
                port.to_string()
            };
            let key = format!("{}:{}", path, port_str);
            map.insert(key, serde_json::Value::Bool(allow));
        }

        let json = serde_json::Value::Object(map);

        match serde_json::to_string_pretty(&json) {
            Ok(content) => {
                // Atomic write: write to temp file, then rename
                let temp_path = format!("{}.tmp", path.display());
                if let Err(e) = fs::write(&temp_path, &content) {
                    error!("Failed to write temp rules file: {}", e);
                    return;
                }
                if let Err(e) = fs::rename(&temp_path, path) {
                    error!("Failed to rename temp rules file: {}", e);
                    // Try to clean up temp file
                    let _ = fs::remove_file(&temp_path);
                } else {
                    info!("Saved {} rules to {}", rules.len(), path.display());
                }
            }
            Err(e) => {
                error!("Failed to serialize rules: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_only_domain_hints() {
        assert_eq!(
            normalize_rule_app("@name:Socket Thread (start.thunderbird.net.)"),
            "@name:Socket Thread"
        );
        assert_eq!(
            normalize_rule_app("@name:npm view @cloud (registry.npmjs.org.)"),
            "@name:npm view @cloud"
        );
        // A truncated comm that merely contains a parenthesis stays as-is.
        assert_eq!(normalize_rule_app("@name:next-server (v1"), "@name:next-server (v1");
        assert_eq!(normalize_rule_app("/usr/bin/curl"), "/usr/bin/curl");
        assert_eq!(normalize_rule_app("@dest:1.2.3.4:443"), "@dest:1.2.3.4:443");
    }

    #[test]
    fn load_repairs_domain_keys_and_rewrites_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        fs::write(
            &path,
            r#"{
                "applications": {}, "services": {},
                "@name:Socket Thread:443": true,
                "@name:Socket Thread (start.thunderbird.net.):443": false,
                "@name:copilot-cabi (api.githubcopilot.com.):443": true,
                "@name:next-server (v1:443": true
            }"#,
        )
        .unwrap();

        let rm = RuleManager::with_path(&path);
        // Existing clean rule wins over the repaired duplicate.
        assert_eq!(rm.get_decision("@name:Socket Thread", 443), Some(true));
        assert_eq!(rm.get_decision("@name:copilot-cabi", 443), Some(true));
        assert_eq!(rm.get_decision("@name:next-server (v1", 443), Some(true));

        let saved: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let keys: Vec<&String> = saved.as_object().unwrap().keys().collect();
        assert!(keys.iter().all(|k| !k.contains(".)")), "{:?}", keys);
        assert!(saved.get("@name:copilot-cabi:443").is_some());
    }

    #[test]
    fn add_rule_drops_domain_hint() {
        let dir = tempfile::tempdir().unwrap();
        let rm = RuleManager::with_path(dir.path().join("rules.json"));
        rm.add_rule("@name:Chrome_ChildIOT (static.whatsapp.net.)", Some(5222), true, false);
        assert_eq!(rm.get_decision("@name:Chrome_ChildIOT", 5222), Some(true));
    }
}
