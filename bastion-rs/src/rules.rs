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
use std::path::Path;

const RULES_PATH: &str = "/etc/bastion/rules.json";

pub struct RuleManager {
    // Key: (app_path, port) -> allow
    rules: RwLock<HashMap<(String, u16), bool>>,
}

impl RuleManager {
    pub fn new() -> Self {
        let manager = Self {
            rules: RwLock::new(HashMap::new()),
        };
        manager.load_rules();
        manager
    }

    pub fn reload(&self) {
        self.load_rules();
    }

    pub fn load_rules(&self) {
        let path = Path::new(RULES_PATH);
        if !path.exists() {
            info!("No rules file at {}, starting with empty rules", RULES_PATH);
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
            error!("Rules file is a symlink, refusing to load: {}", RULES_PATH);
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

                        info!("Loaded {} rules from {}", rules.len(), RULES_PATH);
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
        if let Some(p) = port {
            // Use port 0 as wildcard marker when all_ports is true
            let stored_port = if all_ports { 0 } else { p };
            {
                let mut rules = self.rules.write();
                rules.insert((app_path.to_string(), stored_port), allow);
            }
            self.save_rules();
        }
    }

    pub fn delete_rule(&self, key: &str) -> bool {
        // Parse "path:port" format (port can be * for wildcard)
        if let Some(colon_pos) = key.rfind(':') {
            let app_path = &key[..colon_pos];
            let port_str = &key[colon_pos + 1..];

            // Handle wildcard port (stored as 0 internally)
            let port = if port_str == "*" {
                Some(0u16)
            } else if let Ok(p) = port_str.parse::<u16>() {
                Some(p)
            } else {
                // Invalid port format - try deleting all ports for this app
                // This handles @dest:IP:PORT format where port is embedded in key
                None
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
        let path = Path::new(RULES_PATH);

        // Security: Reject symlinks
        if path.exists()
            && path
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
        {
            error!("Rules file is a symlink, refusing to save: {}", RULES_PATH);
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
                let temp_path = format!("{}.tmp", RULES_PATH);
                if let Err(e) = fs::write(&temp_path, &content) {
                    error!("Failed to write temp rules file: {}", e);
                    return;
                }
                if let Err(e) = fs::rename(&temp_path, RULES_PATH) {
                    error!("Failed to rename temp rules file: {}", e);
                    // Try to clean up temp file
                    let _ = fs::remove_file(&temp_path);
                } else {
                    info!("Saved {} rules to {}", rules.len(), RULES_PATH);
                }
            }
            Err(e) => {
                error!("Failed to serialize rules: {}", e);
            }
        }
    }
}
