//! Rules management module
//! Loads and matches firewall rules from JSON
//! 
//! Python format: {"path:port": true/false, ...}
//! Also supports: {"applications": {}, "services": {}, "path:port": bool}

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use log::{info, warn, error, debug};
use parking_lot::RwLock;

const RULES_PATH: &str = "/etc/bastion/rules.json";

pub struct RuleManager {
    // Key: (app_path, port) -> allow
    rules: RwLock<HashMap<(String, u16), bool>>,
}

impl RuleManager {
    /// Creates a new RuleManager with an empty in-memory rule store and loads persisted rules from disk.
    ///
    /// The manager's rules map is initialized and immediately populated by reading RULES_PATH (if present).
    ///
    ///
    pub fn new() -> Self {
        let manager = Self {
            rules: RwLock::new(HashMap::new()),
        };
        manager.load_rules();
        manager
    }
    
    /// Load rules from the JSON file at RULES_PATH into the manager's in-memory rules map.
    ///
    /// If the file does not exist, this leaves the rules map empty. If the file is present,
    /// the function attempts to parse it as JSON object entries where each rule key uses the
    /// "path:port" format and the corresponding value is a boolean indicating allow (`true`)
    /// or deny (`false`). Entries named "applications" or "services" are treated as metadata
    /// and ignored. On successful load the existing in-memory rules are replaced with the
    /// parsed rules. Read or parse failures are logged.
    ///
    ///
    /// manager.load_rules();
    /// Reload rules from disk - public wrapper for load_rules().
    ///
    /// Used when rules are modified externally (e.g., via GUI) and the daemon
    /// receives a SIGHUP signal to reload configuration.
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
        if path.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
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
                                        0u16  // Wildcard marker
                                    } else if let Ok(p) = port_str.parse::<u16>() {
                                        p
                                    } else {
                                        continue;  // Invalid port format
                                    };

                                    if let serde_json::Value::Bool(allow) = value {
                                        rules.insert((app_path.to_string(), port), allow);
                                        let port_display = if port == 0 { "*".to_string() } else { port.to_string() };
                                        debug!("Loaded rule: {} port {} -> {}", app_path, port_display, if allow { "allow" } else { "deny" });
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
    
    /// Determine whether a specific application path and port combination is allowed.
    ///
    /// Checks rules in precedence order (issue #13):
    /// 1. Specific port rule (app_path:port) - highest priority
    /// 2. Wildcard port rule (app_path:*) - fallback for all ports
    ///
    /// Returns `Some(true)` if the combination is allowed, `Some(false)` if explicitly denied, or `None` if no rule exists for the given app and port.
    ///
    ///
    /// mgr.add_rule("/usr/bin/ssh", Some(22), true, false);
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
    
    /// Adds a rule for a specific application path and port and persists the rules if a port is provided.
    ///
    /// When `port` is `Some(p)`, inserts or updates the rule mapping `(app_path, p) -> allow` and writes
    /// the current rules to the rules file. When `port` is `None`, the function is a no-op.
    ///
    /// If `all_ports` is true, creates a wildcard rule (port 0) that applies to all ports (issue #13).
    ///
    ///
    /// manager.add_rule("/usr/bin/example", Some(8080), true, false);
    ///
    /// manager.add_rule("/usr/bin/zoom", Some(8801), true, true);
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
    
    /// Persists the in-memory rules to the JSON file at RULES_PATH in a Python-compatible format.
    ///
    /// The serialized top-level object contains empty `"applications"` and `"services"` entries and
    /// individual rules as `"path:port": <bool>` pairs. On success, logs the number of saved rules;
    /// on failure, logs an error.
    ///
    ///
    /// mgr.save_rules();
    fn save_rules(&self) {
        let rules = self.rules.read();
        let path = Path::new(RULES_PATH);

        // Security: Reject symlinks
        if path.exists() {
            if path.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                error!("Rules file is a symlink, refusing to save: {}", RULES_PATH);
                return;
            }
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
            let port_str = if *port == 0 { "*".to_string() } else { port.to_string() };
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