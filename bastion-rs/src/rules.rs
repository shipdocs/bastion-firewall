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
    /// # Examples
    ///
    /// ```
    /// let mgr = RuleManager::new();
    /// // No rule expected for an unlikely tuple unless configured on disk
    /// assert!(mgr.get_decision("/unlikely/path", 65535).is_none());
    /// ```
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
    /// # Examples
    ///
    /// ```rust
    /// let manager = RuleManager::new();
    /// // Attempt to populate `manager` from the rules file (may leave empty if file absent)
    /// manager.load_rules();
    /// // Querying for a decision returns `Some(true|false)` if an exact "path:port" rule exists
    /// let decision = manager.get_decision("/usr/bin/myapp", 8080);
    /// ```
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
                                
                                // Parse "path:port" format
                                if let Some(colon_pos) = key.rfind(':') {
                                    let app_path = &key[..colon_pos];
                                    let port_str = &key[colon_pos + 1..];
                                    
                                    if let Ok(port) = port_str.parse::<u16>() {
                                        if let serde_json::Value::Bool(allow) = value {
                                            rules.insert((app_path.to_string(), port), allow);
                                            debug!("Loaded rule: {} port {} -> {}", app_path, port, if allow { "allow" } else { "deny" });
                                        }
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
    /// Returns `Some(true)` if the combination is allowed, `Some(false)` if explicitly denied, or `None` if no rule exists for the given app and port.
    ///
    /// # Examples
    ///
    /// ```
    /// let mgr = RuleManager::new();
    /// mgr.add_rule("/usr/bin/ssh", Some(22), true);
    /// assert_eq!(mgr.get_decision("/usr/bin/ssh", 22), Some(true));
    /// assert_eq!(mgr.get_decision("/usr/bin/ssh", 23), None);
    /// ```
    pub fn get_decision(&self, app_path: &str, port: u16) -> Option<bool> {
        let rules = self.rules.read();
        
        // Try exact match (app + specific port)
        if let Some(&allow) = rules.get(&(app_path.to_string(), port)) {
            return Some(allow);
        }
        
        None
    }
    
    /// Adds a rule for a specific application path and port and persists the rules if a port is provided.
    ///
    /// When `port` is `Some(p)`, inserts or updates the rule mapping `(app_path, p) -> allow` and writes
    /// the current rules to the rules file. When `port` is `None`, the function is a no-op.
    ///
    /// # Examples
    ///
    /// ```
    /// let manager = RuleManager::new();
    /// manager.add_rule("/usr/bin/example", Some(8080), true);
    /// assert_eq!(manager.get_decision("/usr/bin/example", 8080), Some(true));
    /// ```
    pub fn add_rule(&self, app_path: &str, port: Option<u16>, allow: bool) {
        if let Some(p) = port {
            {
                let mut rules = self.rules.write();
                rules.insert((app_path.to_string(), p), allow);
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
    /// # Examples
    ///
    /// ```
    /// let mgr = RuleManager::new();
    /// // add_rule is public; persist the current rules to disk
    /// mgr.save_rules();
    /// ```
    fn save_rules(&self) {
        let rules = self.rules.read();
        
        // Build Python-compatible format
        let mut map = serde_json::Map::new();
        map.insert("applications".to_string(), serde_json::json!({}));
        map.insert("services".to_string(), serde_json::json!({}));
        
        for ((path, port), &allow) in rules.iter() {
            let key = format!("{}:{}", path, port);
            map.insert(key, serde_json::Value::Bool(allow));
        }
        
        let json = serde_json::Value::Object(map);
        
        match serde_json::to_string_pretty(&json) {
            Ok(content) => {
                if let Err(e) = fs::write(RULES_PATH, content) {
                    error!("Failed to write rules file: {}", e);
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