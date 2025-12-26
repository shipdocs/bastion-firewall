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
    pub fn new() -> Self {
        let manager = Self {
            rules: RwLock::new(HashMap::new()),
        };
        manager.load_rules();
        manager
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
    
    /// Get decision for an app/port combination
    /// Returns: Some(true) = allow, Some(false) = deny, None = no rule
    pub fn get_decision(&self, app_path: &str, port: u16) -> Option<bool> {
        let rules = self.rules.read();
        
        // Try exact match (app + specific port)
        if let Some(&allow) = rules.get(&(app_path.to_string(), port)) {
            return Some(allow);
        }
        
        None
    }
    
    /// Add a new rule (Python format: "path:port" = bool)
    pub fn add_rule(&self, app_path: &str, port: Option<u16>, allow: bool) {
        if let Some(p) = port {
            {
                let mut rules = self.rules.write();
                rules.insert((app_path.to_string(), p), allow);
            }
            self.save_rules();
        }
    }
    
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
