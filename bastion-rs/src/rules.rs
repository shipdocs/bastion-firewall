//! Rules management module
//! Loads and matches firewall rules from JSON

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use log::{info, warn, error};
use parking_lot::RwLock;

const RULES_PATH: &str = "/etc/bastion/rules.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub app_path: String,
    pub port: Option<u16>,  // None means any port
    pub allow: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RulesFile {
    rules: Vec<Rule>,
}

pub struct RuleManager {
    // Key: (app_path, port) -> allow
    rules: RwLock<HashMap<(String, Option<u16>), bool>>,
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
                match serde_json::from_str::<RulesFile>(&content) {
                    Ok(rules_file) => {
                        let mut rules = self.rules.write();
                        rules.clear();
                        for rule in rules_file.rules {
                            let port = rule.port;
                            rules.insert((rule.app_path, port), rule.allow);
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
        
        // Try exact match first (app + specific port)
        if let Some(&allow) = rules.get(&(app_path.to_string(), Some(port))) {
            return Some(allow);
        }
        
        // Try wildcard match (app + any port)
        if let Some(&allow) = rules.get(&(app_path.to_string(), None)) {
            return Some(allow);
        }
        
        None
    }
    
    /// Add a new rule
    pub fn add_rule(&self, app_path: &str, port: Option<u16>, allow: bool) {
        {
            let mut rules = self.rules.write();
            rules.insert((app_path.to_string(), port), allow);
        }
        self.save_rules();
    }
    
    fn save_rules(&self) {
        let rules = self.rules.read();
        let rules_vec: Vec<Rule> = rules
            .iter()
            .map(|((path, port), &allow)| Rule {
                app_path: path.clone(),
                port: *port,
                allow,
            })
            .collect();
        
        let rules_file = RulesFile { rules: rules_vec };
        
        // Ensure directory exists
        if let Some(parent) = Path::new(RULES_PATH).parent() {
            let _ = fs::create_dir_all(parent);
        }
        
        match serde_json::to_string_pretty(&rules_file) {
            Ok(content) => {
                if let Err(e) = fs::write(RULES_PATH, content) {
                    error!("Failed to write rules file: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to serialize rules: {}", e);
            }
        }
    }
}
