//! Configuration management

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use log::{info, warn};
use parking_lot::RwLock;

const CONFIG_PATH: &str = "/etc/bastion/config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_mode")]
    pub mode: String,  // "learning" or "enforcement"
    
    #[serde(default = "default_true")]
    pub allow_root_bypass: bool,
    
    #[serde(default = "default_true")]
    pub allow_systemd_bypass: bool,
}

fn default_mode() -> String { "learning".to_string() }
fn default_true() -> bool { true }

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            allow_root_bypass: true,
            allow_systemd_bypass: true,
        }
    }
}

pub struct ConfigManager {
    config: RwLock<Config>,
}

impl ConfigManager {
    pub fn new() -> Self {
        let manager = Self {
            config: RwLock::new(Config::default()),
        };
        manager.load();
        manager
    }
    
    pub fn load(&self) {
        let path = Path::new(CONFIG_PATH);
        if !path.exists() {
            info!("No config file at {}, using defaults", CONFIG_PATH);
            return;
        }
        
        match fs::read_to_string(path) {
            Ok(content) => {
                match serde_json::from_str::<Config>(&content) {
                    Ok(config) => {
                        *self.config.write() = config;
                        info!("Loaded config from {}", CONFIG_PATH);
                    }
                    Err(e) => {
                        warn!("Failed to parse config: {}, using defaults", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read config: {}, using defaults", e);
            }
        }
    }
    
    pub fn get(&self) -> Config {
        self.config.read().clone()
    }
    
    pub fn is_learning_mode(&self) -> bool {
        self.config.read().mode == "learning"
    }
}
