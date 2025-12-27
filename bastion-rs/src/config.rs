//! Configuration management

use serde::Deserialize;  // FIX #27: Remove unused Serialize import
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
        
        // SECURITY: Check for symlink before loading config
        // Reject symlinked config files to prevent symlink-based configuration attacks
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                warn!("Config file at {} is a symlink, rejecting for security", CONFIG_PATH);
                return;
            }
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
        // FIX #22: Default to learning mode on invalid mode strings
        let mode = &self.config.read().mode;
        mode == "learning" || mode != "enforcement"
    }
}
