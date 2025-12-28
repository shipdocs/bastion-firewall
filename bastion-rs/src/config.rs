//! Configuration management

use serde::Deserialize;  // FIX #27: Remove unused Serialize import
use std::fs;
use std::path::Path;
use std::os::unix::fs::OpenOptionsExt;
use std::io::Read;
use log::{info, warn};
use parking_lot::RwLock;

const CONFIG_PATH: &str = "/etc/bastion/config.json";

#[derive(Debug, Clone, Deserialize)]
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
        
        // SECURITY: Open file without following symlinks to prevent TOCTOU attacks
        let content = match std::fs::File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(mut file) => {
                let mut content = String::new();
                if file.read_to_string(&mut content).is_ok() {
                    Ok(content)
                } else {
                    Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to read file"))
                }
            }
            Err(e) => {
                warn!("Config file at {} could not be opened securely: {}. Is it a symlink?", CONFIG_PATH, e);
                return;
            }
        };
        
        match content {
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
