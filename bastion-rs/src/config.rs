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

/// Default configuration mode string.
///
///
/// The default mode string, `"learning"`.
///
///
fn default_mode() -> String { "learning".to_string() }
/// Provide the default `true` value for Serde-backed fields.
///
/// Returns `true`.
///
/// This function is intended to be referenced from `#[serde(default = "default_true")]`.
///
///
fn default_true() -> bool { true }

impl Default for Config {
    /// Creates a `Config` populated with the module's default settings.
    ///
    /// Defaults:
    ///
    ///
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
    /// Creates a ConfigManager initialized with default configuration and attempts to load overrides from disk.
    ///
    /// The manager starts with the default `Config` and then calls `load()` to replace it with values from
    /// the configuration file if available and valid; on any load error the defaults are retained.
    ///
    ///
    pub fn new() -> Self {
        let manager = Self {
            config: RwLock::new(Config::default()),
        };
        manager.load();
        manager
    }
    
    /// Loads configuration from the on-disk config file and updates the in-memory config when valid.
    ///
    /// This attempts to read CONFIG_PATH ("/etc/bastion/config.json") and, if the file exists and
    /// parses successfully as JSON, replaces the manager's current config with the parsed values.
    /// If the file is missing, cannot be opened securely, cannot be read, or fails JSON parsing,
    /// the existing in-memory defaults are preserved and a warning is logged. The file is opened
    /// with `O_NOFOLLOW` to avoid following symlinks.
    ///
    ///
    /// mgr.load();
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
    
    /// Retrieve a cloned copy of the current configuration.
    ///
    /// This returns a snapshot of the in-memory `Config` so callers can read or inspect
    /// configuration without holding locks or affecting the shared state.
    ///
    ///
    ///
    ///
    pub fn get(&self) -> Config {
        self.config.read().clone()
    }
    
    /// Determine whether the current configuration is operating in learning mode.
    ///
    ///
    ///
    ///
    pub fn is_learning_mode(&self) -> bool {
        // FIX #22: Default to learning mode on invalid mode strings
        let mode = &self.config.read().mode;
        mode == "learning" || mode != "enforcement"
    }
}