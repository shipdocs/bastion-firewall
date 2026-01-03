//! Configuration management

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::os::unix::fs::OpenOptionsExt;
use std::io::Read;
use log::info;

use parking_lot::RwLock;
use anyhow::{Context, Result};

const CONFIG_PATH: &str = "/etc/bastion/config.json";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OperationMode {
    #[default]
    Learning,
    Enforcement,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub mode: OperationMode,
    #[serde(default = "default_true")]
    pub popup_enabled: bool,
    #[serde(default = "default_true")]
    pub notifications_enabled: bool,
}

fn default_true() -> bool { true }

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: OperationMode::Learning,
            popup_enabled: true,
            notifications_enabled: true,
        }
    }
}

pub struct ConfigManager {
    config: RwLock<Config>,
    path: PathBuf,
}

impl ConfigManager {
    pub fn new() -> Self {
        Self::with_path(CONFIG_PATH)
    }

    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        let manager = Self {
            config: RwLock::new(Config::default()),
            path: path.as_ref().to_path_buf(),
        };
        let _ = manager.load();
        manager
    }

    pub fn load(&self) -> Result<()> {
        if !self.path.exists() {
            info!("No config file at {:?}, using defaults", self.path);
            return Ok(());
        }

        // Security: O_NOFOLLOW to avoid symlink attacks
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
            .with_context(|| format!("Failed to open config file at {:?}", self.path))?;

        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let config: Config = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file at {:?}", self.path))?;

        let mut current_config = self.config.write();
        *current_config = config;
        
        info!("Config loaded: mode={:?}", current_config.mode);
        Ok(())
    }

    pub fn is_learning_mode(&self) -> bool {
        self.config.read().mode == OperationMode::Learning
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let manager = ConfigManager::with_path("/non/existent/path");
        assert!(manager.is_learning_mode());
    }

    #[test]
    fn test_load_valid_config() {
        let mut tmp_file = NamedTempFile::new().unwrap();
        writeln!(tmp_file, r#"{{"mode": "enforcement", "popup_enabled": false}}"#).unwrap();
        
        let manager = ConfigManager::with_path(tmp_file.path());
        assert!(!manager.is_learning_mode());
    }

    #[test]
    fn test_load_invalid_json() {
        let mut tmp_file = NamedTempFile::new().unwrap();
        writeln!(tmp_file, r#"{{"mode": "invalid"#,).unwrap();
        
        let manager = ConfigManager::with_path(tmp_file.path());
        // Should keep defaults on failure
        assert!(manager.is_learning_mode());
    }
}