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
    #[serde(default)]
    pub mode: OperationMode,
    #[serde(default = "default_true")]
    pub popup_enabled: bool,
    #[serde(default = "default_true")]
    pub notifications_enabled: bool,
    /// When true, packets that cannot be parsed/inspected are dropped in
    /// enforcement mode and the NFQUEUE rule is installed without
    /// `--queue-bypass`. Default false preserves the current fail-open behavior.
    #[serde(default)]
    pub fail_closed: bool,
    /// Opt-in USB device control: new USB devices are blocked until the user decides.
    #[serde(default)]
    pub usb_control: bool,
    /// Seconds to wait for the GUI to answer a USB prompt before blocking the device.
    #[serde(default = "default_usb_timeout")]
    pub usb_prompt_timeout_secs: u64,
}

fn default_usb_timeout() -> u64 { 30 }

fn default_true() -> bool { true }

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: OperationMode::Learning,
            popup_enabled: true,
            notifications_enabled: true,
            fail_closed: false,
            usb_control: false,
            usb_prompt_timeout_secs: default_usb_timeout(),
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

    pub fn is_fail_closed(&self) -> bool {
        self.config.read().fail_closed
    }

    pub fn is_usb_control_enabled(&self) -> bool {
        self.config.read().usb_control
    }

    /// Prompt timeout, clamped to 5..=300 seconds.
    pub fn usb_prompt_timeout_secs(&self) -> u64 {
        self.config.read().usb_prompt_timeout_secs.clamp(5, 300)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_packaged_config_examples_parse() {
        // Must match the fallback JSON in debian/DEBIAN/postinst and the example in build_deb.sh
        let c: Config = serde_json::from_str(
            r#"{"mode": "learning", "popup_enabled": true, "notifications_enabled": true, "fail_closed": false}"#,
        ).unwrap();
        assert_eq!(c.mode, OperationMode::Learning);
        assert!(c.popup_enabled && c.notifications_enabled && !c.fail_closed);
    }

    #[test]
    fn usb_control_is_opt_in() {
        let c: Config = serde_json::from_str("{}").unwrap();
        assert!(!c.usb_control);
        assert_eq!(c.usb_prompt_timeout_secs, 30);
        let c: Config = serde_json::from_str(r#"{"usb_control": true, "usb_prompt_timeout_secs": 1}"#).unwrap();
        assert!(c.usb_control);
        assert_eq!(c.usb_prompt_timeout_secs, 1);
    }

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