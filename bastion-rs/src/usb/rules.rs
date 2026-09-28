//! Persistent USB allow/block rules with device > model > vendor precedence.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use log::warn;
use serde::{Deserialize, Serialize};

use super::device::UsbDeviceInfo;
use super::validation::{sanitize_name, sanitize_serial, validate_key};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub const RULES_PATH: &str = "/etc/bastion/usb_rules.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Exact device, matched by serial.
    Device,
    /// All devices with the same vendor:product.
    Model,
    /// All devices from the vendor.
    Vendor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbRule {
    pub verdict: Verdict,
    pub vendor_id: String,
    pub product_id: String,
    pub vendor_name: String,
    pub product_name: String,
    pub scope: Scope,
    pub added: String,
    #[serde(default)]
    pub last_seen: Option<String>,
    #[serde(default)]
    pub serial: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct RulesFile {
    #[serde(default)]
    rules: BTreeMap<String, UsbRule>,
}

pub struct UsbRuleManager {
    path: PathBuf,
    rules: BTreeMap<String, UsbRule>,
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso_now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

impl UsbRuleManager {
    pub fn new() -> Self {
        Self::with_path(RULES_PATH)
    }

    /// Creates a manager and loads existing rules; a missing or unreadable file yields no rules.
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        let mut m = Self { path: path.as_ref().to_path_buf(), rules: BTreeMap::new() };
        if let Err(e) = m.load() {
            warn!("Failed to load USB rules from {:?}: {:#}", m.path, e);
        }
        m
    }

    pub fn load(&mut self) -> Result<()> {
        if !self.path.exists() {
            self.rules.clear();
            return Ok(());
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)
            .with_context(|| format!("open {:?}", self.path))?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let parsed: RulesFile = serde_json::from_str(&content).context("parse USB rules")?;

        self.rules = parsed
            .rules
            .into_iter()
            .filter(|(k, _)| {
                let ok = validate_key(k);
                if !ok {
                    warn!("Ignoring USB rule with invalid key {:?}", k);
                }
                ok
            })
            .collect();
        Ok(())
    }

    /// Atomic save: write a temp file (0640), fsync, rename over the target.
    pub fn save(&self) -> Result<()> {
        let data = serde_json::to_string_pretty(&RulesFile { rules: self.rules.clone() })?;
        // Unique per process and call so concurrent savers never share a temp file.
        let tmp = self.path.with_extension(format!(
            "json.{}.{}.tmp",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&tmp)
            .with_context(|| format!("create {:?}", tmp))?;
        let result = (|| -> Result<()> {
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640))?;
            std::fs::rename(&tmp, &self.path).with_context(|| format!("rename to {:?}", self.path))
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    fn key_for(device: &UsbDeviceInfo, scope: Scope) -> Result<String> {
        Ok(match scope {
            Scope::Device => {
                let Some(serial) = device.serial.as_deref() else {
                    bail!("device-scope rule requires a serial number");
                };
                let serial = sanitize_serial(serial);
                if serial == "no-serial" {
                    bail!("device-scope rule requires a serial number");
                }
                format!("{}:{}:{}", device.vendor(), device.product(), serial)
            }
            Scope::Model => format!("{}:{}:*", device.vendor(), device.product()),
            Scope::Vendor => format!("{}:*:*", device.vendor()),
        })
    }

    /// Add (or replace) a rule for `device` and persist it. Returns the rule key.
    pub fn add_rule(&mut self, device: &UsbDeviceInfo, verdict: Verdict, scope: Scope) -> Result<String> {
        let key = Self::key_for(device, scope)?;
        if !validate_key(&key) {
            bail!("invalid rule key {:?}", key);
        }
        let rule = UsbRule {
            verdict,
            vendor_id: device.vendor(),
            product_id: if scope == Scope::Vendor { "*".into() } else { device.product() },
            vendor_name: sanitize_name(&device.vendor_name),
            product_name: sanitize_name(&device.product_name),
            scope,
            added: iso_now(),
            last_seen: None,
            serial: (scope == Scope::Device).then(|| sanitize_serial(device.serial.as_deref().unwrap_or(""))),
        };
        let previous = self.rules.insert(key.clone(), rule);
        if let Err(e) = self.save() {
            // Keep memory consistent with disk: a rule that was not persisted must not apply.
            match previous {
                Some(p) => self.rules.insert(key, p),
                None => self.rules.remove(&key),
            };
            return Err(e);
        }
        Ok(key)
    }

    pub fn delete_rule(&mut self, key: &str) -> Result<bool> {
        if !validate_key(key) {
            bail!("invalid rule key");
        }
        let Some(previous) = self.rules.remove(key) else {
            return Ok(false);
        };
        if let Err(e) = self.save() {
            self.rules.insert(key.to_string(), previous);
            return Err(e);
        }
        Ok(true)
    }

    /// Most specific matching rule: device, then model, then vendor.
    pub fn lookup(&self, device: &UsbDeviceInfo) -> Option<&UsbRule> {
        let (v, p) = (device.vendor(), device.product());
        if let Some(serial) = device.serial.as_deref() {
            let serial = sanitize_serial(serial);
            if serial != "no-serial" {
                if let Some(r) = self.rules.get(&format!("{v}:{p}:{serial}")) {
                    return Some(r);
                }
            }
        }
        self.rules
            .get(&format!("{v}:{p}:*"))
            .or_else(|| self.rules.get(&format!("{v}:*:*")))
    }

    pub fn rules(&self) -> &BTreeMap<String, UsbRule> {
        &self.rules
    }

    /// Reload from disk (e.g. on SIGHUP).
    pub fn reload(&mut self) -> Result<()> {
        self.load()
    }
}

impl Default for UsbRuleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::device::test_device;
    use tempfile::tempdir;

    #[test]
    fn iso_format() {
        let s = iso_now();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z') && s.as_bytes()[10] == b'T');
    }

    #[test]
    fn precedence_device_over_model_over_vendor() {
        let dir = tempdir().unwrap();
        let mut m = UsbRuleManager::with_path(dir.path().join("usb_rules.json"));
        let dev = test_device(0x08, Some("SER1"));
        assert!(m.lookup(&dev).is_none());

        m.add_rule(&dev, Verdict::Block, Scope::Vendor).unwrap();
        assert_eq!(m.lookup(&dev).unwrap().verdict, Verdict::Block);
        m.add_rule(&dev, Verdict::Allow, Scope::Model).unwrap();
        assert_eq!(m.lookup(&dev).unwrap().verdict, Verdict::Allow);
        m.add_rule(&dev, Verdict::Block, Scope::Device).unwrap();
        assert_eq!(m.lookup(&dev).unwrap().verdict, Verdict::Block);

        // A different serial of the same model falls back to the model rule.
        let other = test_device(0x08, Some("SER2"));
        assert_eq!(m.lookup(&other).unwrap().verdict, Verdict::Allow);
    }

    #[test]
    fn device_scope_needs_serial() {
        let dir = tempdir().unwrap();
        let mut m = UsbRuleManager::with_path(dir.path().join("r.json"));
        assert!(m.add_rule(&test_device(0, None), Verdict::Allow, Scope::Device).is_err());
        assert!(m.add_rule(&test_device(0, Some("///")), Verdict::Allow, Scope::Device).is_err());
    }

    #[test]
    fn persists_atomically_with_mode_0640() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("usb_rules.json");
        let mut m = UsbRuleManager::with_path(&path);
        let key = m.add_rule(&test_device(3, Some("S")), Verdict::Allow, Scope::Device).unwrap();
        assert_eq!(key, "046d:c52b:S");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
        let leftovers = std::fs::read_dir(dir.path()).unwrap().filter(|e| {
            e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".tmp")
        });
        assert_eq!(leftovers.count(), 0);

        let m2 = UsbRuleManager::with_path(&path);
        assert_eq!(m2.rules().len(), 1);
        assert_eq!(m2.rules()[&key].serial.as_deref(), Some("S"));

        let mut m3 = UsbRuleManager::with_path(&path);
        assert!(m3.delete_rule(&key).unwrap());
        assert!(!m3.delete_rule(&key).unwrap());
        assert!(UsbRuleManager::with_path(&path).rules().is_empty());
    }

    #[test]
    fn invalid_keys_are_dropped_on_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("r.json");
        let rule = r#"{"verdict":"allow","vendor_id":"046d","product_id":"*","vendor_name":"","product_name":"","scope":"vendor","added":"x"}"#;
        std::fs::write(&path, format!(r#"{{"rules":{{"046d:*:*":{rule},"../evil":{rule}}}}}"#)).unwrap();
        let m = UsbRuleManager::with_path(&path);
        assert_eq!(m.rules().len(), 1);
        assert!(m.rules().contains_key("046d:*:*"));
    }

    #[test]
    fn failed_save_rolls_back_in_memory_rule() {
        let dir = tempdir().unwrap();
        let mut m = UsbRuleManager::with_path(dir.path().join("missing_dir/usb_rules.json"));
        let dev = test_device(0x08, Some("S"));
        assert!(m.add_rule(&dev, Verdict::Allow, Scope::Model).is_err());
        assert!(m.lookup(&dev).is_none());
        assert!(m.rules().is_empty());
    }

    #[test]
    fn refuses_symlinked_rules_file() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, r#"{"rules":{}}"#).unwrap();
        let link = dir.path().join("usb_rules.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut m = UsbRuleManager { path: link, rules: BTreeMap::new() };
        assert!(m.load().is_err());
    }
}
