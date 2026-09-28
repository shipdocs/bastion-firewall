//! Authorize / deauthorize USB devices through sysfs.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use log::info;

use super::validation::validate_bus_id;

pub const SYSFS_USB_PATH: &str = "/sys/bus/usb/devices";

pub struct UsbAuthorizer {
    root: PathBuf,
}

impl UsbAuthorizer {
    pub fn new() -> Self {
        Self::with_root(SYSFS_USB_PATH)
    }

    /// Use a different sysfs root (for tests).
    pub fn with_root<P: AsRef<Path>>(root: P) -> Self {
        Self { root: root.as_ref().to_path_buf() }
    }

    fn write_attr(path: &Path, value: &str) -> Result<()> {
        // sysfs attributes are regular files; refuse to follow a symlink at the leaf.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("open {:?}", path))?;
        f.write_all(value.as_bytes()).with_context(|| format!("write {:?}", path))
    }

    fn auth_path(&self, bus_id: &str) -> Result<PathBuf> {
        if !validate_bus_id(bus_id) {
            bail!("invalid USB bus id {:?}", bus_id);
        }
        Ok(self.root.join(bus_id).join("authorized"))
    }

    pub fn authorize(&self, bus_id: &str) -> Result<()> {
        Self::write_attr(&self.auth_path(bus_id)?, "1")?;
        info!("Authorized USB device {}", bus_id);
        Ok(())
    }

    /// Immediately disconnects the device.
    pub fn deauthorize(&self, bus_id: &str) -> Result<()> {
        Self::write_attr(&self.auth_path(bus_id)?, "0")?;
        info!("Deauthorized USB device {}", bus_id);
        Ok(())
    }

    fn is_root_hub(name: &str) -> bool {
        name.len() > 3 && name.starts_with("usb") && name[3..].chars().all(|c| c.is_ascii_digit())
    }

    /// Root hubs (`usbN`) that have an `authorized_default` attribute, sorted.
    pub fn root_hubs(&self) -> Result<Vec<String>> {
        let mut hubs = Vec::new();
        for entry in std::fs::read_dir(&self.root).with_context(|| format!("read {:?}", self.root))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if Self::is_root_hub(&name) && entry.path().join("authorized_default").exists() {
                hubs.push(name);
            }
        }
        hubs.sort();
        Ok(hubs)
    }

    /// Root hubs whose `authorized_default` is currently `1` (new devices are allowed).
    pub fn hubs_with_default_allow(&self) -> Result<Vec<String>> {
        let mut allow = Vec::new();
        for hub in self.root_hubs()? {
            let value = std::fs::read_to_string(self.root.join(&hub).join("authorized_default")).unwrap_or_default();
            if value.trim() == "1" {
                allow.push(hub);
            }
        }
        Ok(allow)
    }

    /// Set `authorized_default` on the named root hubs only. Hubs that have
    /// disappeared are skipped; anything that isn't a `usbN` name is rejected.
    /// Returns how many hubs were updated.
    pub fn set_default_for(&self, hubs: &[String], authorize: bool) -> Result<usize> {
        let value = if authorize { "1" } else { "0" };
        let mut updated = 0;
        for hub in hubs {
            if !Self::is_root_hub(hub) {
                bail!("invalid USB root hub name {:?}", hub);
            }
            let path = self.root.join(hub).join("authorized_default");
            if path.exists() {
                Self::write_attr(&path, value)?;
                updated += 1;
            }
        }
        Ok(updated)
    }

    /// Set `authorized_default` on every root hub (`usbN`) for newly attached devices.
    /// Returns how many controllers were updated.
    pub fn set_default_policy(&self, authorize: bool) -> Result<usize> {
        let value = if authorize { "1" } else { "0" };
        let mut updated = 0;
        for entry in std::fs::read_dir(&self.root).with_context(|| format!("read {:?}", self.root))? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("usb") && name[3..].chars().all(|c| c.is_ascii_digit()) && name.len() > 3 {
                let path = entry.path().join("authorized_default");
                if path.exists() {
                    Self::write_attr(&path, value)?;
                    updated += 1;
                }
            }
        }
        Ok(updated)
    }
}

impl Default for UsbAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn authorize_and_deauthorize() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("1-2.3")).unwrap();
        std::fs::write(dir.path().join("1-2.3/authorized"), "1").unwrap();
        let a = UsbAuthorizer::with_root(dir.path());
        a.deauthorize("1-2.3").unwrap();
        assert_eq!(std::fs::read_to_string(dir.path().join("1-2.3/authorized")).unwrap(), "0");
        a.authorize("1-2.3").unwrap();
        assert_eq!(std::fs::read_to_string(dir.path().join("1-2.3/authorized")).unwrap(), "1");
    }

    #[test]
    fn rejects_bad_bus_ids() {
        let dir = tempdir().unwrap();
        let a = UsbAuthorizer::with_root(dir.path());
        for bad in ["", "../etc", "1-2/../..", "usb1", "1..2"] {
            assert!(a.authorize(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_symlinked_attribute() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("1-1")).unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("1-1/authorized")).unwrap();
        let a = UsbAuthorizer::with_root(dir.path());
        assert!(a.deauthorize("1-1").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }

    #[test]
    fn set_default_for_only_touches_the_named_hubs() {
        let dir = tempdir().unwrap();
        for (hub, v) in [("usb1", "1"), ("usb2", "0"), ("usb3", "1")] {
            std::fs::create_dir_all(dir.path().join(hub)).unwrap();
            std::fs::write(dir.path().join(hub).join("authorized_default"), v).unwrap();
        }
        let a = UsbAuthorizer::with_root(dir.path());
        assert_eq!(a.root_hubs().unwrap(), ["usb1", "usb2", "usb3"]);
        // usb2 already denies: it is not in the list of hubs we would change.
        assert_eq!(a.hubs_with_default_allow().unwrap(), ["usb1", "usb3"]);
        assert_eq!(a.set_default_for(&["usb1".into(), "usb9".into()], false).unwrap(), 1, "missing hub skipped");
        let read = |h: &str| std::fs::read_to_string(dir.path().join(h).join("authorized_default")).unwrap();
        assert_eq!((read("usb1").as_str(), read("usb2").as_str(), read("usb3").as_str()), ("0", "0", "1"));
        assert!(a.set_default_for(&["../etc".into()], true).is_err());
        assert!(a.set_default_for(&["usb".into()], true).is_err());
    }

    #[test]
    fn default_policy_only_touches_root_hubs() {
        let dir = tempdir().unwrap();
        for d in ["usb1", "usb2", "1-1", "usbfoo"] {
            std::fs::create_dir_all(dir.path().join(d)).unwrap();
            std::fs::write(dir.path().join(d).join("authorized_default"), "1").unwrap();
        }
        let a = UsbAuthorizer::with_root(dir.path());
        assert_eq!(a.set_default_policy(false).unwrap(), 2);
        assert_eq!(std::fs::read_to_string(dir.path().join("usb1/authorized_default")).unwrap(), "0");
        assert_eq!(std::fs::read_to_string(dir.path().join("1-1/authorized_default")).unwrap(), "1");
        assert_eq!(std::fs::read_to_string(dir.path().join("usbfoo/authorized_default")).unwrap(), "1");
    }
}
