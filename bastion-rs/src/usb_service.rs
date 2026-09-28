//! Runs USB device control in the daemon: opt-in default-deny, existing-device
//! handling, udev event loop and the GUI prompt.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use log::{error, info, warn};
use parking_lot::Mutex;

use bastion_rs::protocol::UsbDevicePrompt;
use bastion_rs::usb::monitor::enumerate_existing;
use bastion_rs::usb::{
    Decision, Scope, UsbAction, UsbAuthorizer, UsbController, UsbDeviceInfo, UsbMonitor, UsbPrompter,
    UsbRuleManager, Verdict,
};

use crate::config::ConfigManager;
use crate::gui::{ask_usb, GuiState};

/// Present while this daemon has changed `authorized_default` from 1 to 0. It lists,
/// one per line, exactly the root hubs it changed (a hub that already denied is never
/// listed, so shutdown can't widen a policy the system set itself). It lives on tmpfs,
/// so it disappears on reboot, which is also when the kernel default resets.
const DEFAULT_DENY_MARKER: &str = "/var/run/bastion/usb_default_deny";

/// Serialises default-deny setup against restore-on-shutdown, and lets a shutdown that
/// arrives first stop the setup from starting.
static POLICY_LOCK: Mutex<()> = Mutex::new(());
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

struct GuiUsbPrompter {
    gui_state: Arc<Mutex<GuiState>>,
    timeout: Duration,
}

impl UsbPrompter for GuiUsbPrompter {
    fn ask(&self, device: &UsbDeviceInfo) -> Option<Decision> {
        let prompt = UsbDevicePrompt {
            vendor_id: device.vendor(),
            product_id: device.product(),
            vendor_name: device.vendor_name.clone(),
            product_name: device.product_name.clone(),
            device_class: device.device_class,
            is_high_risk: device.is_high_risk(),
            serial: device.serial.clone(),
            bus_id: device.bus_id.clone(),
        };
        let answer = ask_usb(&self.gui_state, prompt, self.timeout)?;
        let scope = match answer.scope.as_str() {
            "device" => Scope::Device,
            "model" => Scope::Model,
            "vendor" => Scope::Vendor,
            other => {
                warn!("Ignoring USB answer with unknown scope {:?}", other);
                return None;
            }
        };
        Some(Decision {
            verdict: if answer.allow { Verdict::Allow } else { Verdict::Block },
            scope,
            permanent: answer.permanent,
        })
    }
}

/// Hubs listed in the marker. A marker written by an older version just contains `1`
/// and meant "every hub".
fn read_marker(authorizer: &UsbAuthorizer, marker: &Path) -> Vec<String> {
    let content = std::fs::read_to_string(marker).unwrap_or_default();
    let hubs: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != "1")
        .map(String::from)
        .collect();
    if hubs.is_empty() && content.trim() == "1" {
        return authorizer.root_hubs().unwrap_or_default();
    }
    hubs
}

/// Undo the default-deny this daemon set, if it set one (marker present), on exactly
/// the hubs it changed. Does nothing without a marker, so a system's own USB policy is
/// left alone.
fn restore_default_policy(authorizer: &UsbAuthorizer, marker: &Path, reason: &str) {
    if !marker.exists() {
        return;
    }
    let hubs = read_marker(authorizer, marker);
    match authorizer.set_default_for(&hubs, true) {
        Ok(_) => {
            let _ = std::fs::remove_file(marker);
            info!("{}: restored USB authorized_default=1 on {} controller(s)", reason, hubs.len());
        }
        Err(e) => error!("{}: could not restore USB authorized_default: {:#}", reason, e),
    }
}

/// Switch hubs that currently allow new devices to deny them. Writes the marker first
/// (merged with any marker left by an earlier run) and rolls back if a write fails.
/// Returns how many hubs were changed.
fn enable_default_deny(authorizer: &UsbAuthorizer, marker: &Path) -> Result<usize> {
    let to_change = authorizer.hubs_with_default_allow()?;
    if to_change.is_empty() {
        return Ok(0);
    }
    let mut listed = if marker.exists() { read_marker(authorizer, marker) } else { Vec::new() };
    for hub in &to_change {
        if !listed.contains(hub) {
            listed.push(hub.clone());
        }
    }
    std::fs::write(marker, listed.join("\n") + "\n")
        .map_err(|e| anyhow::anyhow!("cannot write {}: {}", marker.display(), e))?;
    match authorizer.set_default_for(&to_change, false) {
        Ok(n) => Ok(n),
        Err(e) => {
            // Some hubs may already be changed; undo it now. The marker stays if that fails.
            if authorizer.set_default_for(&to_change, true).is_ok() && listed.len() == to_change.len() {
                let _ = std::fs::remove_file(marker);
            }
            Err(e)
        }
    }
}

/// Called on a normal stop (SIGINT/SIGTERM) so nobody is left with new USB devices
/// blocked and no daemon to approve them. A crash or SIGKILL skips this on purpose:
/// the default stays "blocked" and the next start (or disabling USB control) restores it.
pub fn restore_default_on_shutdown() {
    SHUTTING_DOWN.store(true, Ordering::SeqCst);
    let _guard = POLICY_LOCK.lock();
    restore_default_policy(&UsbAuthorizer::new(), Path::new(DEFAULT_DENY_MARKER), "Shutting down");
}

/// Thread body. Returns immediately when USB control is disabled (after undoing
/// a default-deny this daemon set on an earlier run).
pub fn run(
    config: Arc<ConfigManager>,
    gui_state: Arc<Mutex<GuiState>>,
    usb_rules: Arc<Mutex<UsbRuleManager>>,
) {
    let authorizer = UsbAuthorizer::new();

    if !config.is_usb_control_enabled() {
        let _guard = POLICY_LOCK.lock();
        restore_default_policy(&authorizer, Path::new(DEFAULT_DENY_MARKER), "USB control disabled");
        return;
    }

    // Subscribe before enumerating so nothing attached in between is missed.
    let mut monitor = match UsbMonitor::new() {
        Ok(m) => m,
        Err(e) => {
            error!("USB control disabled: cannot start udev monitor: {:#}", e);
            return;
        }
    };

    {
        // Holding the lock means a shutdown either finishes first (and we don't start) or
        // waits until the marker and the new defaults are both in place, then undoes them.
        let _guard = POLICY_LOCK.lock();
        if SHUTTING_DOWN.load(Ordering::SeqCst) {
            return;
        }
        match enable_default_deny(&authorizer, Path::new(DEFAULT_DENY_MARKER)) {
            Ok(n) if n > 0 => {
                info!("USB control: new devices are blocked until approved ({} controller(s))", n);
            }
            Ok(_) => warn!("USB control: no controller needed changing (already denying, or none found)"),
            Err(e) => {
                error!("USB control disabled: cannot set default-deny: {:#}", e);
                return;
            }
        }
    }

    let prompter = GuiUsbPrompter {
        gui_state,
        timeout: Duration::from_secs(config.usb_prompt_timeout_secs()),
    };
    let mut controller = UsbController::new(usb_rules, authorizer, prompter);

    match enumerate_existing() {
        Ok(devices) => {
            for (device, authorized) in devices {
                if authorized {
                    controller.handle_existing(&device);
                } else {
                    // Left unauthorized by a previous default-deny (e.g. plugged in while the daemon was down).
                    controller.handle_add(&device);
                }
            }
        }
        Err(e) => warn!("Could not enumerate existing USB devices: {:#}", e),
    }

    info!("USB control active");
    loop {
        for (action, device) in monitor.wait_events() {
            match action {
                UsbAction::Add => controller.handle_add(&device),
                UsbAction::Remove => controller.handle_remove(&device),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Fake sysfs with the given (hub, authorized_default) pairs.
    fn setup(hubs: &[(&str, &str)]) -> (tempfile::TempDir, UsbAuthorizer) {
        let dir = tempdir().unwrap();
        for (hub, v) in hubs {
            std::fs::create_dir_all(dir.path().join("sys").join(hub)).unwrap();
            std::fs::write(dir.path().join("sys").join(hub).join("authorized_default"), v).unwrap();
        }
        let authorizer = UsbAuthorizer::with_root(dir.path().join("sys"));
        (dir, authorizer)
    }

    fn value(dir: &tempfile::TempDir, hub: &str) -> String {
        std::fs::read_to_string(dir.path().join("sys").join(hub).join("authorized_default")).unwrap()
    }

    #[test]
    fn enable_then_restore_round_trips() {
        let (dir, a) = setup(&[("usb1", "1"), ("usb2", "1")]);
        let marker = dir.path().join("marker");
        assert_eq!(enable_default_deny(&a, &marker).unwrap(), 2);
        assert_eq!((value(&dir, "usb1").as_str(), value(&dir, "usb2").as_str()), ("0", "0"));
        restore_default_policy(&a, &marker, "test");
        assert_eq!((value(&dir, "usb1").as_str(), value(&dir, "usb2").as_str()), ("1", "1"));
        assert!(!marker.exists());
    }

    #[test]
    fn a_hub_that_already_denied_is_never_widened() {
        // usb2 was set to 0 by the system itself before we started.
        let (dir, a) = setup(&[("usb1", "1"), ("usb2", "0")]);
        let marker = dir.path().join("marker");
        assert_eq!(enable_default_deny(&a, &marker).unwrap(), 1);
        assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "usb1");
        restore_default_policy(&a, &marker, "test");
        assert_eq!(value(&dir, "usb1"), "1");
        assert_eq!(value(&dir, "usb2"), "0", "the system's own policy must survive shutdown");
    }

    #[test]
    fn nothing_to_change_writes_no_marker() {
        let (dir, a) = setup(&[("usb1", "0")]);
        let marker = dir.path().join("marker");
        assert_eq!(enable_default_deny(&a, &marker).unwrap(), 0);
        assert!(!marker.exists());
    }

    #[test]
    fn restart_after_a_crash_keeps_the_earlier_marker_entries() {
        let (dir, a) = setup(&[("usb1", "1"), ("usb2", "1")]);
        let marker = dir.path().join("marker");
        enable_default_deny(&a, &marker).unwrap();
        // Crash, then a new controller appears (usb3, allowing) before the next start.
        std::fs::create_dir_all(dir.path().join("sys/usb3")).unwrap();
        std::fs::write(dir.path().join("sys/usb3/authorized_default"), "1").unwrap();
        assert_eq!(enable_default_deny(&a, &marker).unwrap(), 1);
        restore_default_policy(&a, &marker, "test");
        for hub in ["usb1", "usb2", "usb3"] {
            assert_eq!(value(&dir, hub), "1", "{hub}");
        }
    }

    #[test]
    fn legacy_marker_restores_every_hub() {
        let (dir, a) = setup(&[("usb1", "0"), ("usb2", "0")]);
        let marker = dir.path().join("marker");
        std::fs::write(&marker, b"1").unwrap();
        restore_default_policy(&a, &marker, "test");
        assert_eq!((value(&dir, "usb1").as_str(), value(&dir, "usb2").as_str()), ("1", "1"));
    }

    #[test]
    fn no_marker_means_no_change() {
        let (dir, a) = setup(&[("usb1", "0")]);
        restore_default_policy(&a, &dir.path().join("no-marker"), "test");
        assert_eq!(value(&dir, "usb1"), "0");
    }

    #[test]
    fn marker_stays_when_restore_fails() {
        let dir = tempdir().unwrap();
        let a = UsbAuthorizer::with_root(dir.path().join("missing"));
        let marker = dir.path().join("marker");
        // A hub name that isn't valid makes set_default_for fail; the marker must survive.
        std::fs::write(&marker, b"../evil\n").unwrap();
        restore_default_policy(&a, &marker, "test");
        assert!(marker.exists(), "marker must stay so a later start retries");
    }
}
