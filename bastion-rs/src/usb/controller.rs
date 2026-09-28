//! Policy engine: decides what to do when a USB device appears.
//!
//! Devices present at daemon start are never deauthorized unless an explicit
//! block rule matches (so a connected keyboard is not cut off). New devices
//! without a rule are shown to the user; no answer means blocked.

use std::collections::HashSet;

use log::{info, warn};

use super::authorizer::UsbAuthorizer;
use super::device::UsbDeviceInfo;
use super::rules::{Scope, UsbRuleManager, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    pub scope: Scope,
    pub permanent: bool,
}

/// Asks the user about an unknown device. Returns `None` on timeout / no GUI.
pub trait UsbPrompter {
    fn ask(&self, device: &UsbDeviceInfo) -> Option<Decision>;
}

pub struct UsbController<P: UsbPrompter> {
    pub rules: UsbRuleManager,
    authorizer: UsbAuthorizer,
    prompter: P,
    /// `bus_id|unique_id` of devices allowed for this session only ("allow once").
    session_allowed: HashSet<String>,
}

impl<P: UsbPrompter> UsbController<P> {
    pub fn new(rules: UsbRuleManager, authorizer: UsbAuthorizer, prompter: P) -> Self {
        Self { rules, authorizer, prompter, session_allowed: HashSet::new() }
    }

    fn session_key(device: &UsbDeviceInfo) -> String {
        format!("{}|{}", device.bus_id, device.unique_id())
    }

    fn apply(&self, device: &UsbDeviceInfo, verdict: Verdict) {
        let result = match verdict {
            Verdict::Allow => self.authorizer.authorize(&device.bus_id),
            Verdict::Block => self.authorizer.deauthorize(&device.bus_id),
        };
        if let Err(e) = result {
            warn!("Could not apply {:?} to USB device {}: {:#}", verdict, device.bus_id, e);
        }
    }

    /// A device that was already connected when the daemon started.
    pub fn handle_existing(&mut self, device: &UsbDeviceInfo) {
        if let Some(rule) = self.rules.lookup(device) {
            if rule.verdict == Verdict::Block {
                info!("Blocking connected USB device {} per rule", device.bus_id);
                self.apply(device, Verdict::Block);
            }
        }
    }

    /// A newly attached device.
    pub fn handle_add(&mut self, device: &UsbDeviceInfo) {
        if let Some(rule) = self.rules.lookup(device) {
            let verdict = rule.verdict;
            info!("USB {} ({}): rule verdict {:?}", device.bus_id, device.model_id(), verdict);
            self.apply(device, verdict);
            return;
        }

        if self.session_allowed.contains(&Self::session_key(device)) {
            info!("USB {} ({}): allowed earlier this session", device.bus_id, device.model_id());
            self.apply(device, Verdict::Allow);
            return;
        }

        let Some(decision) = self.prompter.ask(device) else {
            info!("USB {} ({}): no answer, blocking", device.bus_id, device.model_id());
            self.apply(device, Verdict::Block);
            return;
        };

        if decision.permanent {
            if let Err(e) = self.rules.add_rule(device, decision.verdict, decision.scope) {
                // Never silently widen the scope (e.g. device -> model) on failure.
                warn!("Could not store USB rule ({:#}); decision applies to this session only", e);
            }
        } else if decision.verdict == Verdict::Allow {
            self.session_allowed.insert(Self::session_key(device));
        }
        self.apply(device, decision.verdict);
    }

    pub fn handle_remove(&mut self, device: &UsbDeviceInfo) {
        self.session_allowed.remove(&Self::session_key(device));
    }

    pub fn is_session_allowed(&self, device: &UsbDeviceInfo) -> bool {
        self.session_allowed.contains(&Self::session_key(device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::device::test_device;
    use std::cell::RefCell;
    use tempfile::{tempdir, TempDir};

    struct Mock {
        answer: Option<Decision>,
        asked: RefCell<u32>,
    }

    impl UsbPrompter for Mock {
        fn ask(&self, _: &UsbDeviceInfo) -> Option<Decision> {
            *self.asked.borrow_mut() += 1;
            self.answer
        }
    }

    fn setup(answer: Option<Decision>) -> (UsbController<Mock>, TempDir) {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sys/1-2.3")).unwrap();
        std::fs::write(dir.path().join("sys/1-2.3/authorized"), "?").unwrap();
        let c = UsbController::new(
            UsbRuleManager::with_path(dir.path().join("usb_rules.json")),
            UsbAuthorizer::with_root(dir.path().join("sys")),
            Mock { answer, asked: RefCell::new(0) },
        );
        (c, dir)
    }

    fn auth(dir: &TempDir) -> String {
        std::fs::read_to_string(dir.path().join("sys/1-2.3/authorized")).unwrap()
    }

    #[test]
    fn known_allow_rule_authorizes_without_prompt() {
        let (mut c, dir) = setup(None);
        let dev = test_device(0x08, Some("S"));
        c.rules.add_rule(&dev, Verdict::Allow, Scope::Model).unwrap();
        c.handle_add(&dev);
        assert_eq!(auth(&dir), "1");
        assert_eq!(*c.prompter.asked.borrow(), 0);
    }

    #[test]
    fn known_block_rule_deauthorizes() {
        let (mut c, dir) = setup(None);
        let dev = test_device(0x03, Some("S"));
        c.rules.add_rule(&dev, Verdict::Block, Scope::Vendor).unwrap();
        c.handle_add(&dev);
        assert_eq!(auth(&dir), "0");
    }

    #[test]
    fn unknown_device_without_answer_is_blocked() {
        let (mut c, dir) = setup(None);
        c.handle_add(&test_device(0x03, Some("S")));
        assert_eq!(auth(&dir), "0");
        assert_eq!(*c.prompter.asked.borrow(), 1);
    }

    #[test]
    fn permanent_allow_is_stored_and_not_asked_again() {
        let d = Decision { verdict: Verdict::Allow, scope: Scope::Device, permanent: true };
        let (mut c, dir) = setup(Some(d));
        let dev = test_device(0x08, Some("S"));
        c.handle_add(&dev);
        assert_eq!(auth(&dir), "1");
        c.handle_add(&dev);
        assert_eq!(*c.prompter.asked.borrow(), 1);
        assert!(UsbRuleManager::with_path(dir.path().join("usb_rules.json")).lookup(&dev).is_some());
    }

    #[test]
    fn allow_once_is_not_persisted() {
        let d = Decision { verdict: Verdict::Allow, scope: Scope::Model, permanent: false };
        let (mut c, dir) = setup(Some(d));
        let dev = test_device(0x08, Some("S"));
        c.handle_add(&dev);
        assert_eq!(auth(&dir), "1");
        assert!(c.is_session_allowed(&dev));
        assert!(c.rules.lookup(&dev).is_none());
        // A repeated add event for the same device is not prompted again.
        c.handle_add(&dev);
        assert_eq!(*c.prompter.asked.borrow(), 1);
        assert_eq!(auth(&dir), "1");
        c.handle_remove(&dev);
        assert!(!c.is_session_allowed(&dev));
    }

    #[test]
    fn permanent_device_scope_without_serial_is_session_only() {
        let d = Decision { verdict: Verdict::Allow, scope: Scope::Device, permanent: true };
        let (mut c, dir) = setup(Some(d));
        let dev = test_device(0x08, None);
        c.handle_add(&dev);
        assert_eq!(auth(&dir), "1");
        assert!(c.rules.rules().is_empty());
    }

    #[test]
    fn existing_devices_are_left_alone_unless_blocked() {
        let (mut c, dir) = setup(None);
        let dev = test_device(0x03, Some("S"));
        c.handle_existing(&dev);
        assert_eq!(auth(&dir), "?");
        assert_eq!(*c.prompter.asked.borrow(), 0);
        c.rules.add_rule(&dev, Verdict::Block, Scope::Model).unwrap();
        c.handle_existing(&dev);
        assert_eq!(auth(&dir), "0");
    }
}
