//! Runs USB device control in the daemon: opt-in default-deny, existing-device
//! handling, udev event loop and the GUI prompt.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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

/// Present while this daemon has set `authorized_default=0`; lives on tmpfs so it
/// disappears on reboot, which is also when the kernel default resets.
const DEFAULT_DENY_MARKER: &str = "/var/run/bastion/usb_default_deny";

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

/// Thread body. Returns immediately when USB control is disabled (after undoing
/// a default-deny this daemon set on an earlier run).
pub fn run(
    config: Arc<ConfigManager>,
    gui_state: Arc<Mutex<GuiState>>,
    usb_rules: Arc<Mutex<UsbRuleManager>>,
) {
    let authorizer = UsbAuthorizer::new();

    if !config.is_usb_control_enabled() {
        if Path::new(DEFAULT_DENY_MARKER).exists() {
            match authorizer.set_default_policy(true) {
                Ok(_) => {
                    let _ = std::fs::remove_file(DEFAULT_DENY_MARKER);
                    info!("USB control disabled: restored authorized_default=1");
                }
                Err(e) => error!("Could not restore USB authorized_default: {:#}", e),
            }
        }
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

    // Record the marker *before* changing anything: it means "this daemon may have
    // set authorized_default=0", so a later disabled start can always undo it.
    if let Err(e) = std::fs::write(DEFAULT_DENY_MARKER, b"1") {
        error!("USB control disabled: cannot write {}: {}", DEFAULT_DENY_MARKER, e);
        return;
    }
    match authorizer.set_default_policy(false) {
        Ok(n) if n > 0 => {
            info!("USB control: new devices are blocked until approved ({} controller(s))", n);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(DEFAULT_DENY_MARKER);
            warn!("USB control: no USB controllers found to set default-deny on");
        }
        Err(e) => {
            error!("USB control disabled: cannot set default-deny: {:#}", e);
            // The change may have applied to some controllers; roll it back now.
            match authorizer.set_default_policy(true) {
                Ok(_) => {
                    let _ = std::fs::remove_file(DEFAULT_DENY_MARKER);
                }
                Err(e) => error!("Could not roll back USB default-deny; will retry on next start: {:#}", e),
            }
            return;
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
