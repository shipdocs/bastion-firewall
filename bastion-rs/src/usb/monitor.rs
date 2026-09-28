//! udev-based USB device monitor.

use std::os::unix::io::AsRawFd;

use anyhow::{Context, Result};
use log::{debug, warn};

use super::device::UsbDeviceInfo;
use super::validation::{sanitize_hex_id, sanitize_name, sanitize_serial};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbAction {
    Add,
    Remove,
}

/// Parse a hex sysfs attribute such as `bDeviceClass` ("ff").
pub(crate) fn parse_hex_u8(s: &str) -> Option<u8> {
    u8::from_str_radix(s.trim(), 16).ok()
}

fn prop(device: &udev::Device, key: &str) -> Option<String> {
    device.property_value(key).map(|v| v.to_string_lossy().into_owned())
}

fn attr(device: &udev::Device, key: &str) -> Option<String> {
    device.attribute_value(key).map(|v| v.to_string_lossy().into_owned())
}

fn interface_classes(device: &udev::Device) -> Vec<u8> {
    let mut classes = Vec::new();
    let Ok(mut en) = udev::Enumerator::new() else { return classes };
    if en.match_parent(device).is_err() || en.match_subsystem("usb").is_err() {
        return classes;
    }
    if let Ok(children) = en.scan_devices() {
        for child in children {
            if let Some(c) = attr(&child, "bInterfaceClass").as_deref().and_then(parse_hex_u8) {
                classes.push(c);
            }
        }
    }
    classes
}

/// Build a `UsbDeviceInfo` from a udev usb_device node; all strings are sanitised.
pub fn device_info(device: &udev::Device) -> Option<UsbDeviceInfo> {
    let bus_id = device.sysname().to_string_lossy().into_owned();
    // Interfaces look like "3-4:1.0"; only whole devices are handled.
    if bus_id.contains(':') {
        return None;
    }
    let vendor_id = attr(device, "idVendor").or_else(|| prop(device, "ID_VENDOR_ID"))?;
    let product_id = attr(device, "idProduct").or_else(|| prop(device, "ID_MODEL_ID"))?;
    let name = |db: &str, plain: &str, sysattr: &str, fallback: &str| {
        prop(device, db)
            .or_else(|| prop(device, plain))
            .or_else(|| attr(device, sysattr))
            .map(|v| sanitize_name(&v.replace('_', " ")))
            .unwrap_or_else(|| fallback.to_string())
    };
    Some(UsbDeviceInfo {
        vendor_id: sanitize_hex_id(&vendor_id),
        product_id: sanitize_hex_id(&product_id),
        vendor_name: name("ID_VENDOR_FROM_DATABASE", "ID_VENDOR", "manufacturer", "Unknown Vendor"),
        product_name: name("ID_MODEL_FROM_DATABASE", "ID_MODEL", "product", "Unknown Device"),
        device_class: attr(device, "bDeviceClass").as_deref().and_then(parse_hex_u8).unwrap_or(0),
        interface_classes: interface_classes(device),
        serial: attr(device, "serial")
            .or_else(|| prop(device, "ID_SERIAL_SHORT"))
            .map(|s| sanitize_serial(&s))
            .filter(|s| s != "no-serial"),
        bus_id,
        bus_num: attr(device, "busnum").and_then(|v| v.trim().parse().ok()).unwrap_or(0),
        dev_num: attr(device, "devnum").and_then(|v| v.trim().parse().ok()).unwrap_or(0),
    })
}

/// Devices already attached when the daemon starts, with whether the kernel
/// currently has them authorized (`authorized` sysfs attribute).
pub fn enumerate_existing() -> Result<Vec<(UsbDeviceInfo, bool)>> {
    let mut en = udev::Enumerator::new().context("udev enumerator")?;
    en.match_subsystem("usb")?;
    en.match_property("DEVTYPE", "usb_device")?;
    Ok(en
        .scan_devices()?
        .filter_map(|d| {
            let authorized = attr(&d, "authorized").map(|v| v.trim() != "0").unwrap_or(true);
            device_info(&d).map(|info| (info, authorized))
        })
        .collect())
}

pub struct UsbMonitor {
    socket: udev::MonitorSocket,
}

impl UsbMonitor {
    pub fn new() -> Result<Self> {
        let socket = udev::MonitorBuilder::new()?
            .match_subsystem_devtype("usb", "usb_device")?
            .listen()
            .context("udev monitor listen")?;
        Ok(Self { socket })
    }

    /// Block until at least one event is available, then drain them all.
    pub fn wait_events(&mut self) -> Vec<(UsbAction, UsbDeviceInfo)> {
        let mut pfd = libc::pollfd { fd: self.socket.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: pfd is a valid pollfd for the duration of the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                warn!("udev poll failed: {}", err);
            }
            return Vec::new();
        }
        let mut out = Vec::new();
        for event in self.socket.iter() {
            let action = match event.event_type() {
                udev::EventType::Add => UsbAction::Add,
                udev::EventType::Remove => UsbAction::Remove,
                _ => continue,
            };
            match device_info(&event) {
                Some(info) => out.push((action, info)),
                None => debug!("Ignoring udev event without usable device info"),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_attr_parsing() {
        assert_eq!(parse_hex_u8("ff\n"), Some(0xff));
        assert_eq!(parse_hex_u8("03"), Some(3));
        assert_eq!(parse_hex_u8("zz"), None);
        assert_eq!(parse_hex_u8("1ff"), None);
    }
}
