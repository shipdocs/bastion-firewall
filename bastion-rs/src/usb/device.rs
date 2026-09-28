//! USB device identity and risk classification.

use super::validation::sanitize_hex_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbClass {
    PerInterface,
    Audio,
    CdcComm,
    Hid,
    Physical,
    Image,
    Printer,
    MassStorage,
    Hub,
    CdcData,
    SmartCard,
    Video,
    AudioVideo,
    Billboard,
    UsbCBridge,
    Wireless,
    Misc,
    Application,
    VendorSpec,
    Unknown(u8),
}

impl From<u8> for UsbClass {
    fn from(code: u8) -> Self {
        match code {
            0x00 => Self::PerInterface,
            0x01 => Self::Audio,
            0x02 => Self::CdcComm,
            0x03 => Self::Hid,
            0x05 => Self::Physical,
            0x06 => Self::Image,
            0x07 => Self::Printer,
            0x08 => Self::MassStorage,
            0x09 => Self::Hub,
            0x0A => Self::CdcData,
            0x0B => Self::SmartCard,
            0x0E => Self::Video,
            0x10 => Self::AudioVideo,
            0x11 => Self::Billboard,
            0x12 => Self::UsbCBridge,
            0xE0 => Self::Wireless,
            0xEF => Self::Misc,
            0xFE => Self::Application,
            0xFF => Self::VendorSpec,
            other => Self::Unknown(other),
        }
    }
}

impl UsbClass {
    /// Classes that can inject input or create network interfaces (BadUSB vectors);
    /// CDC comm/data cover USB ethernet and modem adapters.
    pub fn is_high_risk(self) -> bool {
        matches!(self, Self::Hid | Self::Wireless | Self::CdcComm | Self::CdcData)
    }

    pub fn is_low_risk(self) -> bool {
        matches!(self, Self::Hub | Self::Audio | Self::Video | Self::Printer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceInfo {
    pub vendor_id: String,
    pub product_id: String,
    pub vendor_name: String,
    pub product_name: String,
    pub device_class: u8,
    pub interface_classes: Vec<u8>,
    pub serial: Option<String>,
    pub bus_id: String,
    pub bus_num: u32,
    pub dev_num: u32,
}

impl UsbDeviceInfo {
    /// Normalise the ids so lookups and keys are always canonical.
    pub fn vendor(&self) -> String {
        sanitize_hex_id(&self.vendor_id)
    }

    pub fn product(&self) -> String {
        sanitize_hex_id(&self.product_id)
    }

    /// Identifier for this exact device (includes serial).
    pub fn unique_id(&self) -> String {
        format!("{}:{}:{}", self.vendor(), self.product(), self.serial.as_deref().unwrap_or("no-serial"))
    }

    /// Identifier for this model (ignores serial).
    pub fn model_id(&self) -> String {
        format!("{}:{}", self.vendor(), self.product())
    }

    pub fn is_high_risk(&self) -> bool {
        UsbClass::from(self.device_class).is_high_risk()
            || self.interface_classes.iter().any(|c| UsbClass::from(*c).is_high_risk())
    }
}

#[cfg(test)]
pub(crate) fn test_device(class: u8, serial: Option<&str>) -> UsbDeviceInfo {
    UsbDeviceInfo {
        vendor_id: "046d".into(),
        product_id: "c52b".into(),
        vendor_name: "Logitech, Inc.".into(),
        product_name: "Unifying Receiver".into(),
        device_class: class,
        interface_classes: vec![],
        serial: serial.map(String::from),
        bus_id: "1-2.3".into(),
        bus_num: 1,
        dev_num: 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_risk() {
        assert!(UsbClass::from(0x03).is_high_risk());
        assert!(UsbClass::from(0xE0).is_high_risk());
        assert!(UsbClass::from(0x02).is_high_risk());
        assert!(UsbClass::from(0x0A).is_high_risk());
        assert!(!UsbClass::from(0x08).is_high_risk());
        assert!(UsbClass::from(0x09).is_low_risk());
        assert_eq!(UsbClass::from(0x42), UsbClass::Unknown(0x42));
    }

    #[test]
    fn device_ids() {
        let d = test_device(0, Some("ABC123"));
        assert_eq!(d.unique_id(), "046d:c52b:ABC123");
        assert_eq!(d.model_id(), "046d:c52b");
        assert_eq!(test_device(0, None).unique_id(), "046d:c52b:no-serial");
    }

    #[test]
    fn high_risk_via_interface() {
        let mut d = test_device(0x00, None);
        assert!(!d.is_high_risk());
        d.interface_classes = vec![0x08, 0x03];
        assert!(d.is_high_risk());
        assert!(test_device(0x03, None).is_high_risk());
    }
}
