"""
USB Device Information

Represents USB device metadata extracted from udev events.
Used for identifying and classifying USB devices.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum


class USBClass(IntEnum):
    """USB Device Class codes (bDeviceClass / bInterfaceClass)"""
    PER_INTERFACE = 0x00  # Class defined at interface level
    AUDIO = 0x01
    CDC_COMM = 0x02       # Communications
    HID = 0x03            # Human Interface Device (keyboard, mouse)
    PHYSICAL = 0x05
    IMAGE = 0x06          # Still image capture
    PRINTER = 0x07
    MASS_STORAGE = 0x08   # USB drives
    HUB = 0x09
    CDC_DATA = 0x0A
    SMART_CARD = 0x0B
    VIDEO = 0x0E
    AUDIO_VIDEO = 0x10
    BILLBOARD = 0x11
    USB_C_BRIDGE = 0x12
    WIRELESS = 0xE0       # Bluetooth, WiFi adapters
    MISC = 0xEF
    APPLICATION = 0xFE
    VENDOR_SPEC = 0xFF


# Device classes that pose higher security risk
HIGH_RISK_CLASSES = {
    USBClass.HID,          # Can type commands
    USBClass.WIRELESS,     # Can create network interfaces
}

# Device classes that are generally safe
LOW_RISK_CLASSES = {
    USBClass.HUB,          # Just provides more ports
    USBClass.AUDIO,        # Speakers, microphones
    USBClass.VIDEO,        # Webcams
    USBClass.PRINTER,      # Printers
}


@dataclass
class USBDeviceInfo:
    """
    Information about a USB device.
    
    Extracted from udev device properties.
    """
    # Core identification
    vendor_id: str          # e.g., "046d" (Logitech)
    product_id: str         # e.g., "c52b"
    vendor_name: str        # e.g., "Logitech, Inc."
    product_name: str       # e.g., "Unifying Receiver"
    
    # Classification
    device_class: int       # USB class code (e.g., 0x03 for HID)
    interface_classes: list[int] = field(default_factory=list)  # Classes at interface level
    
    # Unique identification
    serial: Optional[str] = None   # Unique serial number (if available)
    bus_id: str = ""               # e.g., "1-2.3" (sysfs path component)
    
    # Computed at creation
    bus_num: int = 0               # USB bus number
    dev_num: int = 0               # Device number on bus
    
    @property
    def unique_id(self) -> str:
        """Unique identifier for this exact device (includes serial)"""
        serial_part = self.serial if self.serial else "no-serial"
        return f"{self.vendor_id}:{self.product_id}:{serial_part}"
    
    @property
    def model_id(self) -> str:
        """Identifier for this model (ignores serial, matches all of this type)"""
        return f"{self.vendor_id}:{self.product_id}"
    
    @property
    def is_hid(self) -> bool:
        """True if device claims to be a Human Interface Device"""
        if self.device_class == USBClass.HID:
            return True
        return USBClass.HID in self.interface_classes
    
    @property
    def is_storage(self) -> bool:
        """True if device is mass storage (USB drive)"""
        if self.device_class == USBClass.MASS_STORAGE:
            return True
        return USBClass.MASS_STORAGE in self.interface_classes
    
    @property
    def is_hub(self) -> bool:
        """True if device is a USB hub"""
        return self.device_class == USBClass.HUB
    
    @property
    def is_wireless(self) -> bool:
        """True if device is wireless controller (Bluetooth, WiFi)"""
        if self.device_class == USBClass.WIRELESS:
            return True
        return USBClass.WIRELESS in self.interface_classes
    
    @property
    def is_high_risk(self) -> bool:
        """True if device is in a high-risk category (HID, wireless)"""
        if self.device_class in HIGH_RISK_CLASSES:
            return True
        return bool(set(self.interface_classes) & HIGH_RISK_CLASSES)
    
    @property
    def is_low_risk(self) -> bool:
        """True if device is in a low-risk category (hub, audio, video) and NOT high-risk"""
        # A device cannot be both high-risk and low-risk - high-risk takes precedence
        if self.is_high_risk:
            return False
        if self.device_class in LOW_RISK_CLASSES:
            return True
        # Also check interface classes for consistency with is_high_risk
        return bool(set(self.interface_classes) & LOW_RISK_CLASSES)
    
    @property
    def class_name(self) -> str:
        """Human-readable device class name"""
        if self.is_hid:
            return "HID (Keyboard/Mouse)"
        elif self.is_storage:
            return "Mass Storage"
        elif self.is_hub:
            return "USB Hub"
        elif self.is_wireless:
            return "Wireless Controller"
        elif self.device_class == USBClass.AUDIO:
            return "Audio Device"
        elif self.device_class == USBClass.VIDEO:
            return "Video Device"
        elif self.device_class == USBClass.PRINTER:
            return "Printer"
        else:
            return f"USB Device (Class {self.device_class:02x})"
    
    def __str__(self) -> str:
        return f"{self.vendor_name} {self.product_name} [{self.class_name}]"
    
    def __repr__(self) -> str:
        return (f"USBDeviceInfo(vendor={self.vendor_id}:{self.product_id}, "
                f"name='{self.product_name}', class={self.class_name}, "
                f"bus_id={self.bus_id})")

