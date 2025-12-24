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
        """
        Compute a unique identifier for this exact USB device, including its serial when available.
        
        Returns:
            A string formatted as "vendor_id:product_id:serial" where `serial` is the device serial number or `"no-serial"` if no serial is present.
        """
        serial_part = self.serial if self.serial else "no-serial"
        return f"{self.vendor_id}:{self.product_id}:{serial_part}"
    
    @property
    def model_id(self) -> str:
        """
        Model identifier composed of the vendor and product IDs, ignoring the device serial.
        
        Returns:
            model_id (str): Vendor and product IDs joined by ':' (e.g., "046d:c52b").
        """
        return f"{self.vendor_id}:{self.product_id}"
    
    @property
    def is_hid(self) -> bool:
        """
        Determine whether the device is classified as a Human Interface Device.
        
        Considers both the device-level class and any interface-level classes.
        
        Returns:
            `true` if the device is a HID, `false` otherwise.
        """
        if self.device_class == USBClass.HID:
            return True
        return USBClass.HID in self.interface_classes
    
    @property
    def is_storage(self) -> bool:
        """
        Determine whether the device is a USB mass storage device.
        
        Checks the device class and any interface classes for the mass storage class code.
        
        Returns:
            `true` if the device is mass storage, `false` otherwise.
        """
        if self.device_class == USBClass.MASS_STORAGE:
            return True
        return USBClass.MASS_STORAGE in self.interface_classes
    
    @property
    def is_hub(self) -> bool:
        """
        Determine whether the device's primary USB class identifies it as a USB hub.
        
        Returns:
            `true` if the device class equals the USB hub class, `false` otherwise.
        """
        return self.device_class == USBClass.HUB
    
    @property
    def is_wireless(self) -> bool:
        """
        Indicates whether the device is a wireless controller (for example, Bluetooth or Wi‑Fi).
        
        @returns:
            `true` if the device's class or any interface class is `USBClass.WIRELESS`, `false` otherwise.
        """
        if self.device_class == USBClass.WIRELESS:
            return True
        return USBClass.WIRELESS in self.interface_classes
    
    @property
    def is_high_risk(self) -> bool:
        """
        Determine whether the device belongs to a high-risk USB class.
        
        Returns:
            `true` if the device's primary class or any interface class is a member of HIGH_RISK_CLASSES (e.g., HID or wireless), `false` otherwise.
        """
        if self.device_class in HIGH_RISK_CLASSES:
            return True
        return bool(set(self.interface_classes) & HIGH_RISK_CLASSES)
    
    @property
    def is_low_risk(self) -> bool:
        """
        Determine whether the device belongs to a low-risk USB class such as hub, audio, video, or printer.
        
        @returns `true` if the device_class or any interface class is in the low-risk set, `false` otherwise.
        """
        if self.device_class in LOW_RISK_CLASSES:
            return True
        # Also check interface classes for consistency with is_high_risk
        return bool(set(self.interface_classes) & LOW_RISK_CLASSES)
    
    @property
    def class_name(self) -> str:
        """
        Provide a human-readable category name for the device's USB class.
        
        Returns:
            str: A human-readable class name such as "HID (Keyboard/Mouse)", "Mass Storage",
                 "USB Hub", "Wireless Controller", or "USB Device (Class XX)" where XX is the
                 two-digit hex class code.
        """
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
        """
        Short human-readable description of the USB device.
        
        Returns:
            str: Combined vendor name, product name, and class name in brackets (e.g. "Logitech Unifying Receiver [HID (Keyboard/Mouse)]").
        """
        return f"{self.vendor_name} {self.product_name} [{self.class_name}]"
    
    def __repr__(self) -> str:
        """
        Provide a concise, unambiguous representation of the USBDeviceInfo for debugging.
        
        Returns:
            A string containing vendor_id:product_id, product name, class name, and bus_id.
        """
        return (f"USBDeviceInfo(vendor={self.vendor_id}:{self.product_id}, "
                f"name='{self.product_name}', class={self.class_name}, "
                f"bus_id={self.bus_id})")
