"""
USB Device Monitor

Monitors USB device insertion/removal events using pyudev.
Notifies callbacks when new devices are connected.
"""

import logging
import threading
from typing import Callable, Optional

try:
    import pyudev
    PYUDEV_AVAILABLE = True
except ImportError:
    PYUDEV_AVAILABLE = False
    pyudev = None

from bastion.usb_device import USBDeviceInfo, USBClass
from bastion.usb_validation import USBValidation

logger = logging.getLogger(__name__)


class USBMonitor:
    """
    Monitor USB device events using pyudev.
    
    Usage:
        def on_device(device: USBDeviceInfo, action: str):
            print(f"{action}: {device}")
        
        monitor = USBMonitor(on_device)
        monitor.start()
        # ... later ...
        monitor.stop()
    """
    
    def __init__(self, callback: Callable[[USBDeviceInfo, str], None]):
        """
        Create a USB monitor that invokes a callback for device connect and disconnect events.
        
        Parameters:
            callback (Callable[[USBDeviceInfo, str], None]): Function called with a USBDeviceInfo and an action string; action will be 'add' when a device is connected and 'remove' when a device is disconnected.
        """
        self.callback = callback
        self._observer: Optional['pyudev.MonitorObserver'] = None
        self._running = False
        
        if not PYUDEV_AVAILABLE:
            logger.error("pyudev not available - USB monitoring disabled")
    
    def start(self) -> bool:
        """
        Start monitoring USB events.
        
        Returns:
            True if monitoring started successfully, False otherwise.
        """
        if not PYUDEV_AVAILABLE:
            logger.error("Cannot start USB monitor: pyudev not installed")
            return False
        
        if self._running:
            logger.warning("USB monitor already running")
            return True
        
        try:
            context = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(context)
            # Only filter by subsystem - device_type filter is too restrictive
            monitor.filter_by(subsystem='usb')

            self._observer = pyudev.MonitorObserver(
                monitor,
                callback=self._handle_event,
                name='bastion-usb-monitor'
            )
            self._observer.daemon = True
            self._observer.start()
            self._running = True

            logger.info("USB monitor started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start USB monitor: {e}")
            return False
    
    def stop(self):
        """
        Stop the USB monitor and terminate its background observer.
        
        Stops the internal pyudev MonitorObserver if present, clears the observer reference, and sets the monitor's running state to False.
        """
        if self._observer:
            self._observer.stop()
            self._observer = None
        self._running = False
        logger.info("USB monitor stopped")
    
    @property
    def is_running(self) -> bool:
        """
        Indicates whether the monitor is currently running.
        
        Returns:
            True if the monitor is running, False otherwise.
        """
        return self._running
    
    def _handle_event(self, device: 'pyudev.Device'):
        """
        Process a pyudev device event and, when relevant, notify the monitor callback.
        
        Only handles 'add' and 'remove' actions and ignores USB interface entries (sys_name containing ':').
        If the event corresponds to a device, extracts a USBDeviceInfo and invokes the monitor's callback
        with the device info and the action string.
        
        Parameters:
            device (pyudev.Device): The udev device event provided by pyudev.
        """
        action = device.action

        # Only handle add/remove for now
        if action not in ('add', 'remove'):
            return

        # Skip USB interfaces (e.g., "3-4:1.0") - only handle devices (e.g., "3-4")
        if ':' in device.sys_name:
            return

        try:
            device_info = self._extract_device_info(device)
            if device_info:
                logger.info(f"USB {action}: {device_info.product_name} ({device_info.vendor_id}:{device_info.product_id})")
                self.callback(device_info, action)
        except Exception as e:
            logger.error(f"Error processing USB event: {e}")
    
    def _extract_device_info(self, device: 'pyudev.Device') -> Optional[USBDeviceInfo]:
        """
        Builds a USBDeviceInfo from a pyudev Device when the device represents a USB device.
        
        Extracted fields include vendor/product IDs (hex, sanitized), vendor and product names (underscores replaced and sanitized), device class (parsed from database field or bDeviceClass), optionally sanitized serial, sysfs bus id, and numeric bus/dev numbers (parsed with defaults of 0). If vendor or product IDs are missing, or if an error occurs during extraction, this returns None.
        
        Returns:
            USBDeviceInfo: Populated and sanitized USBDeviceInfo for the device, or `None` if the device is not a USB device or extraction fails.
        """
        try:
            # Get vendor/product IDs
            vendor_id = device.get('ID_VENDOR_ID', '') or ''
            product_id = device.get('ID_MODEL_ID', '') or ''
            
            if not vendor_id or not product_id:
                # Not a real USB device (might be a hub port)
                return None
            
            # Get human-readable names
            vendor_name = device.get('ID_VENDOR_FROM_DATABASE', '') or \
                         device.get('ID_VENDOR', '') or 'Unknown Vendor'
            product_name = device.get('ID_MODEL_FROM_DATABASE', '') or \
                          device.get('ID_MODEL', '') or 'Unknown Device'
            
            # Clean up underscores in names
            vendor_name = vendor_name.replace('_', ' ')
            product_name = product_name.replace('_', ' ')
            
            # Get device class
            device_class_str = device.get('ID_USB_CLASS_FROM_DATABASE', '') or \
                              device.attributes.get('bDeviceClass', b'00').decode('utf-8', errors='ignore')
            try:
                device_class = int(device_class_str, 16) if device_class_str else 0
            except ValueError:
                device_class = 0
            
            # Get serial number and sanitize it (USB serials can contain malicious data)
            raw_serial = device.get('ID_SERIAL_SHORT', None)
            serial = USBValidation.sanitize_serial(raw_serial) if raw_serial else None

            # Get bus ID (sysfs name like "1-2.3")
            bus_id = device.sys_name

            # Get bus/device numbers
            try:
                bus_num = int(device.get('BUSNUM', 0))
                dev_num = int(device.get('DEVNUM', 0))
            except ValueError:
                bus_num = dev_num = 0

            # Sanitize vendor/product IDs
            return USBDeviceInfo(
                vendor_id=USBValidation.sanitize_hex_id(vendor_id),
                product_id=USBValidation.sanitize_hex_id(product_id),
                vendor_name=USBValidation.sanitize_string(vendor_name),
                product_name=USBValidation.sanitize_string(product_name),
                device_class=device_class,
                serial=serial,
                bus_id=bus_id,
                bus_num=bus_num,
                dev_num=dev_num
            )
            
        except Exception as e:
            logger.warning(f"Failed to extract USB device info: {e}")
            return None

    def get_connected_devices(self) -> list[USBDeviceInfo]:
        """
        Return information for all currently connected USB devices.
        
        Returns:
            list[USBDeviceInfo]: USBDeviceInfo objects for each connected USB device. Returns an empty list if pyudev is unavailable or no devices are found.
        """
        if not PYUDEV_AVAILABLE:
            return []

        devices = []
        try:
            context = pyudev.Context()
            for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
                info = self._extract_device_info(device)
                if info:
                    devices.append(info)
        except Exception as e:
            logger.error(f"Failed to enumerate USB devices: {e}")

        return devices


def list_usb_devices() -> list[USBDeviceInfo]:
    """
    Return a list of currently connected USB devices.
    
    Returns:
        list[USBDeviceInfo]: USBDeviceInfo objects for each connected USB device.
    """
    monitor = USBMonitor(callback=lambda d, a: None)
    return monitor.get_connected_devices()


def is_pyudev_available() -> bool:
    """
    Report whether the pyudev library is available for USB monitoring.
    
    Returns:
        bool: `True` if pyudev is available, `False` otherwise.
    """
    return PYUDEV_AVAILABLE
