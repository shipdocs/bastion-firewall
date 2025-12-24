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
        Initialize USB monitor.
        
        Args:
            callback: Function called with (USBDeviceInfo, action) where
                     action is 'add', 'remove', 'bind', or 'unbind'
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
        """Stop monitoring USB events."""
        if self._observer:
            self._observer.stop()
            self._observer = None
        self._running = False
        logger.info("USB monitor stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self._running
    
    def _handle_event(self, device: 'pyudev.Device'):
        """Handle udev event for USB device."""
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
        """Extract USBDeviceInfo from pyudev device."""
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
            
            # Get device class (prefer numeric bDeviceClass attribute)
            # Note: ID_USB_CLASS_FROM_DATABASE contains text like "Hub" not hex codes
            device_class = 0
            bclass = device.attributes.get('bDeviceClass')
            if bclass:
                try:
                    device_class = int(bclass.decode('utf-8', errors='ignore'), 16)
                except (ValueError, TypeError):
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

            # Extract interface classes (for devices with class defined at interface level)
            interface_classes = []
            if device_class == 0:  # PER_INTERFACE - class defined at interface level
                try:
                    # Look for child interface devices and extract their classes
                    for child in device.children:
                        if child.subsystem == 'usb' and ':' in child.sys_name:
                            # This is an interface (e.g., "1-2:1.0")
                            iface_class_str = child.attributes.get('bInterfaceClass')
                            if iface_class_str:
                                try:
                                    iface_class = int(iface_class_str.decode('utf-8', errors='ignore'), 16)
                                    if iface_class not in interface_classes:
                                        interface_classes.append(iface_class)
                                except (ValueError, UnicodeDecodeError):
                                    pass
                except Exception:
                    pass  # If we can't read interfaces, proceed without them

            # Sanitize vendor/product IDs
            return USBDeviceInfo(
                vendor_id=USBValidation.sanitize_hex_id(vendor_id),
                product_id=USBValidation.sanitize_hex_id(product_id),
                vendor_name=USBValidation.sanitize_string(vendor_name),
                product_name=USBValidation.sanitize_string(product_name),
                device_class=device_class,
                interface_classes=interface_classes,
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
        Get list of currently connected USB devices.

        Returns:
            List of USBDeviceInfo for all connected devices.
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
    Convenience function to list all connected USB devices.

    Returns:
        List of USBDeviceInfo for all connected devices.
    """
    monitor = USBMonitor(callback=lambda d, a: None)
    return monitor.get_connected_devices()


def is_pyudev_available() -> bool:
    """Check if pyudev is available."""
    return PYUDEV_AVAILABLE

