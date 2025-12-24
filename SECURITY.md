# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities by opening a private security advisory on GitHub or contacting the maintainer directly.

## Security Model

### Architecture Overview

Bastion uses privilege separation with multiple security boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│                    User Space (Unprivileged)                │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │  GUI (Qt)   │    │  USB GUI    │    │  Tray Icon      │  │
│  │  gui_qt.py  │    │  usb_gui.py │    │  gui_manager.py │  │
│  └──────┬──────┘    └──────┬──────┘    └─────────────────┘  │
│         │                  │                                 │
│         │ pkexec           │ pkexec                          │
│         ▼                  ▼                                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              bastion-root-helper CLI                    ││
│  │  - Fixed command set (no arbitrary code execution)      ││
│  │  - All inputs validated before use                      ││
│  │  - Audit logging to syslog (LOG_AUTH)                   ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              │ polkit authorization
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Root Space (Privileged)                  │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   Daemon (bastion-daemon)               ││
│  │  - Packet interception via iptables/nfqueue             ││
│  │  - eBPF for process identification                      ││
│  │  - Rule enforcement                                     ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### Trust Boundaries

1. **User ↔ GUI**: The GUI runs as the logged-in user. Any authenticated local user can interact with the GUI.

2. **GUI ↔ Root Helper**: The root helper (`bastion-root-helper`) is invoked via `pkexec`, which uses polkit for authorization. By default, any authenticated local user can authorize privileged operations.

3. **Root Helper ↔ System**: The root helper has a fixed command set and validates all inputs before performing privileged operations.

### Authorization Model

- **Who can use Bastion**: Any authenticated local user
- **What requires authorization**: USB policy changes, rule modifications, firewall enable/disable
- **How authorization works**: polkit prompts for password (configurable via polkit rules)

### Input Validation

All user-controllable inputs are validated and sanitized:

| Input Type | Validation | Max Length |
|------------|------------|------------|
| USB Vendor/Product ID | Hex chars only [0-9a-f] | 4 chars |
| USB Serial Number | Alphanumeric + `._-` | 128 chars |
| USB Rule Key | Format: `vid:pid:serial` or `vid:pid:*` | 256 chars |
| Vendor/Product Name | Printable ASCII, no control chars | 256 chars |

Shell metacharacters are stripped from USB identifiers (vendor/product IDs, serial numbers, rule keys).
User-facing strings (vendor/product names) have control characters removed but may contain safe punctuation.

### Audit Logging

Privileged operations are logged to syslog (LOG_AUTH facility):
- USB policy changes (authorize/block default)
- USB rule additions and deletions
- Invoking user UID
- Operation result (success/failure)

View logs: `journalctl -t bastion-root-helper`

## USB Device Control Security

### Threat Model

The USB device control feature protects against:
- **Unauthorized USB devices**: Block unknown devices by default
- **BadUSB attacks**: Require explicit authorization for HID devices
- **Data exfiltration**: Block unauthorized storage devices

### Limitations

- **DoS via deauthorization**: A malicious local user could block all USB devices
- **Kernel bypass**: Attacks at the kernel level bypass userspace controls
- **Pre-boot attacks**: USB devices connected before boot are not controlled

## Dependencies

The project uses eBPF (via BCC) for process identification. Ensure your kernel supports eBPF and that BCC is installed from trusted repositories.

## Security Checklist

Before deploying, verify:
- [ ] All tests pass: `python3 -m pytest tests/`
- [ ] No pkexec calls with user-controlled code
- [ ] All inputs validated before use
- [ ] Audit logging enabled
- [ ] polkit policy installed in `/usr/share/polkit-1/actions/`
