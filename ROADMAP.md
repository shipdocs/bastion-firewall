# 🏰 Bastion Security Suite - Roadmap

**Vision**: Transform Bastion from an application firewall into a comprehensive **desktop security suite** for Linux — filling gaps that enterprise tools cover on Windows but are missing on the Linux desktop.

---

## 📊 Current Status

| Component | Status | Version |
|-----------|--------|---------|
| **Outbound Firewall** | ✅ Production | v1.4.1 |
| **Inbound Firewall (UFW)** | ✅ Integrated | v1.4.0 |
| **eBPF Process ID** | ✅ Implemented | v1.3.0 |
| **GUI & Tray** | ✅ Polished | v1.4.1 |
| **Platform** | Zorin OS 18 (Ubuntu 24.04 LTS) | |

---

## 🎯 The Vision: Security Suite Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    BASTION SECURITY SUITE                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │   Outbound    │  │    Inbound    │  │     USB       │       │
│  │   Firewall    │  │   Firewall    │  │   Control     │       │
│  │   (Bastion)   │  │    (UFW)      │  │  🆕 v1.5.0    │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │   Startup     │  │   Intrusion   │  │    File       │       │
│  │   Auditing    │  │  Prevention   │  │  Integrity    │       │
│  │  🆕 v1.6.0    │  │  🆕 v1.7.0    │  │  🆕 v1.8.0    │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐       │
│  │   Network     │  │   Security    │  │   Flatpak/    │       │
│  │   Anomaly     │  │    Audit      │  │ Snap Sandbox  │       │
│  │  🔮 v2.0.0    │  │  🔮 v2.0.0    │  │  🔮 v2.1.0    │       │
│  └───────────────┘  └───────────────┘  └───────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Module 1: USB Device Control (v1.5.0) — NEXT UP

**Why**: BadUSB attacks are real. No good Linux desktop solution exists. Windows has enterprise tools; Linux has nothing user-friendly.

**Features**:
| Feature | Description |
|---------|-------------|
| **Device Whitelisting** | Only allow known/trusted USB devices |
| **New Device Prompts** | "Unknown USB keyboard detected - Allow?" |
| **BadUSB Protection** | Block HID devices pretending to be keyboards |
| **Device History** | Log all USB insertions with timestamps |
| **Quick Actions** | Allow once, allow always, block always |

**User Education**: Explain *why* this matters — USB attacks are used in targeted attacks, public charging stations, etc.

**Implementation**: See [USB_DEVICE_CONTROL.md](USB_DEVICE_CONTROL.md)

---

## 🚀 Module 2: Startup Auditing (v1.6.0)

**Why**: Malware installs persistence. Users don't know what starts on boot.

**Features**:
| Feature | Description |
|---------|-------------|
| **Monitor Autostart** | Watch `~/.config/autostart`, systemd user units, cron |
| **New Entry Alerts** | "Chrome wants to start on boot - Allow?" |
| **Persistence Detection** | Flag suspicious mechanisms (hidden files, unusual locations) |
| **Startup Manager** | View/disable all startup items from one place |
| **Baseline Comparison** | Alert when something new appears |

**Locations to Monitor**:
```
~/.config/autostart/*.desktop
~/.local/share/systemd/user/*.service
/etc/xdg/autostart/*.desktop
crontab -l
~/.bashrc, ~/.profile (for suspicious additions)
```

---

## 🔒 Module 3: Intrusion Prevention (v1.7.0)

**Why**: fail2ban is essential for servers, but desktop users don't know they need it.

**Features**:
| Feature | Description |
|---------|-------------|
| **SSH Protection** | Monitor `/var/log/auth.log`, auto-block after X failures |
| **Service Protection** | Protect VNC, xrdp, any listening service |
| **Geo-blocking** | Optional: block IPs from specific countries |
| **Attack Dashboard** | Show blocked IPs, attempt counts, geo-location |
| **Whitelist** | Never block trusted IPs (home, office) |

**Integration**: Works alongside UFW inbound rules.

---

## 📁 Module 4: File Integrity Monitoring (v1.8.0)

**Why**: Rootkits and malware modify system files. AIDE/Tripwire are server tools with no GUI.

**Features**:
| Feature | Description |
|---------|-------------|
| **Critical File Watch** | `/etc/passwd`, `/etc/shadow`, sudoers, SSH keys |
| **Binary Verification** | Alert if `/usr/bin/*` changes unexpectedly |
| **Config Drift** | Track firewall rules, SSH config changes |
| **Baseline Creation** | Snapshot known-good state after install |
| **Change Alerts** | "⚠️ /etc/passwd was modified - Review?" |

**Watched Paths**:
```
/etc/passwd, /etc/shadow, /etc/sudoers, /etc/sudoers.d/*
/etc/ssh/sshd_config
~/.ssh/authorized_keys
/usr/bin/*, /usr/sbin/* (hash verification)
Bastion's own rules and config
```

---

## 🔮 Future Modules (v2.0.0+)

### Network Anomaly Detection
| Feature | Description |
|---------|-------------|
| **Baseline Learning** | Learn normal patterns per app |
| **Data Exfil Alerts** | "Firefox uploading 500MB to unknown server" |
| **DNS Monitoring** | Detect DNS tunneling, suspicious queries |
| **Beaconing Detection** | Catch malware calling home on intervals |

### Security Audit Dashboard
| Feature | Description |
|---------|-------------|
| **Hardening Score** | Like Lynis, but with GUI (score out of 100) |
| **One-Click Fixes** | "SSH allows root login - Fix?" |
| **SUID Scanner** | Find potentially dangerous binaries |
| **Open Ports** | What's listening, should it be? |

### Flatpak/Snap Sandbox Awareness
| Feature | Description |
|---------|-------------|
| **Permission Audit** | "Spotify has full filesystem access - Restrict?" |
| **Sandbox Escapes** | Alert on unusual portal requests |
| **App Isolation Score** | Rate how isolated each app is |

---

## 📅 Release Schedule

| Version | Module | Target | Status |
|---------|--------|--------|--------|
| v1.4.1 | GUI & Tray Polish | Dec 2024 | ✅ Released |
| **v1.5.0** | **USB Device Control** | **Q1 2025** | 🔜 Next |
| v1.6.0 | Startup Auditing | Q1 2025 | 📅 Planned |
| v1.7.0 | Intrusion Prevention | Q2 2025 | 📅 Planned |
| v1.8.0 | File Integrity | Q2 2025 | 📅 Planned |
| v2.0.0 | Anomaly + Audit Dashboard | Q3 2025 | 🔮 Future |

---

## 🎯 What Makes Bastion Unique

| Feature | OpenSnitch | Bastion |
|---------|------------|---------|
| Outbound Firewall | ✅ | ✅ |
| Inbound (UFW) Integration | ❌ | ✅ |
| USB Device Control | ❌ | 🔜 v1.5.0 |
| Startup Auditing | ❌ | 🔜 v1.6.0 |
| Intrusion Prevention | ❌ | 🔜 v1.7.0 |
| File Integrity | ❌ | 🔜 v1.8.0 |
| Zorin OS Optimized | ❌ | ✅ |
| Single Binary (Python) | ❌ (Go+Python) | ✅ |

**Bastion's Differentiator**: Not just a firewall — a **complete desktop security suite**.

---

## 🤝 Contributing

Each module has its own implementation plan:
- [USB_DEVICE_CONTROL.md](USB_DEVICE_CONTROL.md) - USB protection (v1.5.0)
- More coming soon...

Want to help? Pick a module and start contributing! 🚀

---

**Last Updated**: 2024-12-23
**Current Version**: v1.4.1 (Pre-release)
**Stable Version**: v1.4.0
**Repository**: https://github.com/shipdocs/bastion-firewall
**Platform**: Zorin OS 18 (Ubuntu 24.04 LTS)
