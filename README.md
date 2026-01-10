# Bastion Firewall

An application firewall for Linux that gives you control over outbound network connections.

[![Release](https://img.shields.io/github/v/release/shipdocs/bastion-firewall)](https://github.com/shipdocs/bastion-firewall/releases/latest)
[![License](https://img.shields.io/badge/License-GPLv3-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Debian%2FUbuntu-green)](https://github.com/shipdocs/bastion-firewall)

![Bastion Firewall Control Panel](screenshots/status.png)

## Overview

Bastion intercepts outbound connections and prompts you to allow or deny them per application. It features a **high-performance Rust daemon** with **kernel-level eBPF process tracking** and a Qt 6 control panel.

**NEW:** v2.0 introduces a Rust daemon with eBPF for <1µs process identification, solving timing issues with short-lived connections (curl, wget, etc).

**Target Platform:** Zorin OS 18 / Ubuntu 24.04 LTS (Debian-based distributions)

## Features

### Core Functionality
- **eBPF Process Tracking** - Kernel-level hooks capture process info at connection creation (~<1µs latency)
- **Rust Daemon** - High-performance, memory-safe packet processing
- **Real-time Interception** - iptables NFQUEUE integration
- **GUI Popups** - Instant allow/deny prompts with Qt 6
- **Persistent Rules** - Per-application rules in `/etc/bastion/rules.json`
- **Learning Mode** - Automatic rule discovery
- **System Bypass** - Root and systemd traffic exempted for stability
- **Status-Aware Icons** - Color-coded tray icons showing connection status, learning mode, and errors

### Advanced Features
- Identifies short-lived connections (curl, wget) that timing-based methods miss
- /proc scanning fallback for compatibility
- Connection caching with TTL
- **DNS Hostname Display** - Shows destination hostname in popups (e.g., "google.com" instead of just IP)
- **Inbound Firewall Protection** - Automatic UFW integration or standalone INPUT rules
- **mDNS Auto-Allow** - No popups for local network discovery (.local hostnames)
- **LAN Broadcast Auto-Allow** - Automatic allow for broadcast traffic (Steam, DLNA, printers)
- **Wildcard Port Rules** - Apply rules to all ports for an application (e.g., Zoom, Slack)
- **Rule Search & Filtering** - Quickly find rules by app name, path, port, or action
- **Import/Export Rules** - Backup and restore your firewall rules
- **Manual Rule Entry** - Add custom rules without waiting for prompts
- **Inline Action Toggle** - Double-click rules to toggle allow/deny
- **App Icons** - Visual identification in rules table

## Installation

Download the latest `.deb` package from [Releases](https://github.com/shipdocs/bastion-firewall/releases) and install:

```bash
sudo dpkg -i bastion-firewall_*.deb
sudo apt-get install -f  # Install dependencies if needed
```

Or build from source:

```bash
git clone https://github.com/shipdocs/bastion-firewall.git
cd bastion-firewall
./build_deb.sh
sudo dpkg -i bastion-firewall_*.deb
```

### Development Setup

For development and testing:

```bash
git clone https://github.com/shipdocs/bastion-firewall.git
cd bastion-firewall

# Install dependencies
pip install -r requirements.txt

# Run tests
./run_tests.sh

# Or manually:
pip install -r test-requirements.txt
python -m pytest tests/
```

### Requirements

#### System Requirements
- **Linux kernel 6.0+** with BTF support (check: `ls /sys/kernel/btf/vmlinux`)
- **eBPF support** enabled in kernel
- **CAP_BPF and CAP_NET_ADMIN** capabilities (daemon runs as root)

#### Build Dependencies (for Rust daemon)
- Rust 1.75+ (stable + nightly toolchain)
- clang 18+
- llvm-18-dev
- bpf-linker (`cargo install bpf-linker`)
- kernel headers

#### GUI Dependencies (Python)
- Python 3.10+
- PyQt6
- psutil>=5.9.0
- pystray>=0.19.0
- Pillow>=10.2.0

## Usage

Launch from the application menu or run:

```bash
bastion-gui
```

The system tray icon provides access to the control panel where you can:
- View and manage rules
- Switch between learning and enforcement modes
- Monitor connection logs

## Configuration

Configuration is stored in `/etc/bastion/config.json`:

```json
{
  "mode": "learning",
  "timeout_seconds": 30,
  "allow_localhost": true
}
```

## Architecture

```
Application calls connect()
    ↓
┌─────────────────────────────────────────────┐
│ Kernel: tcp_v4_connect/udp_sendmsg          │
│    ↓                                        │
│ eBPF kprobe → Capture PID + socket info     │
│    ↓                                        │
│ Store in BPF HashMap                        │
└─────────────────────────────────────────────┘
    ↓
Packet sent → iptables NFQUEUE
    ↓
┌─────────────────────────────────────────────┐
│ Rust Daemon (bastion-daemon)                │
│  - Query eBPF map (~<1µs)                    │
│  - Fallback to /proc if needed              │
│  - Check existing rules                     │
│  - Send GUI popup request                   │
└──────────────┬──────────────────────────────┘
               │ Unix socket
┌──────────────▼──────────────────────────────┐
│ Python GUI (bastion-gui)                    │
│  - Show allow/deny popup                    │
│  - Send decision to daemon                  │
│  - System tray management                   │
└─────────────────────────────────────────────┘
```

## Icon Design & Status Indicators

Bastion Firewall uses a unified shield icon design with color-coded status variants for instant visual feedback:

- **Connected (Green)** - Firewall is active and protecting your system
- **Disconnected (Gray)** - Firewall is stopped or daemon is not running
- **Learning Mode (Blue)** - Firewall is in learning mode, automatically discovering rules
- **Error (Red)** - Firewall encountered an error
- **Warning (Orange)** - Firewall needs attention

The icon is installed to `/usr/share/icons/hicolor/scalable/apps/bastion-icon.svg` and follows the freedesktop.org icon theme specification.

## Uninstall

```bash
sudo dpkg --purge bastion-firewall
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Development & Release

### Automated Local Release
To create a new release (update versions, build packages, tag git, release on GitHub):
```bash
# 1. Update CHANGELOG.md with new notes
# 2. Run the release tool
./release_tool.sh 2.0.28
```
This requires `rpm` and `gh` CLI to be installed and authenticated.

## Roadmap

- [x] **DNS Proxy/Sniffing** - Implement a local DNS proxy or eBPF DNS sniffer to attribute connections to hostnames and processes more robustly.
- [ ] **Advanced Rule Grouping** - Group rules by application suites or categories.
- [ ] **Network Profiles** - Different rule sets for Home, Work, and Public networks.

## Security & Privacy

Bastion Firewall is designed with transparency and user privacy as its core principles. Below are details on technical implementations that involve system-level monitoring:

### eBPF Process Identification
Traditional process identification (via `/proc` scanning) is prone to timing attacks where short-lived processes (like `curl` or `wget`) complete their network request and exit before the firewall can identify them.
- **How we use it**: Bastion uses kernel-level eBPF kprobes to capture process metadata at the exact nanosecond a connection is requested.
- **Privacy Focus**: These hooks only capture the PID and the command name (comm) of the initiating process. No other system activity is monitored.

### DNS Snooping (Hostname Correlation)
To provide meaningful popups, the firewall needs to know that an IP like `142.250.190.46` is actually `google.com`.
- **How we use it**: The daemon captures DNS responses locally to maintain a short-lived mapping of IP addresses to hostnames.
- **Privacy Focus**: This mapping is entirely local, transient (cleared on exit), and is only used to populate the "Destination" field in your alerts. No browsing history is logged or transmitted.

### External IP Lookups
When an application connects to a raw IP address (not via DNS), Bastion may perform an optional lookup to identify the Organization/ISP.
- **How we use it**: An anonymous request is sent to a public IP-API.
- **Privacy Focus**: These lookups are only performed for unknown IPs to provide security context. No local identity tokens or tracking information are included in these requests.

### Root Privileges
The `bastion-daemon` requires root privileges (`CAP_NET_ADMIN` and `CAP_BPF`) to manage `iptables` rules and attach eBPF probes.
- **Security Design**: The GUI dashboard and tray icon run as a regular user. Communication between the GUI and the root daemon occurs over a hardened Unix socket with peer credential verification (`SO_PEERCRED`), ensuring only you can authorize firewall decisions.

## License

GPL-3.0. See [LICENSE](LICENSE) for details.
