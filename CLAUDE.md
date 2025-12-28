# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bastion Firewall is a Linux application firewall providing user-level control over outbound network connections. It combines high-performance Rust code with kernel-level eBPF for process tracking and a Python Qt6 GUI for user interaction.

**Current Version: v2.0 (Rust Daemon)**

**Key architectural pattern: Multi-layer defense**
- Kernel-level eBPF hooks capture process info at connection creation (~1µs)
- User-space Rust daemon processes packets via Netfilter NFQUEUE
- Python GUI provides user interaction and control
- IPC via Unix domain sockets connects components

### Daemon Architecture

**Current (v2.0+):** Rust daemon (`bastion-rs/src/main.rs`)
- Native NFQUEUE bindings via `nfq` crate
- eBPF loader with /proc fallback
- <1µs process lookup, 98% success rate

**Legacy:** Python daemon (`bastion-daemon-legacy.py`) - deprecated, not packaged

## Build Commands

### Full Package Build
```bash
# Build complete .deb package (includes eBPF + Rust daemon + Python GUI)
./build_deb.sh

# Install the package
sudo dpkg -i bastion-firewall_*.deb
sudo apt-get install -f  # If dependencies are missing
```

### Rust Daemon Development
```bash
cd bastion-rs

# Build eBPF program (requires nightly Rust)
./build_ebpf.sh

# Build Rust daemon
cargo build --release

# Run daemon directly (for testing)
./start_daemon.sh  # Sets up iptables rules and starts daemon
```

### Python GUI Development
```bash
# Run GUI directly (daemon must be running)
python3 bastion-gui.py

# Run control panel
python3 bastion_control_panel.py
```

### Testing
```bash
# Python tests with coverage
./run_tests.sh

# Or manually
python -m pytest tests/ -v --cov=bastion --cov-report=term-missing

# Run specific test file
pytest tests/test_rules.py -v
```

### Release Process
```bash
# 1. Update CHANGELOG.md with new version notes
# 2. Run release tool (requires rpm and gh CLI)
./release_tool.sh 1.4.8
```

## Architecture Deep Dive

### Component Interaction Flow

```
[Application connects]
    ↓
[Kernel: tcp_v4_connect/udp_sendmsg kprobes]
    ↓
[eBPF program captures PID + socket info, stores in BPF HashMap]
    ↓
[Packet hits iptables NFQUEUE (queue 1)]
    ↓
[Rust Daemon: bastion-daemon]
    ├─ Query eBPF map (<1µs)
    ├─ Fallback to /proc scanning if eBPF miss
    ├─ Check rules.json for existing rule
    ├─ Apply service_whitelist logic
    └─ Send popup request to GUI via Unix socket
        ↓
[Python GUI: bastion-gui]
    ├─ Show allow/deny dialog
    ├─ User decision
    └─ Send response to daemon
        ↓
[Daemon renders verdict: ACCEPT or DROP]
```

### Key Components

**eBPF Program** (`bastion-rs/ebpf/src/main.rs`)
- Kprobes on `tcp_v4_connect` and `udp_sendmsg`
- Captures PID, destination IP/port at connection time
- Stores in BPF HashMap with TTL
- Solves race condition for short-lived processes (curl, wget)

**Rust Daemon** (`bastion-rs/src/main.rs`)
- NFQUEUE packet interception (queue 1)
- Process identification: eBPF → /proc fallback
- Rule engine with persistent storage at `/etc/bastion/rules.json`
- IPC server at `/var/run/bastion/bastion-daemon.sock`
- Stats tracking and GUI popup coordination

**Python GUI** (`bastion/gui_qt.py`)
- Qt6-based modern interface
- System tray integration
- Decision popups (allow/deny)
- Control panel dashboard
- IPC client connecting to daemon socket

**Rule Manager** (`bastion/rules.py` + `bastion-rs/src/rules.rs`)
- Persistent storage format: `"app_path:port" → allow/deny`
- Atomic writes with symlink protection
- Thread-safe access in Rust, file-locked access in Python

**Service Whitelist** (`bastion/service_whitelist.py`)
- Smart auto-allow for system services (DNS, NTP, DHCP, package managers)
- Prevents unnecessary popups for trusted system components
- Port restrictions for defense-in-depth

### Directory Structure

```
/bastion-firewall/
├── bastion/              # Python package (GUI, legacy daemon components)
│   ├── gui_qt.py        # Main Qt6 GUI
│   ├── firewall_core.py # Packet processing & identification
│   ├── rules.py         # Rule storage & management
│   ├── service_whitelist.py  # Smart auto-allow logic
│   └── [other modules]
├── bastion-rs/          # Rust daemon (v2.0+)
│   ├── src/
│   │   ├── main.rs      # Daemon entry point
│   │   ├── process.rs   # Process identification
│   │   ├── ebpf_loader.rs  # eBPF program loader
│   │   ├── rules.rs     # Rule engine
│   │   └── ipc.rs       # Unix socket IPC
│   ├── ebpf/            # eBPF kernel programs
│   │   └── src/main.rs  # Kernel-space eBPF code
│   ├── build_ebpf.sh    # eBPF build script
│   └── start_daemon.sh  # Daemon startup with iptables setup
├── debian/              # Debian package staging
│   ├── DEBIAN/         # Package control files, install scripts
│   ├── usr/bin/        # Executables
│   ├── usr/lib/        # Python modules
│   └── lib/systemd/system/  # Systemd service
├── tests/              # Python test suite
└── build_deb.sh        # Main package builder
```

### Runtime Directories

- `/etc/bastion/` - Configuration and rules
  - `config.json` - Daemon configuration
  - `rules.json` - Persistent firewall rules
- `/var/run/bastion/` - Runtime directory
  - `bastion-daemon.sock` - Unix socket for IPC
- `/usr/share/bastion-firewall/` - Data files
  - `bastion-ebpf.o` - Compiled eBPF program

## Technology Stack

**Languages:**
- Rust (v1.75+): High-performance daemon, eBPF loader
- Python (3.10+): GUI and legacy components
- eBPF/C: Kernel-level process tracking

**Key Rust Dependencies:**
- `nfq = "0.2"` - Netfilter NFQUEUE bindings
- `aya = "0.13"` - eBPF framework
- `etherparse = "0.13"` - Packet parsing
- `parking_lot = "0.12"` - Fast synchronization primitives
- `crossbeam-channel = "0.5"` - Thread communication

**Key Python Dependencies:**
- PyQt6 - GUI framework
- NetfilterQueue - NFQUEUE bindings
- psutil - Process utilities
- pystray - System tray icon

**Build Requirements:**
- Rust stable + nightly toolchains
- clang 18+, llvm-18-dev
- bpf-linker: `cargo install bpf-linker`
- Linux kernel headers
- dpkg-deb (Debian packaging)

## Important Implementation Details

### eBPF Process Tracking
- eBPF solves the race condition where packets arrive before process info is available
- Success rate: 98% (eBPF) vs 30% (/proc only) for short-lived connections
- Process lookup: <1µs (eBPF) vs 5-10ms (/proc)
- eBPF program is loaded at daemon startup from `/usr/share/bastion-firewall/bastion-ebpf.o`

### Security Considerations
- **Symlink protection**: All file operations use O_NOFOLLOW
- **Atomic writes**: Config/rules use temp files + rename
- **Socket permissions**: Unix socket is 0600
- **Root bypass**: Root-owned processes bypass firewall (system stability)
- **Whitelist**: Trusted system services auto-allowed with port restrictions
- **Path validation**: Executable paths validated before rule creation

### IPC Protocol
- Unix domain socket at `/var/run/bastion/bastion-daemon.sock`
- JSON message format
- Message types:
  - `popup_request` - Daemon asks GUI for decision
  - `popup_response` - GUI sends user decision
  - `stats_update` - Daemon sends stats (every 2 seconds)
  - `get_stats` - GUI requests current stats

### Systemd Integration
- Service file: `/lib/systemd/system/bastion-firewall.service`
- Runs as root (required for NFQUEUE and eBPF)
- Dependencies: network.target, iptables
- Auto-restart on failure
- GUI launched separately per user session

## Code Style

**Python:**
- PEP 8 compliant
- 4 spaces indentation
- 100 character line limit
- Google-style docstrings

**Rust:**
- Standard rustfmt formatting
- Comprehensive error handling with anyhow
- Thread-safe access with parking_lot
- Structured logging with env_logger

## Performance Characteristics

- eBPF lookup: <1µs
- /proc fallback: 5-10ms
- Memory usage: ~10-20 MB
- CPU usage: <1% idle, ~5% under load
- Success rate for short-lived connections: 98%

## Common Gotchas

1. **eBPF Build**: Requires nightly Rust toolchain and bpf-linker in PATH
2. **Kernel BTF**: For eBPF support, kernel needs BTF (check `/sys/kernel/btf/vmlinux`)
3. **NFQUEUE Rules**: Daemon uses `--queue-bypass` - network stays up if daemon crashes
4. **Socket Path**: `/var/run/bastion/bastion-daemon.sock`
5. **Version Sync**: Keep versions consistent across setup.py, debian/DEBIAN/control, build_deb.sh
6. **Dependencies**: Rust daemon uses native `nfq` crate, not Python NetfilterQueue
7. **Legacy Code**: `bastion-daemon-legacy.py` and `bastion/daemon.py` are deprecated
