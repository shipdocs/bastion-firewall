# Bastion Firewall - Rust Daemon Rewrite Progress

**Date:** December 27, 2025  
**Branch:** `feature/rust-rewrite`  
**Version:** v0.5.2

## Executive Summary

The Rust daemon rewrite has achieved **core functionality parity** with the Python daemon:
- ✅ Packet interception via NFQUEUE
- ✅ GUI popup support for user decisions
- ✅ Rule management (allow/deny, permanent rules)
- ✅ Process identification (partial - established connections)
- ⚠️ Short-lived connection identification needs eBPF

---

## What's Working

### 1. Packet Processing
- Uses `nfq` crate (pure Rust, MIT license) instead of `nfqueue` (GPL)
- Intercepts outgoing packets via iptables NFQUEUE
- Parses IP/TCP/UDP headers with `etherparse`

### 2. GUI Popups
- **Blocking GUI queries** - daemon waits for user response
- Sends `connection_request` JSON to GUI via Unix socket
- Receives `allow`/`deny` + `permanent` response
- 30-second timeout for user decision

### 3. Rule Management
- Loads rules from `/etc/bastion/rules.json`
- Saves permanent rules after user decisions
- Matches by app path and port

### 4. Process Identification
- Direct `/proc/net/tcp` and `/proc/net/udp` reading
- Maps socket inodes to PIDs via `/proc/[pid]/fd`
- **Works for:** Established connections, long-running processes
- **Struggles with:** Quick one-shot connections (curl, wget)

### 5. Systemd Integration
- Service file: `bastion-daemon.service`
- Auto-starts iptables rules
- Runs with appropriate capabilities

---

## Current Limitations

### Process Identification Timing Issue

The fundamental challenge is **NFQUEUE intercepts the SYN packet BEFORE the socket is fully registered** in the kernel's connection tables.

**What happens:**
1. Application calls `connect()`
2. Kernel creates socket, queues SYN packet
3. **NFQUEUE intercepts SYN** (our code runs here)
4. We try to look up the socket in `/proc/net/tcp`
5. Socket may not be visible yet, or has already closed

**The Python daemon has the same limitation.**

### Solutions Investigated

| Approach | Result |
|----------|--------|
| Background `ss` scanning | Too slow, socket closes before scan |
| Direct `/proc` reading | Works for established connections |
| On-demand `ss` query | Same timing issue |
| Destination-based caching | Helps for repeat connections |
| **eBPF** | **Best solution but requires setup** |

---

## eBPF - The Right Solution

### Why eBPF?

eBPF hooks into the kernel at the **moment of socket creation**, before any packets are sent:

```
Application calls connect()
    ↓
kprobe:tcp_v4_connect ← eBPF captures (PID, socket info)
    ↓
Socket created, SYN queued
    ↓
NFQUEUE intercepts SYN → We already know the PID from eBPF!
```

### Implementation Plan

1. **Create eBPF program** (Rust + Aya)
   - Attach kprobe to `tcp_v4_connect` and `udp_sendmsg`
   - Capture: PID, src_port, dest_ip, dest_port
   - Store in BPF HashMap

2. **User-space daemon reads BPF map**
   - When packet arrives, query the map by (src_port, dest_port, dest_ip)
   - Get PID instantly

3. **Requirements**
   - Nightly Rust toolchain (installed)
   - `rust-src` component (installed)
   - Kernel with BTF support (✅ available)
   - ~2GB free disk space (❌ currently at 99%)

### Files needed:
```
bastion-rs/
├── ebpf/
│   ├── Cargo.toml          # eBPF program dependencies
│   └── src/
│       └── main.rs         # eBPF kprobe code
├── src/
│   ├── main.rs             # Main daemon
│   ├── process.rs          # Process identification (use eBPF map)
│   └── ebpf_loader.rs      # Load and manage eBPF program
└── Cargo.toml              # Add aya dependency
```

---

## File Structure

```
bastion-rs/
├── Cargo.toml              # Dependencies: nfq, etherparse, serde, etc.
├── build.sh                # Build script
├── bastion-daemon.service  # Systemd service file
├── rescue.sh               # Emergency restore script
├── test_safe.sh            # Safe testing script
└── src/
    ├── main.rs             # Main loop, packet processing, GUI queries
    ├── config.rs           # Configuration loading
    ├── rules.rs            # Rule management
    ├── process.rs          # Process identification (/proc reading)
    └── whitelist.rs        # Auto-allow whitelist
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/bastion/config.json` | Mode (learning/enforcement), settings |
| `/etc/bastion/rules.json` | Application rules |
| `/var/run/bastion/bastion-daemon.sock` | GUI communication socket |
| `/var/log/bastion-daemon.log` | Daemon logs |

---

## Testing

### Start daemon manually:
```bash
sudo RUST_LOG=debug /usr/bin/bastion-daemon
```

### View logs:
```bash
sudo journalctl -u bastion-firewall -f
```

### Test with GUI:
```bash
python3 /path/to/bastion-gui.py
```

### Quick test:
```bash
curl https://example.com  # Should trigger popup if unknown
```

---

## Next Steps (Priority Order)

### High Priority
1. **Free disk space** - Currently 99% full, need ~2GB for eBPF
2. **Implement eBPF** - Will solve process identification completely
3. **Add destination-based rules** - Allow "always allow connections to google.com"

### Medium Priority
4. **Improve error handling** - Better recovery from socket errors
5. **Add statistics dashboard** - Send stats to GUI
6. **IPv6 support** - Currently IPv4 only

### Low Priority
7. **Cleanup compiler warnings** - Several unused import warnings
8. **Add tests** - Unit and integration tests
9. **Documentation** - API docs, user guide

---

## Git History (Recent)

```
dd4f39d feat(rust): v0.5.2 - Direct /proc reading like Python psutil
cb0d6d3 feat(rust): v0.5 - Working popup support via blocking GUI queries!
082e11b wip(rust): v0.4 - Switch to nfq crate, learning mode stable
e98ffd0 Previous commits...
```

---

## Dependencies

```toml
[dependencies]
nfq = "0.2"                 # Netfilter queue (pure Rust)
etherparse = "0.13"         # Packet parsing
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
anyhow = "1.0"
log = "0.4"
env_logger = "0.10"
once_cell = "1.18"
parking_lot = "0.12"
crossbeam-channel = "0.5"
# Future: aya = "0.13" for eBPF
```

---

## Contact & Handover Notes

- **Repository:** https://github.com/shipdocs/bastion-firewall
- **Branch:** `feature/rust-rewrite`
- **Primary daemon:** `/home/martin/Ontwikkel/bastion-firewall/bastion-rs/`

The Rust daemon is functional and can be used as the primary daemon. Process identification for quick connections requires eBPF implementation.

The Python daemon (`bastion/daemon.py`) remains available as a fallback.
