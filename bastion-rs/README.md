# Bastion Firewall - Rust Daemon

High-performance application firewall daemon written in Rust with eBPF support for kernel-level process tracking.

## Features

- **eBPF Process Tracking**: Kernel hooks capture process information at connection time (~1µs latency)
- **Rust Implementation**: Memory-safe, high-performance packet processing
- **/proc Fallback**: Compatible with older kernels without eBPF
- **NFQUEUE Integration**: Real-time packet interception via netfilter
- **Rule Engine**: Per-application firewall rules with persistent storage

## Requirements

- Linux kernel 6.0+ (5.8+ minimum) with BTF support
- Rust 1.75+ (stable + nightly toolchains)
- clang 18+, llvm-18-dev
- bpf-linker: `cargo install bpf-linker`
- Kernel headers for your running kernel

## Building

### eBPF Program

```bash
./build_ebpf.sh
```

### Daemon

```bash
cargo build --release
```

The daemon binary will be at `target/release/bastion-daemon`.

## Running

```bash
# Manual start with proper iptables rules
./start_daemon.sh

# Or via systemd
sudo systemctl start bastion-daemon
```

## Architecture

```
Application → connect() → Kernel (tcp_v4_connect/udp_sendmsg)
                            ↓
                    eBPF kprobe captures PID
                            ↓
                    Stores in BPF HashMap
                            ↓
Packet → iptables NFQUEUE → Daemon queries eBPF
                            ↓
                    Identifies process (1µs)
                            ↓
                    Checks rules → GUI popup
```

## Performance

- Process lookup: <1µs (eBPF) vs 5-10ms (/proc)
- Success rate for short-lived connections: 98% vs 30%
- Memory usage: ~10-20 MB
- CPU usage: <1% idle, ~5% under load

## Files

- `src/` - Rust daemon source code
- `ebpf/` - eBPF kernel program
- `build_ebpf.sh` - Build script for eBPF
- `start_daemon.sh` - Startup script with iptables rules

## License

GPL-3.0 - See LICENSE file in repository root.
