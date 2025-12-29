# Bastion Firewall - System Requirements

## Rust Daemon (bastion-daemon)

### Runtime Requirements
- **Linux Kernel:** 5.8+ with BTF support (6.0+ recommended for optimal eBPF performance)
  - Check: `ls /sys/kernel/btf/vmlinux` (file should exist for eBPF support)
  - Check: `uname -r` (version should be 5.8+)
  - Note: Falls back to /proc on kernels without eBPF/BTF support
- **eBPF Support:** Recommended but not required (fallback available)
- **Root Access:** Daemon requires CAP_BPF and CAP_NET_ADMIN capabilities
- **Architecture:** x86_64 (amd64)

### Build Dependencies
```bash
# Debian/Ubuntu
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    clang-18 \
    llvm-18-dev \
    libelf-dev \
    libz-dev \
    linux-headers-$(uname -r)

# Rust toolchains
rustup toolchain install stable
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# eBPF linker
cargo install bpf-linker
```

### Optional Dependencies
- `bpftool` - For debugging eBPF programs
- `llvm-objdump` - For inspecting eBPF binaries

## Python GUI (bastion-gui)

### Runtime Requirements
- **Python:** 3.10+
- **Display Server:** X11 or Wayland
- **Desktop Environment:** Any (GNOME, KDE, XFCE, etc.)

### Python Dependencies
```bash
pip install \
    PyQt6>=6.0.0 \
    psutil>=5.9.0 \
    pystray>=0.19.0 \
    Pillow>=10.2.0
```

## System Configuration

### Network
- Outbound connections must be routable through iptables
- No conflicts with other NFQUEUE users

### Permissions
- User must be in `sudo` group for daemon management
- GUI runs as normal user
- Daemon runs as root

### Disk Space
- Runtime: ~50 MB
- Build: ~2 GB (for eBPF compilation)

## Verified Platforms

| Distribution | Version | Status |
|--------------|---------|--------|
| Zorin OS | 18 | ✅ Fully Tested |
| Ubuntu | 24.04 LTS | ✅ Supported |
| Ubuntu | 22.04 LTS | ✅ Supported |
| Debian | 12 (Bookworm) | ✅ Supported |
| Linux Mint | 21+ | ⚠️ Should work |
| Pop!_OS | 22.04+ | ⚠️ Should work |

## Feature Requirements

### eBPF Process Tracking
- Kernel 5.8+ (6.0+ recommended)
- BTF (BPF Type Format) enabled
- `CONFIG_DEBUG_INFO_BTF=y` in kernel config

### /proc Fallback
- Standard Linux `/proc` filesystem
- Works on all kernels (no special requirements)

### GUI Popups
- Active X11/Wayland session
- `DISPLAY` environment variable set
- D-Bus session running

## Troubleshooting

### eBPF Not Loading
```bash
# Check kernel version
uname -r  # Should be 6.0+

# Check BTF support
ls /sys/kernel/btf/vmlinux  # Should exist

# Check eBPF capability
capsh --print | grep cap_bpf  # Should show cap_bpf
```

### Build Failures
```bash
# Ensure clang is version 18+
clang --version

# Ensure LLVM is installed
llvm-config-18 --version

# Check Rust toolchains
rustup show
```

### GUI Not Appearing
```bash
# Check display
echo $DISPLAY  # Should show :0 or similar

# Check if GUI is running
ps aux | grep bastion-gui
```

## Minimum vs Recommended

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Kernel | 5.8 | 6.0+ |
| RAM | 256 MB | 512 MB |
| CPU | 1 core | 2+ cores |
| Disk (runtime) | 50 MB | 100 MB |
| Disk (build) | 2 GB | 5 GB |

## Performance Notes

- **eBPF**: ~1µs per connection lookup
- **Daemon**: ~10-20 MB RAM usage
- **GUI**: ~50-80 MB RAM usage
- **CPU**: <1% on idle, ~5% during heavy traffic
