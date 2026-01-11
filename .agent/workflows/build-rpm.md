---
description: Build RPM package for Fedora/RHEL/openSUSE
---

# Build RPM Package

Build a cross-distro compatible RPM that works on Fedora, RHEL, and openSUSE.

## Prerequisites

1. Build on Debian/Ubuntu (cross-distro build)
2. Ensure rpmbuild is installed: `sudo apt install rpm`

## Build Steps

// turbo-all

1. Navigate to project root:
```bash
cd /home/martin/Ontwikkel/bastion-firewall
```

2. Build the Rust daemon and eBPF (if not already built):
```bash
cd bastion-rs && ./build_ebpf.sh && cargo build --release && cd ..
```

3. Build the RPM:
```bash
./build_rpm.sh
```

4. Output: `bastion-firewall-X.X.X-1.x86_64.rpm`

## Cross-Distro Compatibility Features

The RPM includes these fixes for cross-distro compatibility:

### 1. libpcap Symlink
- Built on Debian (libpcap.so.0.8) but Fedora has libpcap.so.1
- Post-install script creates symlink automatically
- Removed on uninstall

### 2. Python Module Path
- Modules installed to `/usr/share/bastion-firewall/bastion/`
- Python scripts use `sys.path.insert(0, "/usr/share/bastion-firewall")`
- Works on any Python version

### 3. Dependencies (Fedora package names)
- python3-pyqt6
- python3-gobject
- python3-pillow
- python3-psutil
- libpcap
- gtk3
- libayatana-appindicator-gtk3

### 4. AutoReqProv Disabled
- Prevents rpmbuild from detecting Debian-specific library versions
- Manual dependencies specified instead

## Install on Fedora

```bash
sudo dnf install ./bastion-firewall-X.X.X-1.x86_64.rpm
```

## Reinstall (same version)

```bash
sudo dnf reinstall ./bastion-firewall-X.X.X-1.x86_64.rpm
```
