#!/bin/bash
# Bastion Firewall - Rust Daemon Installation Script
# Installs dependencies and builds the Rust daemon with eBPF support

set -e

echo "=== Bastion Firewall - Rust Daemon Setup ==="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "Please run as normal user (not root). Sudo will be requested when needed."
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo "Cannot detect OS. /etc/os-release not found."
    exit 1
fi

echo "Detected: $PRETTY_NAME"
echo ""

# Check kernel version
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
echo "Kernel version: $(uname -r)"

# Check BTF support
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "⚠️  Warning: BTF support not detected (/sys/kernel/btf/vmlinux missing)"
    echo "   eBPF may not work on this kernel. K kernel 5.8+ with BTF recommended."
else
    echo "✅ BTF support detected"
fi
echo ""

# Install system dependencies
echo "==> Installing system dependencies..."

if [ "$OS" = "ubuntu" ] || [ "$OS" = "zorin" ] || [ "$OS" = "debian" ]; then
    sudo apt-get update
    
    # Core build tools
    sudo apt-get install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        clang-18 \
        llvm-18-dev \
        libelf-dev \
        libz-dev \
        linux-headers-$(uname -r)
    
    echo "✅ System dependencies installed"
else
    echo "⚠️  Unsupported OS: $OS"
    echo "   Please install manually: clang-18, llvm-18-dev, libelf-dev, linux-headers"
fi

echo ""

# Check Rust installation
if ! command -v rustc &> /dev/null; then
    echo "==> Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "✅ Rust installed"
else
    echo "✅ Rust already installed: $(rustc --version)"
fi

# Ensure nightly toolchain
echo "==> Setting up Rust toolchains..."
rustup toolchain install stable
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

echo "✅ Rust toolchains configured"
echo ""

# Install bpf-linker
echo "==> Installing bpf-linker..."
if ! command -v bpf-linker &> /dev/null; then
    cargo install bpf-linker
    echo "✅ bpf-linker installed"
else
    echo "✅ bpf-linker already installed: $(bpf-linker --version)"
fi

echo ""
echo "==> Building eBPF program..."
cd bastion-rs
chmod +x build_ebpf.sh
./build_ebpf.sh

echo ""
echo "==> Building Rust daemon..."
cargo build --release

echo ""
echo "=== Installation Complete ==="
echo ""
echo "The Rust daemon has been built:"
echo "  Binary: bastion-rs/target/release/bastion-daemon"
echo "  eBPF:   bastion-rs/ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o"
echo ""
echo "To install system-wide:"
echo "  sudo cp bastion-rs/target/release/bastion-daemon /usr/bin/"
echo "  sudo cp bastion-rs/bastion-daemon.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable bastion-daemon"
echo "  sudo systemctl start bastion-daemon"
echo ""
echo "Or run manually:"
echo "  cd bastion-rs"
echo "  ./start_daemon.sh"
