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
else
    echo "Cannot detect OS. /etc/os-release not found."
    exit 1
fi

echo "Detected: $PRETTY_NAME"
echo ""

# Check kernel version
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

    # Core build tools (non-LLVM)
    sudo apt-get install -y \
        build-essential \
        pkg-config \
        libssl-dev \
        libelf-dev \
        libz-dev \
        linux-headers-"$(uname -r)"

    # Try to install clang-18, fall back to available version if not found
    if sudo apt-get install -y clang-18 llvm-18-dev 2>/dev/null; then
        echo "✅ clang-18 installed"
    else
        echo "⚠️  clang-18 not available in standard repositories"
        echo "   Attempting to add LLVM repository..."

        # Add LLVM repository for Ubuntu/Debian
        if command -v lsb_release &> /dev/null; then
            CODENAME=$(lsb_release -cs)
            wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
            echo "deb http://apt.llvm.org/$CODENAME/ llvm-toolchain-$CODENAME-18 main" | sudo tee /etc/apt/sources.list.d/llvm.list
            sudo apt-get update

            if sudo apt-get install -y clang-18 llvm-18-dev; then
                echo "✅ clang-18 installed from LLVM repository"
            else
                echo "❌ Error: Failed to install clang-18"
                echo "   Please install manually from https://apt.llvm.org/"
                exit 1
            fi
        else
            echo "❌ Error: Cannot detect distribution codename"
            echo "   Please install clang-18 manually from https://apt.llvm.org/"
            exit 1
        fi
    fi

    echo "✅ System dependencies installed"
else
    # FIX #18: Exit with error on unsupported OS instead of continuing
    echo "❌ Error: Unsupported OS: $OS"
    echo "   Supported OS: ubuntu, debian, zorin"
    echo "   Please install manually: clang-18, llvm-18-dev, libelf-dev, linux-headers"
    exit 1
fi

echo ""

# Check Rust installation
if ! command -v rustc &> /dev/null; then
    echo "==> Installing Rust..."
    # SECURITY: Download script to temp file first, verify before executing
    # This prevents arbitrary code execution if the remote server is compromised
    RUST_INSTALLER=$(mktemp /tmp/rustup.XXXXXX.sh)
    # Pinned SHA256 of the installer script (sh.rustup.rs) as of 2025-12-28
    # If this fails, the upstream script has changed. Please verify and update the hash.
    RUSTUP_SHA256="17247e4bcacf6027ec2e11c79a72c494c9af69ac8d1abcc1b271fa4375a106c2"

    if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$RUST_INSTALLER"; then
        # Verify SHA256 checksum
        if ! echo "$RUSTUP_SHA256  $RUST_INSTALLER" | sha256sum -c - >/dev/null 2>&1; then
             echo "❌ Error: Rust installer checksum verification failed!"
             echo "   Expected: $RUSTUP_SHA256"
             echo "   Actual:   $(sha256sum "$RUST_INSTALLER" | awk '{print $1}')"
             rm -f "$RUST_INSTALLER"
             exit 1
        fi

        # Verify the file is not empty and looks like a shell script
        if [ -s "$RUST_INSTALLER" ] && head -1 "$RUST_INSTALLER" | grep -q "^#!/"; then
            sh "$RUST_INSTALLER" -y
            # Add cargo to PATH for the current script session
            export PATH="$HOME/.cargo/bin:$PATH"
            # Ensure it's in the user's profile for future sessions
            if [ -f "$HOME/.bashrc" ] && ! grep -q 'source "$HOME/.cargo/env"' "$HOME/.bashrc"; then
                echo '' >> "$HOME/.bashrc"
                echo '# Add Rust to PATH' >> "$HOME/.bashrc"
                echo 'source "$HOME/.cargo/env"' >> "$HOME/.bashrc"
            fi
            echo "✅ Rust installed"
        else
            echo "❌ Error: Downloaded installer is invalid or corrupted"
            rm -f "$RUST_INSTALLER"
            exit 1
        fi
        rm -f "$RUST_INSTALLER"
    else
        echo "❌ Error: Failed to download Rust installer"
        rm -f "$RUST_INSTALLER"
        exit 1
    fi
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
echo "  sudo cp bastion-firewall.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable bastion-firewall"
echo "  sudo systemctl start bastion-firewall"
echo ""
echo "Or run manually:"
echo "  cd bastion-rs"
echo "  ./start_daemon.sh"
