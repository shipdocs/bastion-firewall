#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EBPF_DIR="$SCRIPT_DIR/ebpf"

echo ">>> Building eBPF program with Aya..."

if [ ! -d "$EBPF_DIR" ]; then
    echo "ERROR: eBPF directory not found"
    exit 1
fi

# Check for Rust
if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: Rust not installed"
    echo "Install with: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Validate kernel environment
if [ ! -f "/sys/kernel/btf/vmlinux" ]; then
    echo "WARNING: Kernel BTF not detected. eBPF may not work (will fall back to /proc)"
fi

# Check if we have the required toolchain
if ! rustup toolchain list 2>/dev/null | grep -q "nightly"; then
    echo "Installing nightly toolchain..."
    rustup toolchain install nightly
fi

if ! rustup component list --toolchain nightly 2>/dev/null | grep -q "rust-src"; then
    echo "Installing rust-src for nightly..."
    rustup component add rust-src --toolchain nightly
fi

# Build eBPF program
cd "$EBPF_DIR"

# Ensure bpf-linker is in PATH
export PATH="$HOME/.cargo/bin:$PATH"

echo "Running cargo build..."
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core

# Check and prepare the binary
SRC_BIN="target/bpfel-unknown-none/release/bastion-ebpf"
DST_BIN="target/bpfel-unknown-none/release/bastion-ebpf.o"

if [ -f "$SRC_BIN" ]; then
    cp "$SRC_BIN" "$DST_BIN"
    echo "✅ eBPF program built successfully"
    ls -la "$DST_BIN"
else
    echo "❌ Failed to build eBPF program"
    exit 1
fi