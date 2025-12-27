#!/bin/bash
set -e

# FIX #13: Use absolute paths to avoid CWD assumptions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EBPF_DIR="$SCRIPT_DIR/ebpf"

echo ">>> Building eBPF program with Aya..."
echo "Script directory: $SCRIPT_DIR"
echo "eBPF directory: $EBPF_DIR"

# Check if eBPF directory exists
if [ ! -d "$EBPF_DIR" ]; then
    echo "ERROR: eBPF directory not found at $EBPF_DIR"
    echo "Please run this script from the bastion-rs directory"
    exit 1
fi

# Check if we have the required toolchain
if ! rustup toolchain list | grep -q "nightly"; then
    echo "Installing nightly toolchain..."
    rustup toolchain install nightly
fi

if ! rustup component list --toolchain nightly | grep -q "rust-src"; then
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