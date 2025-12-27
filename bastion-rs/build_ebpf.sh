#!/bin/bash
set -e

echo ">>> Building eBPF program..."

# Check if we have the required toolchain
if ! rustup component list --installed | grep -q "rust-src"; then
    echo "Installing rust-src component..."
    rustup component add rust-src
fi

# Install cargo-bpf if not present
if ! command -v cargo-bpf &> /dev/null; then
    echo "Installing cargo-bpf..."
    cargo install cargo-bpf
fi

# Check for BTF support
if ! ls /sys/kernel/btf/vmlinux 2>/dev/null; then
    echo "Warning: No BTF support detected, eBPF may not work"
fi

# Build eBPF program
cd ebpf
cargo bpf build --release --target-dir=target

# Check if the binary was created
if [ -f "target/bpfel-unknown-none/release/bastion-ebpf.o" ]; then
    echo "✅ eBPF program built successfully"
    ls -la target/bpfel-unknown-none/release/bastion-ebpf.o
else
    echo "❌ Failed to build eBPF program"
    exit 1
fi