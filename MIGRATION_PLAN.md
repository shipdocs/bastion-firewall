# Bastion Firewall - Python to Rust Migration Plan

## STATUS: Phase 1-4 COMPLETE ✅

**Objective**: Replace the instability and runtime overhead of the Python-based daemon with a high-performance, statically compiled Rust binary, while preserving the existing Python GUI for a smooth transition.

## What's Done
- ✅ **Phase 1**: Packet interception via NFQUEUE
- ✅ **Phase 2**: Process identification via /proc
- ✅ **Phase 3**: Rule loading and config management
- ✅ **Phase 4**: IPC module skeleton for GUI

## What's Left
- 🔲 Wire up IPC server with packet handler
- 🔲 Test with existing Python GUI
- 🔲 Create systemd service
- 🔲 Build Debian package


## Why Rust?
- **Stability**: No more `RuntimeError`, `NameError`, or Python dependency hell (`pip` vs `apt`).
- **Performance**: Zero-overhead packet inspection. No Python interpreter lag on every network packet.
- **Distribution**: Compiles to a single binary `bastion-daemon` that runs anywhere without installing 50+ packages.
- **Safety**: Thread-safety and memory safety guaranteed at compile time.

---

## Phase 0: Environment Setup
**Goal**: Get the development environment ready.

1.  **Install Rust Toolchain**:
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
2.  **Initialize Rust Project**:
    - Create `bastion-binder` (or `bastion-core`) alongside the python `bastion` folder.
    - Workspace structure:
      ```text
      /bastion-firewall
        /bastion (Legacy Python)
        /bastion-rs (New Rust Core)
          Cargo.toml
          src/main.rs
      ```

---

## Phase 1: The "Interceptor" Prototype (Packet Core)
**Goal**: Replicate `firewall_core.py` (PacketProcessor) in Rust.

**Tasks**:
1.  **NFQUEUE Integration**:
    - Use crate `nfqueue` or `nfq`.
    - Create a binary that listens on Queue 1 and just prints packet info (Size, IP headers).
    - *Success Criteria*: Running the binary and generating traffic shows logs in stdout.
2.  **Packet Parsing**:
    - Use crate `etherparse` or `pnet` (lighter than Scapy) to extract:
      - Source/Dest IP
      - Source/Dest Port
      - Protocol (TCP/UDP)
3.  **Verdict Handling**:
    - Implement `accept()` and `drop()` logic.
    - *Success Criteria*: Can block all ping requests while allowing web traffic.

**Estimated Time**: 1-2 Days

---

## Phase 2: Application Identification (The Hard Part)
**Goal**: Replicate `ApplicationIdentifier` class (mapping Sockets to PIDs/Exes).

**Tasks**:
1.  **ProcFS Scanning** (Legacy Mode):
    - Implement reading `/proc/net/tcp` and `/proc/net/udp` directly (much faster than `psutil`).
    - Map `inode` from socket to PID by iterating `/proc/[pid]/fd`.
2.  **Netlink / SockDiag** (Performance Mode):
    - Use `netlink-packet-sock-diag` crate to query the kernel directly for socket ownership (faster than parsing text files).
3.  **Caching**:
    - Implement a `TTL Cache` (HashMap with timestamps) similar to the Python version to avoid scanning for every packet.

**Estimated Time**: 2-3 Days

---

## Phase 3: The Sentinel Daemon (Control Plane)
**Goal**: Replicate `daemon.py` (The Socket Server & Logic).

**Tasks**:
1.  **Unix Socket Server**:
    - Use `tokio::net::UnixListener` to listen on `/var/run/bastion/bastion-daemon.sock`.
    - **Critical**: Ensure the JSON protocol matches the *exact* format the Python GUI expects.
      - `{"type": "connection_request", ...}`
      - `{"type": "stats_update", ...}`
2.  **Configuration & State**:
    - Use `serde_json` to read `config.json` and `rules.json`.
    - Implement `ConfigManager` and `RuleManager` structs.
3.  **Concurrency**:
    - Run the **Packet Listener** and **Socket Server** in separate Async Tasks (`tokio::spawn`).
    - Use `Arc<Mutex<State>>` to share stats and rules between the packet processor and the GUI thread.

**Estimated Time**: 3-4 Days

---

## Phase 4: The Hybrid Merger
**Goal**: Ship Rust Backend + Python Frontend.

**Tasks**:
1.  **Build System Update**:
    - Modify `build_deb.sh` to compile the Rust binary.
    - Replace the `bastion-daemon` python entry point with the compiled binary.
2.  **GUI Compat Check**:
    - Test the existing Python GUI against the Rust daemon.
    - Fix any JSON serialization mismatches.
3.  **Removal**:
    - Delete `bastion/daemon.py`, `bastion/firewall_core.py`, `bastion/ebpf.py`.

**Estimated Time**: 1 Day

---

## Phase 5: Future (Pure Rust)
**Goal**: (Optional) Rewrite GUI.
- Move from Qt/Python to **Tauri** (uses web tech) or **Iced** (Pure Rust).
- This is not urgent if the Hybrid model works well.
