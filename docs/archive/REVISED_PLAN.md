# Bastion Firewall – Comprehensive Implementation Plan

## Status
**Current State:** System is stable but accumulates duplicate iptables rules.
**Goal:** Fix stability issues, implement robust monitoring, and upgrade identification mechanism to eBPF.
**Timeline:** Phases 1-3 (Immediate), Phase 4 (Next Sprint)

## Phase 1: Fix iptables Rule Management (High Priority)
**Objective:** Ensure iptables rules are idempotent and do not accumulate duplicates.

### 1.1 Backend Core Updates (`bastion/firewall_core.py`)
- [x] **Rewrite `cleanup_nfqueue()`**:
    - Modify command to remove **ALL** instances of `BASTION_BYPASS` and `NFQUEUE` rules, not just the first match.
    - Loop until `iptables -D` returns failure (indicating no more rules).
- [x] **Update `setup_nfqueue()`**:
    - Enforce a "Clean First" policy: Always call `cleanup_nfqueue()` before adding new rules.
    - Verify rule count after addition to ensure exactly one instance exists.

### 1.2 Verification
- [x] Create a regression test script (`verify_fix.py`) that:
    - Restarts the daemon 10 times.
    - Checks `iptables -L OUTPUT -n -v` to ensure rule count remains constant (3 rules: 1 NFQUEUE, 2 BYPASS).
- [x] Run verification script (Confirmed: 0 duplicates found).

---

## Phase 2: System Health & Resilience (High Priority)
**Objective:** Improve daemon reliability and observability using Systemd features.

### 2.1 Systemd Integration
- [x] **Watchdog Support**:
    - Integrate `sd_notify` in the daemon main loop.
    - Configure `WatchdogSec=` in the systemd service file.
    - Allow systemd to restart the process automatically if it hangs.
- [x] **Restart Policy**:
    - Ensure `Restart=on-failure` and `RestartSec=5s` are correctly configured.

### 2.2 Internal Monitoring
- [x] **Rule Count Monitor**:
    - Add a periodic check (every 1 min) inside the daemon to verify iptables rule integrity.
    - Log warnings if rules are missing or duplicated.

---

## Phase 3: Crash Detection & User Notification (Medium Priority)
**Objective:** Turn the "crash on overload" behavior into a managed user experience.

### 3.1 Detection Logic
- [x] **Rate Limiting**:
    - Refine the existing popup overload detection (implemented in `bastion/daemon.py`).
    - Instead of a silent crash, trigger a specific "Emergency Mode" (dropping packets).

### 3.2 User Notification
- [x] **Notification System**:
    - Before exiting/entering safeguarding mode, send a desktop notification:
      > "Bastion Firewall detected abnormal network activity and has temporarily paused connections to protect your system."
- [x] **GUI Feedback**:
    - Update the Tray Icon/MainWindow to show a "Safeguard Mode" indicator if the daemon is in this state (Implemented via Tray Notification).

---

## Phase 4: eBPF Process Identification (High Priority)
**Objective:** Replace `/proc` scanning with kernel-level event tracing for perfect accuracy and performance.

### 4.1 Preparation
- [x] Verify kernel support for eBPF on target OS (Zorin OS 18 / Ubuntu 24.04).
- [x] Install necessary dependencies (`bcc-tools`, `python3-bpfcc` or `libbpf`).

### 4.2 Implementation
- [x] **Kernel Probe**:
    - Write a BPF program to hook `tcp_connect`, `udp_sendmsg`, and `tcp_close`.
    - Use `BPF_LRU_HASH` to store `IP:Port -> PID` mappings efficiently.
- [x] **Daemon Integration**:
    - Modify `bastion/firewall.py` (via `firewall_core.py`) to check the BPF Map.
    - Implemented Hybrid Approach:
        - eBPF provides fast, race-free `Socket -> PID` and `Command Name`.
        - Userspace (`psutil`) resolves `PID -> Full Path` (fallback to Command Name if process dies).
- [x] **Fallback Mechanism**:
    - Maintains legacy `/proc` method if eBPF fails to load.

---

## Success Criteria
- [ ] **Zero Duplicates**: iptables rules remain clean after multiple restarts.
- [ ] **Self-Healing**: Systemd automatically recovers the daemon if it hangs.
- [ ] **User Awareness**: Users are notified if the firewall engages safety countermeasures.
- [ ] **High Performance**: Process identification uses eBPF where available, reducing CPU usage and latency.
