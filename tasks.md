# Bastion Firewall - Implementation Tasks

> Generated: 2025-12-29  
> Based on analysis of `PLAN.md` vs actual codebase

---

## Implementation Status Overview

| Feature | PLAN.md Status | Actual Status | Notes |
|---------|---------------|---------------|-------|
| IPv4 TCP (tcp_v4_connect) | ✅ | ✅ Implemented | Working kprobe |
| IPv4 UDP (udp_sendmsg) | ✅ | ✅ Implemented | Working kprobe |
| IPv6 TCP (tcp_v6_connect) | ✅ Sprint 1 | ❌ **Not Implemented** | Missing kprobe |
| IPv6 UDP (udpv6_sendmsg) | ✅ Sprint 1 | ❌ **Not Implemented** | Missing kprobe |
| Kretprobes | ✅ Sprint 2 | ❌ **Not Implemented** | No return probes |
| /proc caching | ✅ Sprint 2 | ✅ Implemented | 100ms TTL in ProcessCache |
| eBPF map caching | - | ✅ Implemented | 5s TTL in EbpfManager |
| Root process exe in eBPF | ✅ Sprint 1 | ❌ **Not Implemented** | Only captures PID/timestamp |
| Process tree (ppid) | ⚠️ Sprint 3 | ❌ **Not Implemented** | No parent tracking |
| Binary checksums (SHA256) | ⚠️ Sprint 3 | ❌ **Not Implemented** | No hash verification |
| Command-line arguments | ⚠️ Sprint 3 | ❌ **Not Implemented** | No cmdline capture |
| Connection logging | ⚠️ Sprint 3 | ❌ **Not Implemented** | No forensic logs |
| Container detection | ⚠️ Phase 3 | ❌ **Not Implemented** | No namespace checks |

**Legend:** ✅ Done | ❌ Missing | ⚠️ Low Priority

---

## Phase 1: Core Identification (Priority: HIGH)

### 1.1 IPv6 Support
**Expected improvement: +15-20% identification rate**

- [ ] **eBPF: Add `tcp_v6_connect` kprobe**
  - File: `bastion-rs/ebpf/src/main.rs`
  - Add kprobe function for IPv6 TCP connections
  - Extract IPv6 destination from `struct sockaddr_in6`
  - Store in SOCKET_MAP (needs IPv6-compatible key structure)

- [ ] **eBPF: Add `udpv6_sendmsg` kprobe**
  - File: `bastion-rs/ebpf/src/main.rs`
  - Add kprobe function for IPv6 UDP messages
  - Parse `msghdr` with IPv6 sockaddr

- [ ] **Data structures: Support IPv6 addresses**
  - File: `bastion-rs/ebpf/src/main.rs`
  - Option A: Extend `SocketKey.dst_ip` from `u32` to `[u8; 16]`
  - Option B: Create separate `SOCKET_MAP_V6` for IPv6

- [ ] **Loader: Attach IPv6 kprobes**
  - File: `bastion-rs/src/ebpf_loader.rs`
  - Add program loading for `tcp_v6_connect`
  - Add program loading for `udpv6_sendmsg`

- [ ] **Lookup: Handle IPv6 in PID resolution**
  - File: `bastion-rs/src/ebpf_loader.rs`
  - Modify `lookup_pid()` to accept IPv6 addresses
  - Query appropriate map based on IP version

### 1.2 Root Process Identification in eBPF
**Expected improvement: +10-15% identification rate**

- [ ] **eBPF: Capture executable path in kernel**
  - File: `bastion-rs/ebpf/src/main.rs`
  - Extend `SocketInfo` to include `exe_path: [u8; 256]`
  - Use `bpf_get_current_task()` to read task struct
  - Extract exe path from `task->mm->exe_file->f_path`
  - Requires BTF (BPF Type Format) for CO-RE

- [ ] **Loader: Parse exe_path from eBPF map**
  - File: `bastion-rs/src/ebpf_loader.rs`
  - Update `SocketInfo` struct to match eBPF
  - Return exe_path along with PID

---

## Phase 2: Refinement (Priority: MEDIUM)

### 2.1 Kretprobes (Return Probes)
**Expected improvement: +5% accuracy**

- [ ] **eBPF: Add `tcp_v4_connect` return probe**
  - File: `bastion-rs/ebpf/src/main.rs`
  - Add `#[kretprobe]` function
  - Check return value; if failed, remove entry from map
  - Mark as confirmed if succeeded

- [ ] **eBPF: Add `tcp_v6_connect` return probe**
  - Same pattern as IPv4

- [ ] **Loader: Attach kretprobes**
  - File: `bastion-rs/src/ebpf_loader.rs`
  - Load and attach return probes

### 2.2 /proc Caching Optimization
**Status: Already partially implemented**

- [x] **ProcessCache with TTL** - 100ms refresh in `process.rs`
- [x] **EbpfManager local cache** - 5s TTL in `ebpf_loader.rs`
- [ ] **Increase eBPF map size** - Currently 10240, consider 65536 for high traffic

---

## Phase 3: Advanced Features (Priority: LOW)

### 3.1 Process Tree Tracking

- [ ] **Extend ProcessInfo struct**
  - File: `bastion-rs/src/process.rs`
  - Add `ppid: u32`
  - Add `parent_name: String`
  - Add `process_tree: Vec<String>`

- [ ] **Implement get_process_tree()**
  - File: `bastion-rs/src/process.rs`
  - Walk `/proc/PID/status` for `PPid:` field
  - Build chain: `[init → ... → parent → process]`

- [ ] **Update GUI popup**
  - Show parent process chain
  - Help user identify suspicious spawn patterns

### 3.2 Binary Checksums (SHA256)

- [ ] **Add sha2 crate dependency**
  - File: `bastion-rs/Cargo.toml`
  - Add `sha2 = "0.10"`

- [ ] **Extend ProcessInfo struct**
  - File: `bastion-rs/src/process.rs`
  - Add `binary_sha256: Option<String>`

- [ ] **Implement hash calculation**
  - File: `bastion-rs/src/process.rs`
  - Hash exe file when path is known
  - Cache hash per (path, mtime) to avoid re-hashing

- [ ] **Store hash in rules**
  - File: `bastion-rs/src/rules.rs`
  - Add `binary_hash` field to rule structure
  - Verify hash on rule match
  - Warn if hash changed: "Binary modified!"

### 3.3 Command-Line Arguments

- [ ] **Capture cmdline**
  - File: `bastion-rs/src/process.rs`
  - Read `/proc/PID/cmdline`
  - Split on null bytes

- [ ] **Extend ProcessInfo**
  - Add `cmdline: Vec<String>`

- [ ] **Show in popup**
  - Display full command for context

### 3.4 Connection Logging

- [ ] **Create logging module**
  - File: `bastion-rs/src/connection_log.rs` (new)
  - Log format: JSON with timestamp, PID, process, user, destination, decision
  - Rotate daily, keep 7 days

- [ ] **Integrate with packet handler**
  - Log every allow/block decision
  - Include all available process context

### 3.5 Container Detection

- [ ] **Detect containerized processes**
  - File: `bastion-rs/src/process.rs`
  - Compare `/proc/PID/ns/pid` with `/proc/1/ns/pid`
  - Read container runtime metadata if different

- [ ] **Show container name in popup**
  - "Process: nginx (container: myapp_web_1)"

---

## Testing Checklist

### Unit Tests
- [ ] IPv6 address parsing in `parse_hex_address()`
- [ ] Process tree building
- [ ] SHA256 hash calculation

### Integration Tests
```bash
# IPv4 TCP
curl https://example.com

# IPv6 TCP (requires IPv6 connectivity)
curl -6 https://ipv6.google.com

# IPv4 UDP
dig @8.8.8.8 example.com

# IPv6 UDP
dig @2001:4860:4860::8888 example.com

# Root process
sudo systemctl restart systemd-resolved

# Short-lived process
curl https://example.com &
```

### Success Metrics Target

| Scenario | Current | Target |
|----------|---------|--------|
| IPv4 TCP | ~70% | 95% |
| IPv4 UDP | ~65% | 90% |
| IPv6 TCP | 0% | 95% |
| IPv6 UDP | 0% | 90% |
| Root processes | ~40% | 85% |
| Short-lived (<10ms) | ~30% | 70% |

---

## Recommended Implementation Order

1. **IPv6 kprobes** (biggest impact, clear path)
2. **Kretprobes** (quick win, cleaner data)
3. **Process tree** (better UX, moderate effort)
4. **Binary checksums** (security hardening)
5. **Connection logging** (forensics)
6. **Root exe in eBPF** (complex, requires BTF/CO-RE)
7. **Container detection** (nice to have)

---

## Files to Modify

| File | Changes |
|------|---------|
| `bastion-rs/ebpf/src/main.rs` | IPv6 kprobes, kretprobes, exe_path capture |
| `bastion-rs/src/ebpf_loader.rs` | Attach new probes, IPv6 lookup |
| `bastion-rs/src/process.rs` | ProcessInfo extensions, tree, hash, cmdline |
| `bastion-rs/src/rules.rs` | Binary hash verification |
| `bastion-rs/Cargo.toml` | sha2 dependency |
| `bastion-rs/src/connection_log.rs` | New file for forensic logging |
