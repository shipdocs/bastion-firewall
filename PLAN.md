# Bastion Firewall - Process Identification Improvement Plan

**Goal:** Achieve near-perfect process identification to eliminate "unknown" processes and strengthen application firewall security.

**Inspiration:** OpenSnitch (https://github.com/evilsocket/opensnitch) - proven eBPF application firewall

---

## Current State Analysis

### What Works Well ✅
- **eBPF captures ~60-70% of connections** using kprobes on:
  - `tcp_v4_connect` (IPv4 TCP)
  - `udp_sendmsg` (IPv4 UDP)
- **/proc fallback** catches some processes eBPF misses
- **Fast lookup** (<1μs for eBPF hits)
- **Dedup prevents popup spam**
- **Security fix**: No permanent rules for unknown processes

### Current Problems ❌

1. **30-40% "unknown" processes** - Security risk when user can't identify what's connecting
2. **IPv4 only** - All IPv6 traffic shows as unknown
3. **No IPv6 support** - Missing `tcp_v6_connect`, `udpv6_sendmsg` kprobes
4. **Race conditions** - Short-lived processes exit before /proc lookup
5. **Root process identification fails** - Permission denied on `/proc/PID/exe` for root-owned processes
6. **No kretprobes** - Missing some edge cases where entry probe doesn't capture info
7. **Limited process context** - Only PID, name, path, UID (no parent, args, binary hash)

---

## Improvement Plan - Phase 1: Core Identification

### 1.1 Add IPv6 Support 🎯 **HIGH PRIORITY**

**Problem:** All IPv6 connections show as "unknown"

**Solution:** Add kprobes for IPv6 functions (like OpenSnitch does)

**Implementation:**
```rust
// bastion-rs/ebpf/src/main.rs

#[kprobe]
pub fn tcp_v6_connect(ctx: ProbeContext) -> u32 {
    // Similar to tcp_v4_connect but for IPv6
    // Extract IPv6 destination from struct sockaddr_in6
}

#[kprobe]
pub fn udpv6_sendmsg(ctx: ProbeContext) -> u32 {
    // Similar to udp_sendmsg but for IPv6
}
```

**Changes needed:**
- `ebpf/src/main.rs`: Add IPv6 kprobes
- Update `SocketKey` struct to support IPv6 addresses (use `[u8; 16]` or separate maps)
- `ebpf_loader.rs`: Attach new kprobes
- `main.rs`: Handle IPv6 packets from NFQUEUE

**Testing:**
```bash
# Test IPv6 connectivity
curl -6 https://ipv6.google.com
ping6 2001:4860:4860::8888
```

**Expected improvement:** +15-20% identification rate

---

### 1.2 Add Kretprobes (Return Probes) 🎯 **MEDIUM PRIORITY**

**Problem:** Some connections slip through if entry probe doesn't capture complete info

**Solution:** Hook function returns to catch edge cases (OpenSnitch approach)

**Implementation:**
```rust
// Entry probe - capture PID
#[kprobe]
pub fn tcp_v4_connect(ctx: ProbeContext) -> u32 {
    // Existing code
}

// Return probe - verify connection actually succeeded
#[kretprobe]
pub fn tcp_v4_connect_ret(ctx: ProbeContext) -> i32 {
    // Check return value
    // If connection failed (ret < 0), remove from map
    // If succeeded, mark as confirmed
}
```

**Why this helps:**
- Some connections are attempted but fail (DNS timeouts, refused connections)
- Kretprobes clean up failed attempts from the map
- Reduces false positives

**Expected improvement:** +5% accuracy (fewer false matches)

---

### 1.3 Improve Root Process Identification 🎯 **HIGH PRIORITY**

**Problem:** Can't read `/proc/PID/exe` for root-owned processes (permission denied)

**Current behavior:**
```
NetworkManager (root) → Can read /proc/PID/comm ✅
                     → Can't read /proc/PID/exe ❌
                     → Shows as "NetworkManager ()" with empty path
```

**Solutions:**

**Option A: Use process name matching (already implemented)**
```rust
// whitelist.rs - already done
if app_path.is_empty() && app_name == "NetworkManager" {
    return (true, "DNS (trusted)");
}
```

**Option B: Capture more info in eBPF** ⭐ **RECOMMENDED**
```rust
// Capture in kernel space (before privilege checks)
struct SocketInfo {
    pid: u32,
    uid: u32,
    comm: [u8; 16],      // Task name (always accessible)
    exe_path: [u8; 256], // Binary path (capture in kernel)
}
```

**Implementation:**
```c
// In eBPF program (kernel space)
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct mm_struct *mm = BPF_CORE_READ(task, mm);
struct file *exe_file = BPF_CORE_READ(mm, exe_file);
struct path exe_path_struct = BPF_CORE_READ(exe_file, f_path);
// Get d_name from dentry...
```

**Challenges:**
- Complex kernel struct traversal
- BTF (BPF Type Format) required
- Kernel version compatibility

**Expected improvement:** +10-15% (all root processes identified)

---

### 1.4 Process Tree Tracking 🎯 **LOW PRIORITY** (Nice to have)

**Problem:** Can't distinguish between:
- User manually running `curl https://example.com`
- Script running curl in background
- Malware spawning curl

**Solution:** Track parent processes (like OpenSnitch)

**Data structure:**
```rust
struct ProcessInfo {
    pid: u32,
    ppid: u32,          // Parent PID
    name: String,
    exe_path: String,
    uid: u32,
    parent_name: String, // NEW
    process_tree: Vec<String>, // NEW: ["bash", "script.sh", "curl"]
}
```

**Implementation:**
```rust
fn get_process_tree(pid: u32) -> Vec<String> {
    let mut tree = vec![];
    let mut current_pid = pid;

    while current_pid > 1 {
        if let Some(proc) = read_proc(current_pid) {
            tree.push(proc.name);
            current_pid = proc.ppid;
        } else {
            break;
        }
    }
    tree
}
```

**GUI enhancement:**
```
Popup shows:
┌─────────────────────────────────────┐
│ Process: curl                       │
│ Path: /usr/bin/curl                 │
│ Parent: bash → script.sh → curl    │
│ Destination: 1.2.3.4:443           │
└─────────────────────────────────────┘
```

**Expected improvement:** Better security context for user decisions

---

## Phase 2: Advanced Features

### 2.1 Binary Checksums/Hashes 🎯 **MEDIUM PRIORITY**

**Purpose:** Detect if binary has been modified (malware replacement)

**Implementation:**
```rust
use sha2::{Sha256, Digest};

struct ProcessInfo {
    // ... existing fields
    binary_sha256: String, // NEW
}

fn calculate_binary_hash(path: &str) -> Result<String, Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}
```

**Usage:**
- Store hash when creating rule
- Verify hash on subsequent connections
- Warn if hash changed: "Firefox binary has been modified! Block?"

**Security benefit:** Detects trojaned binaries

---

### 2.2 Command-Line Arguments 🎯 **LOW PRIORITY**

**Purpose:** Distinguish between different uses of same binary

**Example:**
```bash
curl https://legitimate-site.com  # User browsing
curl https://evil-c2-server.com   # Malware beacon
```

**Implementation:**
```rust
fn get_cmdline(pid: u32) -> Vec<String> {
    let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))?;
    cmdline.split('\0')
           .filter(|s| !s.is_empty())
           .map(String::from)
           .collect()
}
```

**Rule enhancement:**
```json
{
  "/usr/bin/curl:443": {
    "allow": true,
    "args_pattern": "https://trusted-domain.com/*"
  }
}
```

---

### 2.3 Connection Context Logging 🎯 **MEDIUM PRIORITY**

**Purpose:** Forensics and debugging

**Log format:**
```
[2025-12-29 01:30:45] CONNECTION
  PID: 1234
  Process: /usr/bin/firefox
  User: martin (UID 1000)
  Parent: gnome-shell (PID 987)
  Destination: 93.184.216.34:443 (example.com)
  Protocol: TCP/IPv4
  Decision: ALLOW (permanent rule)
  Binary SHA256: a1b2c3d4...
```

**Storage:** Rotate logs daily, keep last 7 days

---

## Phase 3: Performance & Edge Cases

### 3.1 eBPF Map Optimization

**Current:** Single map for all connections
**Problem:** May have hash collisions for high traffic

**Improvements:**
- Increase map size from 1024 to 8192 entries
- Separate maps per protocol (like OpenSnitch)
- LRU eviction policy for old entries

### 3.2 /proc Caching

**Problem:** Scanning /proc is slow (5-10ms)

**Solution:** Cache process info
```rust
struct ProcessCache {
    cache: HashMap<u32, (ProcessInfo, Instant)>,
    ttl: Duration,
}

impl ProcessCache {
    fn get_or_fetch(&mut self, pid: u32) -> Option<ProcessInfo> {
        if let Some((info, timestamp)) = self.cache.get(&pid) {
            if timestamp.elapsed() < self.ttl {
                return Some(info.clone());
            }
        }
        // Fetch from /proc and cache
        let info = self.fetch_from_proc(pid)?;
        self.cache.insert(pid, (info.clone(), Instant::now()));
        Some(info)
    }
}
```

### 3.3 Handle Container Processes

**Problem:** Containers (Docker, Podman) have different namespaces

**Detection:**
```rust
fn is_containerized(pid: u32) -> bool {
    let ns = fs::read_link(format!("/proc/{}/ns/pid", pid)).ok()?;
    let init_ns = fs::read_link("/proc/1/ns/pid").ok()?;
    ns != init_ns
}
```

**Solution:** Read container metadata, show container name in popup

---

## Implementation Priority

### Sprint 1: Core Identification (2-3 days)
1. ✅ **IPv6 support** - Biggest bang for buck (+20% identification)
2. ✅ **Root process exe path in eBPF** - Eliminate most unknowns (+15%)

### Sprint 2: Refinement (1-2 days)
3. ✅ **Kretprobes** - Cleaner edge case handling (+5% accuracy)
4. ✅ **/proc caching** - Performance improvement

### Sprint 3: Advanced (2-3 days)
5. ⚠️ **Process tree** - Better UX
6. ⚠️ **Binary checksums** - Security hardening
7. ⚠️ **Connection logging** - Forensics

---

## Testing Strategy

### Unit Tests
```rust
#[test]
fn test_ipv6_identification() {
    // Connect to IPv6 address
    // Verify process identified correctly
}

#[test]
fn test_root_process_capture() {
    // Spawn process as root
    // Verify exe_path captured in eBPF
}
```

### Integration Tests
```bash
#!/bin/bash
# Test various scenarios

# IPv4 TCP
curl https://example.com

# IPv6 TCP
curl -6 https://ipv6.google.com

# UDP
dig @8.8.8.8 example.com

# Short-lived process
curl https://example.com & # Should still identify

# Root process
sudo systemctl restart systemd-resolved
# Check if identified correctly
```

### Success Metrics

**Target:** Reduce "unknown" processes from 30-40% to <5%

| Scenario | Current | Target |
|----------|---------|--------|
| IPv4 TCP | 70% | 95% |
| IPv4 UDP | 65% | 90% |
| IPv6 TCP | 0% | 95% |
| IPv6 UDP | 0% | 90% |
| Root processes | 40% | 85% |
| Short-lived (<10ms) | 30% | 70% |

---

## Security Considerations

1. **No permanent rules for unknowns** ✅ Already implemented
2. **Binary hash verification** - Detect trojaned apps
3. **Audit logging** - Track all decisions for forensics
4. **Container isolation** - Don't let container processes bypass rules
5. **Kernel version compatibility** - Test on Ubuntu 22.04, 24.04, Debian 12

---

## References

- OpenSnitch source: https://github.com/evilsocket/opensnitch
- Linux eBPF docs: https://ebpf.io/
- BPF CO-RE (Compile Once, Run Everywhere): https://nakryiko.com/posts/bpf-core-reference-guide/
- Aya framework: https://aya-rs.dev/

---

## Next Steps

1. **Review this plan** - Get user approval
2. **Start with IPv6** - Highest impact, clear implementation path
3. **Measure before/after** - Track identification rate improvements
4. **Iterate** - Add features incrementally, test thoroughly

**End Goal:** A secure, reliable application firewall where users ALWAYS know what's connecting.
