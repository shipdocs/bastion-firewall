# DNS Implementation Plan - Corrections & Errata

**Date:** 2025-01-10
**Status:** Critical Fixes Required
**Applies to:** [DNS_IMPLEMENTATION_PLAN.md](./DNS_IMPLEMENTATION_PLAN.md)

---

## 🚨 Critical Issues Found

Based on code review, the following issues in the original plan **must be fixed** before implementation.

---

## Issue 1: eBPF String Handling is Invalid

**Location:** Original Plan Section 3.2, lines 340-370

### Problem

The `extract_domain_from_dns()` function uses operations that **don't exist in eBPF**:

```rust
// ❌ BROKEN CODE - Does NOT work in eBPF
fn extract_domain_from_dns(packet: &[u8]) -> Result<&str, i32> {
    let mut domain = String::new();  // ❌ Heap allocation
    domain.push('.');                // ❌ Dynamic memory
    domain.push_str(...);            // ❌ Heap allocation
    Ok(domain.leak())                // ❌ leak() not available
}
```

**Why it fails:**
- eBPF runs in kernel space with **no heap allocator**
- All data structures must be **fixed-size** on the stack
- eBPF verifier requires **bounded loops** with max iteration counts
- String operations require dynamic memory allocation

### Corrected Implementation

```rust
// ✅ CORRECT - eBPF-compatible domain extraction
// Returns: Hash of domain (for map key) + length (for display)
fn extract_domain_hash_from_dns(
    packet: &[u8],
    domain_buf: &mut [u8; 64]
) -> Result<(u32, u32), i32> {
    // Skip DNS header (12 bytes)
    if packet.len() < 13 {
        return Err(1);
    }

    let mut pos = 12;
    let mut buf_pos = 0;
    let mut hash: u32 = 0xDEADBEEF;

    // Max 8 labels (eBPF verifier needs unrollable loop)
    #[allow(unused_comparisons)]
    for _label_idx in 0..8 {
        if pos >= packet.len() as u32 {
            break;
        }

        let label_len = packet[pos as usize] as u32;

        if label_len == 0 {
            break;  // End of domain name
        }

        // Safety check
        if pos + 1 + label_len > packet.len() as u32 {
            return Err(1);  // Packet truncated
        }

        // Add dot separator (except first label)
        if buf_pos > 0 && buf_pos < 63 {
            domain_buf[buf_pos as usize] = b'.';
            buf_pos += 1;
        }

        // Copy label characters
        let mut i = 0u32;
        while i < label_len && buf_pos < 63 {
            domain_buf[buf_pos as usize] = packet[(pos + 1 + i) as usize];
            // Update hash (FNV-1a variant, eBPF-friendly)
            hash = hash ^ domain_buf[buf_pos as usize] as u32;
            hash = hash.wrapping_mul(0x01000193);
            buf_pos += 1;
            i += 1;
        }

        pos += 1 + label_len;
    }

    // Null-terminate
    if buf_pos < 64 {
        domain_buf[buf_pos as usize] = 0;
    }

    Ok((hash, buf_pos))
}
```

### Usage in eBPF Program

```rust
// In udp_sendmsg handler
fn handle_dns_query(ctx: &KProbe, pid: u32, msg_ptr: u64) -> Result<(), i32> {
    let mut dns_buf = [0u8; 512];  // Packet buffer
    let mut domain_buf = [0u8; 64]; // Domain name buffer

    // Read DNS packet from userspace
    if let Err(_) = read_dns_packet(ctx, msg_ptr, &mut dns_buf) {
        return Err(1);
    }

    // Extract domain hash
    let (domain_hash, domain_len) = extract_domain_hash_from_dns(
        &dns_buf,
        &mut domain_buf
    )?;

    // Get process name
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    // Store in map (using hash as key)
    let key = DnsQueryKey {
        domain_hash,
        _pad: [0u8; 4],
    };

    let value = DnsQueryValue {
        pid,
        comm,
        timestamp: bpf_ktime_get_ns(),
        // We can't store full domain in eBPF map (too large)
        // Userspace will reverse-lookup when needed
    };

    unsafe {
        DNS_QUERY_MAP.insert(&key, &value, 0);
    }

    Ok(())
}
```

### Userspace Reverse Lookup

```rust
// In bastion-rs/src/process.rs

impl DnsCache {
    /// When polling eBPF maps, we also track hash → domain mappings
    pub fn insert_from_ebpf(
        &mut self,
        domain_hash: u32,
        pid: u32,
        comm: String,
        domain_hint: Option<String>,  // If available from other sources
    ) {
        let entry = DnsQueryEntry {
            domain: domain_hint.unwrap_or_else(|| {
                format!("<hash:{}>", domain_hash)  // Fallback
            }),
            process_name: comm.clone(),
            pid,
            exe_path: String::new(),  // Fill in later
            timestamp: Instant::now(),
        };

        // Store by hash
        self.hash_to_entry.insert(domain_hash, entry);
    }

    /// Verify hash matches before trusting the entry
    pub fn verify_hash(&self, domain_hash: u32, domain: &str) -> bool {
        let computed = jhash_string(domain);
        computed == domain_hash
    }
}

fn jhash_string(domain: &str) -> u32 {
    let mut hash: u32 = 0xDEADBEEF;
    for byte in domain.bytes() {
        hash = hash ^ byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}
```

---

## Issue 2: getaddrinfo Requires Uprobe, Not Kprobe

**Location:** Original Plan Section 3.2, Phase 1

### Problem

`getaddrinfo()` is a **userspace libc function**, not a kernel function.
- `kprobe` hooks kernel functions only
- Need `uprobe` to hook userspace functions
- Different distros have different libc paths

### Corrected Approach

#### Option A: Use Uprobe (More Complex)

```rust
// ✅ CORRECT - Using uprobe for getaddrinfo
// Requires: Aya's Uprobe support

// In eBPF program
#[uprobe]
fn getaddrinfo_entry(ctx: UprobeContext) -> u32 {
    // getaddrinfo(const char *node, const char *service,
    //             const struct addrinfo *hints,
    //             struct addrinfo **res)

    let node_ptr = unsafe {
        let regs = ctx.regs;
        if regs.is_null() { return 0; }
        // For uprobe, first arg is in rdi (x86_64)
        (*regs).rdi
    };

    if node_ptr == 0 { return 0; }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // Read domain string (first 64 bytes)
    let mut domain_buf = [0u8; 64];
    let _ = bpf_probe_read_user_str(
        node_ptr,
        &mut domain_buf as *mut _ as *mut u8,
        64
    );

    let hash = jhash(&domain_buf);

    let key = DnsQueryKey {
        domain_hash: hash,
        _pad: [0u8; 4],
    };

    let value = DnsQueryValue {
        pid,
        comm,
        timestamp: bpf_ktime_get_ns(),
    };

    unsafe {
        let _ = DNS_QUERY_MAP.insert(&key, &value, 0);
    }

    0
}

// In userspace loader (bastion-rs/src/ebpf_loader.rs)
pub fn attach_getaddrinfo_uprobe(&mut self) -> Result<(), anyhow::Error> {
    use aya::programs::Uprobe;

    // Find libc path
    let libc_path = find_libc_path()?;
    info!("Attaching getaddrinfo uprobe to: {}", libc_path);

    let bpf = self.bpf.as_mut().ok_or(anyhow!("eBPF not loaded"))?;

    let program: &mut Uprobe = bpf
        .program_mut("getaddrinfo_entry")
        .ok_or(anyhow!("getaddrinfo_entry program not found"))?
        .try_into()?;

    program.load()?;

    // Attach to getaddrinfo in libc
    program
        .target(&libc_path)
        .offset(getaddrinfo_offset(&libc_path)?)  // Need to find symbol offset
        .attach()?;

    info!("✓ getaddrinfo uprobe attached");
    Ok(())
}

fn find_libc_path() -> Result<String, anyhow::Error> {
    // Try common locations
    let paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
    ];

    for path in &paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }

    // Fallback: read from /proc/self/maps
    let maps = std::fs::read_to_string("/proc/self/maps")?;
    for line in maps.lines() {
        if line.contains("libc.so.6") && line.contains("r-xp") {
            let path = line.split_whitespace().nth(5);
            if let Some(p) = path {
                return Ok(p.to_string());
            }
        }
    }

    Err(anyhow!("libc.so.6 not found"))
}

fn getaddrinfo_offset(libc_path: &str) -> Result<u64, anyhow::Error> {
    // Use nm or readelf to find symbol offset
    use std::process::Command;

    let output = Command::new("nm")
        .arg("-D")
        .arg(libc_path)
        .output()?;

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.contains("getaddrinfo") {
            let offset_str = line.split_whitespace().next();
            if let Some(s) = offset_str {
                return Ok(u64::from_str_radix(s, 16)?);
            }
        }
    }

    Err(anyhow!("getaddrinfo symbol not found"))
}
```

#### Option B: Skip Phase 1, Start with Phase 2 (Recommended)

**Reasoning:**
- Uprobe attachment is complex and distro-specific
- UDP port 53 detection (Phase 2) is more reliable
- Most apps use standard DNS queries anyway
- Can add Phase 1 later if needed

---

## Issue 3: Missing DNS Response Parsing

**Location:** Original Plan Section 3.2, Phase 2

### Problem

Phase 2 only captures **DNS queries** (domain name) but doesn't parse **DNS responses** (IP addresses).

**Without DNS responses:**
- ✅ We know: "chrome queried api.github.com"
- ❌ We don't know: "api.github.com resolved to 140.82.112.3"
- ❌ Result: Can't map IP → process when connection happens

### Solution: Add DNS Response Handler

```rust
// ✅ NEW - Parse DNS responses to get IP addresses
#[kprobe]
fn udp_recvmsg(ctx: KProbe) -> u32 {
    // This is called when receiving UDP packet (DNS response)

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // We need to:
    // 1. Check if this is DNS (src_port == 53)
    // 2. Parse DNS response packet
    // 3. Extract transaction ID (TXID) to match with query
    // 4. Extract IP addresses from A/AAAA records
    // 5. Store IP → process mapping

    let sk = unsafe {
        let regs = ctx.regs;
        if regs.is_null() { return 0; }
        (*regs).rdi  // struct sock *sk
    };

    if sk == 0 { return 0; }

    // Get source port from sock structure
    let src_port = read_sock_src_port(sk);

    if src_port != 53 {
        return 0;  // Not DNS
    }

    // Read UDP packet
    let msg_ptr = unsafe {
        let regs = ctx.regs;
        if regs.is_null() { return 0; }
        (*regs).rsi  // struct msghdr *
    };

    if msg_ptr == 0 { return 0; }

    let mut dns_buf = [0u8; 512];
    if let Err(_) = read_udp_packet(ctx, msg_ptr, &mut dns_buf) {
        return 0;
    }

    // Parse DNS response header
    if dns_buf.len() < 12 {
        return 0;
    }

    // Check if response (QR bit = 1)
    let flags = u16::from_be_bytes([dns_buf[2], dns_buf[3]]);
    if (flags & 0x8000) == 0 {
        return 0;  // Not a response
    }

    let txid = u16::from_be_bytes([dns_buf[0], dns_buf[1]]);

    // Find matching query in DNS_TX_MAP
    let src_addr = read_sock_src_addr(sk);
    let src_port = read_sock_src_port(sk);  // Client's port (not 53)

    let tx_key = DnsTxKey {
        txid,
        src_port,
        _pad: [0u8; 4],
    };

    let tx_value = unsafe {
        match DNS_TX_MAP.get(&tx_key, 0) {
            Ok(v) => v,
            Err(_) => return 0,  // No matching query
        }
    };

    // Extract IP addresses from DNS response
    let mut answer_count = u16::from_be_bytes([dns_buf[6], dns_buf[7]]);
    let mut pos = 12;

    // Skip question section
    let qdcount = u16::from_be_bytes([dns_buf[4], dns_buf[5]]);
    for _ in 0..qdcount {
        // Skip domain name
        while pos < dns_buf.len() && dns_buf[pos] != 0 {
            let label_len = dns_buf[pos] as usize;
            if label_len == 0 { break; }
            pos += 1 + label_len;
        }
        pos += 5;  // Skip null byte, QTYPE, QCLASS
    }

    // Parse answer section
    #[allow(unused_comparisons)]
    for _i in 0..20 {  // Max 20 answers (eBPF verifier limit)
        if answer_count == 0 || pos >= dns_buf.len() as u16 {
            break;
        }

        // Skip domain name (might be compressed)
        if dns_buf[pos] & 0xC0 == 0xC0 {
            // Compressed name pointer
            pos += 2;
        } else {
            // Full domain name
            while pos < dns_buf.len() && dns_buf[pos] != 0 {
                let label_len = dns_buf[pos] as usize;
                pos += 1 + label_len;
            }
            pos += 1;  // Null terminator
        }

        if pos + 10 > dns_buf.len() {
            break;
        }

        // Read TYPE, CLASS, TTL, RDLENGTH
        let rr_type = u16::from_be_bytes([dns_buf[pos], dns_buf[pos + 1]]);
        // pos += 2;  // TYPE
        // pos += 2;  // CLASS
        // let _ttl = u32::from_be_bytes([
        //     dns_buf[pos + 4], dns_buf[pos + 5],
        //     dns_buf[pos + 6], dns_buf[pos + 7]
        // ]);
        let rdlen = u16::from_be_bytes([dns_buf[pos + 8], dns_buf[pos + 9]]);
        pos += 10;

        // Check if A record (IPv4)
        if rr_type == 1 && rdlen == 4 && pos + 4 <= dns_buf.len() {
            let ip = u32::from_be_bytes([
                dns_buf[pos],
                dns_buf[pos + 1],
                dns_buf[pos + 2],
                dns_buf[pos + 3],
            ]);

            // Store IP → process mapping
            let ip_key = DnsIpKey {
                ip,
                _pad: [0u8; 4],
            };

            let ip_value = DnsIpValue {
                pid: tx_value.pid,
                comm: tx_value.comm,
                domain_hash: tx_value.domain_hash,
                timestamp: bpf_ktime_get_ns(),
                ttl: 60,  // Default TTL (should parse from response)
            };

            unsafe {
                let _ = DNS_IP_MAP.insert(&ip_key, &ip_value, 0);
            }
        }

        // Check if AAAA record (IPv6)
        if rr_type == 28 && rdlen == 16 && pos + 16 <= dns_buf.len() {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&dns_buf[pos..pos + 16]);

            // Would need separate map for IPv6
            // For now, skip or log
        }

        pos += rdlen as u32;
        answer_count -= 1;
    }

    // Clean up transaction entry
    unsafe {
        let _ = DNS_TX_MAP.delete(&tx_key);
    }

    0
}

// Also need to store transaction info when sending query
#[kprobe]
fn udp_sendmsg(ctx: KProbe) -> i32 {
    // ... existing code ...

    // NEW: Also check if this is DNS query and store TXID
    if dst_port == 53 {
        let mut dns_buf = [0u8; 512];
        if read_udp_packet(ctx, msg_ptr, &mut dns_buf).is_ok() {
            if dns_buf.len() >= 12 {
                let txid = u16::from_be_bytes([dns_buf[0], dns_buf[1]]);

                // Extract domain hash
                let mut domain_buf = [0u8; 64];
                if let Ok((hash, _len)) = extract_domain_hash_from_dns(&dns_buf, &mut domain_buf) {
                    // Store transaction for later matching
                    let tx_key = DnsTxKey {
                        txid,
                        src_port: src_port,  // Client's source port
                        _pad: [0u8; 4],
                    };

                    let tx_value = DnsTxValue {
                        pid,
                        comm,
                        domain_hash: hash,
                    };

                    unsafe {
                        let _ = DNS_TX_MAP.insert(&tx_key, &tx_value, 0);
                    }
                }
            }
        }
    }

    // ... rest of existing code ...
}
```

---

## Issue 4: Hash Collision Risk

**Location:** Original Plan Section 3.2

### Problem

Using 32-bit hash for 10,000 entries:
- Collision probability: ~0.02% (1 in 5000)
- **Could cause misattribution** (chrome appears as firefox)

### Mitigation Strategy

```rust
// ✅ CORRECT - Verify hash in userspace before trusting

impl DnsCache {
    /// Insert with hash verification
    pub fn insert_with_verification(
        &mut self,
        domain_hash: u32,
        pid: u32,
        comm: String,
        domain_from_other_source: Option<String>
    ) -> Result<(), DnsCacheError> {
        // Check if we already have this hash
        if let Some(existing) = self.hash_to_entry.get(&domain_hash) {
            // Verify it's the same domain (collision detection)
            if let Some(domain) = domain_from_other_source {
                let computed = jhash_string(&domain);
                if computed != domain_hash {
                    return Err(DnsCacheError::HashCollision);
                }

                if existing.domain != domain {
                    warn!("Hash collision detected: {} vs {} (hash: {})",
                        existing.domain, domain, domain_hash);
                    return Err(DnsCacheError::HashCollision);
                }
            }
        }

        let entry = DnsQueryEntry {
            domain: domain_from_other_source
                .unwrap_or_else(|| format!("<hash:{}>", domain_hash)),
            process_name: comm,
            pid,
            exe_path: String::new(),
            timestamp: Instant::now(),
        };

        self.hash_to_entry.insert(domain_hash, entry);
        Ok(())
    }
}
```

---

## Issue 5: Use Actual DNS TTL Instead of Fixed 60s

**Location:** Original Plan Section 6

### Problem

DNS responses include TTL values (often 300-3600s). Using fixed 60s ignores these.

### Solution: Parse TTL from DNS Response

```rust
// ✅ CORRECT - Use actual DNS TTL

// In DNS response parsing (udp_recvmsg)
let rr_ttl = u32::from_be_bytes([
    dns_buf[pos + 4],
    dns_buf[pos + 5],
    dns_buf[pos + 6],
    dns_buf[pos + 7]
]);

let ip_value = DnsIpValue {
    pid: tx_value.pid,
    comm: tx_value.comm,
    domain_hash: tx_value.domain_hash,
    timestamp: bpf_ktime_get_ns(),
    ttl: rr_ttl,  // Use actual TTL from DNS response
};

// In userspace cache
impl DnsCache {
    pub fn cleanup_with_actual_ttls(&mut self) {
        let now = Instant::now();

        self.ip_map.retain(|_, entry| {
            // Use entry-specific TTL (default to 60s if not set)
            let ttl = Duration::from_secs(entry.ttl as u64);
            now.duration_since(entry.timestamp) < ttl
        });
    }
}
```

---

## Issue 6: Add IPv6 Support

**Location:** Original Plan Section 3.2

### Problem

Original `DnsIpKey` only supports IPv4 (`pub ip: u32`).

### Solution: Use IP Version Field

```rust
// ✅ CORRECT - Support both IPv4 and IPv6

#[repr(C)]
pub struct DnsIpKey {
    pub ip_version: u8,     // 4 or 6
    pub _pad: [u8; 3],
    pub ip_bytes: [u8; 16], // IPv4 uses first 4 bytes
}

// Helper functions
impl DnsIpKey {
    pub fn from_v4(ip: u32) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&ip.to_be_bytes());

        Self {
            ip_version: 4,
            _pad: [0u8; 3],
            ip_bytes: bytes,
        }
    }

    pub fn from_v6(ip: [u8; 16]) -> Self {
        Self {
            ip_version: 6,
            _pad: [0u8; 3],
            ip_bytes: ip,
        }
    }

    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        match self.ip_version {
            4 => {
                let ip = u32::from_be_bytes(self.ip_bytes[0..4].try_into().ok()?);
                Some(IpAddr::V4(Ipv4Addr::from(ip)))
            }
            6 => {
                Some(IpAddr::V6(Ipv6Addr::from(self.ip_bytes)))
            }
            _ => None,
        }
    }
}

// In DNS response parsing
if rr_type == 1 && rdlen == 4 {  // A record
    let ip = u32::from_be_bytes([
        dns_buf[pos], dns_buf[pos + 1],
        dns_buf[pos + 2], dns_buf[pos + 3],
    ]);

    let ip_key = DnsIpKey::from_v4(ip);

    unsafe {
        let _ = DNS_IP_MAP.insert(&ip_key, &ip_value, 0);
    }
}

if rr_type == 28 && rdlen == 16 {  // AAAA record
    let mut ip_bytes = [0u8; 16];
    ip_bytes.copy_from_slice(&dns_buf[pos..pos + 16]);

    let ip_key = DnsIpKey::from_v6(ip_bytes);

    unsafe {
        let _ = DNS_IP_V6_MAP.insert(&ip_key, &ip_value_v6, 0);
    }
}
```

---

## 🔄 Revised Implementation Priority

Based on these corrections, the recommended implementation order is:

| Priority | Phase | Reason |
|----------|-------|--------|
| **1** | **Phase 2: UDP port 53** | Most reliable, kernel-based |
| **2** | Add DNS Response Parsing | Critical for IP → process mapping |
| **3** | Phase 1: getaddrinfo uprobe | Add only if Phase 2 insufficient |
| **4** | Phase 3: Advanced tracking | Optional, for edge cases |

---

## 📋 Updated Testing Checklist

Add these tests after corrections:

- [ ] Test hash collision detection
- [ ] Verify IPv6 DNS responses (AAAA records)
- [ ] Test with different libc locations for uprobe
- [ ] Verify DNS TTL is respected (not hardcoded)
- [ ] Test with DNS responses containing multiple A records
- [ ] Test with compressed DNS names (pointer records)

---

## ✅ Summary of Changes

| Issue | Status | Fix |
|-------|--------|-----|
| eBPF string handling | 🚨 Critical | Use fixed buffers, no allocations |
| getaddrinfo kprobe | 🚨 Critical | Change to uprobe or skip |
| Missing DNS response parsing | 🚨 Critical | Add udp_recvmsg handler |
| Hash collisions | ⚠️ Important | Add verification in userspace |
| Fixed TTL | ⚠️ Important | Parse actual TTL from response |
| IPv6 support | ⚠️ Important | Add ip_version field |

---

**Status:** Ready for implementation with corrections applied.

**Next Steps:**
1. Start with Phase 2 (UDP port 53 detection)
2. Add DNS response parsing (udp_recvmsg)
3. Test with curl, wget, chrome
4. Add IPv6 support
5. Consider Phase 1 only if coverage < 80%
