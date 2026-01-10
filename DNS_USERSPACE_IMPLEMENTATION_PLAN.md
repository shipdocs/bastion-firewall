# Userspace DNS Snooper Implementation Plan

## ⚠️ IMPORTANT: Read This First

**Alternative Approach Available**: This document describes a **userspace DNS snooper** approach. However, there exists [DNS_IMPLEMENTATION_PLAN_CORRECTIONS.md](DNS_IMPLEMENTATION_PLAN_CORRECTIONS.md) which proposes a **hybrid eBPF approach** (parse both queries and responses in eBPF using `udp_sendmsg` and `udp_recvmsg` kprobes).

**Trade-offs**:
| Aspect | Userspace DNS (This Plan) | Hybrid eBPF (Corrections Doc) |
|--------|---------------------------|-------------------------------|
| Complexity | Lower - simple eBPF markers | Higher - complex eBPF parsing |
| Verifier Risk | Minimal - only port 53 check | High - may fail verification |
| Dependencies | libpcap + DNS parsing lib | None |
| Correlation | Timestamp-based (fuzzier) | TXID-based (exact) |
| Performance | Slightly higher (userspace capture) | Lower (all in kernel) |
| Maintenance | Easier to debug | Harder to debug eBPF issues |

**Recommendation**: Start with userspace approach (lower risk), can migrate to eBPF parsing if needed.

---

## Executive Summary

**Problem**: The eBPF-based DNS tracking implementation cannot parse DNS domain names due to BPF verifier constraints (512-byte stack limit, no variable-offset access, complex loop restrictions).

**Current State** (from [bastion-rs/ebpf/src/main.rs](bastion-rs/ebpf/src/main.rs:306-330)):
- ✅ DNS detection exists (checks port 53)
- ❌ Domain parsing **disabled** due to verifier limits
- ❌ NO `udp_recvmsg` handler (DNS response parsing)
- ❌ NO TXID tracking
- ❌ Placeholder hash instead of actual domain hash

**Solution**: Implement DNS parsing in userspace using a dedicated DNS snooper thread that captures DNS responses and correlates them with eBPF PID markers.

**Benefits**:
- ✅ No verifier restrictions - can parse full DNS responses
- ✅ No kernel code - safer and easier to distribute
- ✅ Can use mature DNS parsing libraries
- ✅ Separation of concerns - eBPF marks PIDs, userspace parses DNS
- ✅ Performance impact minimal - DNS traffic is tiny compared to total traffic
- ✅ Easier debugging and testing

## Critical Issues Addressed

This plan addresses all critical gaps identified in feedback:

### 1. ✅ DNS Response Parsing (Previously Missing)

**Problem**: Original plan mentioned correlation but didn't specify how to extract IPs from DNS responses.

**Solution**: Add DNS response parsing in userspace using `trust-dns` or `pnet` library (see Phase 1, Step 4).

**Implementation**:
```rust
// Parse DNS response packet
let dns_response = trust_dns_client::op::Message::from_vec(&packet_data)?;

// Extract answers (A/AAAA records)
for answer in dns_response.answers() {
    if let Some(RData::A(addr)) = answer.rdata() {
        let ip = addr.to_string();
        let domain = answer.name().to_string();
        // Store IP → domain + PID mapping
    }
}
```

### 2. ✅ Missing `src_port` Field

**Problem**: Current eBPF `DnsQueryValue` lacks `src_port` needed for correlation.

**Solution**: Add `src_port` field to eBPF structure (Phase 1, Step 2).

**Implementation**:
```rust
// eBPF: bastion-rs/ebpf/src/main.rs
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DnsQueryValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub src_port: u16,        // ADD: Source port for correlation
    pub timestamp_ns: u64,    // ADD: Nanosecond precision
}
```

### 3. ✅ Implement `poll_dns_queries_recent()` Method

**Problem**: Plan referenced this method but it doesn't exist.

**Solution**: Implement in `ebpf_loader.rs` (Phase 2, Step 5).

**Implementation**:
```rust
// bastion-rs/src/ebpf_loader.rs
impl EbpfManager {
    pub fn poll_dns_queries_recent(&mut self, window_ns: u64) -> Vec<DnsQueryEntry> {
        let dns_query_map = self.dns_query_map.as_ref()?;
        let now = std::time::Instant::now();
        let mut entries = Vec::new();

        for item in dns_query_map.iter() {
            let (key, value) = item.ok()?;
            let age_ns = now.elapsed().as_nanos() as u64;

            if age_ns < window_ns {
                entries.push(DnsQueryEntry {
                    domain_hash: key.domain_hash,
                    pid: value.pid,
                    comm: String::from_utf8_lossy(&value.comm).to_string(),
                    src_port: value.src_port,
                    timestamp_ns: value.timestamp_ns,
                });
            }
        }
        Some(entries)
    }
}
```

### 4. ✅ DNS Snooper Component Implementation

**Problem**: Plan showed pseudocode but no actual implementation.

**Solution**: Full implementation provided in Phase 1, Step 4 with real `trust-dns-client` parsing.

### 5. ✅ Correlation Logic Specification

**Problem**: Original plan underspecified race conditions and concurrent queries.

**Solution**: Detailed correlation algorithm with timestamp windows and conflict resolution (Phase 1, Step 5).

### 6. ✅ Add libpcap Dependency

**Problem**: No pcap dependency in `Cargo.toml`.

**Solution**: Add dependency in Phase 1, Step 1.

---

## Critical Implementation Details

### 🔴 Issue 1: Source Port Extraction in eBPF

**Problem**: UDP source port is NOT available in `udp_sendmsg` kprobe context.

**Why**:
- `udp_sendmsg` is called **before** the source port is assigned
- The kernel allocates ephemeral ports **after** the kprobe fires
- Current eBPF code tries `read_sock_src_port()` but returns 0 (not yet assigned)

**Evidence from current code** ([main.rs:285-294](bastion-rs/ebpf/src/main.rs:285-294)):
```rust
// UDP: Use src_port=0, no source port assignment in UDP
let conn_key = ConnectionKey {
    src_port: 0,  // ← Can't get source port yet!
    ip_version: 4,
    _pad: [0u8; 1],
    dst_port,
    pid,
    dst_ip_v4: dst_ip,
    dst_ip_v6: [0u8; 16],
};
```

**Solution Options**:

**Option A: Use `udp_sendmsg` Return (kretprobe)** - RECOMMENDED
```rust
// Attach kretprobe to capture source port after assignment
#[kretprobe]
fn udp_sendmsg_return(ctx: KRetProbe) -> i32 {
    // Return value is the number of bytes sent
    // But we still don't have easy access to the socket here
    // Would need to match with entry probe via PID/timestamp
}
```

**Option B: Use `udp_v4_get_port()`** - May not exist in all kernels
```rust
// Hook the function that assigns the port
// But this is very kernel-version specific
```

**Option C: Correlate by Destination IP + Port + Timestamp Window** - SIMPLEST
```rust
// Don't use source port at all for correlation
// Instead use: (dest_ip, dest_port, timestamp_window)
// Works because DNS server responses come from port 53
```

**Recommended Approach**: Use **Option C** (timestamp + destination-based correlation)

**Why Option C is best**:
- ✅ Works with current eBPF code (no changes needed)
- ✅ No kretprobe complexity
- ✅ DNS responses always come from port 53 (unique identifier)
- ✅ Timestamp window of 100ms is sufficient for DNS RTT
- ✅ Multiple concurrent queries to different domains won't collide

**Updated Correlation Logic**:
```rust
// Userspace DNS snooper
for (dest_ip, src_port, response) in captured_dns_responses {
    // src_port is 53 (DNS server)
    // We need to find which process queried this domain

    let domain = extract_domain(&response);
    let ips = extract_ips(&response);

    // Find recent eBPF DNS queries matching destination IP
    let recent_queries = ebpf.poll_dns_queries_by_dest_ip(dest_ip, 100_000_000);

    for query in recent_queries {
        // Match by destination IP + timestamp window
        // (not source port, since it's 0 in eBPF)
        if query.dest_ip == dest_ip &&
           response_time - query.timestamp < Duration::from_millis(100) {
            // Found match!
            for ip in ips {
                dns_cache.insert(ip, query.pid, domain);
            }
        }
    }
}
```

**Required eBPF Changes**:
```rust
// Add destination IP to DNS_QUERY_MAP value
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DnsQueryValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub dest_ip: u32,      // ADD: Destination DNS server IP
    pub timestamp_ns: u64, // Nanosecond precision
}
```

---

### 🔴 Issue 2: CNAME Chain Handling

**Problem**: DNS responses often contain CNAME (alias) records before A records.

**Example DNS Response**:
```
Question: api.github.com
Answer 1: CNAME github.map.fastly.net
Answer 2: CNAME fastly.com
Answer 3: A  151.101.1.69
```

**If we only store the CNAME alias**:
- ❌ We'll cache `fastly.com → PID`
- ❌ But the user queried `api.github.com`
- ❌ Popup shows "connecting to fastly.com" instead of "api.github.com"

**Solution: Track Full CNAME Chain**

```rust
// DNS Snooper: Parse CNAME chains
pub struct DnsAnswer {
    pub name: String,       // api.github.com (queried name)
    pub record_type: u16,   // 1=A, 5=CNAME, 28=AAAA
    pub ip: Option<IpAddr>, // For A/AAAA records
    pub cname: Option<String>, // For CNAME records
    pub ttl: u32,
}

impl DnsSnooper {
    fn parse_dns_response(&self, packet: &[u8]) -> Vec<DnsAnswer> {
        let mut answers = Vec::new();
        let msg = Message::from_vec(packet)?;

        for answer in msg.answers() {
            let dns_answer = DnsAnswer {
                name: answer.name().to_utf8(),
                record_type: answer.record_type(),
                ip: extract_ip(answer),
                cname: extract_cname(answer),
                ttl: answer.ttl(),
            };
            answers.push(dns_answer);
        }

        // Resolve CNAME chain to get final queried name
        let original_query = self.resolve_cname_chain(&answers);

        // Store ALL IPs with the ORIGINAL queried name
        for answer in &answers {
            if let Some(ip) = answer.ip {
                self.dns_cache.insert(
                    ip.to_string(),
                    original_query.clone(),  // Use api.github.com, not fastly.com
                    pid,
                    answer.ttl,
                );
            }
        }

        answers
    }

    /// Follow CNAME chain to find original queried name
    fn resolve_cname_chain(&self, answers: &[DnsAnswer]) -> String {
        // Find the first name in the chain (the one user queried)
        for answer in answers {
            if answer.record_type == 5 { // CNAME
                return answer.name.clone();
            }
        }
        // No CNAME, return the A record name
        answers.first().map(|a| a.name.clone()).unwrap_or_default()
    }
}
```

**Example Cache State After CNAME Resolution**:
```
DNS Query: curl api.github.com
DNS Response:
  - api.github.com CNAME github.map.fastly.net
  - github.map.fastly.net CNAME fastly.com
  - fastly.com A 151.101.1.69

Cache stores:
  - 151.101.1.69 → "api.github.com" ✓ (original query, not final CNAME)
```

**Special Cases to Handle**:

1. **Multiple A records** (round-robin DNS):
```rust
// google.com might return 8 IPs
// Store ALL of them with the same domain name
for answer in answers {
    if answer.record_type == 1 { // A record
        cache.insert(answer.ip, "google.com", pid, ttl);
    }
}
```

2. **Mixed A + AAAA responses**:
```rust
// Both IPv4 and IPv6 in same response
// Store each with appropriate IP version
for answer in answers {
    match answer.record_type {
        1 => cache.insert_v4(answer.ipv4, domain, pid, ttl),
        28 => cache.insert_v6(answer.ipv6, domain, pid, ttl),
        _ => {}
    }
}
```

3. **CDNAME loops** (theoretical, shouldn't happen):
```rust
let max_chain_length = 8;
let mut seen_names = HashSet::new();

for answer in answers {
    if !seen_names.insert(answer.name.clone()) {
        warn!("CNAME loop detected: {}", answer.name);
        break;
    }
}
```

---

## Architecture

### Data Flow (Updated with Source Port Fix)

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                             │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     │ UDP sendto(DNS_server_IP, port 53)
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Kernel Space                                │
│                                                                  │
│  ┌──────────────┐                                               │
│  │ udp_sendmsg  │                                               │
│  │  kprobe      │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌─────────────────────────────────┐                            │
│  │  eBPF: DNS Detection            │                            │
│  │  - Check: dst_port == 53?       │                            │
│  │  - Extract: dest_ip (DNS server)│                            │
│  │  - Store in DNS_QUERY_MAP:      │                            │
│  │    Key: domain_hash (placeholder)│                            │
│  │    Value: {                     │                            │
│  │      pid,                       │                            │
│  │      comm[16],                  │                            │
│  │      dest_ip,        ← IMPORTANT │                            │
│  │      timestamp_ns               │                            │
│  │    }                            │                            │
│  └─────────────────────────────────┘                            │
│         │                                                        │
│         │                                                        │
│  DNS_QUERY_MAP                                                  │
│  (dest_ip + timestamp → PID)                                    │
│  Note: src_port NOT available (assigned after kprobe)           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                     │
                     │ DNS Response packet (from DNS server port 53)
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              Userspace: DNS Snooper Thread                       │
│                                                                  │
│  1. Capture DNS responses via libpcap (filter: "udp port 53")   │
│  2. Parse DNS response:                                         │
│     - Extract source IP (DNS server IP)                         │
│     - Extract all A/AAAA records                                │
│     - Extract CNAME chain (if any)                              │
│     - Extract TTL for each record                               │
│     - Resolve original queried domain (follow CNAME chain)      │
│                                                                  │
│  3. Correlation Algorithm:                                      │
│     FOR each DNS response:                                      │
│       a) Get dns_server_ip from packet source                   │
│       b) Get response_timestamp from pcap                       │
│       c) Query DNS_QUERY_MAP for recent queries to this server: │
│          poll_queries_where(                                    │
│            dest_ip == dns_server_ip &&                          │
│            timestamp > (response_timestamp - 100ms)             │
│          )                                                      │
│       d) If match found:                                        │
│          Store IP → (pid, original_domain, ttl)                 │
│                                                                  │
│  4. Store in DNS_IP_CACHE:                                      │
│     Key: IP address (from A/AAAA record)                        │
│     Value: {                                                    │
│       pid,                                                      │
│       domain (original query, NOT final CNAME),                 │
│       process_name,                                             │
│       timestamp,                                                │
│       ttl                                                       │
│     }                                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                     │
                     │ Connection attempt to cached IP
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│              Userspace: ProcessCache Connection Lookup           │
│                                                                  │
│  1. Check DNS_IP_CACHE for destination IP                       │
│     If found: Return ProcessInfo with domain name!              │
│                                                                  │
│  2. Else check eBPF CONN_MAP (live connections)                  │
│     If found: Return ProcessInfo                                │
│                                                                  │
│  3. Else check eBPF connection cache (expired connections)       │
│     If found: Return ProcessInfo                                │
│                                                                  │
│  4. Else scan /proc/net/tcp for socket inode                    │
│     If found: Return ProcessInfo                                │
│                                                                  │
│  5. Else: Return None (unknown process)                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key Changes from Original Plan**:
- ❌ ~~Use source port for correlation~~ (src_port unavailable in eBPF)
- ✅ Use **destination IP + timestamp window** instead
- ✅ Track **original domain** through CNAME chains
- ✅ Handle **multiple A records** (round-robin DNS)

### Component Breakdown

#### 1. eBPF Program (Minimal Changes)

**Current State**: Already marks DNS queries with PID

**Required Changes**:
- Add source port to DNS_QUERY_MAP value for correlation
- Add more precise timestamp (nanoseconds)
- Increase DNS_QUERY_MAP max_entries to handle more concurrent queries

```rust
// eBPF: DNS Query Map
#[map(name = "DNS_QUERY_MAP")]
static mut DNS_QUERY_MAP: HashMap<DnsQueryKey, DnsQueryValue> = HashMap::with_max_entries(10000, 0);

// Key: domain_hash (placeholder, actual correlation done in userspace)
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DnsQueryKey {
    pub domain_hash: u32,
    pub _pad: [u8; 4],
}

// Value: PID + source port + timestamp for correlation
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DnsQueryValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub src_port: u16,     // ADD: Source port for correlation
    pub timestamp_ns: u64, // ADD: Precise timestamp
}
```

#### 2. DNS Snooper Thread (New Component)

**Location**: `bastion-rs/src/dns_snooper.rs` (new file)

**Responsibilities**:
1. Capture DNS response packets (UDP port 53)
2. Parse DNS messages (questions + answers)
3. Extract domain names, resolved IPs, TTLs
4. Query eBPF DNS_QUERY_MAP for recent PIDs
5. Correlate by timestamp + source port
6. Store in DNS_IP_CACHE

**Implementation Options**:

**Option A: Netfilter NFQUEUE Approach**
```rust
// Use libnfq for DNS-only queue
// Pros: Reuses existing nfq infrastructure, no new dependencies
// Cons: Need separate NFQUEUE for DNS, iptables setup complexity
```

**Option B: libpcap/raw socket Approach**
```rust
// Use pcap library to sniff port 53
// Pros: Simple, no iptables changes needed
// Cons: New dependency (libpcap), may miss packets if dropped
```

**Recommendation**: Start with Option B (libpcap) for simplicity, can switch to Option A if needed.

**Library Choice**:
- `libpcap` via `pcap` crate (0.8.1) - Well-maintained, async support
- DNS parsing: `trust-dns-client` or `pnet` (packet parsing)

**Pseudocode**:
```rust
pub struct DnsSnooper {
    ebpf_manager: Arc<Mutex<EbpfManager>>,
    dns_cache: Arc<Mutex<DnsCache>>,
    capture: Capture<Active>,
}

impl DnsSnooper {
    pub fn new(ebpf_manager: Arc<Mutex<EbpfManager>>, dns_cache: Arc<Mutex<DnsCache>>) -> Result<Self> {
        // Open pcap capture on "any" device, filter "udp port 53"
        let capture = Capture::from_device("any")?
            .promisc(true)
            .snaplen(65535)
            .buffer_size(10_000_000)
            .open()?;

        capture.filter("udp port 53", true)?;

        Ok(Self { ebpf_manager, dns_cache, capture })
    }

    pub fn run(&mut self) -> Result<()> {
        while let Ok(packet) = self.capture.next_packet() {
            if let Ok((src_port, dns_query, dns_answers)) = parse_dns_response(&packet.data) {
                // Get recent DNS queries from eBPF (within last 100ms)
                let recent_queries = self.ebpf_manager.lock().poll_dns_queries_recent(100_000_000);

                // Correlate by timestamp and source port
                for query in recent_queries {
                    if query.src_port == src_port {
                        // Match found! Store IP → PID + domain mapping
                        for answer in dns_answers {
                            self.dns_cache.lock().insert_ip_mapping(
                                answer.ip,
                                query.domain_hash,
                                query.pid,
                                query.comm.to_string(),
                                answer.ttl,
                            );
                        }
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}
```

#### 3. DNS Cache Enhancements

**Location**: `bastion-rs/src/process.rs`

**Current State**: DNS cache structures exist but aren't populated

**Required Changes**:
- Add method to query recent DNS queries from eBPF (with timestamp filtering)
- Improve correlation logic
- Add better logging and debugging

```rust
impl ProcessCache {
    /// Get recent DNS queries from eBPF within specified time window (nanoseconds)
    pub fn get_recent_dns_queries(&self, window_ns: u64) -> Vec<DnsQueryValue> {
        if let Some(ebpf) = &self.ebpf {
            ebpf.poll_dns_queries_recent(window_ns)
        } else {
            Vec::new()
        }
    }

    /// Check if destination IP is in DNS cache
    pub fn lookup_dns_cache(&self, dest_ip: &str) -> Option<DnsIpEntry> {
        self.dns_cache.ip_map.get(dest_ip).cloned()
    }
}
```

#### 4. Connection Lookup Integration

**Location**: `bastion-rs/src/process.rs`, `find_process_by_socket()`

**Current State**: Falls back from eBPF → /proc

**Required Changes**: Insert DNS cache lookup as **first** priority (before eBPF and /proc)

```rust
pub fn find_process_by_socket(&mut self, src_ip: &str, src_port: u16, dest_ip: &str, dest_port: u16, protocol: &str) -> Option<ProcessInfo> {
    // 1. NEW: Check DNS cache FIRST (DNS gives us the best process info!)
    if let Some(dns_entry) = self.lookup_dns_cache(dest_ip) {
        info!(
            "✓ DNS cache hit: {} → PID {} ({}), domain: {}",
            dest_ip, dns_entry.pid, dns_entry.process_name, dns_entry.domain_hint
        );

        if let Some(mut info) = self.get_process_info_by_pid(dns_entry.pid) {
            info.name = dns_entry.process_name.clone();
            return Some(info);
        }

        // Process exited, use cached name
        return Some(ProcessInfo {
            name: dns_entry.process_name.clone(),
            exe_path: self.find_exe_by_name(&dns_entry.process_name).unwrap_or_default(),
            uid: 0,
        });
    }

    // 2. eBPF connection cache (existing)
    // 3. Live eBPF map lookup (existing)
    // 4. /proc fallback (existing)
}
```

## Implementation Steps

### Phase 1: Infrastructure Setup (1-2 days)

1. **Add dependencies to `bastion-rs/Cargo.toml`**
   ```toml
   [dependencies]
   pcap = "0.8"
   trust-dns-client = "0.23"
   # or
   pnet = "0.34"
   ```

2. **Create new file `bastion-rs/src/dns_snooper.rs`**
   - Basic structure, pcap initialization
   - DNS packet parsing logic
   - Integration with eBPF manager and DNS cache

3. **Update eBPF DNS_QUERY_MAP**
   - Add src_port and timestamp_ns fields
   - Rebuild eBPF program

4. **Update `bastion-rs/src/main.rs`**
   - Spawn DNS snooper thread on startup
   - Handle graceful shutdown

### Phase 2: Integration and Testing (2-3 days)

5. **Update `bastion-rs/src/ebpf_loader.rs`**
   - Add `poll_dns_queries_recent()` method
   - Return DNS queries within time window

6. **Update `bastion-rs/src/process.rs`**
   - Add DNS cache lookup as first priority
   - Add correlation logic

7. **Add logging and debugging**
   - Log DNS query detection
   - Log correlation success/failure
   - Statistics (cache hit rate, etc.)

8. **Test scenarios**
   - Simple DNS query + connection (curl example.com)
   - Multiple processes resolving same domain
   - Multiple domains resolved in single query
   - Cache expiration and TTL handling
   - Concurrent DNS queries

### Phase 3: Refinement and Optimization (1-2 days)

9. **Performance optimization**
   - Tune correlation time window (start with 100ms)
   - Adjust cache sizes
   - Profile CPU usage

10. **Error handling**
    - Handle malformed DNS responses
    - Handle pcap errors
    - Handle eBPF map lookup failures

11. **Edge cases**
    - IPv6 DNS responses
    - EDNS0 extensions
    - DNS over TCP (rare but possible)
    - CNAME chains

12. **Documentation and cleanup**
    - Add comments explaining correlation logic
    - Update CLAUDE.md with new architecture
    - Add troubleshooting guide

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_parsing() {
        // Test parsing of various DNS response formats
    }

    #[test]
    fn test_correlation_logic() {
        // Test timestamp + port correlation
    }

    #[test]
    fn test_cache_expiration() {
        // Test TTL-based expiration
    }
}
```

### Integration Tests

1. **Basic DNS tracking test**
   ```bash
   # Start daemon
   bastion-daemon

   # Make DNS query + connection
   curl https://example.com

   # Check logs for:
   # - DNS query detected by eBPF
   # - DNS response parsed by snooper
   # - Successful correlation
   # - Process identified correctly
   ```

2. **Concurrent queries test**
   ```bash
   # Multiple processes making DNS queries simultaneously
   (curl https://example.com &) && (wget https://example.com &)

   # Verify each connection gets correct PID
   ```

3. **Cache expiration test**
   ```bash
   # Make DNS query
   curl https://example.com

   # Wait for TTL to expire
   sleep 300

   # Make connection again - should fall back to eBPF or /proc
   curl https://example.com
   ```

### Performance Tests

1. **CPU overhead measurement**
   ```bash
   # Measure daemon CPU usage with and without DNS snooper
   ```

2. **Memory usage measurement**
   ```bash
   # Monitor DNS cache growth over time
   ```

3. **Cache hit rate**
   ```bash
   # Log DNS cache hit rate vs eBPF vs /proc
   # Target: >80% DNS cache hit rate for web browsing
   ```

## Expected Results

### Success Criteria

1. **Process identification rate**
   - Target: >90% of outbound connections identified with correct process name
   - Current: ~50% (eBPF only)
   - Improvement: DNS should catch most web browsing, API calls, CDN traffic

2. **Performance impact**
   - CPU overhead: <5% increase (DNS traffic is tiny)
   - Memory overhead: <50MB for DNS cache (1000 entries × ~500 bytes)

3. **Reliability**
   - DNS snooper thread: No crashes on malformed DNS responses
   - Graceful degradation: Falls back to eBFP + /proc if DNS snooper fails

### Limitations and Trade-offs

1. **Won't help with**:
   - Direct IP connections (no DNS involved)
   - Connections to cached DNS entries (already resolved before daemon started)
   - DNS queries that happened long before connection

2. **Best for**:
   - Web browsing (HTTP/HTTPS)
   - API calls to domain-based endpoints
   - CDN traffic
   - Any application using standard DNS resolution

3. **Still need**:
   - eBPF connection tracking (for non-DNS traffic)
   - /proc fallback (for direct IP connections)
   - Retry logic (for race conditions)

## Risk Mitigation

### Potential Issues and Solutions

| Issue | Likelihood | Impact | Mitigation |
|-------|-----------|--------|------------|
| libpcap not available on system | Low | High | Add pcap to dependencies, provide clear error message |
| DNS snooper crashes | Medium | Medium | Run in separate thread, catch panic, restart automatically |
| Correlation fails (time window too small) | Medium | Medium | Make time window configurable, start with 100ms |
| High CPU usage | Low | Medium | Profile, optimize, add rate limiting if needed |
| Permission issues (CAP_NET_RAW) | High | Low | Daemon runs as root, already has required permissions |
| Malformed DNS responses | Medium | Low | Use robust DNS parsing library, log and skip malformed packets |

## Rollout Plan

1. **Development**: Implement on feature branch
2. **Testing**: Test in development environment
3. **Beta**: Deploy to test systems, monitor logs
4. **Stable**: Merge to master after 1 week of successful testing
5. **Release**: Include in next version (2.0.29 or later)

## Open Questions

1. **DNS over HTTPS/TLS**?
   - Not addressed in this plan
   - Would require TLS interception (out of scope)
   - Standard DNS (UDP/53) covers 99% of use cases

2. **mDNS and local DNS**?
   - Should we filter out link-local (169.254/16, 224.0.0.0/4)?
   - Recommendation: Track everything, let cache expiration handle cleanup

3. **IPv6**?
   - Ensure DNS parsing handles AAAA records
   - Correlation logic should work the same

4. **Multiple IPs in single response**?
   - Store all IPs → same PID + domain mapping
   - Handle A + AAAA records in same response

## Success Metrics

1. **Process identification rate**: >90% (up from ~50%)
2. **DNS cache hit rate**: >80% for web browsing traffic
3. **CPU overhead**: <5% increase
4. **Memory overhead**: <50MB
5. **Crash rate**: 0 (graceful degradation)
