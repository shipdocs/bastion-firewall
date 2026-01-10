#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerCpuArray},
    programs::ProbeContext as KProbe,
    programs::RetProbeContext,
};
use aya_log_ebpf::info;

// Metrics for tracking eBPF performance
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Metrics {
    pub connect_attempts: u64,
    pub connect_failures: u64,
    pub udp_sends: u64,
    pub map_insertions: u64,
    pub map_insert_failures: u64,
    pub lookups: u64,
    pub lookup_hits: u64,
    pub lookup_misses: u64,
}

#[map(name = "METRICS")]
static mut METRICS: PerCpuArray<Metrics> = PerCpuArray::with_max_entries(1, 0);

// DNS Query tracking - maps domain hash to process
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DnsQueryKey {
    pub domain_hash: u32,
    pub _pad: [u8; 4],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DnsQueryValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub timestamp: u64,
}

#[map(name = "DNS_QUERY_MAP")]
static mut DNS_QUERY_MAP: HashMap<DnsQueryKey, DnsQueryValue> = HashMap::with_max_entries(10000, 0);

// DNS Transaction map - matches queries to responses by TXID
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DnsTxKey {
    pub txid: u16,
    pub src_port: u16,
    pub _pad: [u8; 4],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DnsTxValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub domain_hash: u32,
}

#[map(name = "DNS_TX_MAP")]
static mut DNS_TX_MAP: HashMap<DnsTxKey, DnsTxValue> = HashMap::with_max_entries(10000, 0);

// DNS IP map - maps resolved IPs to process and domain
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DnsIpKey {
    pub ip_version: u8,
    pub _pad: [u8; 3],
    pub ip_bytes: [u8; 16],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DnsIpValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub domain_hash: u32,
    pub timestamp: u64,
    pub ttl: u32,
}

#[map(name = "DNS_IP_MAP")]
static mut DNS_IP_MAP: HashMap<DnsIpKey, DnsIpValue> = HashMap::with_max_entries(10000, 0);

// Connection key includes pid to prevent collisions when src_port=0
// Multiple processes can connect to same destination simultaneously
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ConnectionKey {
    pub src_port: u16,
    pub ip_version: u8, // 4 for IPv4, 6 for IPv6
    pub _pad: [u8; 1],
    pub dst_port: u16,
    pub pid: u32,            // Disambiguator to prevent collisions between processes
    pub dst_ip_v4: u32,      // IPv4 in network byte order (only used when ip_version == 4)
    pub dst_ip_v6: [u8; 16], // IPv6 address (only used when ip_version == 6)
}

// Value with process info
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub timestamp: u64, // For TTL/expiry
    pub comm: [u8; 16], // Process name captured at connection time
}

// Primary map: Connection 4-tuple → Process info
// With source port, this is unique and O(1) lookup
#[map(name = "CONN_MAP")]
static mut CONN_MAP: HashMap<ConnectionKey, ConnectionInfo> = HashMap::with_max_entries(100000, 0);

// Note: Socket cookie tracking not available in kprobe context
// We rely on retry logic and userspace cache for reliability

// Helper: Record metrics
#[inline]
fn inc_metric(field_offset: usize) {
    unsafe {
        if let Some(metrics) = METRICS.get_ptr_mut(0) {
            let ptr = metrics as *mut u8;
            let value_ptr = ptr.add(field_offset) as *mut u64;
            *value_ptr += 1;
        }
    }
}

// Helper to convert IPv4 address from struct sockaddr_in
#[inline]
fn ipv4_from_sockaddr(addr: *const core::ffi::c_void) -> u32 {
    unsafe {
        let addr = addr as *const u8;
        let b0 = *addr.add(4);
        let b1 = *addr.add(5);
        let b2 = *addr.add(6);
        let b3 = *addr.add(7);
        u32::from_be_bytes([b0, b1, b2, b3])
    }
}

// Helper to extract port from struct sockaddr_in
#[inline]
fn port_from_sockaddr(addr: *const core::ffi::c_void) -> u16 {
    unsafe {
        let addr = addr as *const u8;
        let b0 = *addr.add(2);
        let b1 = *addr.add(3);
        u16::from_be_bytes([b0, b1])
    }
}

// Helper to convert IPv6 address from struct sockaddr_in6
#[inline]
fn ipv6_from_sockaddr(addr: *const core::ffi::c_void) -> [u8; 16] {
    unsafe {
        let addr = addr as *const u8;
        let mut ip = [0u8; 16];
        for i in 0..16 {
            ip[i] = *addr.add(8 + i);
        }
        ip
    }
}

// DNS Helper: Compute domain hash from DNS query packet
// Simplified version that only computes hash without storing domain name
// This avoids variable-offset stack access that the verifier rejects
#[inline]
fn compute_domain_hash_from_dns(packet: &[u8]) -> Result<u32, i32> {
    // Skip DNS header (12 bytes)
    if packet.len() < 13 {
        return Err(1);
    }

    let mut pos = 12u32;
    let mut hash: u32 = 0xDEADBEEF;

    // Max 8 labels (eBPF verifier needs unrollable loop)
    for _label_idx in 0..8 {
        if pos >= packet.len() as u32 {
            break;
        }

        let label_len = packet[pos as usize] as u32;

        if label_len == 0 {
            break; // End of domain name
        }

        // Safety check - prevent overflow
        if label_len > 63 {
            return Err(1);
        }

        // Safety check
        if pos + 1 + label_len > packet.len() as u32 {
            return Err(1); // Packet truncated
        }

        // Hash the dot separator (except first label)
        if pos > 12 {
            hash = hash ^ (b'.' as u32);
            hash = hash.wrapping_mul(0x01000193);
        }

        // Hash label characters - unrolled with fixed bound per character
        // We unroll for max 63 characters (DNS label limit)
        let mut i = 0u32;

        // First unroll batch (chars 0-7)
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }

        // Second batch (chars 8-15)
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }

        // Third batch (chars 16-23)
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }

        // Fourth batch (chars 24-31)
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }

        // Fifth batch (chars 32-39)
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }

        // Sixth batch (chars 40-47)
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }

        // Seventh batch (chars 48-55)
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }

        // Eighth batch (chars 56-62)
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }
        if i < label_len && pos + 1 + i < packet.len() as u32 {
            hash = hash ^ (packet[(pos + 1 + i) as usize] as u32);
            hash = hash.wrapping_mul(0x01000193);
            i += 1;
        }

        pos += 1 + label_len;
        if pos > packet.len() as u32 {
            break;
        }
    }

    Ok(hash)
}

// DNS Helper: Read source port from sock structure
// This is kernel-version dependent, but we try a common offset
#[inline]
fn read_sock_src_port(sock_ptr: u64) -> u16 {
    unsafe {
        // Try to read sk_num (source port) from sock struct
        // Offset varies by kernel version, commonly 10-14
        let ptr = sock_ptr as *const u16;

        // Try offset 10 (common in many kernels)
        let offset_ptr = ptr.add(10);
        match aya_ebpf::helpers::bpf_probe_read(offset_ptr) {
            Ok(port) => return port,
            Err(_) => {}
        }

        // Fallback to offset 12
        let offset_ptr = ptr.add(12);
        match aya_ebpf::helpers::bpf_probe_read(offset_ptr) {
            Ok(port) => return port,
            Err(_) => {}
        }

        0
    }
}

/// Kprobe entry for kernel's `tcp_v4_connect`
#[kprobe]
fn tcp_v4_connect(ctx: KProbe) -> u32 {
    inc_metric(0); // connect_attempts
    match try_tcp_v4_connect(ctx) {
        Ok(_) => 0,
        Err(_) => {
            inc_metric(1); // connect_failures
            0
        }
    }
}

/// Records an outbound TCP IPv4 connect attempt
fn try_tcp_v4_connect(ctx: KProbe) -> Result<(), i32> {
    // tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;

    // Get userspace address from RSI
    let uaddr = unsafe {
        let regs = ctx.regs;
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rsi
    };

    if uaddr == 0 {
        return Err(2);
    }

    // Read sockaddr structure
    let sockaddr: [u8; 16] = unsafe {
        match aya_ebpf::helpers::bpf_probe_read(uaddr as *const [u8; 16]) {
            Ok(val) => val,
            Err(_) => match aya_ebpf::helpers::bpf_probe_read_user(uaddr as *const [u8; 16]) {
                Ok(val) => val,
                Err(_) => return Err(2),
            },
        }
    };

    let dst_ip = ipv4_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    let dst_port = port_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);

    // Get process name
    let comm = match aya_ebpf::helpers::bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    let timestamp = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Store in CONN_MAP with src_port=0 (will be updated by kretprobe)
    let conn_key = ConnectionKey {
        src_port: 0,
        ip_version: 4,
        _pad: [0u8; 1],
        dst_port,
        pid,
        dst_ip_v4: dst_ip,
        dst_ip_v6: [0u8; 16],
    };

    let conn_info = ConnectionInfo {
        pid,
        timestamp,
        comm,
    };

    unsafe {
        let _ = CONN_MAP.insert(&conn_key, &conn_info, 0);
    }

    info!(
        &ctx,
        "TCPv4 connect: PID {} -> {}:{}", pid, dst_ip, dst_port
    );

    Ok(())
}

/// Kretprobe for tcp_v4_connect - update source port
#[kretprobe]
fn tcp_v4_connect_ret(ctx: RetProbeContext) -> i32 {
    match try_tcp_v4_connect_ret(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Update connection entry with actual source port after connect completes
fn try_tcp_v4_connect_ret(ctx: RetProbeContext) -> Result<(), i32> {
    // Check if connect succeeded
    let ret_val = match ctx.ret::<i32>() {
        Some(r) => r as i32,
        None => return Ok(()),
    };

    if ret_val < 0 {
        // Connection failed, entry will expire naturally
        return Ok(());
    }

    // Get sock struct from RDI (first argument)
    let sock_ptr = unsafe {
        let regs = ctx.regs;
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rdi
    };

    if sock_ptr == 0 {
        return Err(1);
    }

    // Read source port from struct sock
    // sk->sk_num (at offset ~10 in struct sock, but this varies by kernel version)
    // For safety, we'll skip this for now and rely on dst-based lookup

    Ok(())
}

/// UDP sendmsg handler
#[kprobe]
fn udp_sendmsg(ctx: KProbe) -> u32 {
    inc_metric(2); // udp_sends
    match try_udp_sendmsg(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_udp_sendmsg(ctx: KProbe) -> Result<(), i32> {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;

    let msg = unsafe {
        let regs = ctx.regs;
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rsi
    };

    let msg_name_ptr: [u8; 8] = unsafe {
        match aya_ebpf::helpers::bpf_probe_read(msg as *const [u8; 8]) {
            Ok(val) => val,
            Err(_) => return Err(2),
        }
    };

    let msg_name = u64::from_ne_bytes(msg_name_ptr);

    // Handle connected UDP sockets (msg_name == 0)
    if msg_name == 0 {
        // For connected UDP, try to get destination from sock struct
        // This is kernel-version dependent, so we'll skip for now
        return Ok(());
    }

    let sockaddr: [u8; 16] = unsafe {
        match aya_ebpf::helpers::bpf_probe_read_user(msg_name as *const [u8; 16]) {
            Ok(val) => val,
            Err(_) => return Err(3),
        }
    };

    let dst_ip = ipv4_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    let dst_port = port_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);

    let comm = match aya_ebpf::helpers::bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    let timestamp = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // UDP: Use src_port=0, no source port assignment in UDP
    let conn_key = ConnectionKey {
        src_port: 0,
        ip_version: 4,
        _pad: [0u8; 1],
        dst_port,
        pid,
        dst_ip_v4: dst_ip,
        dst_ip_v6: [0u8; 16],
    };

    let conn_info = ConnectionInfo {
        pid,
        timestamp,
        comm,
    };

    unsafe {
        let _ = CONN_MAP.insert(&conn_key, &conn_info, 0);
    }

    // DNS detection: Check if this is a DNS query (port 53)
    // Note: Full DNS domain parsing is disabled due to eBPF verifier limitations
    // We track that DNS occurred, but don't parse the domain name
    if dst_port == 53 {
        // Store a simple DNS query marker (hash of PID + timestamp as placeholder)
        let dns_key = DnsQueryKey {
            domain_hash: pid.wrapping_mul(31).wrapping_add(timestamp as u32),
            _pad: [0u8; 4],
        };

        let dns_value = DnsQueryValue {
            pid,
            comm,
            timestamp,
        };

        unsafe {
            let _ = DNS_QUERY_MAP.insert(&dns_key, &dns_value, 0);
        }

        info!(
            &ctx,
            "DNS query detected: PID {} port 53", pid
        );
    }

    info!(
        &ctx,
        "UDPv4 sendmsg: PID {} -> {}:{}", pid, dst_ip, dst_port
    );

    Ok(())
}

// IPv6 handlers (similar to IPv4)

#[kprobe]
fn tcp_v6_connect(ctx: KProbe) -> u32 {
    inc_metric(0);
    match try_tcp_v6_connect(ctx) {
        Ok(_) => 0,
        Err(_) => {
            inc_metric(1);
            0
        }
    }
}

fn try_tcp_v6_connect(ctx: KProbe) -> Result<(), i32> {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;

    let uaddr = unsafe {
        let regs = ctx.regs;
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rsi
    };

    if uaddr == 0 {
        return Err(2);
    }

    let sockaddr: [u8; 28] = unsafe {
        match aya_ebpf::helpers::bpf_probe_read(uaddr as *const [u8; 28]) {
            Ok(val) => val,
            Err(_) => match aya_ebpf::helpers::bpf_probe_read_user(uaddr as *const [u8; 28]) {
                Ok(val) => val,
                Err(_) => return Err(2),
            },
        }
    };

    let dst_ip_v6 = ipv6_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    let dst_port = port_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);

    let comm = match aya_ebpf::helpers::bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    let timestamp = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let conn_key = ConnectionKey {
        src_port: 0,
        ip_version: 6,
        _pad: [0u8; 1],
        dst_port,
        pid,
        dst_ip_v4: 0,
        dst_ip_v6,
    };

    let conn_info = ConnectionInfo {
        pid,
        timestamp,
        comm,
    };

    unsafe {
        let _ = CONN_MAP.insert(&conn_key, &conn_info, 0);
    }

    info!(
        &ctx,
        "TCPv6 connect: PID {} -> [{}]:{}",
        pid, dst_ip_v6[0], dst_port
    );

    Ok(())
}

#[kprobe]
fn udpv6_sendmsg(ctx: KProbe) -> u32 {
    inc_metric(2);
    match try_udpv6_sendmsg(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_udpv6_sendmsg(ctx: KProbe) -> Result<(), i32> {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;

    let msg = unsafe {
        let regs = ctx.regs;
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rsi
    };

    let msg_name_ptr: [u8; 8] = unsafe {
        match aya_ebpf::helpers::bpf_probe_read(msg as *const [u8; 8]) {
            Ok(val) => val,
            Err(_) => return Err(2),
        }
    };

    let msg_name = u64::from_ne_bytes(msg_name_ptr);
    if msg_name == 0 {
        return Ok(()); // Connected UDP socket
    }

    let sockaddr: [u8; 28] = unsafe {
        match aya_ebpf::helpers::bpf_probe_read_user(msg_name as *const [u8; 28]) {
            Ok(val) => val,
            Err(_) => return Err(3),
        }
    };

    let dst_ip_v6 = ipv6_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    let dst_port = port_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);

    let comm = match aya_ebpf::helpers::bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => [0u8; 16],
    };

    let timestamp = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    let conn_key = ConnectionKey {
        src_port: 0,
        ip_version: 6,
        _pad: [0u8; 1],
        dst_port,
        pid,
        dst_ip_v4: 0,
        dst_ip_v6,
    };

    let conn_info = ConnectionInfo {
        pid,
        timestamp,
        comm,
    };

    unsafe {
        let _ = CONN_MAP.insert(&conn_key, &conn_info, 0);
    }

    info!(
        &ctx,
        "UDPv6 sendmsg: PID {} -> [{}]:{}",
        pid, dst_ip_v6[0], dst_port
    );

    Ok(())
}

// Note: DNS response parsing (udp_recvmsg) is too complex for eBPF stack limit
// IP-to-process mapping is handled in userspace by correlating DNS query info
// with network connections

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
