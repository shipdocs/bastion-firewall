//! eBPF loader and management for process identification
//! Hooks into socket creation to provide PID lookup by socket.

use aya::{maps::HashMap, programs::KProbe, Pod};
use log::{debug, info, warn};

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Metrics tracking
#[derive(Debug)]
pub struct EbpfMetrics {
    pub connect_attempts: Arc<AtomicU64>,
    pub connect_failures: Arc<AtomicU64>,
    pub udp_sends: Arc<AtomicU64>,
    pub map_insertions: Arc<AtomicU64>,
    pub map_insert_failures: Arc<AtomicU64>,
    pub lookups: Arc<AtomicU64>,
    pub lookup_hits: Arc<AtomicU64>,
    pub lookup_misses: Arc<AtomicU64>,
    pub last_report: Arc<std::sync::Mutex<Instant>>,
}

impl Default for EbpfMetrics {
    fn default() -> Self {
        Self {
            connect_attempts: Arc::new(AtomicU64::new(0)),
            connect_failures: Arc::new(AtomicU64::new(0)),
            udp_sends: Arc::new(AtomicU64::new(0)),
            map_insertions: Arc::new(AtomicU64::new(0)),
            map_insert_failures: Arc::new(AtomicU64::new(0)),
            lookups: Arc::new(AtomicU64::new(0)),
            lookup_hits: Arc::new(AtomicU64::new(0)),
            lookup_misses: Arc::new(AtomicU64::new(0)),
            last_report: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }
}

impl EbpfMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn log_summary(&self) {
        let now = Instant::now();
        let should_log = self
            .last_report
            .lock()
            .map(|last| now.duration_since(*last) > Duration::from_secs(30))
            .unwrap_or(true);

        if !should_log {
            return;
        }

        let lookups = self.lookups.load(Ordering::Relaxed);
        let hits = self.lookup_hits.load(Ordering::Relaxed);
        let misses = self.lookup_misses.load(Ordering::Relaxed);

        if lookups > 0 {
            let hit_rate = (hits as f64 / lookups as f64) * 100.0;
            info!(
                "eBPF Metrics: {} lookups, {:.1}% hit rate ({} hits, {} misses)",
                lookups, hit_rate, hits, misses
            );
        }

        *self.last_report.lock().unwrap() = now;
    }

    pub fn record_lookup(&self, hit: bool) {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        if hit {
            self.lookup_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.lookup_misses.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// Mirror of eBPF structures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct ConnectionKey {
    pub src_port: u16,
    pub ip_version: u8,
    pub _pad: [u8; 1],
    pub dst_port: u16,
    pub pid: u32,            // Disambiguator to prevent collisions between processes
    pub dst_ip_v4: u32,
    pub dst_ip_v6: [u8; 16],
}

unsafe impl Pod for ConnectionKey {}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub timestamp: u64,
    pub comm: [u8; 16],
}

unsafe impl Pod for ConnectionInfo {}

impl ConnectionInfo {
    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).to_string()
    }
}

// DNS tracking structures

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct DnsQueryKey {
    pub domain_hash: u32,
    pub _pad: [u8; 4],
}

unsafe impl Pod for DnsQueryKey {}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DnsQueryValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub dest_ip: u32,      // DNS server IP (for correlation)
    pub timestamp_ns: u64, // Nanosecond precision timestamp
}

unsafe impl Pod for DnsQueryValue {}

impl DnsQueryValue {
    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct DnsTxKey {
    pub txid: u16,
    pub src_port: u16,
    pub _pad: [u8; 4],
}

unsafe impl Pod for DnsTxKey {}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DnsTxValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub domain_hash: u32,
}

unsafe impl Pod for DnsTxValue {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct DnsIpKey {
    pub ip_version: u8,
    pub _pad: [u8; 3],
    pub ip_bytes: [u8; 16],
}

unsafe impl Pod for DnsIpKey {}

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

    pub fn to_ip_addr(&self) -> Option<std::net::IpAddr> {
        use std::net::{Ipv4Addr, Ipv6Addr};
        match self.ip_version {
            4 => {
                let ip = u32::from_be_bytes(self.ip_bytes[0..4].try_into().ok()?);
                Some(std::net::IpAddr::V4(Ipv4Addr::from(ip)))
            }
            6 => Some(std::net::IpAddr::V6(Ipv6Addr::from(self.ip_bytes))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DnsIpValue {
    pub pid: u32,
    pub comm: [u8; 16],
    pub domain_hash: u32,
    pub timestamp: u64,
    pub ttl: u32,
}

unsafe impl Pod for DnsIpValue {}

impl DnsIpValue {
    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).to_string()
    }
}

pub struct EbpfManager {
    bpf: Option<aya::Ebpf>,
    pub metrics: EbpfMetrics,
}

impl EbpfManager {
    pub fn new() -> Self {
        Self {
            bpf: None,
            metrics: EbpfMetrics::new(),
        }
    }

    /// Load eBPF object and attach kprobes.
    pub fn load_from_file(&mut self, path: &str) -> Result<(), anyhow::Error> {
        debug!("Loading eBPF program from: {}", path);
        let mut bpf = aya::Ebpf::load_file(path)?;
        debug!("eBPF program loaded successfully");

        // Initialize eBPF logging
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            warn!("Failed to initialize eBPF logging: {}", e);
        }

        // Attach tcp_v4_connect kprobe
        debug!("Attaching tcp_v4_connect...");
        let program: &mut KProbe = bpf
            .program_mut("tcp_v4_connect")
            .ok_or(anyhow::anyhow!("tcp_v4_connect program not found"))?
            .try_into()?;
        program.load()?;
        program
            .attach("tcp_v4_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v4_connect: {}", e))?;
        info!("tcp_v4_connect kprobe attached");

        // Attach tcp_v4_connect_ret kretprobe
        debug!("Attaching tcp_v4_connect_ret...");
        let program: &mut KProbe = bpf
            .program_mut("tcp_v4_connect_ret")
            .ok_or(anyhow::anyhow!("tcp_v4_connect_ret program not found"))?
            .try_into()?;
        program.load()?;
        program
            .attach("tcp_v4_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v4_connect_ret: {}", e))?;
        info!("tcp_v4_connect_ret kretprobe attached");

        // Attach tcp_v6_connect kprobe
        debug!("Attaching tcp_v6_connect...");
        let program: &mut KProbe = bpf
            .program_mut("tcp_v6_connect")
            .ok_or(anyhow::anyhow!("tcp_v6_connect program not found"))?
            .try_into()?;
        program.load()?;
        program
            .attach("tcp_v6_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v6_connect: {}", e))?;
        info!("tcp_v6_connect kprobe attached");

        // Attach udp_sendmsg kprobe
        debug!("Attaching udp_sendmsg...");
        let program: &mut KProbe = bpf
            .program_mut("udp_sendmsg")
            .ok_or(anyhow::anyhow!("udp_sendmsg program not found"))?
            .try_into()?;
        program.load()?;
        program
            .attach("udp_sendmsg", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach udp_sendmsg: {}", e))?;
        info!("udp_sendmsg kprobe attached");

        // Attach udpv6_sendmsg kprobe
        debug!("Attaching udpv6_sendmsg...");
        let program: &mut KProbe = bpf
            .program_mut("udpv6_sendmsg")
            .ok_or(anyhow::anyhow!("udpv6_sendmsg program not found"))?
            .try_into()?;
        program.load()?;
        program
            .attach("udpv6_sendmsg", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach udpv6_sendmsg: {}", e))?;
        info!("udpv6_sendmsg kprobe attached");

        // Attach udp_recvmsg kprobe (for DNS responses) - optional
        if let Some(program_result) = bpf.program_mut("udp_recvmsg") {
            match program_result.try_into() {
                Ok(program) => {
                    let program: &mut KProbe = program;
                    if program.load().is_ok()
                        && program.attach("udp_recvmsg", 0).is_ok()
                    {
                        info!("udp_recvmsg kprobe attached");
                    } else {
                        warn!("udp_recvmsg available but failed to attach (DNS response tracking disabled)");
                    }
                }
                Err(_) => {
                    warn!("udp_recvmsg program type mismatch (DNS response tracking disabled)");
                }
            }
        } else {
            debug!("udp_recvmsg program not found (DNS response tracking disabled)");
        }

        self.bpf = Some(bpf);
        info!("eBPF program loaded and all probes attached successfully");
        Ok(())
    }

    /// Lookup process info with multiple strategies and retry logic.
    /// This is the main entry point for process identification.
    pub fn lookup_process_info(
        &mut self,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<(u32, String)> {
        // Log metrics summary every 30 seconds
        self.metrics.log_summary();

        let (ip_version, dst_ip_v4, dst_ip_v6) = parse_dst_ip(dst_ip)?;

        // Strategy 1: Try with src_port=0 in CONN_MAP first
        // Most connections are stored with src_port=0 since it's assigned after connect()
        if let Some(result) = self.lookup_conn_map_pending(ip_version, dst_port, dst_ip_v4, dst_ip_v6) {
            self.metrics.record_lookup(true);
            return Some(result);
        }

        // Strategy 2: Try exact match in CONN_MAP (including src_port)
        // This works if the kretprobe successfully updated the source port
        if let Some(result) =
            self.lookup_conn_map_exact(src_port, ip_version, dst_port, dst_ip_v4, dst_ip_v6)
        {
            self.metrics.record_lookup(true);
            return Some(result);
        }

        // Strategy 3: Fallback to iterating CONN_MAP (slow, but comprehensive)
        if let Some(result) = self.lookup_conn_map_iterate(ip_version, dst_port, dst_ip_v4, dst_ip_v6) {
            self.metrics.record_lookup(true);
            return Some(result);
        }

        self.metrics.record_lookup(false);
        None
    }

    /// Strategy 1: Lookup with src_port=0 - iterate to find any matching connection
    /// Since key includes pid, we need to iterate to find any process connecting to this destination
    fn lookup_conn_map_pending(
        &mut self,
        ip_version: u8,
        dst_port: u16,
        dst_ip_v4: u32,
        dst_ip_v6: [u8; 16],
    ) -> Option<(u32, String)> {
        let bpf = self.bpf.as_ref()?;
        let conn_map: HashMap<_, ConnectionKey, ConnectionInfo> =
            match bpf.map("CONN_MAP").and_then(|m| HashMap::try_from(m).ok()) {
                Some(m) => m,
                None => return None,
            };

        // Iterate to find src_port=0 entries matching dst_ip:dst_port (any pid)
        let mut count = 0u32;
        for (key, info) in conn_map.iter().flatten() {
            count += 1;
            if count <= 3 {
                debug!("eBPF map entry {}: src_port={}, ip_ver={}, dst_port={}, pid={}, comm={}",
                    count, key.src_port, key.ip_version, key.dst_port, info.pid, info.comm_str());
            }

            if key.src_port == 0 && key.ip_version == ip_version && key.dst_port == dst_port {
                let ip_matches = match ip_version {
                    4 => key.dst_ip_v4 == dst_ip_v4,
                    6 => key.dst_ip_v6 == dst_ip_v6,
                    _ => false,
                };

                if ip_matches {
                    let pid = info.pid;
                    let comm = info.comm_str();
                    debug!("eBPF src_port=0 match: PID {} ({})", pid, comm);
                    return Some((pid, comm));
                }
            }
        }

        if count == 0 {
            debug!("eBPF CONN_MAP is empty!");
        } else {
            debug!("eBPF CONN_MAP has {} entries, no match found for {}:{}",
                count, dst_ip_v4, dst_port);
        }

        None
    }

    /// Strategy 2: Exact match with source port - iterate to find matching connection
    fn lookup_conn_map_exact(
        &mut self,
        src_port: u16,
        ip_version: u8,
        dst_port: u16,
        dst_ip_v4: u32,
        dst_ip_v6: [u8; 16],
    ) -> Option<(u32, String)> {
        let bpf = self.bpf.as_ref()?;
        let conn_map: HashMap<_, ConnectionKey, ConnectionInfo> =
            match bpf.map("CONN_MAP").and_then(|m| HashMap::try_from(m).ok()) {
                Some(m) => m,
                None => return None,
            };

        // Iterate to find entries matching full 4-tuple (any pid)
        for (key, info) in conn_map.iter().flatten() {
            if key.src_port == src_port && key.ip_version == ip_version && key.dst_port == dst_port {
                let ip_matches = match ip_version {
                    4 => key.dst_ip_v4 == dst_ip_v4,
                    6 => key.dst_ip_v6 == dst_ip_v6,
                    _ => false,
                };

                if ip_matches {
                    let pid = info.pid;
                    let comm = info.comm_str();
                    debug!("eBPF exact match: PID {} ({})", pid, comm);
                    return Some((pid, comm));
                }
            }
        }

        None
    }

    /// Strategy 3: Full iteration of CONN_MAP (slow, comprehensive fallback)
    fn lookup_conn_map_iterate(
        &mut self,
        ip_version: u8,
        dst_port: u16,
        _dst_ip_v4: u32,
        dst_ip_v6: [u8; 16],
    ) -> Option<(u32, String)> {
        let bpf = self.bpf.as_ref()?;
        let conn_map: HashMap<_, ConnectionKey, ConnectionInfo> =
            match bpf.map("CONN_MAP").and_then(|m| HashMap::try_from(m).ok()) {
                Some(m) => m,
                None => return None,
            };

        // Only log this occasionally since it's the slow path
        let start = Instant::now();

        for (key, info) in conn_map.iter().flatten() {
            let matches = match key.ip_version {
                4 => key.ip_version == ip_version && key.dst_port == dst_port,
                6 => {
                    key.ip_version == ip_version
                        && key.dst_port == dst_port
                        && key.dst_ip_v6 == dst_ip_v6
                }
                _ => false,
            };

            if matches {
                let elapsed = start.elapsed();
                warn!(
                    "eBPF iteration took {:?} - found PID {} ({})",
                    elapsed,
                    info.pid,
                    info.comm_str()
                );
                return Some((info.pid, info.comm_str()));
            }
        }

        None
    }

    /// Get current map size for monitoring
    pub fn get_map_size(&self) -> Option<usize> {
        let bpf = self.bpf.as_ref()?;

        let conn_map: HashMap<_, ConnectionKey, ConnectionInfo> =
            bpf.map("CONN_MAP").and_then(|m| HashMap::try_from(m).ok())?;

        Some(conn_map.iter().flatten().count())
    }

    /// Lookup DNS IP mapping - returns (pid, comm, domain_hash) for an IP
    pub fn lookup_dns_ip(&mut self, dst_ip: &str) -> Option<(u32, String, u32)> {
        let bpf = self.bpf.as_ref()?;

        let (ip_version, dst_ip_v4, dst_ip_v6) = parse_dst_ip(dst_ip)?;

        let dns_ip_map: HashMap<_, DnsIpKey, DnsIpValue> =
            match bpf.map("DNS_IP_MAP").and_then(|m| HashMap::try_from(m).ok()) {
                Some(m) => m,
                None => return None,
            };

        let ip_key = DnsIpKey {
            ip_version,
            _pad: [0u8; 3],
            ip_bytes: match ip_version {
                4 => {
                    let mut bytes = [0u8; 16];
                    bytes[0..4].copy_from_slice(&dst_ip_v4.to_be_bytes());
                    bytes
                }
                6 => dst_ip_v6,
                _ => return None,
            },
        };

        dns_ip_map.get(&ip_key, 0).ok().map(|value| {
            debug!(
                "DNS IP match: {} -> PID {} ({}), domain_hash={}",
                dst_ip,
                value.pid,
                value.comm_str(),
                value.domain_hash
            );
            (value.pid, value.comm_str(), value.domain_hash)
        })
    }

    /// Poll DNS query map - returns all DNS query entries
    pub fn poll_dns_queries(&self) -> Vec<(u32, String, u32)> {
        let mut results = Vec::new();

        let Some(bpf) = self.bpf.as_ref() else {
            return results;
        };

        let Some(dns_query_map): Option<HashMap<_, DnsQueryKey, DnsQueryValue>> =
            bpf.map("DNS_QUERY_MAP").and_then(|m| HashMap::try_from(m).ok())
        else {
            return results;
        };

        for (key, value) in dns_query_map.iter().flatten() {
            results.push((value.pid, value.comm_str(), key.domain_hash));
        }

        results
    }

    /// Poll DNS queries for a specific DNS server within a time window
    /// Used by DNS snooper to correlate responses with queries
    pub fn poll_dns_queries_by_dest_ip(&self, dns_server_ip: u32, window_ns: u64) -> Vec<DnsQueryValue> {
        let mut results = Vec::new();

        let Some(bpf) = self.bpf.as_ref() else {
            return results;
        };

        let Some(dns_query_map): Option<HashMap<_, DnsQueryKey, DnsQueryValue>> =
            bpf.map("DNS_QUERY_MAP").and_then(|m| HashMap::try_from(m).ok())
        else {
            return results;
        };

        // Get current monotonic time in nanoseconds
        let now_ns = get_monotonic_ns();

        // Filter queries by DNS server IP and time window
        let mut count = 0;
        for (_key, value) in dns_query_map.iter().flatten() {
            count += 1;
            if value.dest_ip == dns_server_ip {
                let age_ns = now_ns.saturating_sub(value.timestamp_ns);
                if age_ns < window_ns {
                    results.push(value);
                }
            }
        }

        if !results.is_empty() {
            info!("Polled {} queries for DNS server {}, found {} matches (map size: {})", 
                results.len(), dns_server_ip, results.len(), count);
        } else if count > 0 {
            info!("Polled {} queries for DNS server {}, found 0 matches (map size: {})", 
                results.len(), dns_server_ip, count);
        }

        results
    }

    /// Poll DNS IP map - returns all IP->process mappings
    pub fn poll_dns_ips(&self) -> Vec<(std::net::IpAddr, u32, String, u32)> {
        let mut results = Vec::new();

        let Some(bpf) = self.bpf.as_ref() else {
            return results;
        };

        let Some(dns_ip_map): Option<HashMap<_, DnsIpKey, DnsIpValue>> =
            bpf.map("DNS_IP_MAP").and_then(|m| HashMap::try_from(m).ok())
        else {
            return results;
        };

        for (key, value) in dns_ip_map.iter().flatten() {
            if let Some(ip_addr) = key.to_ip_addr() {
                results.push((
                    ip_addr,
                    value.pid,
                    value.comm_str(),
                    value.domain_hash,
                ));
            }
        }

        results
    }
}

impl Default for EbpfManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current monotonic time in nanoseconds (matching bpf_ktime_get_ns)
pub fn get_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

/// Parse destination IP into version-specific components
fn parse_dst_ip(dst_ip: &str) -> Option<(u8, u32, [u8; 16])> {
    if dst_ip.contains(':') {
        match Ipv6Addr::from_str(dst_ip) {
            Ok(ip) => Some((6u8, 0u32, ip.octets())),
            Err(_) => None,
        }
    } else {
        match dst_ip.parse::<Ipv4Addr>() {
            Ok(ip) => Some((4u8, u32::from_be_bytes(ip.octets()), [0u8; 16])),
            Err(_) => None,
        }
    }
}
