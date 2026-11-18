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
    pub lookups: Arc<AtomicU64>,
    pub lookup_hits: Arc<AtomicU64>,
    pub lookup_misses: Arc<AtomicU64>,
    pub last_report: Arc<std::sync::Mutex<Instant>>,
}

impl Default for EbpfMetrics {
    fn default() -> Self {
        Self {
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


/// Only trust an eBPF-only match if the connect() happened this recently.
pub const EBPF_MATCH_MAX_AGE_NS: u64 = 10 * 1_000_000_000;

/// A process eBPF saw connecting to a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfCandidate {
    pub pid: u32,
    pub comm: String,
    pub timestamp_ns: u64,
}

fn key_matches(key: &ConnectionKey, ip_version: u8, dst_ip_v4: u32, dst_ip_v6: [u8; 16], dst_port: u16) -> bool {
    key.ip_version == ip_version
        && key.dst_port == dst_port
        && match ip_version {
            4 => key.dst_ip_v4 == dst_ip_v4,
            6 => key.dst_ip_v6 == dst_ip_v6,
            _ => false,
        }
}

/// Newest candidate (input is sorted newest first) that is not older than `max_age_ns`.
pub fn pick_recent(candidates: &[EbpfCandidate], now_ns: u64, max_age_ns: u64) -> Option<&EbpfCandidate> {
    candidates
        .iter()
        .find(|c| now_ns.saturating_sub(c.timestamp_ns) <= max_age_ns)
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

    /// All processes that eBPF saw connecting to exactly this destination, newest first.
    ///
    /// The kernel side stores every connection with src_port=0 (keyed per pid), so the
    /// source port cannot be used here; callers that know the source port should first
    /// resolve the socket owner via /proc and use these candidates only to narrow that
    /// search or as a last resort.
    pub fn connection_candidates(&mut self, dst_ip: &str, dst_port: u16) -> Vec<EbpfCandidate> {
        let mut out = Vec::new();
        let Some((ip_version, dst_ip_v4, dst_ip_v6)) = parse_dst_ip(dst_ip) else {
            return out;
        };
        let Some(bpf) = self.bpf.as_ref() else {
            return out;
        };
        let Some(conn_map) = bpf
            .map("CONN_MAP")
            .and_then(|m| HashMap::<_, ConnectionKey, ConnectionInfo>::try_from(m).ok())
        else {
            return out;
        };

        for (key, info) in conn_map.iter().flatten() {
            if key_matches(&key, ip_version, dst_ip_v4, dst_ip_v6, dst_port) {
                out.push(EbpfCandidate {
                    pid: info.pid,
                    comm: info.comm_str(),
                    timestamp_ns: info.timestamp,
                });
            }
        }
        out.sort_by(|a, b| b.timestamp_ns.cmp(&a.timestamp_ns));
        self.metrics.record_lookup(!out.is_empty());
        self.metrics.log_summary();
        out
    }

    /// Remove CONN_MAP entries older than `max_age_ns`. The kernel side never deletes
    /// entries; without this the map fills up (100k entries) and new connections are
    /// silently no longer recorded.
    pub fn prune_conn_map(&mut self, max_age_ns: u64) -> usize {
        let Some(bpf) = self.bpf.as_mut() else {
            return 0;
        };
        let Some(mut conn_map) = bpf
            .map_mut("CONN_MAP")
            .and_then(|m| HashMap::<_, ConnectionKey, ConnectionInfo>::try_from(m).ok())
        else {
            return 0;
        };
        let now = get_monotonic_ns();
        let stale: Vec<ConnectionKey> = conn_map
            .iter()
            .flatten()
            .filter(|(_, info)| now.saturating_sub(info.timestamp) > max_age_ns)
            .map(|(key, _)| key)
            .collect();
        let mut removed = 0;
        for key in &stale {
            if conn_map.remove(key).is_ok() {
                removed += 1;
            }
        }
        removed
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

#[cfg(test)]
mod lookup_tests {
    use super::*;

    fn key(dst_ip_v4: u32, dst_port: u16) -> ConnectionKey {
        ConnectionKey {
            src_port: 0,
            ip_version: 4,
            _pad: [0],
            dst_port,
            pid: 1,
            dst_ip_v4,
            dst_ip_v6: [0; 16],
        }
    }

    #[test]
    fn key_must_match_ip_not_only_port() {
        let (_, ip, v6) = parse_dst_ip("104.18.25.232").unwrap();
        assert!(key_matches(&key(ip, 443), 4, ip, v6, 443));
        // Same port, other host: this used to match in the old fallback.
        let (_, other, _) = parse_dst_ip("1.1.1.1").unwrap();
        assert!(!key_matches(&key(other, 443), 4, ip, v6, 443));
        assert!(!key_matches(&key(ip, 80), 4, ip, v6, 443));
    }

    #[test]
    fn pick_recent_takes_newest_and_ignores_stale() {
        let now = 10_000 * 1_000_000_000;
        let c = |pid, age_s: u64| EbpfCandidate {
            pid,
            comm: format!("p{}", pid),
            timestamp_ns: now - age_s * 1_000_000_000,
        };
        // Sorted newest first, as connection_candidates returns them.
        let list = vec![c(2, 1), c(1, 5)];
        assert_eq!(pick_recent(&list, now, EBPF_MATCH_MAX_AGE_NS).unwrap().pid, 2);
        let stale = vec![c(3, 3600)];
        assert!(pick_recent(&stale, now, EBPF_MATCH_MAX_AGE_NS).is_none());
    }
}
