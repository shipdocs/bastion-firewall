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
                "📊 eBPF Metrics: {} lookups, {:.1}% hit rate ({} hits, {} misses)",
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
        info!("✓ tcp_v4_connect kprobe attached");

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
        info!("✓ tcp_v4_connect_ret kretprobe attached");

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
        info!("✓ tcp_v6_connect kprobe attached");

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
        info!("✓ udp_sendmsg kprobe attached");

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
        info!("✓ udpv6_sendmsg kprobe attached");

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

    /// Strategy 1: Lookup with src_port=0 (O(1)) - should be most common
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

        let key = ConnectionKey {
            src_port: 0,
            ip_version,
            _pad: [0u8; 1],
            dst_port,
            dst_ip_v4,
            dst_ip_v6,
        };

        conn_map.get(&key, 0).ok().map(|info| {
            let pid = info.pid;
            let comm = info.comm_str();
            debug!("✓ eBPF src_port=0 match: PID {} ({})", pid, comm);
            (pid, comm)
        })
    }

    /// Strategy 2: Exact match with source port (O(1))
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

        let key = ConnectionKey {
            src_port,
            ip_version,
            _pad: [0u8; 1],
            dst_port,
            dst_ip_v4,
            dst_ip_v6,
        };

        conn_map.get(&key, 0).ok().map(|info| {
            let pid = info.pid;
            let comm = info.comm_str();
            debug!("✓ eBPF exact match: PID {} ({})", pid, comm);
            (pid, comm)
        })
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
                    "⚠ eBPF iteration took {:?} - found PID {} ({})",
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
}

impl Default for EbpfManager {
    fn default() -> Self {
        Self::new()
    }
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
