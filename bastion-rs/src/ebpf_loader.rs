//! eBPF loader and management for process identification
//! Hooks into socket creation to provide PID lookup by socket.

use aya::{
    programs::KProbe,
    Pod,
    maps::HashMap,
};
use log::{info, debug};
use std::collections::HashMap as StdHashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

// Mirror of eBPF structures
// FIX #2: Field order must match eBPF exactly for compatibility
// FIX #1: Added pid disambiguator to prevent key collisions
// IPv6 Support: Added ip_version field and dst_ip_v6 array
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SocketKey {
    pub src_port: u16,
    pub ip_version: u8,  // 4 for IPv4, 6 for IPv6
    pub _pad: [u8; 1],   // Padding for alignment
    pub dst_port: u16,
    pub pid: u32,        // Disambiguator to prevent collisions between processes
    pub dst_ip_v4: u32,  // IPv4 in network byte order (only used when ip_version == 4)
    pub dst_ip_v6: [u8; 16],  // IPv6 address (only used when ip_version == 6)
}

unsafe impl Pod for SocketKey {}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SocketInfo {
    pub pid: u32,
    pub timestamp: u64,
    pub comm: [u8; 16],  // Process name captured at connection time
}

unsafe impl Pod for SocketInfo {}

impl SocketInfo {
    /// Returns the process name as a string, trimming null bytes
    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).to_string()
    }
}

pub struct EbpfManager {
    bpf: Option<aya::Ebpf>,
    // Local cache of eBPF map entries with TTL
    // FIX #1: Include pid in cache key to prevent collisions
    // IPv6 Support: Cache now stores IP version and full address
    local_cache: StdHashMap<(u16, u8, u16, u32, [u8; 16]), (u32, Instant)>, // (src_port, ip_version, dst_port, pid, dst_ip) -> (timestamp)
    last_cleanup: Instant,
    ttl: Duration,
}

impl EbpfManager {
    pub fn new() -> Self {
        Self {
            bpf: None,
            local_cache: StdHashMap::new(),
            last_cleanup: Instant::now(),
            ttl: Duration::from_secs(5),
        }
    }

    /// Attempts to load a compiled eBPF object and attach the configured kprobes.
    ///
    /// On success the manager will hold the loaded eBPF object ready for map queries and probe attachments.
    /// On failure, an error is returned describing why the eBPF object could not be loaded or attached (for example, when the eBPF program is not compiled).
    ///
    ///
    pub fn load(&mut self) -> Result<(), anyhow::Error> {
        // This would typically load from a compiled .o file
        // For now, we'll return an error since we need to compile eBPF program first
        info!("eBPF support not yet fully implemented - falling back to /proc scanning");
        Err(anyhow::anyhow!("eBPF program not compiled yet"))
    }

    pub fn load_from_file(&mut self, path: &str) -> Result<(), anyhow::Error> {
        // Load compiled eBPF program
        debug!("Loading eBPF program from: {}", path);
        let mut bpf = aya::Ebpf::load_file(path)?;
        debug!("eBPF program loaded successfully");

        // Attach tcp_v4_connect kprobe
        debug!("Looking for tcp_v4_connect program...");
        let program: &mut KProbe = bpf.program_mut("tcp_v4_connect")
            .ok_or(anyhow::anyhow!("tcp_v4_connect program not found"))?
            .try_into()?;
        debug!("tcp_v4_connect program found, loading...");
        program.load()?;
        debug!("tcp_v4_connect loaded, attaching to kernel function...");
        program.attach("tcp_v4_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v4_connect: {}", e))?;
        info!("✓ tcp_v4_connect kprobe attached");

        // Attach udp_sendmsg kprobe
        debug!("Looking for udp_sendmsg program...");
        let program: &mut KProbe = bpf.program_mut("udp_sendmsg")
            .ok_or(anyhow::anyhow!("udp_sendmsg program not found"))?
            .try_into()?;
        debug!("udp_sendmsg program found, loading...");
        program.load()?;
        debug!("udp_sendmsg loaded, attaching to kernel function...");
        program.attach("udp_sendmsg", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach udp_sendmsg: {}", e))?;
        info!("✓ udp_sendmsg kprobe attached");

        // Attach tcp_v6_connect kprobe
        debug!("Looking for tcp_v6_connect program...");
        let program: &mut KProbe = bpf.program_mut("tcp_v6_connect")
            .ok_or(anyhow::anyhow!("tcp_v6_connect program not found"))?
            .try_into()?;
        debug!("tcp_v6_connect program found, loading...");
        program.load()?;
        debug!("tcp_v6_connect loaded, attaching to kernel function...");
        program.attach("tcp_v6_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v6_connect: {}", e))?;
        info!("✓ tcp_v6_connect kprobe attached");

        // Attach udpv6_sendmsg kprobe
        debug!("Looking for udpv6_sendmsg program...");
        let program: &mut KProbe = bpf.program_mut("udpv6_sendmsg")
            .ok_or(anyhow::anyhow!("udpv6_sendmsg program not found"))?
            .try_into()?;
        debug!("udpv6_sendmsg program found, loading...");
        program.load()?;
        debug!("udpv6_sendmsg loaded, attaching to kernel function...");
        program.attach("udpv6_sendmsg", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach udpv6_sendmsg: {}", e))?;
        info!("✓ udpv6_sendmsg kprobe attached");

        // Attach tcp_v4_connect kretprobe
        debug!("Looking for tcp_v4_connect_ret program...");
        let program: &mut KProbe = bpf.program_mut("tcp_v4_connect_ret")
            .ok_or(anyhow::anyhow!("tcp_v4_connect_ret program not found"))?
            .try_into()?;
        debug!("tcp_v4_connect_ret program found, loading...");
        program.load()?;
        debug!("tcp_v4_connect_ret loaded, attaching to kernel function...");
        program.attach("tcp_v4_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v4_connect_ret: {}", e))?;
        info!("✓ tcp_v4_connect_ret kretprobe attached");

        // Attach tcp_v6_connect kretprobe
        debug!("Looking for tcp_v6_connect_ret program...");
        let program: &mut KProbe = bpf.program_mut("tcp_v6_connect_ret")
            .ok_or(anyhow::anyhow!("tcp_v6_connect_ret program not found"))?
            .try_into()?;
        debug!("tcp_v6_connect_ret program found, loading...");
        program.load()?;
        debug!("tcp_v6_connect_ret loaded, attaching to kernel function...");
        program.attach("tcp_v6_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v6_connect_ret: {}", e))?;
        info!("✓ tcp_v6_connect_ret kretprobe attached");

        self.bpf = Some(bpf);
        info!("eBPF program loaded and kprobes attached successfully");
        Ok(())
    }

    pub fn lookup_pid(&mut self, src_port: u16, dst_ip: &str, dst_port: u16) -> Option<u32> {
        // First check local cache
        self.cleanup_cache();
        
        // Determine IP version and convert to appropriate format
        let (ip_version, dst_ip_v4, dst_ip_v6) = if dst_ip.contains(':') {
            // IPv6 address
            match Ipv6Addr::from_str(dst_ip) {
                Ok(ip) => (6u8, 0u32, ip.octets()),
                Err(_) => {
                    debug!("Failed to parse IPv6 address: {}", dst_ip);
                    return None;
                }
            }
        } else {
            // IPv4 address
            match dst_ip.parse::<Ipv4Addr>() {
                Ok(ip) => (4u8, u32::from_be_bytes(ip.octets()), [0u8; 16]),
                Err(_) => {
                    debug!("Failed to parse IPv4 address: {}", dst_ip);
                    return None;
                }
            }
        };

        // Check local cache first (faster than eBPF map query)
        let found_pid = self.local_cache.iter()
            .filter(|((_, cached_ip_version, cached_dst_port, _, cached_dst_ip), (_, timestamp))| {
                *cached_ip_version == ip_version &&
                *cached_dst_port == dst_port &&
                timestamp.elapsed() < self.ttl &&
                match ip_version {
                    4 => {
                        let cached_ip = u32::from_ne_bytes([
                            cached_dst_ip[0], cached_dst_ip[1], cached_dst_ip[2], cached_dst_ip[3]
                        ]);
                        cached_ip == dst_ip_v4
                    },
                    6 => *cached_dst_ip == dst_ip_v6,
                    _ => false,
                }
            })
            .find(|((cached_src_port, _, _, _, _), _)| {
                *cached_src_port == src_port || *cached_src_port == 0
            })
            .map(|((_, _, _, pid, _), _)| *pid);

        if let Some(pid) = found_pid {
            debug!("Found PID {} in local cache for {}:{}", pid, dst_ip, dst_port);
            return Some(pid);
        }
        
        // If eBPF is not loaded, return None
        if self.bpf.is_none() {
            debug!("eBPF not loaded, skipping eBPF lookup");
            return None;
        }

        // Query eBPF map by iterating through all entries
        let bpf = self.bpf.as_ref().unwrap();
        let socket_map: HashMap<_, SocketKey, SocketInfo> = match bpf.map("SOCKET_MAP") {
            Some(map) => match HashMap::try_from(map) {
                Ok(m) => {
                    debug!("Got eBPF SOCKET_MAP");
                    m
                },
                Err(e) => {
                    debug!("Failed to convert SOCKET_MAP: {:?}", e);
                    return None;
                }
            },
            None => {
                debug!("SOCKET_MAP not found in eBPF program");
                return None;
            }
        };

        // Count entries for debugging
        let mut entry_count = 0;
        let mut match_found = false;

        // Iterate through all entries to find matching dst_ip:dst_port
        for result in socket_map.iter() {
            entry_count += 1;
            if let Ok((key, info)) = result {
                let matches = match key.ip_version {
                    4 => key.ip_version == ip_version && key.dst_ip_v4 == dst_ip_v4 && key.dst_port == dst_port,
                    6 => key.ip_version == ip_version && key.dst_ip_v6 == dst_ip_v6 && key.dst_port == dst_port,
                    _ => false,
                };

                if matches {
                    let pid = info.pid;
                    // Cache for future lookups
                    let cache_key = (src_port, ip_version, dst_port, pid, match ip_version {
                        4 => {
                            let mut ip = [0u8; 16];
                            ip[0..4].copy_from_slice(&dst_ip_v4.to_ne_bytes());
                            ip
                        },
                        6 => dst_ip_v6,
                        _ => [0u8; 16],
                    });
                    self.local_cache.insert(cache_key, (pid, Instant::now()));
                    info!("✓ eBPF match: Found PID {} for {}:{}", pid, dst_ip, dst_port);
                    match_found = true;
                    return Some(pid);
                }
            }
        }

        if entry_count == 0 {
            debug!("eBPF SOCKET_MAP is empty - no processes captured yet");
        } else if !match_found {
            debug!("eBPF lookup: checked {} entries, no match for {}:{}", entry_count, dst_ip, dst_port);
        }

        None
    }

    /// Lookup process info (PID and comm name) from eBPF map.
    /// Returns (pid, comm_name) if found, None otherwise.
    /// The comm name is captured at connection time, so it's available even if the process has exited.
    pub fn lookup_process_info(&mut self, src_port: u16, dst_ip: &str, dst_port: u16) -> Option<(u32, String)> {
        // Determine IP version and convert to appropriate format
        let (ip_version, dst_ip_v4, dst_ip_v6) = if dst_ip.contains(':') {
            match Ipv6Addr::from_str(dst_ip) {
                Ok(ip) => (6u8, 0u32, ip.octets()),
                Err(_) => return None,
            }
        } else {
            match dst_ip.parse::<Ipv4Addr>() {
                Ok(ip) => (4u8, u32::from_be_bytes(ip.octets()), [0u8; 16]),
                Err(_) => return None,
            }
        };

        // If eBPF is not loaded, return None
        if self.bpf.is_none() {
            return None;
        }

        let bpf = self.bpf.as_ref().unwrap();
        let socket_map: HashMap<_, SocketKey, SocketInfo> = match bpf.map("SOCKET_MAP") {
            Some(map) => match HashMap::try_from(map) {
                Ok(m) => m,
                Err(_) => return None,
            },
            None => return None,
        };

        // Iterate through all entries to find matching dst_ip:dst_port
        for result in socket_map.iter() {
            if let Ok((key, info)) = result {
                let matches = match key.ip_version {
                    4 => key.ip_version == ip_version && key.dst_ip_v4 == dst_ip_v4 && key.dst_port == dst_port,
                    6 => key.ip_version == ip_version && key.dst_ip_v6 == dst_ip_v6 && key.dst_port == dst_port,
                    _ => false,
                };

                if matches {
                    let pid = info.pid;
                    let comm = info.comm_str();
                    info!("✓ eBPF match: Found PID {} ({}) for {}:{}", pid, comm, dst_ip, dst_port);
                    return Some((pid, comm));
                }
            }
        }

        None
    }

    /// Remove entries from the local TTL cache that are older than the manager's `ttl`.
    ///
    /// This runs at most once per second (no-op if called more frequently) and updates
    /// `last_cleanup` to the current time when a cleanup occurs.
    ///
    ///
    /// mgr.local_cache.insert((1, 0, 2, 3), (3, std::time::Instant::now() - std::time::Duration::from_secs(10)));
    /// mgr.cleanup_cache();
    fn cleanup_cache(&mut self) {
        if self.last_cleanup.elapsed() < Duration::from_secs(1) {
            return;
        }
        
        let now = Instant::now();
        self.local_cache.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < self.ttl
        });
        
        self.last_cleanup = now;
    }

    /// Reports whether an eBPF object is currently loaded.
    ///
    ///
    pub fn is_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    /// Unloads any currently loaded eBPF program and clears the local socket cache.
    ///
    ///
    /// mgr.unload();
    ///
    pub fn unload(&mut self) {
        self.bpf = None;
        self.local_cache.clear();
        info!("eBPF program unloaded");
    }
}

impl Default for EbpfManager {
    /// Creates a new `EbpfManager` with default runtime state.
    ///
    /// The manager is initialized with no loaded eBPF object, an empty local cache,
    /// the current instant as `last_cleanup`, and a 5-second time-to-live for cache entries.
    ///
    ///
    fn default() -> Self {
        Self::new()
    }
}