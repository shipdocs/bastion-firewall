//! eBPF loader and management for process identification
//! 
//! This module loads of eBPF program that hooks into socket creation
//! and provides a map for quick PID lookup by socket information

use aya::{
    programs::{KProbe, ProgramError},
    Bpf, Pod,
    maps::HashMap,
};
use log::{info, warn, error, debug};
use std::collections::HashMap as StdHashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// Mirror of eBPF structures
// FIX #2: Field order must match eBPF exactly for compatibility
// FIX #1: Added pid disambiguator to prevent key collisions
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SocketKey {
    pub src_port: u16,
    pub dst_ip: u32,  // IPv4 in network byte order
    pub dst_port: u16,
    pub pid: u32,     // Disambiguator to prevent collisions between processes
}

unsafe impl Pod for SocketKey {}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SocketInfo {
    pub pid: u32,
    pub timestamp: u64,
}

unsafe impl Pod for SocketInfo {}

pub struct EbpfManager {
    bpf: Option<aya::Ebpf>,
    // Local cache of eBPF map entries with TTL
    // FIX #1: Include pid in cache key to prevent collisions
    local_cache: StdHashMap<(u16, u32, u16, u32), (u32, Instant)>, // (src_port, dst_ip, dst_port, pid) -> (timestamp)
    last_cleanup: Instant,
    ttl: Duration,
}

impl EbpfManager {
    /// Creates a new EbpfManager with default state.
    ///
    /// The manager is initialized with no loaded eBPF object, an empty local cache,
    /// the current instant as the last cleanup time, and a 5-second cache TTL.
    ///
    /// # Examples
    ///
    /// ```
    /// let mgr = EbpfManager::new();
    /// assert!(!mgr.is_loaded());
    /// ```
    pub fn new() -> Self {
        Self {
            bpf: None,
            local_cache: StdHashMap::new(),
            last_cleanup: Instant::now(),
            ttl: Duration::from_secs(5), // 5 second TTL for entries
        }
    }

    /// Attempts to load a compiled eBPF object and attach the configured kprobes.
    ///
    /// On success the manager will hold the loaded eBPF object ready for map queries and probe attachments.
    /// On failure, an error is returned describing why the eBPF object could not be loaded or attached (for example, when the eBPF program is not compiled).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut mgr = crate::ebpf_loader::EbpfManager::new();
    /// // In the current build this will return an error because the eBPF program is not compiled.
    /// assert!(mgr.load().is_err());
    /// ```
    pub fn load(&mut self) -> Result<(), anyhow::Error> {
        // This would typically load from a compiled .o file
        // For now, we'll return an error since we need to compile eBPF program first
        info!("eBPF support not yet fully implemented - falling back to /proc scanning");
        Err(anyhow::anyhow!("eBPF program not compiled yet"))
    }

    /// Loads a compiled eBPF object from the given filesystem path and attaches its kprobe programs.
    ///
    /// On success stores the loaded eBPF object in the manager and attaches `tcp_v4_connect` and
    /// `udp_sendmsg` kprobes so socket events can be observed for PID lookup.
    ///
    /// # Parameters
    ///
    /// - `path`: Filesystem path to the compiled eBPF object file.
    ///
    /// # Errors
    ///
    /// Returns an error if the eBPF object cannot be loaded, if either required program
    /// (`tcp_v4_connect`, `udp_sendmsg`) is missing or cannot be converted to a `KProbe`,
    /// or if attaching either kprobe fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut mgr = EbpfManager::new();
    /// // path should point to a compiled eBPF object containing the expected probes
    /// let res = mgr.load_from_file("/usr/lib/bpf/socket_probes.o");
    /// assert!(res.is_ok());
    /// ```
    pub fn load_from_file(&mut self, path: &str) -> Result<(), anyhow::Error> {
        // Load compiled eBPF program
        let mut bpf = aya::Ebpf::load_file(path)?;
        
        // Attach kprobes
        let program: &mut KProbe = bpf.program_mut("tcp_v4_connect")
            .ok_or(anyhow::anyhow!("tcp_v4_connect program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("tcp_v4_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v4_connect: {}", e))?;
        
        let program: &mut KProbe = bpf.program_mut("udp_sendmsg")
            .ok_or(anyhow::anyhow!("udp_sendmsg program not found"))?
            .try_into()?;
        program.load()?;
        program.attach("udp_sendmsg", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach udp_sendmsg: {}", e))?;
        
        self.bpf = Some(bpf);
        info!("eBPF program loaded and kprobes attached successfully");
        Ok(())
    }

    /// Resolve a process ID (PID) for a socket identified by source port, destination IPv4 address, and destination port.
    ///
    /// Looks up a cached PID first; if not found and an eBPF program is loaded, queries the eBPF `SOCKET_MAP` using the destination IP and port (with a wildcard source port/pid) and caches any discovered PID for subsequent lookups. The function accepts the destination IP as an IPv4 dotted-decimal string.
    ///
    /// # Parameters
    ///
    /// - `dst_ip` — Destination IPv4 address in dotted-decimal notation (e.g., "192.0.2.1").
    ///
    /// # Returns
    ///
    /// `Some(pid)` if a PID matching the socket information is found, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut mgr = EbpfManager::new();
    /// // No eBPF loaded, lookup returns None
    /// assert_eq!(mgr.lookup_pid(1234, "127.0.0.1", 80), None);
    /// ```
    pub fn lookup_pid(&mut self, src_port: u16, dst_ip: &str, dst_port: u16) -> Option<u32> {
        // First check local cache
        self.cleanup_cache();
        
        // Convert IP to the format stored by eBPF:
        // eBPF does *ip_ptr where ip_ptr points to network-order bytes.
        // On little-endian x86, this reads the bytes as a little-endian u32.
        let dst_ip_u32: u32 = match dst_ip.parse::<Ipv4Addr>() {
            Ok(ip) => u32::from_ne_bytes(ip.octets()),  // Native endian from octets
            Err(_) => return None,
        };
        
        // Check local cache first (faster than eBPF map query)
        for ((cached_src_port, cached_dst_ip, cached_dst_port, cached_pid), (_pid, timestamp)) in &self.local_cache {
            // Match on dst_ip and dst_port (src_port may be 0 in eBPF entries)
            if (*cached_src_port == 0 || *cached_src_port == src_port) 
                && *cached_dst_ip == dst_ip_u32 
                && *cached_dst_port == dst_port {
                if timestamp.elapsed() < self.ttl {
                    debug!("Found PID {} in local cache for {}:{}", cached_pid, dst_ip, dst_port);
                    return Some(*cached_pid);
                }
            }
        }
        
        // If eBPF is not loaded, return None
        if self.bpf.is_none() {
            return None;
        }
        
        // Query eBPF map by iterating through all entries
        let bpf = self.bpf.as_ref().unwrap();
        let socket_map: HashMap<_, SocketKey, SocketInfo> = match bpf.map("SOCKET_MAP") {
            Some(map) => match HashMap::try_from(map) {
                Ok(m) => m,
                Err(_) => return None,
            },
            None => return None,
        };
        
        // Iterate through all entries to find matching dst_ip:dst_port
        // (src_port is 0 in eBPF because it's not known at connect time)
        for result in socket_map.iter() {
            if let Ok((key, info)) = result {
                if key.dst_ip == dst_ip_u32 && key.dst_port == dst_port {
                    // Found a match!
                    let pid = info.pid;
                    // Cache for future lookups
                    let cache_key = (src_port, dst_ip_u32, dst_port, pid);
                    self.local_cache.insert(cache_key, (pid, Instant::now()));
                    debug!("Found PID {} in eBPF map for {}:{}", pid, dst_ip, dst_port);
                    return Some(pid);
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
    /// # Examples
    ///
    /// ```
    /// let mut mgr = crate::EbpfManager::new();
    /// // simulate an expired entry (timestamp far in the past)
    /// mgr.local_cache.insert((1, 0, 2, 3), (3, std::time::Instant::now() - std::time::Duration::from_secs(10)));
    /// mgr.cleanup_cache();
    /// assert!(mgr.local_cache.is_empty());
    /// ```
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
    /// # Examples
    ///
    /// ```
    /// let manager = EbpfManager::new();
    /// assert!(!manager.is_loaded());
    /// ```
    pub fn is_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    /// Unloads any currently loaded eBPF program and clears the local socket cache.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut mgr = EbpfManager::new();
    /// // ensure unload is a no-op when nothing is loaded
    /// mgr.unload();
    /// assert!(!mgr.is_loaded());
    ///
    /// // after loading (when available), unload clears state
    /// // mgr.load_from_file("path/to/ebpf.o").unwrap();
    /// // mgr.unload();
    /// // assert!(!mgr.is_loaded());
    /// ```
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
    /// # Examples
    ///
    /// ```
    /// let mgr = bastion_rs::ebpf_loader::EbpfManager::default();
    /// assert!(!mgr.is_loaded());
    /// ```
    fn default() -> Self {
        Self::new()
    }
}