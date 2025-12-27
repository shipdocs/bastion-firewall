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
    pub fn new() -> Self {
        Self {
            bpf: None,
            local_cache: StdHashMap::new(),
            last_cleanup: Instant::now(),
            ttl: Duration::from_secs(5), // 5 second TTL for entries
        }
    }

    /// Load of eBPF program and attach kprobes
    pub fn load(&mut self) -> Result<(), anyhow::Error> {
        // This would typically load from a compiled .o file
        // For now, we'll return an error since we need to compile eBPF program first
        info!("eBPF support not yet fully implemented - falling back to /proc scanning");
        Err(anyhow::anyhow!("eBPF program not compiled yet"))
    }

    /// Alternative: Load from pre-compiled eBPF object
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

    /// Look up PID by socket information
    pub fn lookup_pid(&mut self, src_port: u16, dst_ip: &str, dst_port: u16) -> Option<u32> {
        // First check local cache
        self.cleanup_cache();
        
        // FIX #3: Convert IPv4 to network byte order consistently
        let dst_ip_u32: u32 = match dst_ip.parse::<Ipv4Addr>() {
            Ok(ip) => u32::from_be_bytes(ip.octets()),
            Err(_) => return None,
        };
        
        // FIX #1: Since we don't know PID upfront, we need to iterate through cache
        // to find entries matching our socket parameters (src_port, dst_ip, dst_port)
        for ((cached_src_port, cached_dst_ip, cached_dst_port, cached_pid), (timestamp, _)) in &self.local_cache {
            if *cached_src_port == src_port && *cached_dst_ip == dst_ip_u32 && *cached_dst_port == dst_port {
                if timestamp.elapsed() < self.ttl {
                    debug!("Found PID {} in eBPF cache for {}:{}", cached_pid, dst_ip, dst_port);
                    return Some(*cached_pid);
                }
            }
        }
        
        // If eBPF is not loaded, return None
        if self.bpf.is_none() {
            return None;
        }
        
        // Query eBPF map
        let bpf = self.bpf.as_ref().unwrap();
        let socket_map: HashMap<_, SocketKey, SocketInfo> = match bpf.map("SOCKET_MAP") {
            Some(map) => HashMap::try_from(map).ok()?,
            None => return None,
        };
        
        // FIX #1: Try with src_port=0 (entry might have been created before port was assigned)
        // Note: HashMap doesn't support wildcard searches, so we try with pid=0 as wildcard
        // For production, consider using socket pointers as keys instead
        let key_zero_src = SocketKey {
            src_port: 0,
            dst_ip: dst_ip_u32,
            dst_port,
            pid: 0,  // Wildcard PID for search
        };
        
        match socket_map.get(&key_zero_src, 0) {
            Ok(info) => {
                // Cache for future lookups
                let cache_key = (src_port, dst_ip_u32, dst_port, info.pid);
                self.local_cache.insert(cache_key, (info.pid, Instant::now()));
                debug!("Found PID {} in eBPF map (zero src) for {}:{}", info.pid, dst_ip, dst_port);
                Some(info.pid)
            }
            Err(_) => None,
        }
    }

    /// Clean up expired entries from local cache
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

    /// Check if eBPF is loaded and functional
    pub fn is_loaded(&self) -> bool {
        self.bpf.is_some()
    }

    /// Unload eBPF program
    pub fn unload(&mut self) {
        self.bpf = None;
        self.local_cache.clear();
        info!("eBPF program unloaded");
    }
}

impl Default for EbpfManager {
    fn default() -> Self {
        Self::new()
    }
}
