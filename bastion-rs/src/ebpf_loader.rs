//! eBPF loader and management for process identification
//! 
//! This module loads the eBPF program that hooks into socket creation
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

// Mirror the eBPF structures
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SocketKey {
    pub src_port: u16,
    pub dst_ip: u32,  // IPv4 in network byte order
    pub dst_port: u16,
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
    local_cache: StdHashMap<(u16, u32, u16), (u32, Instant)>, // (src_port, dst_ip, dst_port) -> (pid, timestamp)
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

    /// Load the eBPF program and attach kprobes
    pub fn load(&mut self) -> Result<(), anyhow::Error> {
        // This would typically load from a compiled .o file
        // For now, we'll return an error since we need to compile the eBPF program first
        info!("eBPF support not yet fully implemented - falling back to /proc scanning");
        Err(anyhow::anyhow!("eBPF program not compiled yet"))
    }

    /// Alternative: Load from pre-compiled eBPF object
    pub fn load_from_file(&mut self, path: &str) -> Result<(), anyhow::Error> {
        // Load the compiled eBPF program
        let mut bpf = aya::Ebpf::load(include_bytes!("../ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o"))?;
        
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
        
        let dst_ip_u32: u32 = match dst_ip.parse::<Ipv4Addr>() {
            Ok(ip) => u32::from_be_bytes(ip.octets()),
            Err(_) => return None,
        };
        
        let cache_key = (src_port, dst_ip_u32, dst_port);
        if let Some((pid, timestamp)) = self.local_cache.get(&cache_key) {
            if timestamp.elapsed() < self.ttl {
                debug!("Found PID {} in eBPF cache for {}:{}", pid, dst_ip, dst_port);
                return Some(*pid);
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
        
        let key = SocketKey {
            src_port,
            dst_ip: dst_ip_u32,
            dst_port,
        };
        
        match socket_map.get(&key, 0) {
            Ok(info) => {
                // Cache the result
                self.local_cache.insert(cache_key, (info.pid, Instant::now()));
                debug!("Found PID {} in eBPF map for {}:{}", info.pid, dst_ip, dst_port);
                Some(info.pid)
            }
            Err(_) => {
                // Try with src_port=0 (entry might have been created before port was assigned)
                let key_zero_src = SocketKey {
                    src_port: 0,
                    dst_ip: dst_ip_u32,
                    dst_port,
                };
                
                match socket_map.get(&key_zero_src, 0) {
                    Ok(info) => {
                        // Cache for future lookups
                        self.local_cache.insert(cache_key, (info.pid, Instant::now()));
                        debug!("Found PID {} in eBPF map (zero src) for {}:{}", info.pid, dst_ip, dst_port);
                        Some(info.pid)
                    }
                    Err(_) => None,
                }
            }
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