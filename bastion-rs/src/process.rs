//! Process identification module
//! Reads /proc to identify which process owns a network connection.

use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;
use std::time::{Duration, Instant};

use crate::ebpf_loader::EbpfManager;
use crate::proc_parser;

/// Information about an identified process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub exe_path: String,
    pub uid: u32,
}

/// DNS query entry for caching
#[derive(Debug, Clone)]
pub struct DnsQueryEntry {
    pub domain: String,
    pub process_name: String,
    pub pid: u32,
    pub exe_path: String,
    pub timestamp: Instant,
}

/// DNS IP mapping entry
#[derive(Debug, Clone)]
pub struct DnsIpEntry {
    pub ip: String,
    pub domain_hash: u32,
    pub domain_hint: String,
    pub process_name: String,
    pub pid: u32,
    pub timestamp: Instant,
    pub ttl: u32,
}

/// DNS cache for tracking DNS queries and IP mappings
#[derive(Debug)]
pub struct DnsCache {
    /// Domain hash -> query entry mapping
    hash_to_entry: HashMap<u32, DnsQueryEntry>,
    /// IP address -> process/domain mapping
    ip_map: HashMap<String, DnsIpEntry>,
    last_cleanup: Instant,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            hash_to_entry: HashMap::new(),
            ip_map: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Insert a DNS query entry from eBPF
    pub fn insert_from_ebpf(
        &mut self,
        domain_hash: u32,
        pid: u32,
        comm: String,
        domain_hint: Option<String>,
    ) {
        let entry = DnsQueryEntry {
            domain: domain_hint.unwrap_or_else(|| format!("<hash:{}>", domain_hash)),
            process_name: comm.clone(),
            pid,
            exe_path: String::new(), // Fill in later from /proc
            timestamp: Instant::now(),
        };

        // Store by hash
        self.hash_to_entry.insert(domain_hash, entry);
    }

    /// Insert a DNS IP mapping from eBPF
    pub fn insert_ip_mapping(
        &mut self,
        ip: String,
        domain_hash: u32,
        pid: u32,
        comm: String,
        ttl: u32,
    ) {
        let domain_hint = self
            .hash_to_entry
            .get(&domain_hash)
            .map(|e| e.domain.clone())
            .unwrap_or_else(|| format!("<hash:{}>", domain_hash));

        let entry = DnsIpEntry {
            ip: ip.clone(),
            domain_hash,
            domain_hint,
            process_name: comm,
            pid,
            timestamp: Instant::now(),
            ttl,
        };

        self.ip_map.insert(ip, entry);
    }

    /// Lookup process info by IP address (from DNS cache)
    pub fn lookup_by_ip(&self, ip: &str) -> Option<(&DnsIpEntry, &DnsQueryEntry)> {
        let ip_entry = self.ip_map.get(ip)?;
        let query_entry = self.hash_to_entry.get(&ip_entry.domain_hash)?;
        Some((ip_entry, query_entry))
    }

    /// Get domain for an IP address
    pub fn get_domain_for_ip(&self, ip: &str) -> Option<String> {
        self.ip_map.get(ip).map(|e| e.domain_hint.clone())
    }

    /// Cleanup expired entries
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();

        // Cleanup IP entries based on their TTL
        let initial_ip_size = self.ip_map.len();
        self.ip_map.retain(|_, entry| {
            let ttl_duration = Duration::from_secs(entry.ttl as u64);
            now.duration_since(entry.timestamp) < ttl_duration
        });
        let removed_ip = initial_ip_size - self.ip_map.len();

        // Cleanup query entries (older than 5 minutes)
        let initial_query_size = self.hash_to_entry.len();
        self.hash_to_entry
            .retain(|_, entry| now.duration_since(entry.timestamp) < Duration::from_secs(300));
        let removed_query = initial_query_size - self.hash_to_entry.len();

        if removed_ip > 0 || removed_query > 0 {
            debug!(
                "DNS cache cleanup: removed {} IP entries, {} query entries",
                removed_ip, removed_query
            );
        }

        self.last_cleanup = now;
    }

    /// Check if cleanup is needed
    pub fn needs_cleanup(&self) -> bool {
        self.last_cleanup.elapsed() > Duration::from_secs(60)
    }

    /// Get cache statistics
    pub fn stats(&self) -> (usize, usize) {
        (self.hash_to_entry.len(), self.ip_map.len())
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute FNV-1a hash of a string (matches eBPF implementation)
fn jhash_string(domain: &str) -> u32 {
    let mut hash: u32 = 0xDEADBEEF;
    for byte in domain.bytes() {
        hash = hash ^ byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Cache key for eBPF connection lookups
/// Uses destination IP and port to match connections
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ConnectionKey {
    dst_ip: String,
    dst_port: u16,
}

/// Cached eBPF connection information
/// Stores process name and PID captured at connect time
#[derive(Clone)]
struct CachedEbpfInfo {
    pid: u32,
    comm: String,
    timestamp: Instant,
}

/// Process cache - reads /proc directly like Python's psutil
pub struct ProcessCache {
    inode_to_process: HashMap<u64, ProcessInfo>,
    last_scan: Instant,
    ebpf: Option<EbpfManager>,
    // Cache for eBPF connection info with longer TTL than kernel map
    ebpf_connection_cache: HashMap<ConnectionKey, CachedEbpfInfo>,
    last_ebpf_cleanup: Instant,
    // DNS cache for tracking DNS queries and IP mappings
    dns_cache: DnsCache,
}

impl ProcessCache {
    pub fn new(_ttl_secs: u64) -> Self {
        let mut ebpf = EbpfManager::new();
        let ebpf_paths = [
            "/usr/share/bastion-firewall/bastion-ebpf.o",
            "ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o",
        ];

        let mut ebpf_loaded = false;
        for path in &ebpf_paths {
            match ebpf.load_from_file(path) {
                Ok(_) => {
                    info!("eBPF process tracking loaded from {}", path);
                    ebpf_loaded = true;
                    break;
                }
                Err(e) => {
                    warn!("Failed to load eBPF from {}: {}", path, e);
                }
            }
        }

        if !ebpf_loaded {
            warn!("eBPF not available - falling back to /proc scanning");
        }

        let mut cache = Self {
            inode_to_process: HashMap::new(),
            last_scan: Instant::now(),
            ebpf: if ebpf_loaded { Some(ebpf) } else { None },
            ebpf_connection_cache: HashMap::new(),
            last_ebpf_cleanup: Instant::now(),
            dns_cache: DnsCache::new(),
        };
        cache.scan_processes();
        cache
    }

    fn scan_processes(&mut self) {
        self.inode_to_process.clear();
        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return,
        };

        for entry in proc_dir.flatten() {
            let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };

            if let Some(info) = self.get_process_info_by_pid(pid) {
                let fd_path = format!("/proc/{}/fd", pid);
                if let Ok(fds) = fs::read_dir(fd_path) {
                    for fd_entry in fds.flatten() {
                        if let Ok(link) = fs::read_link(fd_entry.path()) {
                            let link_str = link.to_string_lossy();
                            if link_str.starts_with("socket:[") {
                                if let Ok(inode) = link_str[8..link_str.len() - 1].parse::<u64>() {
                                    self.inode_to_process.insert(inode, info.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        self.last_scan = Instant::now();
    }

    pub fn find_process_by_socket(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dest_ip: &str,
        dest_port: u16,
        protocol: &str,
    ) -> Option<ProcessInfo> {
        // Periodic cleanup of eBPF and DNS cache (every 60 seconds)
        if self.last_ebpf_cleanup.elapsed() > Duration::from_secs(60) {
            self.cleanup_ebpf_cache();
            self.last_ebpf_cleanup = Instant::now();
        }

        // DNS cache cleanup
        if self.dns_cache.needs_cleanup() {
            self.dns_cache.cleanup_expired();
        }

        // Poll eBPF DNS maps periodically (first, before other lookups)
        let dns_match = if let Some(ebpf) = self.ebpf.as_mut() {
            // Check if DNS IP map has the destination IP
            let match_result = ebpf.lookup_dns_ip(dest_ip);

            // Poll DNS maps and update cache
            for (ip_addr, query_pid, query_comm, query_domain_hash) in ebpf.poll_dns_ips() {
                self.dns_cache.insert_ip_mapping(
                    ip_addr.to_string(),
                    query_domain_hash,
                    query_pid,
                    query_comm,
                    60, // Default TTL if not in eBPF value
                );
            }

            match_result
        } else {
            None
        };

        // Process DNS match result (outside the mutable borrow)
        if let Some((pid, comm, _domain_hash)) = dns_match {
            // Get domain name from DNS cache if available
            let domain = self.dns_cache.get_domain_for_ip(dest_ip);

            info!(
                "✓ DNS cache hit: {} -> PID {} ({}), domain: {}",
                dest_ip,
                pid,
                comm,
                domain.as_deref().unwrap_or("<unknown>")
            );

            if let Some(mut info) = self.get_process_info_by_pid(pid) {
                info.name = comm.clone();
                return Some(info);
            }
            if !comm.is_empty() {
                return Some(ProcessInfo {
                    name: comm.clone(),
                    exe_path: self.find_exe_by_name(&comm).unwrap_or_default(),
                    uid: 0,
                });
            }
        }

        let cache_key = ConnectionKey {
            dst_ip: dest_ip.to_string(),
            dst_port: dest_port,
        };

        // 1. Check eBPF connection cache first (fast, has comm name)
        if let Some(cached) = self.ebpf_connection_cache.get(&cache_key) {
            if cached.timestamp.elapsed() < Duration::from_secs(60) {
                // Cache entry is still valid (within 60 seconds)
                // Try to get full process info from /proc
                if let Some(mut info) = self.get_process_info_by_pid(cached.pid) {
                    info.name = cached.comm.clone(); // Use eBPF-captured name
                    return Some(info);
                }
                // Process has exited, but we have the name from eBPF
                info!(
                    "✓ eBPF cache hit: Process {} (PID {}) exited, using cached name",
                    cached.comm, cached.pid
                );
                return Some(ProcessInfo {
                    name: cached.comm.clone(),
                    exe_path: self.find_exe_by_name(&cached.comm).unwrap_or_default(),
                    uid: 0,
                });
            }
        }

        // 2. Query live eBPF map with retry logic
        // Retry up to 3 times with 1ms delay to handle race conditions
        // where packet arrives before eBPF kprobe completes
        let ebpf_result = if let Some(ebpf) = self.ebpf.as_mut() {
            let mut retry_count = 0;
            let max_retries = 3;

            let mut result = None;
            loop {
                if let Some((pid, comm)) = ebpf.lookup_process_info(src_port, dest_ip, dest_port) {
                    debug!("eBPF lookup found: PID {} ({}) for {}:{} (retry {})",
                        pid, comm, dest_ip, dest_port, retry_count);

                    // Cache this result for future lookups
                    self.ebpf_connection_cache.insert(
                        cache_key.clone(),
                        CachedEbpfInfo {
                            pid,
                            comm: comm.clone(),
                            timestamp: Instant::now(),
                        },
                    );

                    // Clone values to release the ebpf borrow before calling other self methods
                    let pid_clone = pid;
                    let comm_clone = comm.clone();

                    result = Some((pid_clone, comm_clone));
                    break;
                }

                retry_count += 1;
                if retry_count >= max_retries {
                    debug!("eBPF lookup failed after {} retries for {}:{}",
                        retry_count, dest_ip, dest_port);
                    break;
                }

                // Small sleep to give eBPF kprobe time to complete
                // Only sleep on first retry to avoid excessive delays
                if retry_count == 1 {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            result
        } else {
            None
        };

        // Now process the result after releasing the ebpf borrow
        if let Some((pid, comm)) = ebpf_result {
            if let Some(mut info) = self.get_process_info_by_pid(pid) {
                info.name = comm.clone(); // Use eBPF-captured name
                return Some(info);
            }
            if !comm.is_empty() {
                return Some(ProcessInfo {
                    name: comm.clone(),
                    exe_path: self.find_exe_by_name(&comm).unwrap_or_default(),
                    uid: 0,
                });
            }
        }

        // 3. /proc fallback (for when eBPF misses or isn't available)
        // Scan every 20ms to catch short-lived processes (was 100ms)
        if self.last_scan.elapsed() > Duration::from_millis(20) {
            self.scan_processes();
        }

        let src_addr: IpAddr = src_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let dest_addr: IpAddr = dest_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let entries = proc_parser::read_net_entries(protocol);

        // Exact match
        for entry in &entries {
            if entry.local_addr == src_addr
                && entry.local_port == src_port
                && entry.remote_addr == dest_addr
                && entry.remote_port == dest_port
            {
                if let Some(info) = self.inode_to_process.get(&entry.inode) {
                    return Some(info.clone());
                }
            }
        }

        // Loose match
        for entry in &entries {
            if entry.local_port == src_port
                && (entry.local_addr == src_addr
                    || entry.local_addr == IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            {
                if let Some(info) = self.inode_to_process.get(&entry.inode) {
                    return Some(info.clone());
                }
            }
        }
        None
    }

    fn get_process_info_by_pid(&self, pid: u32) -> Option<ProcessInfo> {
        let name = fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()?
            .trim()
            .to_string();
        let exe_path = fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| clean_exe_path(&p.to_string_lossy()))
            .unwrap_or_default();

        let uid = fs::read_to_string(format!("/proc/{}/status", pid))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|u| u.parse().ok()))
            })
            .unwrap_or(0);

        Some(ProcessInfo {
            name,
            exe_path,
            uid,
        })
    }

    fn find_exe_by_name(&self, name: &str) -> Option<String> {
        for info in self.inode_to_process.values() {
            if info.name == name && !info.exe_path.is_empty() {
                return Some(info.exe_path.clone());
            }
        }
        None
    }

    /// Clean up expired entries from the eBPF connection cache
    fn cleanup_ebpf_cache(&mut self) {
        let now = Instant::now();
        let initial_size = self.ebpf_connection_cache.len();
        self.ebpf_connection_cache
            .retain(|_, info| now.duration_since(info.timestamp) < Duration::from_secs(60));
        let removed = initial_size - self.ebpf_connection_cache.len();
        if removed > 0 {
            info!(
                "eBPF cache cleanup: removed {} expired entries ({} remaining)",
                removed,
                self.ebpf_connection_cache.len()
            );
        }
    }
}

fn clean_exe_path(path: &str) -> String {
    let path = path.split('\0').next().unwrap_or("");
    if let Some(space_idx) = path.find(' ') {
        path[..space_idx].to_string()
    } else {
        path.to_string()
    }
}
