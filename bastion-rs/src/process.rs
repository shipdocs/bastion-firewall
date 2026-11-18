//! Process identification module
//! Reads /proc to identify which process owns a network connection.

use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ebpf_loader::EbpfManager;
use crate::proc_parser;

/// Keep attacker-controlled DNS responses from retaining cache entries indefinitely.
const MAX_DNS_CACHE_ENTRIES: usize = 4096;
const MAX_DNS_CACHE_TTL_SECS: u32 = 24 * 60 * 60;

/// Information about an identified process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub domain_name: Option<String>,
    pub exe_path: String,
    pub uid: u32,
}

/// DNS IP mapping entry
#[derive(Debug, Clone)]
pub struct DnsIpEntry {
    pub domain_hint: String,
    pub process_name: String,
    pub pid: u32,
    pub timestamp: Instant,
    pub ttl: u32,
}

/// DNS cache for tracking DNS queries and IP mappings
#[derive(Debug)]
pub struct DnsCache {
    /// IP address -> process/domain mapping
    ip_map: HashMap<String, DnsIpEntry>,
    last_cleanup: Instant,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            ip_map: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Insert a DNS IP mapping from DNS snooper
    pub fn insert_ip_mapping(
        &mut self,
        ip: String,
        pid: u32,
        comm: String,
        domain: String,
        ttl: u32,
    ) {
        let ttl = ttl.min(MAX_DNS_CACHE_TTL_SECS);

        // DNS responses are untrusted. Keep the cache bounded even when a response
        // supplies many distinct addresses with long TTLs. Replacing an existing
        // address does not require eviction.
        if !self.ip_map.contains_key(&ip) && self.ip_map.len() >= MAX_DNS_CACHE_ENTRIES {
            if let Some(oldest_ip) = self
                .ip_map
                .iter()
                .min_by_key(|(_, entry)| entry.timestamp)
                .map(|(ip, _)| ip.clone())
            {
                self.ip_map.remove(&oldest_ip);
            }
        }

        let entry = DnsIpEntry {
            domain_hint: domain,
            process_name: comm,
            pid,
            timestamp: Instant::now(),
            ttl,
        };

        self.ip_map.insert(ip, entry);
    }

    /// Lookup process info by IP address (from DNS cache)
    pub fn lookup_by_ip(&self, ip: &str) -> Option<&DnsIpEntry> {
        self.ip_map.get(ip)
    }

    /// Cleanup expired entries
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();

        // Cleanup IP entries based on their TTL
        let initial_size = self.ip_map.len();
        self.ip_map.retain(|_, entry| {
            let ttl_duration = Duration::from_secs(entry.ttl as u64);
            now.duration_since(entry.timestamp) < ttl_duration
        });
        let removed = initial_size - self.ip_map.len();

        if removed > 0 {
            debug!("DNS cache cleanup: removed {} IP entries", removed);
        }

        self.last_cleanup = now;
    }

    /// Check if cleanup is needed
    pub fn needs_cleanup(&self) -> bool {
        self.last_cleanup.elapsed() > Duration::from_secs(60)
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{DnsCache, MAX_DNS_CACHE_ENTRIES, MAX_DNS_CACHE_TTL_SECS};
    use super::{pick_socket_inode, pid_owns_inode};
    use crate::proc_parser::NetEntry;
    use std::net::IpAddr;

    fn entry(local_port: u16, remote: &str, remote_port: u16, inode: u64) -> NetEntry {
        NetEntry { local_port, remote_addr: remote.parse().unwrap(), remote_port, inode }
    }

    #[test]
    fn socket_is_chosen_by_source_port_and_destination() {
        let dest: IpAddr = "104.18.25.232".parse().unwrap();
        let entries = vec![
            // Another program, same destination, other source port.
            entry(40000, "104.18.25.232", 443, 11),
            // Our connection.
            entry(40001, "104.18.25.232", 443, 22),
            // Same source port on another protocol family/host.
            entry(40001, "1.1.1.1", 443, 33),
        ];
        assert_eq!(pick_socket_inode(&entries, 40001, dest, 443), Some(22));
        assert_eq!(pick_socket_inode(&entries, 40002, dest, 443), None);
    }

    #[test]
    fn ipv4_mapped_ipv6_socket_matches_ipv4_destination() {
        let dest: IpAddr = "104.18.25.232".parse().unwrap();
        let entries = vec![entry(40001, "::ffff:104.18.25.232", 443, 44)];
        assert_eq!(pick_socket_inode(&entries, 40001, dest, 443), Some(44));
    }

    #[test]
    fn exact_match_wins_over_unconnected_udp_socket() {
        let dest: IpAddr = "9.9.9.9".parse().unwrap();
        let entries = vec![entry(5353, "0.0.0.0", 0, 55), entry(5353, "9.9.9.9", 53, 66)];
        assert_eq!(pick_socket_inode(&entries, 5353, dest, 53), Some(66));
        let only_unconnected = vec![entry(5353, "0.0.0.0", 0, 55)];
        assert_eq!(pick_socket_inode(&only_unconnected, 5353, dest, 53), Some(55));
    }

    /// Reproduces the reported misattribution: two different programs connect to the
    /// same IP:port right after each other. Each must be resolved to itself.
    #[test]
    fn two_programs_same_destination_are_told_apart() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        use std::process::{Command, Stdio};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Program 1: a python3 child that connects and reports its source port.
        let script = format!(
            "import socket,sys,time\ns=socket.create_connection(('127.0.0.1',{}))\n\
             print(s.getsockname()[1]);sys.stdout.flush();time.sleep(5)",
            port
        );
        let mut child = match Command::new("python3").arg("-c").arg(&script).stdout(Stdio::piped()).spawn() {
            Ok(c) => c,
            Err(_) => return, // no python3: nothing to compare against
        };
        let mut out = [0u8; 16];
        let n = child.stdout.as_mut().unwrap().read(&mut out).unwrap();
        let child_port: u16 = std::str::from_utf8(&out[..n]).unwrap().trim().parse().unwrap();

        // Program 2: this test binary, same destination.
        let own = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let own_port = own.local_addr().unwrap().port();

        let mut cache = super::ProcessCache::new(120);
        let child_info = cache
            .find_process_by_socket("127.0.0.1", child_port, "127.0.0.1", port, "TCP")
            .expect("child resolved");
        let own_info = cache
            .find_process_by_socket("127.0.0.1", own_port, "127.0.0.1", port, "TCP")
            .expect("own process resolved");
        let _ = child.kill();
        let _ = child.wait();

        assert!(child_info.exe_path.contains("python3"), "child: {:?}", child_info.exe_path);
        assert_eq!(
            own_info.exe_path,
            std::env::current_exe().unwrap().to_string_lossy(),
            "own process resolved to {:?}",
            own_info.exe_path
        );
    }

    /// The process that resolved a host via DNS must not become the owner of an
    /// unidentified connection to that host (it would get that program's rules).
    #[test]
    fn dns_record_does_not_lend_its_identity() {
        let mut cache = super::ProcessCache::new(120);
        // This test binary "resolved" 192.0.2.10 (TEST-NET-1, never really used).
        cache.dns_cache.lock().insert_ip_mapping(
            "192.0.2.10".to_string(),
            std::process::id(),
            "bastion-test".to_string(),
            "example.test.".to_string(),
            300,
        );
        // A connection nobody owns (no such socket exists).
        let info = cache
            .find_process_by_socket("10.0.0.1", 1, "192.0.2.10", 443, "TCP")
            .expect("domain hint kept");
        assert_eq!(info.name, "unknown");
        assert_eq!(info.exe_path, "unknown");
        assert_eq!(info.domain_name.as_deref(), Some("example.test."));
    }

    #[test]
    fn own_socket_is_found_in_proc_fd() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let inode = crate::proc_parser::read_net_entries("udp")
            .into_iter()
            .find(|e| e.local_port == port)
            .map(|e| e.inode)
            .expect("socket listed in /proc/net/udp");
        assert!(pid_owns_inode(std::process::id(), inode));
        assert!(!pid_owns_inode(std::process::id(), inode + 1_000_000_000));
    }

    #[test]
    fn dns_cache_clamps_untrusted_ttl() {
        let mut cache = DnsCache::new();
        cache.insert_ip_mapping(
            "192.0.2.1".into(), 1, "resolver".into(), "example.test".into(), u32::MAX,
        );

        assert_eq!(
            cache.lookup_by_ip("192.0.2.1").unwrap().ttl,
            MAX_DNS_CACHE_TTL_SECS
        );
    }

    #[test]
    fn dns_cache_evicts_entries_at_capacity() {
        let mut cache = DnsCache::new();
        for index in 0..=MAX_DNS_CACHE_ENTRIES {
            cache.insert_ip_mapping(
                format!("2001:db8::{index:x}"),
                1,
                "resolver".into(),
                "example.test".into(),
                60,
            );
        }

        assert_eq!(cache.ip_map.len(), MAX_DNS_CACHE_ENTRIES);
        assert!(cache
            .lookup_by_ip(&format!("2001:db8::{MAX_DNS_CACHE_ENTRIES:x}"))
            .is_some());
    }
}


/// Inode of the local socket with this source port talking to `dest_ip:dest_port`.
/// An exact remote match wins; an unconnected UDP socket (remote 0.0.0.0:0) on the
/// same source port is accepted as a fallback.
fn find_socket_inode(protocol: &str, src_port: u16, dest_ip: &str, dest_port: u16) -> Option<u64> {
    let dest: IpAddr = dest_ip.parse().ok()?;
    pick_socket_inode(&proc_parser::read_net_entries(protocol), src_port, dest, dest_port)
}

fn pick_socket_inode(entries: &[proc_parser::NetEntry], src_port: u16, dest: IpAddr, dest_port: u16) -> Option<u64> {
    let dest = dest.to_canonical();
    let mut unconnected = None;
    for e in entries.iter().filter(|e| e.local_port == src_port && e.inode != 0) {
        let remote = e.remote_addr.to_canonical();
        if e.remote_port == dest_port && remote == dest {
            return Some(e.inode);
        }
        if e.remote_port == 0 && remote.is_unspecified() && unconnected.is_none() {
            unconnected = Some(e.inode);
        }
    }
    unconnected
}

fn pid_owns_inode(pid: u32, inode: u64) -> bool {
    let target = format!("socket:[{}]", inode);
    match fs::read_dir(format!("/proc/{}/fd", pid)) {
        Ok(fds) => fds
            .flatten()
            .any(|fd| fs::read_link(fd.path()).map(|l| l.to_string_lossy() == target).unwrap_or(false)),
        Err(_) => false,
    }
}

/// Cache key for resolved socket owners. Includes the source port and protocol:
/// keyed on the destination alone, a second program connecting to the same
/// IP:port within the cache lifetime was attributed to the first one.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ConnectionKey {
    protocol: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
}

/// How long eBPF CONN_MAP entries are kept before the daemon prunes them.
const EBPF_CONN_MAX_AGE_NS: u64 = 5 * 60 * 1_000_000_000;

/// Cached eBPF connection information
/// Stores process name and PID captured at connect time
#[derive(Clone)]
struct CachedEbpfInfo {
    pid: u32,
    timestamp: Instant,
}

/// Process cache - reads /proc directly like Python's psutil
pub struct ProcessCache {
    inode_to_process: HashMap<u64, ProcessInfo>,
    inode_to_pid: HashMap<u64, u32>,
    last_scan: Instant,
    ebpf: Option<Arc<parking_lot::Mutex<EbpfManager>>>,
    // Cache for eBPF connection info with longer TTL than kernel map
    ebpf_connection_cache: HashMap<ConnectionKey, CachedEbpfInfo>,
    last_ebpf_cleanup: Instant,
    // DNS cache for tracking DNS queries and IP mappings
    dns_cache: Arc<parking_lot::Mutex<DnsCache>>,
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

        let ebpf_arc = if ebpf_loaded {
            Some(Arc::new(parking_lot::Mutex::new(ebpf)))
        } else {
            None
        };

        let dns_cache = Arc::new(parking_lot::Mutex::new(DnsCache::new()));

        let mut cache = Self {
            inode_to_process: HashMap::new(),
            inode_to_pid: HashMap::new(),
            last_scan: Instant::now(),
            ebpf: ebpf_arc,
            ebpf_connection_cache: HashMap::new(),
            last_ebpf_cleanup: Instant::now(),
            dns_cache,
        };
        cache.scan_processes();
        cache
    }

    /// Get shared reference to eBPF manager for DNS snooper
    pub fn get_ebpf_manager(&self) -> Option<Arc<parking_lot::Mutex<EbpfManager>>> {
        self.ebpf.clone()
    }

    /// Get shared reference to DNS cache for DNS snooper
    pub fn get_dns_cache(&self) -> Option<Arc<parking_lot::Mutex<DnsCache>>> {
        Some(self.dns_cache.clone())
    }

    fn scan_processes(&mut self) {
        self.inode_to_process.clear();
        self.inode_to_pid.clear();
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
                                    self.inode_to_pid.insert(inode, pid);
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
        _src_ip: &str,
        src_port: u16,
        dest_ip: &str,
        dest_port: u16,
        protocol: &str,
    ) -> Option<ProcessInfo> {
        // Periodic cleanup
        if self.last_ebpf_cleanup.elapsed() > Duration::from_secs(60) {
            self.cleanup_ebpf_cache();
            if let Some(ebpf) = &self.ebpf {
                let removed = ebpf.lock().prune_conn_map(EBPF_CONN_MAX_AGE_NS);
                if removed > 0 {
                    debug!("Pruned {} stale eBPF connection entries", removed);
                }
            }
            self.last_ebpf_cleanup = Instant::now();
        }
        if self.dns_cache.lock().needs_cleanup() {
            self.dns_cache.lock().cleanup_expired();
        }

        let cache_key = ConnectionKey {
            protocol: protocol.to_string(),
            src_port,
            dst_ip: dest_ip.to_string(),
            dst_port: dest_port,
        };

        // --- STEP 1: Find the actual process owner of the socket ---
        let mut process_info = self.lookup_socket_owner(src_port, dest_ip, dest_port, protocol, &cache_key);

        // --- STEP 2: Enrich with DNS domain if available ---
        let domain_info = self.dns_cache.lock().lookup_by_ip(dest_ip).cloned();
        
        if let Some(entry) = &domain_info {
            if let Some(ref mut info) = process_info {
                // We have a process AND a domain! Perfect.
                info.domain_name = Some(entry.domain_hint.clone());
                debug!("Enriched process {} with domain {}", info.name, entry.domain_hint);
            } else {
                // No owner found. Keep the domain as a hint only: the process that
                // made the DNS query (often systemd-resolved, or another program that
                // resolved the same host) says nothing about who opened this socket,
                // and giving the connection that program's identity would apply its
                // rules. "unknown" makes the daemon use destination (@dest) rules.
                debug!(
                    "No socket owner for {}:{}; DNS says {} (queried by {} pid {}), treating as unknown",
                    dest_ip, dest_port, entry.domain_hint, entry.process_name, entry.pid
                );
                process_info = Some(ProcessInfo {
                    name: "unknown".to_string(),
                    domain_name: Some(entry.domain_hint.clone()),
                    exe_path: "unknown".to_string(),
                    uid: 0,
                });
            }
        }

        if let Some(info) = &process_info {
            if let Some(domain) = &info.domain_name {
                info!("Process identified: {} ({})", info.name, domain);
            }
        }

        process_info
    }

    /// Find the process that owns the socket of this connection.
    ///
    /// Order, most to least reliable:
    /// 1. /proc/net/{tcp,udp}[6]: the socket with this source port and destination,
    ///    then the process holding that socket inode (first among the processes eBPF
    ///    saw connecting there, then a full /proc scan).
    /// 2. eBPF alone: the newest connect() to exactly this IP and port, if recent.
    ///
    /// Earlier versions tried eBPF first and took whichever entry for the destination
    /// came up first (possibly an old, unrelated process), and finally any entry with
    /// the same port regardless of IP.
    fn lookup_socket_owner(
        &mut self,
        src_port: u16,
        dest_ip: &str,
        dest_port: u16,
        protocol: &str,
        cache_key: &ConnectionKey,
    ) -> Option<ProcessInfo> {
        // 0. Same socket seen recently (e.g. a retransmitted SYN)
        if let Some(cached) = self.ebpf_connection_cache.get(cache_key) {
            if cached.timestamp.elapsed() < Duration::from_secs(60) {
                if let Some(info) = self.get_process_info_by_pid(cached.pid) {
                    return Some(info);
                }
            }
        }

        let candidates = match &self.ebpf {
            Some(ebpf) => ebpf.lock().connection_candidates(dest_ip, dest_port),
            None => Vec::new(),
        };

        // 1. Exact socket owner via /proc
        if let Some(inode) = find_socket_inode(protocol, src_port, dest_ip, dest_port) {
            if let Some(pid) = self.owner_of_inode(inode, &candidates) {
                if let Some(info) = self.get_process_info_by_pid(pid) {
                    self.remember(cache_key, pid);
                    return Some(info);
                }
            }
        }

        // 2. eBPF only (socket already gone or not visible in /proc).
        //    The eBPF metrics count candidate lookups; see connection_candidates.
        let recent = crate::ebpf_loader::pick_recent(
            &candidates,
            crate::ebpf_loader::get_monotonic_ns(),
            crate::ebpf_loader::EBPF_MATCH_MAX_AGE_NS,
        )
        .cloned();
        if let Some(c) = recent {
            debug!("eBPF-only match for {}:{}: PID {} ({})", dest_ip, dest_port, c.pid, c.comm);
            self.remember(cache_key, c.pid);
            if let Some(info) = self.get_process_info_by_pid(c.pid) {
                return Some(info);
            }
            // Process already exited: name only, never a guessed path.
            return Some(ProcessInfo {
                name: c.comm,
                domain_name: None,
                exe_path: String::new(),
                uid: 0,
            });
        }

        None
    }

    fn remember(&mut self, cache_key: &ConnectionKey, pid: u32) {
        self.ebpf_connection_cache.insert(
            cache_key.clone(),
            CachedEbpfInfo {
                pid,
                timestamp: Instant::now(),
            },
        );
    }

    /// PID holding socket `inode`: known sockets, then the eBPF candidates, then a full scan.
    fn owner_of_inode(&mut self, inode: u64, candidates: &[crate::ebpf_loader::EbpfCandidate]) -> Option<u32> {
        if let Some(pid) = self.inode_to_pid.get(&inode) {
            if pid_owns_inode(*pid, inode) {
                return Some(*pid);
            }
        }
        for c in candidates {
            if pid_owns_inode(c.pid, inode) {
                return Some(c.pid);
            }
        }
        self.scan_processes();
        self.inode_to_pid.get(&inode).copied()
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
            domain_name: None,
            exe_path,
            uid,
        })
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
