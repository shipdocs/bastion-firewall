//! Process identification module
//! Directly reads /proc like Python's psutil does

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use log::{debug, info, warn};
use crate::ebpf_loader::EbpfManager;

/// Information about an identified process  
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
}

/// Connection info from /proc/net/tcp or /proc/net/udp
struct NetEntry {
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    inode: u64,
}

/// Process cache - reads /proc directly like Python's psutil
pub struct ProcessCache {
    // Map inode -> (pid, name, exe_path), built from /proc/[pid]/fd
    inode_to_process: HashMap<u64, ProcessInfo>,
    last_scan: Instant,
    // eBPF manager for kernel-level tracking
    ebpf: Option<EbpfManager>,
}

impl ProcessCache {
    pub fn new(_ttl_secs: u64) -> Self {
        // Try to initialize eBPF
        let mut ebpf = EbpfManager::new();
        let ebpf_loaded = match ebpf.load_from_file("ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o") {
            Ok(_) => {
                info!("✅ eBPF process tracking loaded successfully");
                true
            }
            Err(e) => {
                warn!("eBPF load failed: {}", e);
                false
            }
        };
        
        let mut cache = Self {
            inode_to_process: HashMap::new(),
            last_scan: Instant::now(),
            ebpf: if ebpf_loaded { Some(ebpf) } else { None },
        };
        cache.scan_processes();
        info!("Process identifier initialized (eBPF enabled: {})", ebpf_loaded);
        cache
    }
    
    /// Scan all /proc/[pid]/fd to build inode->process map
    fn scan_processes(&mut self) {
        self.inode_to_process.clear();
        
        let proc_dir = match fs::read_dir("/proc") {
            Ok(d) => d,
            Err(_) => return,
        };
        
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            
            // Only numeric directories (PIDs)
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            
            let proc_path = format!("/proc/{}", pid);
            
            // Get process name and exe
            let (proc_name, exe_path) = match (
                fs::read_to_string(format!("{}/comm", proc_path)),
                fs::read_link(format!("{}/exe", proc_path))
            ) {
                (Ok(name), Ok(exe)) => (
                    name.trim().to_string(),
                    exe.to_string_lossy().into_owned()
                ),
                (Ok(name), Err(_)) => (name.trim().to_string(), String::new()),
                _ => continue,
            };
            
            // Scan fd directory for socket inodes
            let fd_path = format!("{}/fd", proc_path);
            if let Ok(fds) = fs::read_dir(&fd_path) {
                for fd_entry in fds.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") {
                            if let Some(inode_str) = link_str
                                .strip_prefix("socket:[")
                                .and_then(|s| s.strip_suffix(']'))
                            {
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    self.inode_to_process.insert(inode, ProcessInfo {
                                        pid,
                                        name: proc_name.clone(),
                                        exe_path: exe_path.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        self.last_scan = Instant::now();
    }
    
    /// Read /proc/net/tcp or /proc/net/udp
    fn read_net_entries(&self, protocol: &str) -> Vec<NetEntry> {
        let mut entries = Vec::new();
        
        let paths = match protocol.to_lowercase().as_str() {
            "tcp" => vec!["/proc/net/tcp", "/proc/net/tcp6"],
            "udp" => vec!["/proc/net/udp", "/proc/net/udp6"],
            _ => return entries,
        };
        
        for path in paths {
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines().skip(1) {
                    if let Ok(line) = line {
                        if let Some(entry) = self.parse_net_line(&line) {
                            entries.push(entry);
                        }
                    }
                }
            }
        }
        
        entries
    }
    
    /// Parse a line from /proc/net/tcp
    /// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
    fn parse_net_line(&self, line: &str) -> Option<NetEntry> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }
        
        // Parse local address (hex IP:hex port)
        let (local_ip, local_port) = self.parse_hex_address(parts[1])?;
        
        // Parse remote address
        let (remote_ip, remote_port) = self.parse_hex_address(parts[2])?;
        
        // Parse inode (field 9)
        let inode: u64 = parts[9].parse().ok()?;
        
        Some(NetEntry {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            inode,
        })
    }
    
    /// Parse "0100007F:1F90" -> (127.0.0.1, 8080)
    fn parse_hex_address(&self, s: &str) -> Option<(Ipv4Addr, u16)> {
        let (ip_hex, port_hex) = s.split_once(':')?;
        
        // Parse port
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        
        // Parse IP (in reverse byte order for IPv4)
        if ip_hex.len() == 8 {
            let ip_num = u32::from_str_radix(ip_hex, 16).ok()?;
            // Reverse byte order
            let ip = Ipv4Addr::new(
                (ip_num & 0xFF) as u8,
                ((ip_num >> 8) & 0xFF) as u8,
                ((ip_num >> 16) & 0xFF) as u8,
                ((ip_num >> 24) & 0xFF) as u8,
            );
            Some((ip, port))
        } else {
            // IPv6 - simplified handling
            Some((Ipv4Addr::UNSPECIFIED, port))
        }
    }
    
    /// Find process by socket - like Python's find_process_by_socket
    pub fn find_process_by_socket(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dest_ip: &str,
        dest_port: u16,
        protocol: &str,
    ) -> Option<ProcessInfo> {
        // FIRST: Try eBPF lookup (kernel-level tracking, most accurate)
        if let Some(ref mut ebpf) = self.ebpf {
            if let Some(pid) = ebpf.lookup_pid(src_port, dest_ip, dest_port) {
                // Got PID from eBPF, now resolve to process info
                if let Some(info) = self.get_process_info_by_pid(pid) {
                    debug!("eBPF match: {} ({}) PID={}", info.name, info.exe_path, pid);
                    return Some(info);
                }
            }
        }
        
        // FALLBACK: /proc scanning (for established connections or if eBPF unavailable)
        // Refresh inode->process map if stale (>100ms)
        if self.last_scan.elapsed() > Duration::from_millis(100) {
            self.scan_processes();
        }
        
        // Parse IPs
        let src_addr: Ipv4Addr = src_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let dest_addr: Ipv4Addr = dest_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
        
        // Read current network connections
        let entries = self.read_net_entries(protocol);
        
        // First try: exact match
        for entry in &entries {
            if entry.local_ip == src_addr && 
               entry.local_port == src_port &&
               entry.remote_ip == dest_addr &&
               entry.remote_port == dest_port {
                if let Some(info) = self.inode_to_process.get(&entry.inode) {
                    debug!("Exact match: {} ({}) inode={}", info.name, info.exe_path, entry.inode);
                    return Some(info.clone());
                }
            }
        }
        
        // Fallback: match by local port with wildcard IP
        for entry in &entries {
            if entry.local_port == src_port {
                let is_match = entry.local_ip == src_addr || 
                              entry.local_ip == Ipv4Addr::UNSPECIFIED;
                if is_match {
                    if let Some(info) = self.inode_to_process.get(&entry.inode) {
                        debug!("Loose match: {} ({}) on port {}", info.name, info.exe_path, src_port);
                        return Some(info.clone());
                    }
                }
            }
        }
        
        debug!("No process found for {}:{} -> {}:{}", src_ip, src_port, dest_ip, dest_port);
        None
    }
    
    /// Helper: Get process info by PID (used after eBPF lookup)
    fn get_process_info_by_pid(&self, pid: u32) -> Option<ProcessInfo> {
        let proc_path = format!("/proc/{}", pid);
        
        // Get process name and exe
        let (proc_name, exe_path) = match (
            fs::read_to_string(format!("{}/comm", proc_path)),
            fs::read_link(format!("{}/exe", proc_path))
        ) {
            (Ok(name), Ok(exe)) => (
                name.trim().to_string(),
                exe.to_string_lossy().into_owned()
            ),
            (Ok(name), Err(_)) => (name.trim().to_string(), String::new()),
            _ => return None,
        };
        
        Some(ProcessInfo {
            pid,
            name: proc_name,
            exe_path,
        })
    }
    
    /// Compatibility interface
    pub fn get(&mut self, src_port: u16, protocol: &str) -> Option<ProcessInfo> {
        self.find_process_by_socket("0.0.0.0", src_port, "0.0.0.0", 0, protocol)
    }
    
    pub fn get_by_destination(&self, _dest_ip: &str, _dest_port: u16) -> Option<ProcessInfo> {
        None
    }
}
