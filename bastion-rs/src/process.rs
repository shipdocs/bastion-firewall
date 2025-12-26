//! Process identification module
//! Maps network connections to process PIDs by reading /proc

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use log::{debug, warn};

/// Information about an identified process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
}

/// Find the process that owns a socket by source port
pub fn find_process_by_port(src_port: u16, protocol: &str) -> Option<ProcessInfo> {
    // 1. Find inode from /proc/net/tcp or /proc/net/udp
    let inode = find_socket_inode(src_port, protocol)?;
    
    // 2. Find PID that owns this inode
    let pid = find_pid_by_inode(inode)?;
    
    // 3. Get process info
    get_process_info(pid)
}

/// Parse /proc/net/tcp or /proc/net/udp to find socket inode
fn find_socket_inode(src_port: u16, protocol: &str) -> Option<u64> {
    let path = match protocol {
        "tcp" => "/proc/net/tcp",
        "udp" => "/proc/net/udp",
        _ => return None,
    };
    
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    
    // Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
    for line in reader.lines().skip(1) {
        let line = line.ok()?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        
        // local_address is in hex format: IP:PORT
        let local_addr = parts[1];
        if let Some(port_hex) = local_addr.split(':').nth(1) {
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                if port == src_port {
                    // inode is at index 9
                    if let Ok(inode) = parts[9].parse::<u64>() {
                        return Some(inode);
                    }
                }
            }
        }
    }
    
    None
}

/// Find PID that owns a socket inode by scanning /proc/[pid]/fd
fn find_pid_by_inode(target_inode: u64) -> Option<u32> {
    let proc_dir = Path::new("/proc");
    
    for entry in fs::read_dir(proc_dir).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let name_str = name.to_str()?;
        
        // Only process numeric directories (PIDs)
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        
        // Check /proc/[pid]/fd
        let fd_path = proc_dir.join(name_str).join("fd");
        if let Ok(fd_entries) = fs::read_dir(&fd_path) {
            for fd_entry in fd_entries.flatten() {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    let link_str = link.to_string_lossy();
                    // Socket links look like: socket:[12345]
                    if link_str.starts_with("socket:[") {
                        if let Some(inode_str) = link_str
                            .strip_prefix("socket:[")
                            .and_then(|s| s.strip_suffix(']'))
                        {
                            if let Ok(inode) = inode_str.parse::<u64>() {
                                if inode == target_inode {
                                    return Some(pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Get process information from /proc/[pid]
fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    let proc_path = Path::new("/proc").join(pid.to_string());
    
    // Get executable path
    let exe_path = fs::read_link(proc_path.join("exe"))
        .ok()?
        .to_string_lossy()
        .into_owned();
    
    // Get process name from /proc/[pid]/comm
    let name = fs::read_to_string(proc_path.join("comm"))
        .ok()?
        .trim()
        .to_string();
    
    Some(ProcessInfo {
        pid,
        name,
        exe_path,
    })
}

/// Cache for process lookups
pub struct ProcessCache {
    cache: HashMap<(u16, String), (ProcessInfo, std::time::Instant)>,
    ttl: std::time::Duration,
}

impl ProcessCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            cache: HashMap::new(),
            ttl: std::time::Duration::from_secs(ttl_secs),
        }
    }
    
    pub fn get(&mut self, src_port: u16, protocol: &str) -> Option<ProcessInfo> {
        let key = (src_port, protocol.to_string());
        
        // Check cache
        if let Some((info, timestamp)) = self.cache.get(&key) {
            if timestamp.elapsed() < self.ttl {
                return Some(info.clone());
            }
        }
        
        // Cache miss or expired - lookup
        if let Some(info) = find_process_by_port(src_port, protocol) {
            self.cache.insert(key, (info.clone(), std::time::Instant::now()));
            return Some(info);
        }
        
        None
    }
    
    /// Clean expired entries
    pub fn cleanup(&mut self) {
        self.cache.retain(|_, (_, ts)| ts.elapsed() < self.ttl);
    }
}
