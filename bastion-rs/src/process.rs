//! Process identification module using procfs crate
//! Maps network connections to processes efficiently

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use log::{debug, info};
use parking_lot::RwLock;
use procfs::process::{all_processes, FDTarget};
use procfs::net::{TcpNetEntry, UdpNetEntry};

/// Information about an identified process
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
}

/// Cache that maps (port, protocol) -> ProcessInfo
/// Uses procfs for efficient lookup
pub struct ProcessCache {
    // Inode to process mapping (built by background scanner)
    inode_map: Arc<RwLock<HashMap<u64, ProcessInfo>>>,
    // Recent lookups cache
    cache: HashMap<(u16, String), (ProcessInfo, std::time::Instant)>,
    ttl: Duration,
}

impl ProcessCache {
    pub fn new(_ttl_secs: u64) -> Self {
        let inode_map = Arc::new(RwLock::new(HashMap::new()));
        
        // Do initial scan
        Self::scan_all_processes(&inode_map);
        
        // Start background scanner
        let map_clone = inode_map.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_millis(250)); // Faster refresh
                Self::scan_all_processes(&map_clone);
            }
        });
        
        info!("Process scanner started (background refresh every 250ms)");
        
        Self {
            inode_map,
            cache: HashMap::new(),
            ttl: Duration::from_secs(30),
        }
    }
    
    fn scan_all_processes(map: &Arc<RwLock<HashMap<u64, ProcessInfo>>>) {
        let mut new_map = HashMap::new();
        
        // Iterate all processes
        if let Ok(procs) = all_processes() {
            for proc_result in procs {
                if let Ok(proc) = proc_result {
                    let pid = proc.pid as u32;
                    
                    // Get process name and exe path
                    let (name, exe_path) = match (proc.stat(), proc.exe()) {
                        (Ok(stat), Ok(exe)) => (stat.comm, exe.to_string_lossy().into_owned()),
                        (Ok(stat), Err(_)) => (stat.comm, String::new()),
                        _ => continue,
                    };
                    
                    // Get all file descriptors and find sockets
                    if let Ok(fds) = proc.fd() {
                        for fd_result in fds {
                            if let Ok(fd_info) = fd_result {
                                if let FDTarget::Socket(inode) = fd_info.target {
                                    new_map.insert(inode, ProcessInfo {
                                        pid,
                                        name: name.clone(),
                                        exe_path: exe_path.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        let mut lock = map.write();
        *lock = new_map;
    }
    
    pub fn get(&mut self, src_port: u16, protocol: &str) -> Option<ProcessInfo> {
        let key = (src_port, protocol.to_string());
        
        // Check cache first
        if let Some((info, ts)) = self.cache.get(&key) {
            if ts.elapsed() < self.ttl {
                return Some(info.clone());
            }
        }
        
        // Find the inode for this port
        let inode = self.find_inode(src_port, protocol)?;
        
        // Look up in pre-scanned map
        let map = self.inode_map.read();
        if let Some(info) = map.get(&inode) {
            debug!("Identified: {} ({}) via inode {}", info.name, info.exe_path, inode);
            let info_clone = info.clone();
            drop(map);
            self.cache.insert(key, (info_clone.clone(), std::time::Instant::now()));
            return Some(info_clone);
        }
        
        debug!("No process found for inode {} (port {} {})", inode, src_port, protocol);
        None
    }
    
    fn find_inode(&self, src_port: u16, protocol: &str) -> Option<u64> {
        match protocol {
            "tcp" => self.find_tcp_inode(src_port),
            "udp" => self.find_udp_inode(src_port),
            _ => None,
        }
    }
    
    fn find_tcp_inode(&self, port: u16) -> Option<u64> {
        // Check IPv4
        if let Ok(tcp) = procfs::net::tcp() {
            for entry in tcp {
                if entry.local_address.port() == port {
                    return Some(entry.inode);
                }
            }
        }
        
        // Check IPv6
        if let Ok(tcp6) = procfs::net::tcp6() {
            for entry in tcp6 {
                if entry.local_address.port() == port {
                    return Some(entry.inode);
                }
            }
        }
        
        None
    }
    
    fn find_udp_inode(&self, port: u16) -> Option<u64> {
        // Check IPv4
        if let Ok(udp) = procfs::net::udp() {
            for entry in udp {
                if entry.local_address.port() == port {
                    return Some(entry.inode);
                }
            }
        }
        
        // Check IPv6
        if let Ok(udp6) = procfs::net::udp6() {
            for entry in udp6 {
                if entry.local_address.port() == port {
                    return Some(entry.inode);
                }
            }
        }
        
        None
    }
}
