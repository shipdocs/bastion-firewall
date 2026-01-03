//! Process identification module
//! Reads /proc to identify which process owns a network connection.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use log::{info, warn};

use crate::ebpf_loader::EbpfManager;
use crate::proc_parser;

/// Information about an identified process  
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub exe_path: String,
    pub uid: u32,
}

/// Process cache - reads /proc directly like Python's psutil
pub struct ProcessCache {
    inode_to_process: HashMap<u64, ProcessInfo>,
    last_scan: Instant,
    ebpf: Option<EbpfManager>,
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
            if ebpf.load_from_file(path).is_ok() {
                info!("eBPF process tracking loaded from {}", path);
                ebpf_loaded = true;
                break;
            }
        }
        
        if !ebpf_loaded {
            warn!("eBPF not available - falling back to /proc scanning");
        }
        
        let mut cache = Self {
            inode_to_process: HashMap::new(),
            last_scan: Instant::now(),
            ebpf: if ebpf_loaded { Some(ebpf) } else { None },
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
                                if let Some(inode) = link_str[8..link_str.len()-1].parse::<u64>().ok() {
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
        // 1. eBPF lookup
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some((pid, comm)) = ebpf.lookup_process_info(src_port, dest_ip, dest_port) {
                if let Some(info) = self.get_process_info_by_pid(pid) {
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
        }
        
        // 2. /proc fallback
        if self.last_scan.elapsed() > Duration::from_millis(100) {
            self.scan_processes();
        }
        
        let src_addr: IpAddr = src_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let dest_addr: IpAddr = dest_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        
        let entries = proc_parser::read_net_entries(protocol);
        
        // Exact match
        for entry in &entries {
            if entry.local_addr == src_addr && entry.local_port == src_port &&
               entry.remote_addr == dest_addr && entry.remote_port == dest_port {
                if let Some(info) = self.inode_to_process.get(&entry.inode) {
                    return Some(info.clone());
                }
            }
        }
        
        // Loose match
        for entry in &entries {
            if entry.local_port == src_port && (entry.local_addr == src_addr || entry.local_addr == IpAddr::V4(Ipv4Addr::UNSPECIFIED)) {
                if let Some(info) = self.inode_to_process.get(&entry.inode) {
                    return Some(info.clone());
                }
            }
        }
        None
    }
    
    fn get_process_info_by_pid(&self, pid: u32) -> Option<ProcessInfo> {
        let name = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?.trim().to_string();
        let exe_path = fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| clean_exe_path(&p.to_string_lossy()))
            .unwrap_or_default();
            
        let uid = fs::read_to_string(format!("/proc/{}/status", pid)).ok().and_then(|s| {
            s.lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(1).and_then(|u| u.parse().ok()))
        }).unwrap_or(0);

        Some(ProcessInfo { name, exe_path, uid })
    }
    
    
    fn find_exe_by_name(&self, name: &str) -> Option<String> {
        for info in self.inode_to_process.values() {
            if info.name == name && !info.exe_path.is_empty() {
                return Some(info.exe_path.clone());
            }
        }
        None
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