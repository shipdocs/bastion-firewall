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
    pub uid: u32,
}

/// Connection info from /proc/net/tcp or /proc/net/udp
struct NetEntry {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
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
    /// Creates a new `ProcessCache`, attempts to enable eBPF-based tracking, and populates the inode-to-process map.
    ///
    /// The provided `ttl_secs` parameter is currently unused but reserved for future cache TTL behavior.
    /// On success, this initializes an optional eBPF manager and performs an immediate scan of `/proc` to build the
    /// internal mapping of socket inodes to process information.
    ///
    ///
    pub fn new(_ttl_secs: u64) -> Self {
        // Try to initialize eBPF from installed or dev locations
        let mut ebpf = EbpfManager::new();
        
        // Paths to try in order: installed first, then dev
        let ebpf_paths = [
            "/usr/share/bastion-firewall/bastion-ebpf.o",  // Installed location
            "ebpf/target/bpfel-unknown-none/release/bastion-ebpf.o",  // Dev location
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
                    debug!("eBPF load from {} failed: {}", path, e);
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
        };
        cache.scan_processes();
        info!("Process identifier initialized (eBPF enabled: {})", ebpf_loaded);
        cache
    }
    
    /// Rebuilds the inode-to-process mapping by scanning /proc for processes and their open socket file descriptors.
    ///
    /// This clears the current map, iterates numeric entries under `/proc`, reads each process's name, executable path (when available),
    /// and UID, then inspects `/proc/[pid]/fd` for `socket:[inode]` links to associate socket inodes with ProcessInfo entries.
    /// Updates `self.last_scan` to the current time on completion.
    ///
    ///
    /// cache.scan_processes();
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
            
            // Get process name, exe, and uid
            let (proc_name, exe_path, uid) = match (
                fs::read_to_string(format!("{}/comm", proc_path)),
                fs::read_link(format!("{}/exe", proc_path))
            ) {
                (Ok(name), Ok(exe)) => {
                    let uid = self.get_process_uid(pid).unwrap_or(0);
                    (
                        name.trim().to_string(),
                        exe.to_string_lossy().into_owned(),
                        uid
                    )
                },
                (Ok(name), Err(_)) => {
                    let uid = self.get_process_uid(pid).unwrap_or(0);
                    (name.trim().to_string(), String::new(), uid)
                },
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
                                        uid,
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
    
    /// Retrieve the primary UID of a process by reading /proc/[pid]/status.
    ///
    /// Parses the `Uid:` line from `/proc/<pid>/status` and returns the first numeric UID listed.
    ///
    ///
    /// `Some(uid)` if the primary UID was found and parsed, `None` otherwise.
    ///
    ///
    fn get_process_uid(&self, pid: u32) -> Option<u32> {
        let path = format!("/proc/{}/status", pid);
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if line.starts_with("Uid:") {
                    // Line format: Uid:    1000    1000    1000    1000
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        return parts[1].parse().ok();
                    }
                }
            }
        }
        None
    }
    
    /// Reads and system network tables for the specified protocol and returns parsed entries.
    ///
    /// Accepts "tcp" or "udp" (case-insensitive) and will read both the IPv4 and IPv6
    /// files under `/proc/net/` (e.g. `/proc/net/tcp` and `/proc/net/tcp6`).
    /// Lines that cannot be parsed are ignored.
    ///
    ///
    /// A vector of `NetEntry` structs parsed from the matching `/proc/net/*` files.
    ///
    ///
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
    
    /// Parse a single socket entry line from a /proc/net/* file into a NetEntry.
    ///
    /// Parses the local and remote address/port fields and the socket inode. Returns `Some(NetEntry)` when the line contains a valid entry and `None` if the line is malformed or missing required fields.
    ///
    ///
    /// # use bastion_rs::process::ProcessCache;
    /// # use bastion_rs::process::NetEntry;
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
    
    /// Parse a `/proc/net/*` hex address like `IP_HEX:PORT_HEX` into an `IpAddr` and port.
    ///
    /// Accepts IPv4 in the 8-hex-digit reversed-byte format produced by `/proc/net/tcp`
    /// (e.g. `"0100007F:1F90"` -> `127.0.0.1:8080`) and IPv6 in the 32-hex-digit form used by
    /// `/proc/net/tcp6` (four 8-hex-digit words) (e.g. `"00000000000000000000000001000000:1F90"` -> `::1:8080`).
    ///
    ///
    /// `Some((IpAddr, port))` if parsing succeeds, `None` otherwise.
    ///
    ///
    ///
    fn parse_hex_address(&self, s: &str) -> Option<(IpAddr, u16)> {
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
            Some((IpAddr::V4(ip), port))
        } else if ip_hex.len() == 32 {
            // FIX #23: IPv6 - parse 128-bit address in correct byte order
            // /proc/net/tcp6 stores IPv6 as four 32-bit words in host-endian byte order.
            let mut words = [0u32; 4];
            for i in 0..4 {
                let word_hex = &ip_hex[i * 8..(i + 1) * 8];
                words[i] = u32::from_str_radix(word_hex, 16).ok()?;
            }
            // The words are in host-endian, so we must convert to big-endian bytes for Ipv6Addr.
            let ip_bytes: Result<[u8; 16], _> = [
                words[0].to_be_bytes(),
                words[1].to_be_bytes(),
                words[2].to_be_bytes(),
                words[3].to_be_bytes(),
            ].concat().try_into();

            match ip_bytes {
                Ok(bytes) => {
                    let ip = std::net::Ipv6Addr::from(bytes);
                    Some((IpAddr::V6(ip), port))
                }
                Err(_) => None,
            }
        } else {
            None
        }
    }
    
    /// Locate the process that owns a socket identified by source/destination IPs and ports for a given protocol.
    ///
    /// This first attempts a kernel-level lookup using eBPF (if available) and falls back to scanning /proc and /proc/net
    /// entries to match socket inodes to processes.
    ///
    ///
    /// `Some(ProcessInfo)` containing the owning process information if a matching process is found, `None` otherwise.
    ///
    ///
    pub fn find_process_by_socket(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dest_ip: &str,
        dest_port: u16,
        protocol: &str,
    ) -> Option<ProcessInfo> {
        // FIRST: Try eBPF lookup (kernel-level tracking, most accurate)
        // Now uses lookup_process_info which returns both PID and comm name captured at connection time
        if self.ebpf.is_some() {
            // Get both PID and comm from eBPF (comm is captured at connection time, survives process exit)
            let ebpf_result = {
                let ebpf = self.ebpf.as_mut().unwrap();
                ebpf.lookup_process_info(src_port, dest_ip, dest_port)
            };

            if let Some((pid, ebpf_comm)) = ebpf_result {
                // Try to get full process info from /proc (includes exe path)
                if let Some(info) = self.get_process_info_by_pid(pid) {
                    debug!("eBPF match: {} ({}) PID={}", info.name, info.exe_path, pid);
                    return Some(info);
                }

                // Process exited but we have the comm name from eBPF!
                // This is the key improvement - we can still identify short-lived processes
                if !ebpf_comm.is_empty() {
                    info!("eBPF match (process exited): {} PID={} - using cached comm name", ebpf_comm, pid);
                    return Some(ProcessInfo {
                        pid,
                        name: ebpf_comm.clone(),
                        // Try to find exe path from a similar process with same name
                        exe_path: self.find_exe_by_name(&ebpf_comm).unwrap_or_default(),
                        uid: 0, // Unknown since process exited
                    });
                }
            }
        }
        
        // FALLBACK: /proc scanning (for established connections or if eBPF unavailable)
        // Refresh inode->process map if stale (>100ms)
        if self.last_scan.elapsed() > Duration::from_millis(100) {
            self.scan_processes();
        }
        
        // Parse IPs
        let src_addr: IpAddr = src_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let dest_addr: IpAddr = dest_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        
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
                              entry.local_ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED);
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
    
    /// Retrieve basic process information for the given PID by reading /proc entries.
    ///
    /// Reads /proc/{pid}/comm for the process name and /proc/{pid}/exe for the executable path;
    /// also attempts to obtain the process UID from /proc/{pid}/status. Returns `None` if the
    /// required process files are not present or cannot be read.
    ///
    ///
    /// if let Some(info) = cache.get_process_info_by_pid(1) {
    ///     println!("pid={} name={} exe={} uid={}", info.pid, info.name, info.exe_path, info.uid);
    /// }
    fn get_process_info_by_pid(&self, pid: u32) -> Option<ProcessInfo> {
        let proc_path = format!("/proc/{}", pid);

        // Get process name and exe
        let (proc_name, exe_path, uid) = match (
            fs::read_to_string(format!("{}/comm", proc_path)),
            fs::read_link(format!("{}/exe", proc_path))
        ) {
            (Ok(name), Ok(exe)) => {
                let uid = self.get_process_uid(pid).unwrap_or(0);
                let proc_name = name.trim().to_string();
                let exe_path_str = exe.to_string_lossy().into_owned();
                debug!("✓ Resolved PID {} to process: {} ({})", pid, proc_name, exe_path_str);
                (
                    proc_name,
                    exe_path_str,
                    uid
                )
            },
            (Ok(name), Err(exe_err)) => {
                let uid = self.get_process_uid(pid).unwrap_or(0);
                let proc_name = name.trim().to_string();

                // Try cmdline as fallback when /proc/pid/exe fails
                let exe_path = if let Ok(cmdline) = fs::read_to_string(format!("{}/cmdline", proc_path)) {
                    let first_arg = cmdline.split('\0').next().unwrap_or("");
                    // Skip /proc/self/exe (used by Electron/Chromium, not a real path)
                    if !first_arg.is_empty() && first_arg.starts_with('/') && first_arg != "/proc/self/exe" {
                        debug!("Resolved PID {} to process: {} (from cmdline: {})", pid, proc_name, first_arg);
                        first_arg.to_string()
                    } else {
                        debug!("Resolved PID {} to process: {} (no exe: {}, cmdline: {})", pid, proc_name, exe_err, first_arg);
                        String::new()
                    }
                } else {
                    debug!("Resolved PID {} to process: {} (no exe: {})", pid, proc_name, exe_err);
                    String::new()
                };

                (proc_name, exe_path, uid)
            },
            (Err(comm_err), _) => {
                debug!("Failed to resolve PID {} - process likely exited: {}", pid, comm_err);
                return None;
            }
        };

        Some(ProcessInfo {
            pid,
            name: proc_name,
            exe_path,
            uid,
        })
    }
    
    /// Locate the process that owns a socket matching the given source port and protocol, using any local or remote IP.
    ///
    /// Returns `Some(ProcessInfo)` if a matching process is found, `None` otherwise.
    ///
    ///
    /// if let Some(proc_info) = cache.get(8080, "tcp") {
    ///     println!("Found process {} (pid {})", proc_info.name, proc_info.pid);
    /// }
    pub fn get(&mut self, src_port: u16, protocol: &str) -> Option<ProcessInfo> {
        self.find_process_by_socket("0.0.0.0", src_port, "0.0.0.0", 0, protocol)
    }
    
    /// Compatibility stub for locating the process owning a connection by destination address and port.
    ///
    /// This method is a placeholder and intentionally does not perform any lookup.
    ///
    ///
    /// `None` — this function is not implemented and always returns `None`.
    ///
    ///
    pub fn get_by_destination(&self, _dest_ip: &str, _dest_port: u16) -> Option<ProcessInfo> {
        None
    }

    /// Find the executable path for a process by its name.
    /// Searches the inode_to_process cache for a process with matching name.
    /// This is used as a fallback when the original process has exited but we have its name from eBPF.
    fn find_exe_by_name(&self, name: &str) -> Option<String> {
        // Look for any process with the same name that has a valid exe path
        for info in self.inode_to_process.values() {
            if info.name == name && !info.exe_path.is_empty() {
                return Some(info.exe_path.clone());
            }
        }

        // Also try scanning /proc for a matching process
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) {
                    if pid_str.chars().all(|c| c.is_ascii_digit()) {
                        // Check if this process has the same name
                        if let Ok(comm) = fs::read_to_string(format!("{}/comm", path.display())) {
                            if comm.trim() == name {
                                // Found a matching process, get its exe path
                                if let Ok(exe) = fs::read_link(format!("{}/exe", path.display())) {
                                    let exe_str = exe.to_string_lossy().to_string();
                                    if !exe_str.is_empty() && !exe_str.contains("(deleted)") {
                                        return Some(exe_str);
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
}