//! eBPF loader and management for process identification
//! Hooks into socket creation to provide PID lookup by socket.

use aya::{maps::HashMap, programs::KProbe, Pod};
use log::{debug, info};

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// Mirror of eBPF structures
// FIX #2: Field order must match eBPF exactly for compatibility
// FIX #1: Added pid disambiguator to prevent key collisions
// IPv6 Support: Added ip_version field and dst_ip_v6 array
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SocketKey {
    pub src_port: u16,
    pub ip_version: u8, // 4 for IPv4, 6 for IPv6
    pub _pad: [u8; 1],  // Padding for alignment
    pub dst_port: u16,
    pub pid: u32,            // Disambiguator to prevent collisions between processes
    pub dst_ip_v4: u32,      // IPv4 in network byte order (only used when ip_version == 4)
    pub dst_ip_v6: [u8; 16], // IPv6 address (only used when ip_version == 6)
}

unsafe impl Pod for SocketKey {}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SocketInfo {
    pub pid: u32,
    pub timestamp: u64,
    pub comm: [u8; 16], // Process name captured at connection time
}

unsafe impl Pod for SocketInfo {}

impl SocketInfo {
    /// Returns the process name as a string, trimming null bytes
    pub fn comm_str(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..end]).to_string()
    }
}

pub struct EbpfManager {
    bpf: Option<aya::Ebpf>,
}

impl EbpfManager {
    pub fn new() -> Self {
        Self { bpf: None }
    }

    /// Load eBPF object and attach kprobes.
    pub fn load_from_file(&mut self, path: &str) -> Result<(), anyhow::Error> {
        // Load compiled eBPF program
        debug!("Loading eBPF program from: {}", path);
        let mut bpf = aya::Ebpf::load_file(path)?;
        debug!("eBPF program loaded successfully");

        // Attach tcp_v4_connect kprobe
        debug!("Looking for tcp_v4_connect program...");
        let program: &mut KProbe = bpf
            .program_mut("tcp_v4_connect")
            .ok_or(anyhow::anyhow!("tcp_v4_connect program not found"))?
            .try_into()?;
        debug!("tcp_v4_connect program found, loading...");
        program.load()?;
        debug!("tcp_v4_connect loaded, attaching to kernel function...");
        program
            .attach("tcp_v4_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v4_connect: {}", e))?;
        info!("✓ tcp_v4_connect kprobe attached");

        // Attach udp_sendmsg kprobe
        debug!("Looking for udp_sendmsg program...");
        let program: &mut KProbe = bpf
            .program_mut("udp_sendmsg")
            .ok_or(anyhow::anyhow!("udp_sendmsg program not found"))?
            .try_into()?;
        debug!("udp_sendmsg program found, loading...");
        program.load()?;
        debug!("udp_sendmsg loaded, attaching to kernel function...");
        program
            .attach("udp_sendmsg", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach udp_sendmsg: {}", e))?;
        info!("✓ udp_sendmsg kprobe attached");

        // Attach tcp_v6_connect kprobe
        debug!("Looking for tcp_v6_connect program...");
        let program: &mut KProbe = bpf
            .program_mut("tcp_v6_connect")
            .ok_or(anyhow::anyhow!("tcp_v6_connect program not found"))?
            .try_into()?;
        debug!("tcp_v6_connect program found, loading...");
        program.load()?;
        debug!("tcp_v6_connect loaded, attaching to kernel function...");
        program
            .attach("tcp_v6_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v6_connect: {}", e))?;
        info!("✓ tcp_v6_connect kprobe attached");

        // Attach udpv6_sendmsg kprobe
        debug!("Looking for udpv6_sendmsg program...");
        let program: &mut KProbe = bpf
            .program_mut("udpv6_sendmsg")
            .ok_or(anyhow::anyhow!("udpv6_sendmsg program not found"))?
            .try_into()?;
        debug!("udpv6_sendmsg program found, loading...");
        program.load()?;
        debug!("udpv6_sendmsg loaded, attaching to kernel function...");
        program
            .attach("udpv6_sendmsg", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach udpv6_sendmsg: {}", e))?;
        info!("✓ udpv6_sendmsg kprobe attached");

        // Attach tcp_v4_connect kretprobe
        debug!("Looking for tcp_v4_connect_ret program...");
        let program: &mut KProbe = bpf
            .program_mut("tcp_v4_connect_ret")
            .ok_or(anyhow::anyhow!("tcp_v4_connect_ret program not found"))?
            .try_into()?;
        debug!("tcp_v4_connect_ret program found, loading...");
        program.load()?;
        debug!("tcp_v4_connect_ret loaded, attaching to kernel function...");
        program
            .attach("tcp_v4_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v4_connect_ret: {}", e))?;
        info!("✓ tcp_v4_connect_ret kretprobe attached");

        // Attach tcp_v6_connect kretprobe
        debug!("Looking for tcp_v6_connect_ret program...");
        let program: &mut KProbe = bpf
            .program_mut("tcp_v6_connect_ret")
            .ok_or(anyhow::anyhow!("tcp_v6_connect_ret program not found"))?
            .try_into()?;
        debug!("tcp_v6_connect_ret program found, loading...");
        program.load()?;
        debug!("tcp_v6_connect_ret loaded, attaching to kernel function...");
        program
            .attach("tcp_v6_connect", 0)
            .map_err(|e| anyhow::anyhow!("Failed to attach tcp_v6_connect_ret: {}", e))?;
        info!("✓ tcp_v6_connect_ret kretprobe attached");

        self.bpf = Some(bpf);
        info!("eBPF program loaded and kprobes attached successfully");
        Ok(())
    }

    /// Lookup process info (PID and comm name) from eBPF map.
    /// Returns (pid, comm_name) if found, None otherwise.
    /// The comm name is captured at connection time, so it's available even if the process has exited.
    pub fn lookup_process_info(
        &mut self,
        _src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> Option<(u32, String)> {
        // Determine IP version and convert to appropriate format
        let (ip_version, dst_ip_v4, dst_ip_v6) = if dst_ip.contains(':') {
            match Ipv6Addr::from_str(dst_ip) {
                Ok(ip) => (6u8, 0u32, ip.octets() as [u8; 16]),
                Err(_) => return None,
            }
        } else {
            match dst_ip.parse::<Ipv4Addr>() {
                Ok(ip) => (4u8, u32::from_be_bytes(ip.octets()), [0u8; 16]),
                Err(_) => return None,
            }
        };

        // If eBPF is not loaded, return None
        let bpf = self.bpf.as_ref()?;
        let socket_map: HashMap<_, SocketKey, SocketInfo> = match bpf.map("SOCKET_MAP") {
            Some(map) => match HashMap::try_from(map) {
                Ok(m) => m,
                Err(_) => return None,
            },
            None => return None,
        };

        // Iterate through all entries to find matching dst_ip:dst_port
        for (key, info) in socket_map.iter().flatten() {
            let matches = match key.ip_version {
                4 => {
                    key.ip_version == ip_version
                        && key.dst_ip_v4 == dst_ip_v4
                        && key.dst_port == dst_port
                }
                6 => {
                    key.ip_version == ip_version
                        && key.dst_ip_v6 == dst_ip_v6
                        && key.dst_port == dst_port
                }
                _ => false,
            };

            if matches {
                let pid = info.pid;
                let comm = info.comm_str();
                info!(
                    "✓ eBPF match: Found PID {} ({}) for {}:{}",
                    pid, comm, dst_ip, dst_port
                );
                return Some((pid, comm));
            }
        }

        None
    }
}

impl Default for EbpfManager {
    /// Creates a new `EbpfManager` with default runtime state.
    ///
    /// The manager is initialized with no loaded eBPF object, an empty local cache,
    /// the current instant as `last_cleanup`, and a 5-second time-to-live for cache entries.
    ///
    ///
    fn default() -> Self {
        Self::new()
    }
}
