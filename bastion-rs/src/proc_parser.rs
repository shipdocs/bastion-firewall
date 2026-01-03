use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::fs::File;
use std::io::{BufRead, BufReader};


/// Connection info from /proc/net/tcp or /proc/net/udp
#[derive(Debug, Clone)]
pub struct NetEntry {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub inode: u64,
}

pub fn read_net_entries(protocol: &str) -> Vec<NetEntry> {
    let mut entries = Vec::new();
    let files = match protocol.to_lowercase().as_str() {
        "tcp" => vec!["/proc/net/tcp", "/proc/net/tcp6"],
        "udp" => vec!["/proc/net/udp", "/proc/net/udp6"],
        _ => return entries,
    };

    for path in files {
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().skip(1).flatten() {
                if let Some(entry) = parse_net_line(&line) {
                    entries.push(entry);
                }
            }
        }
    }
    entries
}

fn parse_net_line(line: &str) -> Option<NetEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let (local_addr, local_port) = parse_hex_address(parts[1])?;
    let (remote_addr, remote_port) = parse_hex_address(parts[2])?;
    let inode = parts[9].parse::<u64>().ok()?;

    Some(NetEntry {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        inode,
    })
}

fn parse_hex_address(s: &str) -> Option<(IpAddr, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let hex_addr = parts[0];
    let port = u16::from_str_radix(parts[1], 16).ok()?;

    if hex_addr.len() == 8 {
        // IPv4: stored as little-endian hex
        let bytes = u32::from_str_radix(hex_addr, 16).ok()?;
        let ip = IpAddr::V4(Ipv4Addr::from(bytes.swap_bytes()));
        Some((ip, port))
    } else if hex_addr.len() == 32 {
        // IPv6: 4 groups of 4 bytes, each group is little-endian
        let mut octets = [0u8; 16];
        for i in 0..4 {
            let group = u32::from_str_radix(&hex_addr[i * 8..(i + 1) * 8], 16).ok()?;
            let group_bytes = group.to_ne_bytes();
            octets[i * 4..(i + 1) * 4].copy_from_slice(&group_bytes);
        }
        Some((IpAddr::V6(Ipv6Addr::from(octets)), port))
    } else {
        None
    }
}
