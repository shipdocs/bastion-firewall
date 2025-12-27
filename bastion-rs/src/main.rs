//! Bastion Firewall Daemon - Rust Edition v0.4
//! 
//! Uses nfq crate - learning mode for now, popup support planned

mod process;
mod rules;
mod config;
mod ipc;
mod whitelist;

use nfq::{Queue, Verdict};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};
use std::sync::Arc;
use std::time::Duration;
use std::thread;
use log::{info, warn, error, debug};
use parking_lot::Mutex;

use process::ProcessCache;
use rules::RuleManager;
use config::ConfigManager;
use whitelist::should_auto_allow;

const QUEUE_NUM: u16 = 1;

#[derive(Default)]
pub struct Stats {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub blocked_connections: u64,
    pub pending_decisions: u64,
}

/// Request sent to GUI for decision
#[derive(Clone)]
pub struct PendingDecision {
    pub id: u64,
    pub app_name: String,
    pub app_path: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
}

/// Response from GUI
pub struct DecisionResponse {
    pub id: u64,
    pub allow: bool,
    pub permanent: bool,
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
    
    info!("╔════════════════════════════════════════╗");
    info!("║  Bastion Firewall Daemon (Rust) v0.4  ║");
    info!("╚════════════════════════════════════════╝");
    
    let config = ConfigManager::new();
    let learning_mode = config.is_learning_mode();
    let rules = Arc::new(RuleManager::new());
    let stats = Arc::new(Mutex::new(Stats::default()));
    
    info!("Mode: {}", if learning_mode { "🎓 Learning (allow unknown)" } else { "🛡️ Enforcement (block unknown)" });
    
    // Start IPC server for GUI connection (stats only for now)
    ipc::start_ipc_server(stats.clone());
    
    // Open NFQUEUE
    let mut queue = Queue::open()?;
    queue.bind(QUEUE_NUM)?;
    
    info!("Listening on NFQUEUE {}", QUEUE_NUM);
    info!("Ready for packets!");
    
    // Stats printer
    let stats_clone = stats.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(30));
            let s = stats_clone.lock();
            info!("📊 Stats: {} total, {} allowed, {} blocked", 
                s.total_connections, s.allowed_connections, s.blocked_connections);
        }
    });
    
    // Process cache
    let process_cache = Mutex::new(ProcessCache::new(120));
    
    // Main packet processing loop
    loop {
        let mut msg = match queue.recv() {
            Ok(m) => m,
            Err(e) => {
                error!("Queue recv error: {}", e);
                continue;
            }
        };
        
        stats.lock().total_connections += 1;
        
        let payload = msg.get_payload();
        let verdict = process_packet(payload, &rules, &process_cache, learning_mode);
        
        msg.set_verdict(verdict);
        if let Err(e) = queue.verdict(msg) {
            error!("Failed to send verdict: {}", e);
        }
        
        let mut s = stats.lock();
        if verdict == Verdict::Accept {
            s.allowed_connections += 1;
        } else {
            s.blocked_connections += 1;
        }
    }
}

fn process_packet(
    payload: &[u8],
    rules: &RuleManager,
    process_cache: &Mutex<ProcessCache>,
    learning_mode: bool,
) -> Verdict {
    // Parse IP header
    let ip_header = match Ipv4HeaderSlice::from_slice(payload) {
        Ok(h) => h,
        Err(_) => return Verdict::Accept,
    };
    
    let dst_ip = ip_header.destination_addr();
    let dst_ip_str = format!("{}", dst_ip);
    let proto = ip_header.protocol();
    
    let ip_len = ip_header.slice().len();
    if payload.len() <= ip_len {
        return Verdict::Accept;
    }
    
    let transport_slice = &payload[ip_len..];
    
    // Parse transport layer
    let (src_port, dst_port, protocol_str) = match proto {
        6 => match TcpHeaderSlice::from_slice(transport_slice) {
            Ok(tcp) => (tcp.source_port(), tcp.destination_port(), "tcp"),
            Err(_) => return Verdict::Accept,
        },
        17 => match UdpHeaderSlice::from_slice(transport_slice) {
            Ok(udp) => (udp.source_port(), udp.destination_port(), "udp"),
            Err(_) => return Verdict::Accept,
        },
        _ => return Verdict::Accept,
    };
    
    // Identify process
    let process_info = process_cache.lock().get(src_port, protocol_str);
    let (app_name, app_path) = match &process_info {
        Some(info) => (info.name.clone(), info.exe_path.clone()),
        None => ("unknown".to_string(), "unknown".to_string()),
    };
    
    // Check whitelist
    let (auto_allow, reason) = should_auto_allow(&app_path, dst_port, &dst_ip_str);
    if auto_allow {
        debug!("[AUTO] {} - {}", app_name, reason);
        return Verdict::Accept;
    }
    
    // Check rules
    if app_path != "unknown" {
        if let Some(allow) = rules.get_decision(&app_path, dst_port) {
            return if allow {
                debug!("[RULE:ALLOW] {} -> {}:{}", app_name, dst_ip, dst_port);
                Verdict::Accept
            } else {
                info!("[RULE:BLOCK] {} -> {}:{}", app_name, dst_ip, dst_port);
                Verdict::Drop
            };
        }
    }
    
    // Unknown app - use mode default
    if learning_mode {
        info!("[LEARN] {} ({}) -> {}:{}", app_name, app_path, dst_ip, dst_port);
        Verdict::Accept
    } else {
        if app_path == "unknown" {
            debug!("[PASS] Unknown process -> {}:{}", dst_ip, dst_port);
            Verdict::Accept
        } else {
            warn!("[BLOCK] {} -> {}:{} (no rule)", app_name, dst_ip, dst_port);
            Verdict::Drop
        }
    }
}
