//! Bastion Firewall Daemon - Rust Edition
//! 
//! A high-performance application firewall using Netfilter Queue

mod process;
mod rules;
mod config;
mod ipc;

use nfqueue::{Queue, Verdict, CopyMode, Message};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};
use std::sync::Arc;
use log::{info, warn, error, debug};
use parking_lot::Mutex;

use process::ProcessCache;
use rules::RuleManager;
use config::ConfigManager;
use ipc::{IpcServer, Stats};

// Global state (needed because nfqueue uses function pointers)
static mut DAEMON_STATE: Option<Arc<DaemonState>> = None;

struct DaemonState {
    config: ConfigManager,
    rules: Arc<RuleManager>,
    process_cache: Mutex<ProcessCache>,
    stats: Arc<Mutex<Stats>>,
    learning_mode: bool,
}

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
    
    info!("Bastion Daemon (Rust) starting...");
    
    // Initialize components
    let config = ConfigManager::new();
    let learning_mode = config.is_learning_mode();
    let rules = Arc::new(RuleManager::new());
    let stats = Arc::new(Mutex::new(Stats::default()));
    
    let state = Arc::new(DaemonState {
        config,
        rules: rules.clone(),
        process_cache: Mutex::new(ProcessCache::new(120)),
        stats: stats.clone(),
        learning_mode,
    });
    
    // Set global state
    unsafe {
        DAEMON_STATE = Some(state.clone());
    }
    
    info!("Mode: {}", if learning_mode { "Learning" } else { "Enforcement" });
    
    // Setup nfqueue
    let mut queue = Queue::new(());
    queue.open();
    
    if queue.unbind(libc::AF_INET) != 0 {
        debug!("Unbind returned non-zero (first run?)");
    }
    if queue.bind(libc::AF_INET) != 0 {
        error!("Failed to bind AF_INET");
        return;
    }
    
    queue.create_queue(1, packet_handler);
    queue.set_mode(CopyMode::CopyPacket, 0xFFFF);
    
    info!("Listening on NFQUEUE 1");
    info!("Ready to process packets!");
    
    // Run the queue loop (blocking)
    queue.run_loop();
    
    queue.close();
    info!("Daemon stopped");
}

fn packet_handler(msg: &Message, _: &mut ()) {
    let state = unsafe {
        match &DAEMON_STATE {
            Some(s) => s.clone(),
            None => {
                msg.set_verdict(Verdict::Accept);
                return;
            }
        }
    };
    
    let payload = msg.get_payload();
    let verdict = process_packet(payload, &state);
    msg.set_verdict(verdict);
}

fn process_packet(payload: &[u8], state: &DaemonState) -> Verdict {
    // Update stats
    state.stats.lock().total_connections += 1;
    
    // Parse IP header
    let ip_header = match Ipv4HeaderSlice::from_slice(payload) {
        Ok(h) => h,
        Err(_) => {
            state.stats.lock().allowed_connections += 1;
            return Verdict::Accept;
        }
    };
    
    let src_ip = ip_header.source_addr();
    let dst_ip = ip_header.destination_addr();
    let proto = ip_header.protocol();
    
    let ip_len = ip_header.slice().len();
    if payload.len() <= ip_len {
        state.stats.lock().allowed_connections += 1;
        return Verdict::Accept;
    }
    
    let transport_slice = &payload[ip_len..];
    
    // Parse transport layer
    let (src_port, dst_port, protocol_str) = match proto {
        6 => { // TCP
            match TcpHeaderSlice::from_slice(transport_slice) {
                Ok(tcp) => (tcp.source_port(), tcp.destination_port(), "tcp"),
                Err(_) => {
                    state.stats.lock().allowed_connections += 1;
                    return Verdict::Accept;
                }
            }
        }
        17 => { // UDP
            match UdpHeaderSlice::from_slice(transport_slice) {
                Ok(udp) => (udp.source_port(), udp.destination_port(), "udp"),
                Err(_) => {
                    state.stats.lock().allowed_connections += 1;
                    return Verdict::Accept;
                }
            }
        }
        _ => {
            // Not TCP/UDP, accept
            state.stats.lock().allowed_connections += 1;
            return Verdict::Accept;
        }
    };
    
    // Identify the process
    let process_info = state.process_cache.lock().get(src_port, protocol_str);
    
    let (app_name, app_path) = match &process_info {
        Some(info) => (info.name.clone(), info.exe_path.clone()),
        None => ("unknown".to_string(), "unknown".to_string()),
    };
    
    // Check existing rules
    if app_path != "unknown" {
        if let Some(allow) = state.rules.get_decision(&app_path, dst_port) {
            if allow {
                debug!("[ALLOW] {} -> {}:{}", app_name, dst_ip, dst_port);
                state.stats.lock().allowed_connections += 1;
                return Verdict::Accept;
            } else {
                debug!("[BLOCK] {} -> {}:{}", app_name, dst_ip, dst_port);
                state.stats.lock().blocked_connections += 1;
                return Verdict::Drop;
            }
        }
    }
    
    // No rule found
    if state.learning_mode {
        // Learning mode: allow and log
        info!("[LEARN] {} ({}) -> {}:{} {}", 
            app_name, app_path, dst_ip, dst_port, protocol_str.to_uppercase());
        state.stats.lock().allowed_connections += 1;
        Verdict::Accept
    } else {
        // Enforcement mode: block unknown
        warn!("[BLOCK] Unknown app {} -> {}:{}", app_name, dst_ip, dst_port);
        state.stats.lock().blocked_connections += 1;
        Verdict::Drop
    }
}
