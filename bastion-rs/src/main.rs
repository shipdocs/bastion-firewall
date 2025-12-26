//! Bastion Firewall Daemon - Rust Edition
//! 
//! A high-performance application firewall using Netfilter Queue

mod process;
mod rules;
mod config;
mod ipc;
mod whitelist;

use nfqueue::{Queue, Verdict, CopyMode, Message};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use log::{info, warn, error, debug};
use parking_lot::Mutex;
use std::thread;

use process::ProcessCache;
use rules::RuleManager;
use config::ConfigManager;
use whitelist::{should_auto_allow, get_app_category};
use ipc::{IpcServer, Stats, DecisionRequest, GuiResponse};

// Global state (needed because nfqueue uses function pointers)
static mut DAEMON_STATE: Option<Arc<DaemonState>> = None;

struct DaemonState {
    rules: Arc<RuleManager>,
    process_cache: Mutex<ProcessCache>,
    stats: Arc<Mutex<Stats>>,
    learning_mode: bool,
    // Channel to send requests to IPC thread
    ipc_tx: mpsc::Sender<DecisionRequest>,
}

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
    
    info!("╔════════════════════════════════════════╗");
    info!("║  Bastion Firewall Daemon (Rust) v0.1  ║");
    info!("╚════════════════════════════════════════╝");
    
    // Initialize components
    let config = ConfigManager::new();
    let learning_mode = config.is_learning_mode();
    let rules = Arc::new(RuleManager::new());
    let stats = Arc::new(Mutex::new(Stats::default()));
    
    info!("Mode: {}", if learning_mode { "🎓 Learning (allow unknown)" } else { "🛡️ Enforcement (block unknown)" });
    
    // Create IPC channel
    let (ipc_tx, ipc_rx) = mpsc::channel::<DecisionRequest>();
    
    // Start IPC server in background thread
    let ipc_rules = rules.clone();
    let ipc_stats = stats.clone();
    thread::spawn(move || {
        let server = IpcServer::new(ipc_rules, ipc_stats, ipc_rx);
        server.run();
    });
    
    let state = Arc::new(DaemonState {
        rules: rules.clone(),
        process_cache: Mutex::new(ProcessCache::new(120)),
        stats: stats.clone(),
        learning_mode,
        ipc_tx,
    });
    
    // Set global state
    unsafe {
        DAEMON_STATE = Some(state.clone());
    }
    
    // Setup nfqueue
    let mut queue = Queue::new(());
    queue.open();
    
    if queue.unbind(libc::AF_INET) != 0 {
        debug!("Unbind returned non-zero (first run?)");
    }
    if queue.bind(libc::AF_INET) != 0 {
        error!("Failed to bind AF_INET - is another instance running?");
        return;
    }
    
    queue.create_queue(1, packet_handler);
    queue.set_mode(CopyMode::CopyPacket, 0xFFFF);
    
    info!("Listening on NFQUEUE 1");
    info!("Waiting for GUI connection at {}", ipc::SOCKET_PATH);
    info!("Ready to process packets!");
    
    // Print stats periodically
    let stats_clone = stats.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(30));
            let s = stats_clone.lock();
            info!("📊 Stats: {} total, {} allowed, {} blocked", 
                s.total_connections, s.allowed_connections, s.blocked_connections);
        }
    });
    
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
    
    let dst_ip = ip_header.destination_addr();
    let dst_ip_str = format!("{}", dst_ip);
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
    
    // Check whitelist first (essential system services)
    let (auto_allow, reason) = should_auto_allow(&app_path, dst_port, &dst_ip_str);
    if auto_allow {
        debug!("[AUTO] {} - {}", app_name, reason);
        state.stats.lock().allowed_connections += 1;
        return Verdict::Accept;
    }
    
    // Check existing rules
    if app_path != "unknown" {
        if let Some(allow) = state.rules.get_decision(&app_path, dst_port) {
            if allow {
                debug!("[RULE:ALLOW] {} -> {}:{}", app_name, dst_ip, dst_port);
                state.stats.lock().allowed_connections += 1;
                return Verdict::Accept;
            } else {
                info!("[RULE:BLOCK] {} -> {}:{}", app_name, dst_ip, dst_port);
                state.stats.lock().blocked_connections += 1;
                return Verdict::Drop;
            }
        }
    }
    
    // No rule found - ask GUI or use mode default
    let category = get_app_category(&app_path);
    let category_str = format!("{:?}", category);
    
    // Try to ask GUI (with short timeout)
    let (response_tx, response_rx) = mpsc::channel();
    let request = DecisionRequest {
        app_name: app_name.clone(),
        app_path: app_path.clone(),
        app_category: category_str,
        dest_ip: dst_ip_str.clone(),
        dest_port: dst_port,
        protocol: protocol_str.to_string(),
        response_tx,
    };
    
    // Send request to IPC thread
    if state.ipc_tx.send(request).is_ok() {
        // Wait for response with timeout
        match response_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(Some(response)) => {
                if response.allow {
                    info!("[GUI:ALLOW] {} -> {}:{}", app_name, dst_ip, dst_port);
                    state.stats.lock().allowed_connections += 1;
                    return Verdict::Accept;
                } else {
                    info!("[GUI:BLOCK] {} -> {}:{}", app_name, dst_ip, dst_port);
                    state.stats.lock().blocked_connections += 1;
                    return Verdict::Drop;
                }
            }
            Ok(None) | Err(_) => {
                // GUI not connected or timeout - fall through to mode default
            }
        }
    }
    
    // No GUI response - use mode default
    if state.learning_mode {
        info!("[LEARN] {} ({}) -> {}:{}", app_name, app_path, dst_ip, dst_port);
        state.stats.lock().allowed_connections += 1;
        Verdict::Accept
    } else {
        if app_path == "unknown" {
            warn!("[UNKNOWN] -> {}:{} (allowing unidentified)", dst_ip, dst_port);
            state.stats.lock().allowed_connections += 1;
            Verdict::Accept
        } else {
            warn!("[BLOCK] {} -> {}:{} (no rule, enforcement mode)", app_name, dst_ip, dst_port);
            state.stats.lock().blocked_connections += 1;
            Verdict::Drop
        }
    }
}
