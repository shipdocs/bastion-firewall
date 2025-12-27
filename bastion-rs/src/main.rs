//! Bastion Firewall Daemon - Rust Edition v0.5
//! 
//! With WORKING popup support via blocking GUI queries!

mod process;
mod rules;
mod config;
mod whitelist;
mod ebpf_loader;

use nfq::{Queue, Verdict};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};
use std::sync::Arc;
use std::time::Duration;
use std::thread;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::collections::HashMap;
use log::{info, warn, error, debug};
use parking_lot::Mutex;
use serde::{Serialize, Deserialize};

use process::ProcessCache;
use rules::RuleManager;
use config::ConfigManager;
use whitelist::should_auto_allow;

const QUEUE_NUM: u16 = 1;
const SOCKET_PATH: &str = "/var/run/bastion/bastion-daemon.sock";
const GUI_TIMEOUT_SECS: u64 = 30;

#[derive(Default)]
pub struct Stats {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub blocked_connections: u64,
}

#[derive(Serialize)]
struct ConnectionRequest {
    #[serde(rename = "type")]
    msg_type: String,
    app_name: String,
    app_path: String,
    app_category: String,
    dest_ip: String,
    dest_port: u16,
    protocol: String,
}

#[derive(Deserialize)]
struct GuiResponse {
    allow: bool,
    #[serde(default)]
    permanent: bool,
}

/// Shared state for GUI connection (we're the SERVER, GUI connects to us)
struct GuiState {
    stream: Option<UnixStream>,
    reader: Option<BufReader<UnixStream>>,
    pending_cache: HashMap<String, std::time::Instant>,
}

impl GuiState {
    fn new() -> Self {
        Self {
            stream: None,
            reader: None,
            pending_cache: HashMap::new(),
        }
    }
    
    fn set_connection(&mut self, stream: UnixStream) {
        stream.set_read_timeout(Some(Duration::from_secs(GUI_TIMEOUT_SECS))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        
        // FIX #25: Handle clone failure gracefully
        let reader = match stream.try_clone() {
            Ok(s) => BufReader::new(s),
            Err(e) => {
                error!("Failed to clone stream: {}", e);
                return;
            }
        };
        
        self.stream = Some(stream);
        self.reader = Some(reader);
        info!("GUI connection established");
    }
    
    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
    
    fn disconnect(&mut self) {
        info!("GUI disconnected");
        self.stream = None;
        self.reader = None;
    }
    
    /// Ask GUI for decision - BLOCKS until response or timeout
    fn ask_gui(&mut self, request: &ConnectionRequest) -> Option<GuiResponse> {
        if !self.is_connected() {
            return None;
        }
        
        // FIX #29: Implement cache eviction to prevent unlimited growth (memory leak)
        // Clean up old entries if cache gets too large
        if self.pending_cache.len() > 1000 {
            let now = std::time::Instant::now();
            self.pending_cache.retain(|_, (_, timestamp)| {
                now.duration_since(*timestamp) < Duration::from_secs(10)
            });
            debug!("Cleaned pending cache (size was > 1000)");
        }
        
        // Dedup: don't spam same request
        let cache_key = format!("{}:{}", request.app_path, request.dest_port);
        if let Some(time) = self.pending_cache.get(&cache_key) {
            if time.elapsed() < Duration::from_secs(5) {
                debug!("Dedup: already asked for {}", cache_key);
                return None;
            }
        }
        self.pending_cache.insert(cache_key, std::time::Instant::now());
        
        // Send request to GUI
        let json = match serde_json::to_string(request) {
            Ok(j) => j,
            Err(_) => return None,
        };
        
        if let Some(ref mut stream) = self.stream {
            if stream.write_all((json + "\n").as_bytes()).is_err() {
                self.disconnect();
                return None;
            }
        } else {
            return None;
        }
        
        // Wait for response (blocking with timeout)
        if let Some(ref mut reader) = self.reader {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    self.disconnect();
                    return None;
                }
                Ok(_) => {
                    match serde_json::from_str::<GuiResponse>(&line) {
                        Ok(resp) => return Some(resp),
                        Err(e) => {
                            debug!("Failed to parse GUI response: {} - line: {}", e, line.trim());
                            return None;
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock || 
                       e.kind() == std::io::ErrorKind::TimedOut {
                        debug!("GUI timeout - no response");
                    } else {
                        debug!("GUI read error: {}", e);
                        self.disconnect();
                    }
                    return None;
                }
            }
        }
        
        None
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
    
    info!("╔════════════════════════════════════════╗");
    info!("║  Bastion Firewall Daemon (Rust) v0.5  ║");
    info!("║         With Popup Support!           ║");
    info!("╚════════════════════════════════════════╝");
    
    let config = ConfigManager::new();
    let learning_mode = config.is_learning_mode();
    let rules = Arc::new(RuleManager::new());
    let stats = Arc::new(Mutex::new(Stats::default()));
    
    info!("Mode: {}", if learning_mode { "Learning" } else { "Enforcement" });
    
    // Shared GUI state
    let gui_state = Arc::new(Mutex::new(GuiState::new()));
    
    // Start socket server for GUI connections
    let gui_state_server = gui_state.clone();
    thread::spawn(move || {
        run_socket_server(gui_state_server);
    });
    
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
            info!("Stats: {} total, {} allowed, {} blocked", 
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
        let verdict = process_packet(
            payload, 
            &rules, 
            &process_cache, 
            learning_mode,
            &gui_state,
        );
        
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

fn run_socket_server(gui_state: Arc<Mutex<GuiState>>) {
    // FIX #26: Handle missing parent directory gracefully
    // Create socket directory
    let socket_path = std::path::Path::new(SOCKET_PATH);
    let socket_dir = match socket_path.parent() {
        Some(dir) => dir,
        None => {
            error!("Socket path has no parent directory: {}", SOCKET_PATH);
            return;
        }
    };
    std::fs::create_dir_all(socket_dir).ok();
    let _ = std::fs::remove_file(SOCKET_PATH);
    
    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind socket: {}", e);
            return;
        }
    };
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660));
    }
    
    info!("Socket server listening on {}", SOCKET_PATH);
    
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                info!("GUI client connecting...");
                gui_state.lock().set_connection(s);
            }
            Err(e) => {
                error!("Socket accept error: {}", e);
            }
        }
    }
}

fn process_packet(
    payload: &[u8],
    rules: &RuleManager,
    process_cache: &Mutex<ProcessCache>,
    learning_mode: bool,
    gui_state: &Arc<Mutex<GuiState>>,
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
            Ok(tcp) => (tcp.source_port(), tcp.destination_port(), "TCP"),
            Err(_) => return Verdict::Accept,
        },
        17 => match UdpHeaderSlice::from_slice(transport_slice) {
            Ok(udp) => (udp.source_port(), udp.destination_port(), "UDP"),
            Err(_) => return Verdict::Accept,
        },
        _ => return Verdict::Accept,
    };
    
    // Get source IP
    let src_ip = ip_header.source_addr();
    let src_ip_str = format!("{}", src_ip);
    
    // Identify process - exactly like Python's find_process_by_socket
    let mut cache = process_cache.lock();
    let process_info = cache.find_process_by_socket(
        &src_ip_str, src_port,
        &dst_ip_str, dst_port,
        protocol_str
    );
    drop(cache);
    
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
    
    // Unknown app - ask GUI!
    let request = ConnectionRequest {
        msg_type: "connection_request".to_string(),
        app_name: app_name.clone(),
        app_path: app_path.clone(),
        app_category: "unknown".to_string(),
        dest_ip: dst_ip_str.clone(),
        dest_port: dst_port,
        protocol: protocol_str.to_string(),
    };
    
    // Try to get GUI decision (blocking with timeout)
    let mut gui = gui_state.lock();
    if gui.is_connected() {
        info!("[POPUP] {} ({}) -> {}:{}", app_name, app_path, dst_ip, dst_port);
        
        if let Some(response) = gui.ask_gui(&request) {
            if response.permanent {
                rules.add_rule(&app_path, Some(dst_port), response.allow);
            }
            
            return if response.allow {
                info!("[USER:ALLOW] {} -> {}:{}", app_name, dst_ip, dst_port);
                Verdict::Accept
            } else {
                info!("[USER:BLOCK] {} -> {}:{}", app_name, dst_ip, dst_port);
                Verdict::Drop
            };
        }
    }
    drop(gui);
    
    // No GUI or no response - use mode default
    if learning_mode {
        info!("[LEARN] {} ({}) -> {}:{}", app_name, app_path, dst_ip, dst_port);
        Verdict::Accept
    } else {
        if app_path == "unknown" {
            Verdict::Accept
        } else {
            warn!("[BLOCK] {} -> {}:{} (no GUI)", app_name, dst_ip, dst_port);
            Verdict::Drop
        }
    }
}
