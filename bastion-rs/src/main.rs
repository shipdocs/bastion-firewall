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
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;

use process::ProcessCache;
use rules::RuleManager;
use config::ConfigManager;
use whitelist::should_auto_allow;

const QUEUE_NUM: u16 = 1;
const SOCKET_PATH: &str = "/var/run/bastion/bastion-daemon.sock";
const GUI_TIMEOUT_SECS: u64 = 60;  // Increased to 60s to allow user to finish typing

#[derive(Default, Clone)]
pub struct Stats {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub blocked_connections: u64,
    pub learning_mode: bool,
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
    /// When true, create a wildcard rule for all ports (issue #13)
    #[serde(default)]
    all_ports: bool,
}

#[derive(Serialize)]
struct StatsUpdate {
    #[serde(rename = "type")]
    msg_type: String,
    stats: StatsData,
}

#[derive(Serialize)]
struct StatsData {
    total_connections: u64,
    allowed_connections: u64,
    blocked_connections: u64,
    learning_mode: bool,
}

/// User decision for an unknown connection
#[derive(Clone, Copy)]
struct UnknownDecision {
    allow: bool,
    timestamp: std::time::Instant,
}

/// Cached session decision (for apps that don't have persistent rules yet)
#[derive(Clone)]
struct SessionDecision {
    allow: bool,
    timestamp: std::time::Instant,
}

/// Shared state for GUI connection (we're the SERVER, GUI connects to us)
struct GuiState {
    stream: Option<UnixStream>,
    reader: Option<BufReader<UnixStream>>,
    pending_cache: HashMap<String, std::time::Instant>,
    // Cache user decisions for "unknown" apps to prevent popup spam
    // Key: "dest_ip:dest_port", Value: (allow_bool, timestamp)
    unknown_decisions: HashMap<String, UnknownDecision>,
    // Session decision cache: remembers user decisions for this session
    // Key: "app_name:port" or "app_path:port", Value: allow/deny + timestamp
    session_decisions: HashMap<String, SessionDecision>,
}

impl GuiState {
    fn new() -> Self {
        Self {
            stream: None,
            reader: None,
            pending_cache: HashMap::new(),
            unknown_decisions: HashMap::new(),
            session_decisions: HashMap::new(),
        }
    }

    fn get_session_decision(&self, cache_key: &str) -> Option<bool> {
        if let Some(decision) = self.session_decisions.get(cache_key) {
            if decision.timestamp.elapsed() < Duration::from_secs(3600) {
                return Some(decision.allow);
            }
        }
        None
    }

    fn cache_session_decision(&mut self, cache_key: &str, allow: bool) {
        self.session_decisions.insert(cache_key.to_string(), SessionDecision {
            allow,
            timestamp: std::time::Instant::now(),
        });
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
    
    fn ask_gui(&mut self, request: &ConnectionRequest) -> Option<GuiResponse> {
        if !self.is_connected() {
            return None;
        }
        
        // FIX #29: Implement cache eviction to prevent unlimited growth (memory leak)
        // Clean up old entries if cache gets too large
        if self.pending_cache.len() > 1000 {
            let now = std::time::Instant::now();
            self.pending_cache.retain(|_, timestamp| {
                now.duration_since(*timestamp) < Duration::from_secs(10)
            });
            debug!("Cleaned pending cache (size was > 1000)");
        }
        
        // Dedup: don't spam same request
        // Key by app+port only (not destination IP) to reduce popup spam
        // This means one popup per app+port, not per app+destination
        let cache_key = if request.app_path.is_empty() || request.app_path == "unknown" {
            // For unknown paths, use app_name:port
            format!("@name:{}:{}", request.app_name, request.dest_port)
        } else {
            // For known paths, use path:port
            format!("{}:{}", request.app_path, request.dest_port)
        };

        if let Some(time) = self.pending_cache.get(&cache_key) {
            // Extend dedup window to 30 seconds to cover typical browsing sessions
            if time.elapsed() < Duration::from_secs(30) {
                debug!("Dedup: already asked for {} (waiting for response)", cache_key);
                return None;
            }
        }

        // Mark as pending IMMEDIATELY to prevent duplicates while waiting for response
        self.pending_cache.insert(cache_key.clone(), std::time::Instant::now());

        // Log that we're sending a popup (after dedup check)
        info!("[POPUP] {} ({}) -> {}:{}", request.app_name, request.app_path, request.dest_ip, request.dest_port);

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
                        Ok(resp) => {
                            // Cache is already set above
                            return Some(resp);
                        }
                        Err(e) => {
                            debug!("Failed to parse GUI response: {} - line: {}", e, line.trim());
                            return None;
                        }
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock ||
                       e.kind() == std::io::ErrorKind::TimedOut {
                        debug!("GUI timeout - no response, allowing retry");
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

    /// Returns cached decision for unknown app if valid (within 60 seconds)
    fn check_unknown_decision(&self, dest_ip: &str, dest_port: u16) -> Option<bool> {
        let key = format!("{}:{}", dest_ip, dest_port);
        if let Some(decision) = self.unknown_decisions.get(&key) {
            if decision.timestamp.elapsed() < Duration::from_secs(60) {
                debug!("Using cached unknown decision for {}:{} -> {}", dest_ip, dest_port,
                    if decision.allow { "ALLOW" } else { "BLOCK" });
                return Some(decision.allow);
            }
        }
        None
    }

    fn cache_unknown_decision(&mut self, dest_ip: &str, dest_port: u16, allow: bool) {
        let key = format!("{}:{}", dest_ip, dest_port);
        self.unknown_decisions.insert(key, UnknownDecision {
            allow,
            timestamp: std::time::Instant::now(),
        });

        let now = std::time::Instant::now();
        self.unknown_decisions.retain(|_, dec| {
            now.duration_since(dec.timestamp) < Duration::from_secs(60)
        });
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
    
    let config = Arc::new(ConfigManager::new());
    let rules = Arc::new(RuleManager::new());
    let learning_mode = config.is_learning_mode();
    let stats = Arc::new(Mutex::new(Stats {
        learning_mode,
        ..Stats::default()
    }));

    info!("Mode: {}", if learning_mode { "Learning" } else { "Enforcement" });

    // Shared GUI state
    let gui_state = Arc::new(Mutex::new(GuiState::new()));

    // Start socket server for GUI connections
    let gui_state_server = gui_state.clone();
    let stats_server = stats.clone();
    let config_server = config.clone();
    thread::spawn(move || {
        run_socket_server(gui_state_server, stats_server, config_server);
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
            let mode = if s.learning_mode { "learning" } else { "enforcement" };
            info!("Stats: {} total, {} allowed, {} blocked ({})",
                s.total_connections, s.allowed_connections, s.blocked_connections, mode);
        }
    });

    // SIGHUP handler - reload config, clear pending cache, reload rules
    let gui_state_sighup = gui_state.clone();
    let rules_sighup = rules.clone();
    let config_sighup = config.clone();
    thread::spawn(move || {
        let mut signals = match Signals::new(&[SIGHUP]) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to register SIGHUP handler: {}", e);
                return;
            }
        };

        for sig in signals.forever() {
            if sig == SIGHUP {
                info!("Received SIGHUP - reloading config and rules");
                config_sighup.load();
                gui_state_sighup.lock().pending_cache.clear();
                rules_sighup.reload();
                let mode = if config_sighup.is_learning_mode() { "learning" } else { "enforcement" };
                info!("Config reloaded: mode={}, rules reloaded, cache cleared", mode);
            }
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
            &config,
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

fn run_socket_server(
    gui_state: Arc<Mutex<GuiState>>,
    stats: Arc<Mutex<Stats>>,
    config: Arc<ConfigManager>
) {
    // FIX #26: Handle missing parent directory gracefully
    let socket_path = std::path::Path::new(SOCKET_PATH);
    let socket_dir = match socket_path.parent() {
        Some(dir) => dir,
        None => {
            error!("Socket path has no parent directory: {}", SOCKET_PATH);
            return;
        }
    };
    std::fs::create_dir_all(socket_dir).ok();

    // Security: Only remove if it's a socket, not a symlink or other file
    if let Ok(meta) = std::fs::symlink_metadata(SOCKET_PATH) {
        if meta.file_type().is_symlink() {
            error!("Socket path is a symlink, refusing to remove: {}", SOCKET_PATH);
            return;
        }
        let _ = std::fs::remove_file(SOCKET_PATH);
    }

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
        // SECURITY: Use 0o666 to allow GUI connections, but verify peer credentials below
        // This allows any user to connect, but we validate UID before accepting
        let _ = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o666));
    }
    
    info!("Socket server listening on {}", SOCKET_PATH);
    
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // SECURITY: Verify peer credentials before accepting connection
                // This prevents system processes or malicious scripts from impersonating the GUI
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    
                    // Get peer credentials using SO_PEERCRED
                    let fd = s.as_raw_fd();
                    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
                    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
                    
                    let result = unsafe {
                        libc::getsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_PEERCRED,
                            &mut cred as *mut _ as *mut libc::c_void,
                            &mut len,
                        )
                    };
                    
                    if result == 0 {
                        let peer_uid = cred.uid;
                        // Allow: root (uid 0) for system tools, or regular users (uid >= 1000)
                        // Block: system users (uid 1-999) which are typically daemons/services
                        if peer_uid == 0 || peer_uid >= 1000 {
                            info!("GUI client connected (UID: {})", peer_uid);
                        } else {
                            warn!("Rejected connection from system user (UID: {})", peer_uid);
                            drop(s);
                            continue;
                        }
                    } else {
                        warn!("Failed to get peer credentials, allowing connection");
                    }
                }
                
                #[cfg(not(unix))]
                info!("GUI client connecting");
                gui_state.lock().set_connection(s.try_clone().expect("Failed to clone stream"));

                // Spawn a thread to send stats updates every 2 seconds
                let stats_clone = stats.clone();
                let gui_state_clone = gui_state.clone();
                let config_clone = config.clone();
                thread::spawn(move || {
                    send_stats_updates(s, stats_clone, gui_state_clone, config_clone);
                });
            }
            Err(e) => {
                error!("Socket accept error: {}", e);
            }
        }
    }
}

fn send_stats_updates(
    mut stream: UnixStream,
    stats: Arc<Mutex<Stats>>,
    gui_state: Arc<Mutex<GuiState>>,
    config: Arc<ConfigManager>
) {
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    loop {
        if !gui_state.lock().is_connected() {
            info!("Stats updater: GUI disconnected, stopping stats updates");
            break;
        }

        // Send stats update
        let s = stats.lock().clone();
        let learning_mode = config.is_learning_mode();
        let update = StatsUpdate {
            msg_type: "stats_update".to_string(),
            stats: StatsData {
                total_connections: s.total_connections,
                allowed_connections: s.allowed_connections,
                blocked_connections: s.blocked_connections,
                learning_mode,
            },
        };
        drop(s);

        if let Ok(json) = serde_json::to_string(&update) {
            if let Err(e) = stream.write_all((json + "\n").as_bytes()) {
                debug!("Failed to send stats update: {}", e);
                break;
            }
        }

        thread::sleep(Duration::from_secs(2));
    }

    info!("Stats updater thread exiting");
}

fn process_packet(
    payload: &[u8],
    rules: &RuleManager,
    process_cache: &Mutex<ProcessCache>,
    config: &Arc<ConfigManager>,
    gui_state: &Arc<Mutex<GuiState>>,
) -> Verdict {
    let learning_mode = config.is_learning_mode();
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
    
    let (app_name, app_path, app_uid) = match &process_info {
        Some(info) => (info.name.clone(), info.exe_path.clone(), info.uid),
        None => ("unknown".to_string(), "unknown".to_string(), 0),
    };
    
    // Check whitelist
    let (auto_allow, reason) = should_auto_allow(&app_path, &app_name, dst_port, &dst_ip_str);
    if auto_allow {
        debug!("[AUTO] {} - {}", app_name, reason);
        return Verdict::Accept;
    }
    
    // Check path-based rules first
    if app_path != "unknown" && !app_path.is_empty() {
        if let Some(allow) = rules.get_decision(&app_path, dst_port) {
            if allow {
                debug!("[RULE:ALLOW] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                return Verdict::Accept;
            } else if !learning_mode {
                // In learning mode, ignore DENY rules (observe only)
                info!("[RULE:BLOCK] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                return Verdict::Drop;
            } else {
                // Learning mode: log but don't block
                info!("[LEARN:RULE-DENIED-BUT-ALLOWED] app=\"{}\" dst=\"{}:{}\" (would block in enforcement)", app_name, dst_ip, dst_port);
            }
        }
    }

    // Check name-based rules as fallback
    if app_name != "unknown" && !app_name.is_empty() {
        let name_based_key = format!("@name:{}", app_name);
        if let Some(allow) = rules.get_decision(&name_based_key, dst_port) {
            if allow {
                debug!("[RULE:ALLOW:NAME] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                return Verdict::Accept;
            } else if !learning_mode {
                // In learning mode, ignore DENY rules (observe only)
                info!("[RULE:BLOCK:NAME] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                return Verdict::Drop;
            } else {
                // Learning mode: log but don't block
                info!("[LEARN:RULE-DENIED-BUT-ALLOWED] app=\"@name:{}\" dst=\"{}:{}\" (would block in enforcement)", app_name, dst_ip, dst_port);
            }
        }
    }

    // No rule found - check session cache first, then ask user
    // Build cache key (same format as dedup key)
    let session_cache_key = if app_path.is_empty() || app_path == "unknown" {
        format!("@name:{}:{}", app_name, dst_port)
    } else {
        format!("{}:{}", app_path, dst_port)
    };

    // Try to get GUI decision (blocking with timeout)
    let mut gui = gui_state.lock();

    // Check session decision cache first (covers all apps, not just unknown)
    if let Some(cached_allow) = gui.get_session_decision(&session_cache_key) {
        if cached_allow {
            drop(gui);
            debug!("[SESSION:ALLOW] app=\"{}\" dst=\"{}:{}\"", app_name, dst_ip, dst_port);
            return Verdict::Accept;
        } else if !learning_mode {
            // Enforce cached DENY only in enforcement mode
            drop(gui);
            debug!("[SESSION:BLOCK] app=\"{}\" dst=\"{}:{}\"", app_name, dst_ip, dst_port);
            return Verdict::Drop;
        } else {
            // Learning mode: log cached deny but don't block
            info!("[LEARN:SESSION-DENIED-BUT-ALLOWED] app=\"{}\" dst=\"{}:{}\" (cached deny ignored)", app_name, dst_ip, dst_port);
        }
    }

    // For unknown apps, also check the legacy destination-based cache
    if app_name == "unknown" || app_path == "unknown" {
        if let Some(cached_decision) = gui.check_unknown_decision(&dst_ip_str, dst_port) {
            if cached_decision {
                drop(gui);
                debug!("[CACHED:ALLOW] unknown app dst=\"{}:{}\"", dst_ip, dst_port);
                return Verdict::Accept;
            } else if !learning_mode {
                // Enforce cached DENY only in enforcement mode
                drop(gui);
                debug!("[CACHED:BLOCK] unknown app dst=\"{}:{}\"", dst_ip, dst_port);
                return Verdict::Drop;
            } else {
                // Learning mode: log cached deny but don't block
                info!("[LEARN:UNKNOWN-DENIED-BUT-ALLOWED] dst=\"{}:{}\" (cached deny ignored)", dst_ip, dst_port);
            }
        }
    }

    let request = ConnectionRequest {
        msg_type: "connection_request".to_string(),
        app_name: app_name.clone(),
        app_path: app_path.clone(),
        app_category: "unknown".to_string(),
        dest_ip: dst_ip_str.clone(),
        dest_port: dst_port,
        protocol: protocol_str.to_string(),
    };

    if gui.is_connected() {
        if let Some(response) = gui.ask_gui(&request) {
            // Always cache the session decision (reduces popups for same app+port)
            gui.cache_session_decision(&session_cache_key, response.allow);
            debug!("[SESSION] Cached decision for {} (allow: {})", session_cache_key, response.allow);

            // For unknown apps, also cache by destination
            if app_name == "unknown" || app_path == "unknown" {
                gui.cache_unknown_decision(&dst_ip_str, dst_port, response.allow);
            }

            if response.permanent && app_name != "unknown" && !app_name.is_empty() {
                let rule_key = if !app_path.is_empty() && app_path != "unknown" {
                    app_path.clone()
                } else {
                    // Name-based rule when path unavailable (less secure)
                    let name_based_key = format!("@name:{}", app_name);
                    warn!("[SECURITY] Creating name-based rule (no path): {} -> port {}", app_name, dst_port);
                    name_based_key
                };
                // Pass all_ports flag for wildcard rules (issue #13)
                rules.add_rule(&rule_key, Some(dst_port), response.allow, response.all_ports);
                let port_display = if response.all_ports { "*".to_string() } else { dst_port.to_string() };
                info!("[RULE] Created permanent rule: {} -> port {}", rule_key, port_display);
            } else if response.permanent {
                warn!("[SECURITY] Cannot create permanent rule for unidentified process");
            }

            drop(gui);
            return if response.allow {
                info!("[USER:ALLOW] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                Verdict::Accept
            } else {
                info!("[USER:BLOCK] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                Verdict::Drop
            };
        }
    }
    drop(gui);
    
    // No GUI or no response - use mode default
    if learning_mode {
        info!("[LEARN] app=\"{}\" path=\"{}\" dst=\"{}:{}\" user={}", app_name, app_path, dst_ip, dst_port, app_uid);
        Verdict::Accept
    } else {
        if app_path == "unknown" {
            Verdict::Accept
        } else {
            warn!("[BLOCK] app=\"{}\" dst=\"{}:{}\" user={} (no GUI)", app_name, dst_ip, dst_port, app_uid);
            Verdict::Drop
        }
    }
}