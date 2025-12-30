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

/// Shared state for GUI connection (we're the SERVER, GUI connects to us)
struct GuiState {
    stream: Option<UnixStream>,
    reader: Option<BufReader<UnixStream>>,
    pending_cache: HashMap<String, std::time::Instant>,
    // Cache user decisions for "unknown" apps to prevent popup spam
    // Key: "dest_ip:dest_port", Value: (allow_bool, timestamp)
    unknown_decisions: HashMap<String, UnknownDecision>,
}

impl GuiState {
    /// Creates an empty GuiState with no active connection and an empty pending request cache.
    ///
    /// # Examples
    ///
    /// ```
    /// let state = crate::GuiState::new();
    /// assert!(state.stream.is_none());
    /// assert!(state.reader.is_none());
    /// assert!(state.pending_cache.is_empty());
    /// ```
    fn new() -> Self {
        Self {
            stream: None,
            reader: None,
            pending_cache: HashMap::new(),
            unknown_decisions: HashMap::new(),
        }
    }
    
    /// Sets up and stores a GUI connection from the given `UnixStream`.
    ///
    /// This configures read and write timeouts on the stream, clones it for buffered reading,
    /// and stores both the original stream and the cloned reader in the `GuiState`.
    /// If cloning the stream fails the function logs an error and leaves the state unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::os::unix::net::UnixStream;
    /// // create a connected pair of streams for testing
    /// let (a, _b) = UnixStream::pair().unwrap();
    /// let mut state = GuiState::new();
    /// state.set_connection(a);
    /// assert!(state.is_connected());
    /// ```
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
    
    /// Checks whether a GUI connection is currently established.
    ///
    /// # Returns
    ///
    /// `true` if a GUI connection is established, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// let gui = GuiState::new();
    /// assert!(!gui.is_connected());
    /// ```
    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
    
    /// Marks the GUI as disconnected and clears any stored connection.
    ///
    /// Clears the stored `UnixStream` and its associated buffered reader so the
    /// `GuiState` no longer represents an active GUI connection.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut state = GuiState::new();
    /// state.disconnect();
    /// assert!(!state.is_connected());
    /// ```
    fn disconnect(&mut self) {
        info!("GUI disconnected");
        self.stream = None;
        self.reader = None;
    }
    
    /// Request a decision from the connected GUI for a given connection.
    ///
    /// Sends the given `ConnectionRequest` to the GUI (if connected), waits for a single
    /// JSON `GuiResponse`, and returns the parsed response. Recent duplicate requests
    /// (same `app_path` and `dest_port`) are deduplicated and will return `None` if asked
    /// again within a short interval. Also performs bounded pending-cache eviction.
    ///
    /// Returns `None` when there is no GUI connection, the request is a recent duplicate,
    /// JSON serialization fails, writing or reading the socket fails, the GUI times out,
    /// or the GUI response cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut gui = GuiState::new();
    /// let req = ConnectionRequest {
    ///     msg_type: "connection_request".to_string(),
    ///     app_name: "example".to_string(),
    ///     app_path: "/usr/bin/example".to_string(),
    ///     app_category: "unknown".to_string(),
    ///     dest_ip: "1.2.3.4".to_string(),
    ///     dest_port: 80,
    ///     protocol: "TCP".to_string(),
    /// };
    /// // No GUI connected, so this returns None.
    /// assert!(gui.ask_gui(&req).is_none());
    /// ```
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
        // Use app_name if app_path is empty, and include dest_ip for better dedup
        let cache_key = if request.app_path.is_empty() || request.app_path == "unknown" {
            format!("{}:{}:{}", request.app_name, request.dest_ip, request.dest_port)
        } else {
            format!("{}:{}:{}", request.app_path, request.dest_ip, request.dest_port)
        };

        if let Some(time) = self.pending_cache.get(&cache_key) {
            if time.elapsed() < Duration::from_secs(5) {
                debug!("Dedup: already asked for {}", cache_key);
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

    /// Check if we have a cached decision for an unknown app connection
    /// Returns Some(allow) if cached and still valid (within 60 seconds)
    fn check_unknown_decision(&self, dest_ip: &str, dest_port: u16) -> Option<bool> {
        let key = format!("{}:{}", dest_ip, dest_port);
        if let Some(decision) = self.unknown_decisions.get(&key) {
            // Cache valid for 60 seconds
            if decision.timestamp.elapsed() < Duration::from_secs(60) {
                debug!("Using cached unknown decision for {}:{} -> {}", dest_ip, dest_port,
                    if decision.allow { "ALLOW" } else { "BLOCK" });
                return Some(decision.allow);
            }
        }
        None
    }

    /// Store a user decision for an unknown app connection
    fn cache_unknown_decision(&mut self, dest_ip: &str, dest_port: u16, allow: bool) {
        let key = format!("{}:{}", dest_ip, dest_port);
        self.unknown_decisions.insert(key, UnknownDecision {
            allow,
            timestamp: std::time::Instant::now(),
        });

        // Clean up old entries
        let now = std::time::Instant::now();
        self.unknown_decisions.retain(|_, dec| {
            now.duration_since(dec.timestamp) < Duration::from_secs(60)
        });
    }
}

/// Daemon entry point that initializes logging, configuration, GUI socket server, NFQUEUE, and the main packet processing loop.
///
/// This function bootstraps the firewall: it configures logging, reads configuration (learning vs enforcement),
/// starts the GUI Unix socket server, opens and binds the NFQUEUE, spawns background threads for statistics and
/// the socket server, and then enters the main packet processing loop which inspects packets, consults rules,
/// optionally prompts the GUI, and issues accept/drop verdicts.
///
/// # Returns
///
/// `Ok(())` on successful startup and run (the function runs indefinitely under normal operation).
/// `Err` if initialization fails (for example, opening/binding NFQUEUE or other startup errors).
///
/// # Examples
///
/// ```no_run
/// // Start the daemon (do not run inside doc tests).
/// // Use `cargo run` or run the compiled binary to start the Bastion Firewall Daemon.
/// ```
fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
    
    info!("╔════════════════════════════════════════╗");
    info!("║  Bastion Firewall Daemon (Rust) v0.5  ║");
    info!("║         With Popup Support!           ║");
    info!("╚════════════════════════════════════════╝");
    
    let config = Arc::new(ConfigManager::new());
    let learning_mode = config.is_learning_mode();
    let rules = Arc::new(RuleManager::new());
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
            info!("Stats: {} total, {} allowed, {} blocked",
                s.total_connections, s.allowed_connections, s.blocked_connections);
        }
    });

    // SIGHUP handler - clear pending cache when rules are modified
    let gui_state_sighup = gui_state.clone();
    let rules_sighup = rules.clone();
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
                info!("Received SIGHUP - clearing pending cache and reloading rules");
                gui_state_sighup.lock().pending_cache.clear();
                rules_sighup.reload();
                info!("Cache cleared and rules reloaded");
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

/// Starts a Unix-domain socket server that accepts a single GUI connection, stores it in `gui_state`,
/// and spawns a background thread to send periodic stats updates.
///
/// The server ensures the socket directory exists, binds to SOCKET_PATH, sets socket permissions (on Unix),
/// and assigns each accepted stream to the provided `GuiState`. For each connection, a background thread
/// is spawned to send stats_update messages every 2 seconds. Errors during setup or accept are logged
/// and cause the function to return or continue accepting respectively.
///
/// # Examples
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use std::thread;
/// use std::time::Duration;
/// use std::os::unix::net::UnixStream;
///
/// // Start the server in a background thread.
/// let gui_state = Arc::new(Mutex::new(crate::GuiState::new()));
/// let stats = Arc::new(Mutex::new(crate::Stats::default()));
/// let gs = gui_state.clone();
/// let st = stats.clone();
/// thread::spawn(move || {
///     crate::run_socket_server(gs, st);
/// });
///
/// // Give the server a moment to start, then connect as a client.
/// std::thread::sleep(Duration::from_millis(100));
/// let _ = UnixStream::connect(crate::SOCKET_PATH).expect("connect to socket");
/// ```
fn run_socket_server(
    gui_state: Arc<Mutex<GuiState>>,
    stats: Arc<Mutex<Stats>>,
    config: Arc<ConfigManager>
) {
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
        // Permission 0o666 allows the user-space GUI/tray (running as normal user)
        // to connect to the daemon socket (daemon runs as root)
        let _ = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o666));
    }
    
    info!("Socket server listening on {}", SOCKET_PATH);
    
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
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

/// Sends periodic stats updates to a connected GUI client.
///
/// Runs in a loop sending `stats_update` JSON messages every 2 seconds until the
/// connection is closed or an error occurs. Updates the GUI with current firewall statistics.
///
/// # Arguments
///
/// * `stream` - The Unix socket stream connected to the GUI client
/// * `stats` - Shared statistics state
/// * `gui_state` - Shared GUI state to detect disconnections
/// * `config` - Configuration manager to get current learning mode
fn send_stats_updates(
    mut stream: UnixStream,
    stats: Arc<Mutex<Stats>>,
    gui_state: Arc<Mutex<GuiState>>,
    config: Arc<ConfigManager>
) {
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    loop {
        // Check if still connected
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

///Decides whether a captured packet should be accepted or dropped based on
///IP/transport headers, the originating process (if discovered), whitelists,
///existing rules, GUI operator decisions, and the daemon's learning mode.
///
///This function:
///- Parses the IPv4 and transport headers to determine source/destination IPs,
///  ports, and protocol.
///- Looks up the originating process via the provided `ProcessCache`.
///- Automatically accepts packets that match the auto-allow whitelist.
///- Applies an existing per-application rule (allow or block) when present.
///- If no rule exists, asks the connected GUI for a decision; if the GUI's
///  response is marked `permanent`, a new rule will be added.
///- Falls back to learning or enforcement behavior when no GUI decision is
///  available: in learning mode unknown traffic is accepted; in enforcement
///  mode unknown apps are accepted only if the app path is `"unknown"`, otherwise
///  they are blocked.
///
///Parameters:
///- `payload`: raw packet bytes starting with an IPv4 header.
///- `rules`: rule manager consulted for existing per-app decisions; may be
///  updated if the GUI returns a permanent decision.
///- `process_cache`: cache used to map socket tuples to process metadata.
///- `learning_mode`: when `true`, unknown connections are accepted by default.
///- `gui_state`: GUI connection state used to prompt the operator for decisions.
///
///Returns:
///`Verdict::Accept` when the packet should be allowed, `Verdict::Drop` when it
///should be blocked.
///
///# Examples
///
///```
/// // A minimal example: an empty or truncated payload cannot be parsed as IPv4,
/// // so it is accepted.
/// let payload: &[u8] = &[];
/// // The following managers are placeholders; in real usage provide the actual instances.
/// // Here we only illustrate the function call and expected early-accept behavior.
/// let rules = RuleManager::new(); // assume constructor exists
/// let process_cache = parking_lot::Mutex::new(ProcessCache::new());
/// let gui_state = std::sync::Arc::new(parking_lot::Mutex::new(GuiState::new()));
/// let verdict = process_packet(payload, &rules, &process_cache, true, &gui_state);
/// assert_eq!(verdict, Verdict::Accept);
/// ```
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
            return if allow {
                debug!("[RULE:ALLOW] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                Verdict::Accept
            } else {
                info!("[RULE:BLOCK] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                Verdict::Drop
            };
        }
    }

    // Check name-based rules as fallback
    if app_name != "unknown" && !app_name.is_empty() {
        let name_based_key = format!("@name:{}", app_name);
        if let Some(allow) = rules.get_decision(&name_based_key, dst_port) {
            return if allow {
                debug!("[RULE:ALLOW:NAME] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                Verdict::Accept
            } else {
                info!("[RULE:BLOCK:NAME] app=\"{}\" dst=\"{}:{}\" user={}", app_name, dst_ip, dst_port, app_uid);
                Verdict::Drop
            };
        }
    }

    // No rule found - ask user
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

    // For unknown apps, check if we have a recent cached decision to prevent popup spam
    if app_name == "unknown" || app_path == "unknown" {
        if let Some(cached_decision) = gui.check_unknown_decision(&dst_ip_str, dst_port) {
            drop(gui);
            return if cached_decision {
                debug!("[CACHED:ALLOW] unknown app dst=\"{}:{}\"", dst_ip, dst_port);
                Verdict::Accept
            } else {
                debug!("[CACHED:BLOCK] unknown app dst=\"{}:{}\"", dst_ip, dst_port);
                Verdict::Drop
            };
        }
    }

    if gui.is_connected() {
        if let Some(response) = gui.ask_gui(&request) {
            // For unknown apps, cache the decision to prevent popup spam
            if app_name == "unknown" || app_path == "unknown" {
                gui.cache_unknown_decision(&dst_ip_str, dst_port, response.allow);
                debug!("[CACHE] Stored decision for unknown app -> {}:{} (allow: {})",
                    dst_ip_str, dst_port, response.allow);
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
                rules.add_rule(&rule_key, Some(dst_port), response.allow);
                info!("[RULE] Created permanent rule: {} -> port {}", rule_key, dst_port);
            } else if response.permanent {
                warn!("[SECURITY] Cannot create permanent rule for unidentified process");
            }

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