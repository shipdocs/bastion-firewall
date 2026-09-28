use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use crate::config::ConfigManager;
use crate::rules::RuleManager;
use bastion_rs::protocol::*;

pub const SOCKET_PATH: &str = "/var/run/bastion/bastion-daemon.sock";
pub const GUI_TIMEOUT_SECS: u64 = 60;

#[derive(Default, Clone)]
pub struct Stats {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub blocked_connections: u64,
    pub learning_mode: bool,
}

#[derive(Clone, Copy)]
pub struct UnknownDecision {
    pub allow: bool,
    pub timestamp: Instant,
}

#[derive(Clone)]
pub struct SessionDecision {
    pub allow: bool,
    pub timestamp: Instant,
}

pub struct GuiState {
    pub stream: Option<UnixStream>,
    pub reader: Option<BufReader<UnixStream>>,
    pub pending_cache: HashMap<String, Instant>,
    pub unknown_decisions: HashMap<String, UnknownDecision>,
    pub session_decisions: HashMap<String, SessionDecision>,
    /// Cache for popup responses from the GUI (to handle race condition with handler thread)
    /// Keyed by request_id
    pub pending_responses: HashMap<String, GuiResponse>,
    /// Request IDs sent to the GUI that may still receive one response.
    pending_response_ids: HashSet<String>,
    /// USB prompts awaiting an answer, keyed by nonce (`None` until answered).
    pending_usb: HashMap<String, Option<UsbResponse>>,
}

impl GuiState {
    pub fn new() -> Self {
        Self {
            stream: None,
            reader: None,
            pending_cache: HashMap::new(),
            unknown_decisions: HashMap::new(),
            session_decisions: HashMap::new(),
            pending_responses: HashMap::new(),
            pending_response_ids: HashSet::new(),
            pending_usb: HashMap::new(),
        }
    }

    pub fn get_session_decision(&self, cache_key: &str) -> Option<bool> {
        if let Some(decision) = self.session_decisions.get(cache_key) {
            if decision.timestamp.elapsed() < Duration::from_secs(3600) {
                return Some(decision.allow);
            }
        }
        None
    }

    pub fn cache_session_decision(&mut self, cache_key: &str, allow: bool) {
        self.session_decisions.insert(
            cache_key.to_string(),
            SessionDecision {
                allow,
                timestamp: Instant::now(),
            },
        );
    }

    pub fn set_connection(&mut self, stream: UnixStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(GUI_TIMEOUT_SECS)))
            .ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

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

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn disconnect(&mut self) {
        info!("GUI disconnected");
        self.stream = None;
        self.reader = None;
        self.pending_responses.clear();
        self.pending_response_ids.clear();
        self.pending_usb.clear();
    }

    pub fn ask_gui(&mut self, request: &ConnectionRequest) -> Option<GuiResponse> {
        if !self.is_connected() {
            return None;
        }

        if self.pending_cache.len() > 1000 {
            let now = Instant::now();
            self.pending_cache
                .retain(|_, timestamp| now.duration_since(*timestamp) < Duration::from_secs(10));
            debug!("Cleaned pending cache (size was > 1000)");
        }

        let cache_key = if request.app_path.is_empty() || request.app_path == "unknown" {
            format!("@name:{}:{}", request.app_name, request.dest_port)
        } else {
            format!("{}:{}", request.app_path, request.dest_port)
        };

        if let Some(time) = self.pending_cache.get(&cache_key) {
            if time.elapsed() < Duration::from_secs(30) {
                info!(
                    "Dedup: already asked for {} (waiting for response)",
                    cache_key
                );
                return None;
            }
        }

        self.pending_cache.insert(cache_key.clone(), Instant::now());

        info!(
            "[POPUP] {} ({}) -> {}:{}",
            request.app_name, request.app_path, request.dest_ip, request.dest_port
        );

        let json = match serde_json::to_string(request) {
            Ok(j) => j,
            Err(_) => return None,
        };

        if !request.learning_mode {
            // Register before writing: the handler may receive a response as
            // soon as the request reaches the socket.
            self.pending_response_ids.insert(request.request_id.clone());
        }

        if let Some(ref mut stream) = self.stream {
            if stream.write_all((json + "\n").as_bytes()).is_err() {
                self.disconnect();
                return None;
            }
        } else {
            return None;
        }

        if request.learning_mode {
            info!(
                "Learning mode: fired-and-forgot popup request for {}",
                cache_key
            );
            return None;
        }

        // Check if a response for THIS request is already cached (race condition).
        // Match by request_id so we never return another session's response.
        if let Some(resp) = self.pending_responses.remove(&request.request_id) {
            info!("[GUI:IMMEDIATE] Using existing cached response: allow={}", resp.allow);
            return Some(resp);
        }

        // Return None - caller should check response cache after releasing lock
        // This prevents deadlock where we hold lock while waiting for handler to cache response
        info!("[GUI:POLL] Returning to caller to poll for response without holding lock (request_id={})", request.request_id);
        None
    }

    /// Notify GUI to cancel a specific popup
    pub fn cancel_popup(&mut self, request_id: &str) {
        self.pending_response_ids.remove(request_id);
        self.pending_responses.remove(request_id);

        if !self.is_connected() {
            return;
        }

        let cancel = GuiNotification {
            msg_type: "cancel_popup".to_string(),
            request_id: request_id.to_string(),
        };

        if let Ok(json) = serde_json::to_string(&cancel) {
            if let Some(ref mut stream) = self.stream {
                let _ = stream.write_all((json + "\n").as_bytes());
            }
        }
    }

    /// Check if a response has been cached by the handler thread
    pub fn check_response_cache(&mut self, request_id: &str) -> Option<GuiResponse> {
        self.pending_responses.remove(request_id)
    }

    /// Cache a response only when it matches a request that this daemon sent.
    /// Removing the ID also ensures that duplicate responses are ignored.
    fn cache_response(&mut self, response: GuiResponse) -> bool {
        if !self.pending_response_ids.remove(&response.request_id) {
            return false;
        }
        self.pending_responses
            .insert(response.request_id.clone(), response);
        true
    }

    /// Store a USB answer only if it matches an unanswered prompt we sent.
    pub fn accept_usb_response(&mut self, response: UsbResponse) -> bool {
        match self.pending_usb.get_mut(&response.nonce) {
            Some(slot @ None) => {
                *slot = Some(response);
                true
            }
            _ => false,
        }
    }

    pub fn check_unknown_decision(&self, dest_ip: &str, dest_port: u16) -> Option<bool> {
        let key = format!("{}:{}", dest_ip, dest_port);
        if let Some(decision) = self.unknown_decisions.get(&key) {
            if decision.timestamp.elapsed() < Duration::from_secs(60) {
                info!(
                    "Using cached unknown decision for {}:{} -> {}",
                    dest_ip,
                    dest_port,
                    if decision.allow { "ALLOW" } else { "BLOCK" }
                );
                return Some(decision.allow);
            }
        }
        None
    }

    pub fn cache_unknown_decision(&mut self, dest_ip: &str, dest_port: u16, allow: bool) {
        let key = format!("{}:{}", dest_ip, dest_port);
        self.unknown_decisions.insert(
            key,
            UnknownDecision {
                allow,
                timestamp: Instant::now(),
            },
        );

        let now = Instant::now();
        self.unknown_decisions
            .retain(|_, dec| now.duration_since(dec.timestamp) < Duration::from_secs(60));
    }
}

/// Look up the numeric GID of the `bastion` group, if it exists.
#[cfg(unix)]
fn bastion_gid() -> Option<libc::gid_t> {
    let name = std::ffi::CString::new("bastion").ok()?;
    let grp = unsafe { libc::getgrnam(name.as_ptr()) };
    if grp.is_null() {
        None
    } else {
        Some(unsafe { (*grp).gr_gid })
    }
}

/// Decide whether a peer (by uid, from SO_PEERCRED) may talk to the control
/// socket. Root is always allowed; any other user must be a member of the
/// `bastion` group (primary or supplementary). Fails closed on lookup errors.
#[cfg(unix)]
fn peer_is_authorized(peer_uid: libc::uid_t) -> bool {
    if peer_uid == 0 {
        return true;
    }

    let bastion_gid = match bastion_gid() {
        Some(gid) => gid,
        None => return false,
    };

    unsafe {
        let pw = libc::getpwuid(peer_uid);
        if pw.is_null() {
            return false;
        }
        // Primary group membership.
        if (*pw).pw_gid == bastion_gid {
            return true;
        }
        // Supplementary membership: scan the group's member list.
        let user_name = (*pw).pw_name;
        if user_name.is_null() {
            return false;
        }
        let user_cstr = std::ffi::CStr::from_ptr(user_name);
        let grp_name = match std::ffi::CString::new("bastion") {
            Ok(n) => n,
            Err(_) => return false,
        };
        let grp = libc::getgrnam(grp_name.as_ptr());
        if grp.is_null() {
            return false;
        }
        let mut members = (*grp).gr_mem;
        while !members.is_null() && !(*members).is_null() {
            if std::ffi::CStr::from_ptr(*members) == user_cstr {
                return true;
            }
            members = members.add(1);
        }
    }

    false
}

fn new_nonce() -> Option<String> {
    use std::io::Read;
    let mut buf = [0u8; 16];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut buf).ok()?;
    Some(buf.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Ask the GUI whether a USB device may be used. Returns `None` when no GUI is
/// connected, the request can't be sent, or no valid answer arrives in time.
/// The state lock is not held while waiting.
pub fn ask_usb(
    gui_state: &Arc<Mutex<GuiState>>,
    device: UsbDevicePrompt,
    timeout: Duration,
) -> Option<UsbResponse> {
    let nonce = new_nonce()?;
    let request = UsbRequest { msg_type: "usb_request".to_string(), nonce: nonce.clone(), device };
    let json = serde_json::to_string(&request).ok()?;

    {
        let mut state = gui_state.lock();
        if !state.is_connected() {
            return None;
        }
        state.pending_usb.insert(nonce.clone(), None);
        let written = match state.stream.as_mut() {
            Some(stream) => stream.write_all((json + "\n").as_bytes()).is_ok(),
            None => false,
        };
        if !written {
            state.pending_usb.remove(&nonce);
            state.disconnect();
            return None;
        }
    }

    let deadline = Instant::now() + timeout;
    loop {
        {
            let mut state = gui_state.lock();
            match state.pending_usb.get(&nonce) {
                Some(Some(_)) => return state.pending_usb.remove(&nonce).flatten(),
                None => return None, // cleared by a disconnect
                Some(None) => {}
            }
            if Instant::now() >= deadline {
                state.pending_usb.remove(&nonce);
                return None;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn run_socket_server(
    gui_state: Arc<Mutex<GuiState>>,
    stats: Arc<Mutex<Stats>>,
    config: Arc<ConfigManager>,
    rule_manager: Arc<RuleManager>,
) {
    let socket_path = std::path::Path::new(SOCKET_PATH);
    if let Some(socket_dir) = socket_path.parent() {
        std::fs::create_dir_all(socket_dir).ok();
    }

    if let Ok(meta) = std::fs::symlink_metadata(SOCKET_PATH) {
        if meta.file_type().is_symlink() {
            error!(
                "Socket path is a symlink, refusing to remove: {}",
                SOCKET_PATH
            );
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
        // 0o660 + root:bastion ownership: only root and members of the bastion
        // group can connect. The kernel enforces this at connect() time.
        //
        // Fail closed: if the mode cannot be tightened to 0o660 the socket may
        // be left world-accessible, so remove it and refuse to serve rather
        // than expose a weakly-permissioned control socket.
        if let Err(e) = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660))
        {
            error!("Failed to set control socket mode to 0o660: {}", e);
            let _ = std::fs::remove_file(SOCKET_PATH);
            return;
        }
        let gid = bastion_gid().unwrap_or(0);
        let chown_ok = match std::ffi::CString::new(SOCKET_PATH) {
            Ok(path_c) => (unsafe { libc::chown(path_c.as_ptr(), 0, gid) }) == 0,
            Err(_) => false,
        };
        if !chown_ok {
            // Ownership is not root:bastion, so 0o660 does not restrict access
            // to the intended group. Fail closed.
            error!("Failed to chown control socket to root:bastion; refusing to serve");
            let _ = std::fs::remove_file(SOCKET_PATH);
            return;
        }
    }

    info!("Socket server listening on {}", SOCKET_PATH);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
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
                        if peer_is_authorized(peer_uid) {
                            info!("GUI client connected (UID: {})", peer_uid);
                        } else {
                            warn!("Rejected unauthorized connection (UID: {})", peer_uid);
                            drop(s);
                            continue;
                        }
                    } else {
                        // Fail closed: if we cannot verify the peer, reject it.
                        warn!("Rejected connection: failed to get peer credentials");
                        drop(s);
                        continue;
                    }
                }

                #[cfg(not(unix))]
                info!("GUI client connecting");

                // Refuse a second concurrent GUI: an already-connected session
                // owns the socket until it disconnects (prevents hijack, #33).
                {
                    let mut state = gui_state.lock();
                    if state.is_connected() {
                        warn!("Refusing GUI connection: a GUI is already connected");
                        drop(state);
                        drop(s);
                        continue;
                    }
                    match s.try_clone() {
                        Ok(c) => state.set_connection(c),
                        Err(e) => {
                            error!("Failed to clone GUI stream: {}", e);
                            drop(state);
                            drop(s);
                            continue;
                        }
                    }
                }

                let stats_clone = stats.clone();
                let gui_state_clone = gui_state.clone();
                let config_clone = config.clone();
                let rules_clone = rule_manager.clone();
                thread::spawn(move || {
                    handle_gui_connection(
                        s,
                        stats_clone,
                        gui_state_clone,
                        config_clone,
                        rules_clone,
                    );
                });
            }
            Err(e) => {
                error!("Socket accept error: {}", e);
            }
        }
    }
}

pub fn handle_gui_connection(
    mut stream: UnixStream,
    stats: Arc<Mutex<Stats>>,
    gui_state: Arc<Mutex<GuiState>>,
    config: Arc<ConfigManager>,
    rules: Arc<RuleManager>,
) {
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .expect("Failed to clone GUI stream for reader"),
    );
    let mut last_stats_send = Instant::now();

    loop {
        if !gui_state.lock().is_connected() {
            info!("GUI handler: Disconnected, stopping thread");
            break;
        }

        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                info!("GUI handler: Connection closed by peer");
                gui_state.lock().disconnect();
                break;
            }
            Ok(_) => {
                if let Ok(cmd) = serde_json::from_str::<GuiCommand>(&line) {
                    match cmd {
                        GuiCommand::Response(resp) => {
                            // Determine duration: use explicit duration field or fall back to permanent flag
                            let duration = if resp.duration.is_empty() {
                                (if resp.permanent { "always" } else { "once" }).to_string()
                            } else {
                                resp.duration.clone()
                            };
                            let request_id = resp.request_id.clone();
                            let allow = resp.allow;
                            if gui_state.lock().cache_response(resp) {
                                info!(
                                    "[GUI:RESPONSE] Caching response for {}: allow={}, duration={}",
                                    request_id, allow, duration
                                );
                            } else {
                                warn!(
                                    "[GUI:RESPONSE] Ignoring unsolicited or duplicate response for {}",
                                    request_id
                                );
                            }
                        }
                        GuiCommand::CancelPopup(req) => {
                            // Daemon received cancel from GUI? (Not common, usually other way)
                            info!("[GUI:CANCEL] Cancel request received for {}", req.request_id);
                        }
                        GuiCommand::AddRule(req) => {
                            info!(
                                "[ASYNC:RULE] Adding rule from GUI: {} -> {} (allow: {})",
                                req.app_name, req.port, req.allow
                            );
                            // For unknown apps, use destination-based rules (@dest:IP:PORT)
                            // This is more secure than @name:unknown which would allow any unknown app
                            let rule_key = if !req.app_path.is_empty() && req.app_path != "unknown"
                            {
                                req.app_path
                            } else if req.app_name == "unknown" && !req.dest_ip.is_empty() {
                                // Destination-based rule for unknown apps
                                format!("@dest:{}:{}", req.dest_ip, req.port)
                            } else {
                                format!("@name:{}", req.app_name)
                            };
                            // For @dest rules, port is embedded in key, so pass 0
                            let port = if rule_key.starts_with("@dest:") {
                                None
                            } else {
                                Some(req.port)
                            };
                            rules.add_rule(&rule_key, port, req.allow, req.all_ports);
                        }
                        GuiCommand::DeleteRule(req) => {
                            info!(
                                "[ASYNC:DELETE] Deleting rule from GUI: {}",
                                req.key
                            );
                            let success = rules.delete_rule(&req.key);

                            // Send confirmation response
                            let response = RuleDeletedResponse {
                                msg_type: "rule_deleted".to_string(),
                                key: req.key.clone(),
                                success,
                            };
                            if let Ok(json) = serde_json::to_string(&response) {
                                if let Err(e) = stream.write_all((json + "\n").as_bytes()) {
                                    debug!("Failed to send deletion confirmation: {}", e);
                                }
                            }
                        }
                        GuiCommand::ListRules => {
                            info!("[ASYNC:LIST] Sending rules list to GUI");
                            let rules_json = rules.get_all_rules();
                            let response = RulesListResponse {
                                msg_type: "rules_list".to_string(),
                                rules: rules_json,
                            };
                            if let Ok(json) = serde_json::to_string(&response) {
                                if let Err(e) = stream.write_all((json + "\n").as_bytes()) {
                                    debug!("Failed to send rules list: {}", e);
                                }
                            }
                        }
                        GuiCommand::UsbResponse(resp) => {
                            let nonce = resp.nonce.clone();
                            if gui_state.lock().accept_usb_response(resp) {
                                info!("[GUI:USB] Received answer for prompt {}", nonce);
                            } else {
                                warn!("[GUI:USB] Ignoring unsolicited or duplicate USB response");
                            }
                        }
                        GuiCommand::ClearCache(req) => {
                            info!(
                                "[ASYNC:CLEAR_CACHE] Clearing session cache for: {}",
                                req.cache_key
                            );
                            // Remove from session_decisions in gui_state
                            let mut state = gui_state.lock();
                            state.session_decisions.remove(&req.cache_key);
                            // Also remove from pending_cache to allow retry
                            state.pending_cache.remove(&req.cache_key);
                            info!("[ASYNC:CLEAR_CACHE] Cache cleared for: {}", req.cache_key);
                        }
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            }
            Err(e) => {
                warn!("GUI handler read error: {}", e);
                gui_state.lock().disconnect();
                break;
            }
        }

        if last_stats_send.elapsed() >= Duration::from_secs(2) {
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
            // Stats unlocked implicitly when moving to json serialization or scope ends
            if let Ok(json) = serde_json::to_string(&update) {
                if let Err(e) = stream.write_all((json + "\n").as_bytes()) {
                    debug!("GUI handler write error: {}", e);
                    gui_state.lock().disconnect();
                    break;
                }
            }
            last_stats_send = Instant::now();
        }

        thread::sleep(Duration::from_millis(50));
    }

    info!("GUI handler thread exiting");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usb_prompt() -> UsbDevicePrompt {
        UsbDevicePrompt {
            vendor_id: "046d".into(),
            product_id: "c52b".into(),
            vendor_name: "V".into(),
            product_name: "P".into(),
            device_class: 3,
            is_high_risk: true,
            serial: None,
            bus_id: "1-2".into(),
        }
    }

    fn usb_answer(nonce: &str, allow: bool) -> UsbResponse {
        UsbResponse {
            msg_type: "usb_response".into(),
            nonce: nonce.into(),
            allow,
            scope: "model".into(),
            permanent: false,
        }
    }

    #[test]
    fn usb_prompt_round_trip_and_unsolicited_answers() {
        let (daemon_side, gui_side) = UnixStream::pair().unwrap();
        let state = Arc::new(Mutex::new(GuiState::new()));
        state.lock().set_connection(daemon_side);

        assert!(!state.lock().accept_usb_response(usb_answer("nope", true)));

        let gui_state = state.clone();
        let gui = thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(gui_side).read_line(&mut line).unwrap();
            let req: UsbRequest = serde_json::from_str(&line).unwrap();
            assert_eq!(req.msg_type, "usb_request");
            // A wrong nonce is rejected, the right one accepted exactly once.
            assert!(!gui_state.lock().accept_usb_response(usb_answer("wrong", true)));
            assert!(gui_state.lock().accept_usb_response(usb_answer(&req.nonce, true)));
            assert!(!gui_state.lock().accept_usb_response(usb_answer(&req.nonce, false)));
        });

        let answer = ask_usb(&state, usb_prompt(), Duration::from_secs(5)).unwrap();
        assert!(answer.allow);
        gui.join().unwrap();
        assert!(state.lock().pending_usb.is_empty());
    }

    #[test]
    fn usb_prompt_times_out_and_needs_a_gui() {
        let state = Arc::new(Mutex::new(GuiState::new()));
        assert!(ask_usb(&state, usb_prompt(), Duration::from_millis(200)).is_none());

        let (daemon_side, _gui_side) = UnixStream::pair().unwrap();
        state.lock().set_connection(daemon_side);
        assert!(ask_usb(&state, usb_prompt(), Duration::from_millis(200)).is_none());
        assert!(state.lock().pending_usb.is_empty());
    }

    fn response(request_id: &str) -> GuiResponse {
        GuiResponse {
            request_id: request_id.to_string(),
            allow: true,
            ..GuiResponse::default()
        }
    }

    #[test]
    fn unsolicited_responses_are_not_cached() {
        let mut state = GuiState::new();

        assert!(!state.cache_response(response("invented")));
        assert!(state.pending_responses.is_empty());
    }

    #[test]
    fn expected_response_is_cached_only_once() {
        let mut state = GuiState::new();
        state.pending_response_ids.insert("expected".to_string());

        assert!(state.cache_response(response("expected")));
        assert!(!state.cache_response(response("expected")));
        assert_eq!(
            state.check_response_cache("expected").unwrap().request_id,
            "expected"
        );
        assert!(state.pending_responses.is_empty());
    }
}
