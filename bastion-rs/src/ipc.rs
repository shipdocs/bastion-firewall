//! IPC module for GUI communication via Unix socket
//! 
//! Protocol: JSON messages separated by newlines
//! 
//! Daemon -> GUI:
//!   {"type": "connection_request", "app_name": "...", "app_path": "...", "dest_ip": "...", "dest_port": N, "protocol": "tcp"}
//!   {"type": "stats_update", "stats": {...}}
//! 
//! GUI -> Daemon:
//!   {"allow": true/false, "permanent": true/false}

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use log::{info, warn, error, debug};
use parking_lot::Mutex;

use crate::rules::RuleManager;

pub const SOCKET_PATH: &str = "/var/run/bastion/bastion-daemon.sock";

/// Request from daemon to GUI
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionRequest {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub app_name: String,
    pub app_path: String,
    pub app_category: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
}

/// Response from GUI
#[derive(Debug, Clone, Deserialize)]
pub struct GuiResponse {
    pub allow: bool,
    #[serde(default)]
    pub permanent: bool,
}

/// Stats update to GUI
#[derive(Debug, Clone, Serialize)]
pub struct StatsUpdate {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub stats: Stats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub blocked_connections: u64,
    pub pending_gui: u64,
}

/// Request to ask GUI for a decision
pub struct DecisionRequest {
    pub app_name: String,
    pub app_path: String,
    pub app_category: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub response_tx: std::sync::mpsc::Sender<Option<GuiResponse>>,
}

/// Synchronous IPC Server (runs in separate thread)
pub struct IpcServer {
    pub stats: Arc<Mutex<Stats>>,
    rules: Arc<RuleManager>,
    request_rx: std::sync::mpsc::Receiver<DecisionRequest>,
    gui_stream: Mutex<Option<UnixStream>>,
}

impl IpcServer {
    pub fn new(
        rules: Arc<RuleManager>,
        stats: Arc<Mutex<Stats>>,
        request_rx: std::sync::mpsc::Receiver<DecisionRequest>,
    ) -> Self {
        Self {
            stats,
            rules,
            request_rx,
            gui_stream: Mutex::new(None),
        }
    }
    
    /// Run the IPC server (blocking)
    pub fn run(&self) {
        // Ensure socket directory exists
        let socket_dir = std::path::Path::new(SOCKET_PATH).parent().unwrap();
        if let Err(e) = std::fs::create_dir_all(socket_dir) {
            error!("Failed to create socket directory: {}", e);
            return;
        }
        
        // Remove existing socket
        let _ = std::fs::remove_file(SOCKET_PATH);
        
        let listener = match UnixListener::bind(SOCKET_PATH) {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to bind socket: {}", e);
                return;
            }
        };
        
        // Set socket permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o660);
            if let Err(e) = std::fs::set_permissions(SOCKET_PATH, perms) {
                warn!("Failed to set socket permissions: {}", e);
            }
        }
        
        info!("IPC server listening on {}", SOCKET_PATH);
        
        // Accept connections in a loop
        for stream_result in listener.incoming() {
            match stream_result {
                Ok(stream) => {
                    info!("GUI connected");
                    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                    
                    *self.gui_stream.lock() = Some(stream.try_clone().unwrap());
                    
                    // Handle this connection
                    self.handle_connection(stream);
                    
                    *self.gui_stream.lock() = None;
                    info!("GUI disconnected, waiting for new connection...");
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }
    
    fn handle_connection(&self, mut stream: UnixStream) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        
        loop {
            // Check for pending decision requests
            match self.request_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(request) => {
                    // Send request to GUI
                    let msg = ConnectionRequest {
                        msg_type: "connection_request".to_string(),
                        app_name: request.app_name.clone(),
                        app_path: request.app_path.clone(),
                        app_category: request.app_category,
                        dest_ip: request.dest_ip,
                        dest_port: request.dest_port,
                        protocol: request.protocol,
                    };
                    
                    let json = match serde_json::to_string(&msg) {
                        Ok(j) => j + "\n",
                        Err(e) => {
                            error!("Failed to serialize request: {}", e);
                            let _ = request.response_tx.send(None);
                            continue;
                        }
                    };
                    
                    if let Err(e) = stream.write_all(json.as_bytes()) {
                        error!("Failed to send to GUI: {}", e);
                        let _ = request.response_tx.send(None);
                        return; // Connection broken
                    }
                    
                    // Wait for response
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            // EOF
                            let _ = request.response_tx.send(None);
                            return;
                        }
                        Ok(_) => {
                            match serde_json::from_str::<GuiResponse>(&line) {
                                Ok(response) => {
                                    // Save permanent rules
                                    if response.permanent {
                                        self.rules.add_rule(
                                            &request.app_path,
                                            Some(request.dest_port),
                                            response.allow
                                        );
                                    }
                                    let _ = request.response_tx.send(Some(response));
                                }
                                Err(e) => {
                                    warn!("Failed to parse GUI response: {}", e);
                                    let _ = request.response_tx.send(None);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to read from GUI: {}", e);
                            let _ = request.response_tx.send(None);
                            return;
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // No requests, send stats update periodically
                    // (handled by separate thread to avoid blocking)
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    info!("Request channel closed, shutting down IPC");
                    return;
                }
            }
        }
    }
    
    /// Send stats update (called from stats thread)
    pub fn send_stats(&self) {
        let guard = self.gui_stream.lock();
        if let Some(ref stream) = *guard {
            let stats_msg = StatsUpdate {
                msg_type: "stats_update".to_string(),
                stats: self.stats.lock().clone(),
            };
            
            if let Ok(json) = serde_json::to_string(&stats_msg) {
                let mut s = stream.try_clone().unwrap();
                let _ = s.write_all((json + "\n").as_bytes());
            }
        }
    }
}
