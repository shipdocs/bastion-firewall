//! IPC module for GUI communication via Unix socket

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use log::{info, warn, error, debug};
use parking_lot::Mutex;

use crate::rules::RuleManager;

const SOCKET_PATH: &str = "/var/run/bastion/bastion-daemon.sock";

/// Request from daemon to GUI
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionRequest {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub app_name: String,
    pub app_path: String,
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

/// Pending request waiting for GUI response
pub struct PendingRequest {
    pub app_path: String,
    pub dest_port: u16,
    pub response_tx: tokio::sync::oneshot::Sender<bool>,
}

pub struct IpcServer {
    pub stats: Arc<Mutex<Stats>>,
    pub pending_tx: mpsc::Sender<PendingRequest>,
    pending_rx: Mutex<Option<mpsc::Receiver<PendingRequest>>>,
    rules: Arc<RuleManager>,
}

impl IpcServer {
    pub fn new(rules: Arc<RuleManager>) -> Self {
        let (tx, rx) = mpsc::channel(100);
        Self {
            stats: Arc::new(Mutex::new(Stats::default())),
            pending_tx: tx,
            pending_rx: Mutex::new(Some(rx)),
            rules,
        }
    }
    
    pub async fn run(&self) -> anyhow::Result<()> {
        // Ensure socket directory exists
        let socket_dir = std::path::Path::new(SOCKET_PATH).parent().unwrap();
        std::fs::create_dir_all(socket_dir)?;
        
        // Remove existing socket
        let _ = std::fs::remove_file(SOCKET_PATH);
        
        let listener = UnixListener::bind(SOCKET_PATH)?;
        info!("IPC server listening on {}", SOCKET_PATH);
        
        // Set socket permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o660);
            std::fs::set_permissions(SOCKET_PATH, perms)?;
        }
        
        // Take the receiver (can only do this once)
        let pending_rx = self.pending_rx.lock().take()
            .expect("IPC server can only be run once");
        
        let stats = self.stats.clone();
        let rules = self.rules.clone();
        
        // Handle connections
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    info!("GUI connected");
                    // Handle this connection
                    // For simplicity, we handle one GUI at a time
                    if let Err(e) = Self::handle_gui(stream, pending_rx, stats.clone(), rules.clone()).await {
                        warn!("GUI connection ended: {}", e);
                    }
                    break; // Exit after first GUI disconnects for now
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_gui(
        stream: UnixStream,
        mut pending_rx: mpsc::Receiver<PendingRequest>,
        stats: Arc<Mutex<Stats>>,
        rules: Arc<RuleManager>,
    ) -> anyhow::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        
        loop {
            tokio::select! {
                // Handle pending requests to send to GUI
                Some(req) = pending_rx.recv() => {
                    let msg = ConnectionRequest {
                        msg_type: "connection_request".to_string(),
                        app_name: req.app_path.split('/').last().unwrap_or("unknown").to_string(),
                        app_path: req.app_path.clone(),
                        dest_ip: "".to_string(), // TODO: pass this through
                        dest_port: req.dest_port,
                        protocol: "tcp".to_string(),
                    };
                    
                    let json = serde_json::to_string(&msg)? + "\n";
                    writer.write_all(json.as_bytes()).await?;
                    
                    // Wait for response
                    let mut line = String::new();
                    reader.read_line(&mut line).await?;
                    
                    if let Ok(response) = serde_json::from_str::<GuiResponse>(&line) {
                        // Save permanent rules
                        if response.permanent {
                            rules.add_rule(&req.app_path, Some(req.dest_port), response.allow);
                        }
                        
                        // Send response back to packet handler
                        let _ = req.response_tx.send(response.allow);
                    } else {
                        let _ = req.response_tx.send(false);
                    }
                }
                
                // Could add stats broadcast here
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                    let stats_msg = StatsUpdate {
                        msg_type: "stats_update".to_string(),
                        stats: stats.lock().clone(),
                    };
                    let json = serde_json::to_string(&stats_msg)? + "\n";
                    if writer.write_all(json.as_bytes()).await.is_err() {
                        break;
                    }
                }
            }
        }
        
        Ok(())
    }
}
