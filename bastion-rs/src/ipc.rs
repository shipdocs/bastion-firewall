//! IPC module for GUI communication via Unix socket
//! 
//! Non-blocking IPC server that runs in a separate thread.
//! Sends stats updates, accepts GUI connections.

use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use log::{info, warn, error, debug};
use parking_lot::Mutex;

pub const SOCKET_PATH: &str = "/var/run/bastion/bastion-daemon.sock";

/// Stats update to GUI
#[derive(Debug, Clone, Serialize)]
pub struct StatsUpdate {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub stats: StatsData,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatsData {
    pub total_connections: u64,
    pub allowed_connections: u64,
    pub blocked_connections: u64,
    pub pending_gui: u64,
}

/// Start the IPC server in a background thread
pub fn start_ipc_server(stats: Arc<Mutex<crate::Stats>>) {
    thread::spawn(move || {
        run_server(stats);
    });
}

fn run_server(stats: Arc<Mutex<crate::Stats>>) {
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
        let perms = std::fs::Permissions::from_mode(0o666);
        if let Err(e) = std::fs::set_permissions(SOCKET_PATH, perms) {
            warn!("Failed to set socket permissions: {}", e);
        }
    }
    
    info!("IPC server listening on {}", SOCKET_PATH);
    
    // Set listener to non-blocking for graceful shutdown
    listener.set_nonblocking(true).ok();
    
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                info!("GUI connected");
                let stats_clone = stats.clone();
                // Handle each connection in its own thread
                thread::spawn(move || {
                    handle_connection(stream, stats_clone);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection, sleep briefly
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                error!("Accept error: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn handle_connection(mut stream: UnixStream, stats: Arc<Mutex<crate::Stats>>) {
    stream.set_read_timeout(Some(Duration::from_millis(100))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    
    loop {
        // Send stats update every 2 seconds
        let stats_data = {
            let s = stats.lock();
            StatsData {
                total_connections: s.total_connections,
                allowed_connections: s.allowed_connections,
                blocked_connections: s.blocked_connections,
                pending_gui: 0,
            }
        };
        
        let update = StatsUpdate {
            msg_type: "stats_update".to_string(),
            stats: stats_data,
        };
        
        if let Ok(json) = serde_json::to_string(&update) {
            if stream.write_all((json + "\n").as_bytes()).is_err() {
                debug!("GUI disconnected (write failed)");
                break;
            }
        }
        
        // Check for incoming messages (non-blocking)
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // EOF - client disconnected
                debug!("GUI disconnected (EOF)");
                break;
            }
            Ok(_) => {
                // Got a message from GUI (probably a response)
                debug!("Received from GUI: {}", line.trim());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data, that's fine
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Timeout, that's fine
            }
            Err(e) => {
                debug!("GUI read error: {}", e);
                break;
            }
        }
        
        thread::sleep(Duration::from_secs(2));
    }
    
    info!("GUI connection closed");
}
