//! IPC module for GUI communication
//! Sends stats updates, accepts GUI connections

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;
use std::thread;
use log::{info, error, debug};
use parking_lot::Mutex;
use serde::Serialize;

use crate::Stats;

pub const SOCKET_PATH: &str = "/var/run/bastion/bastion-daemon.sock";

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
    pending_gui: u64,
}

pub fn start_ipc_server(stats: Arc<Mutex<Stats>>) {
    thread::spawn(move || {
        run_server(stats);
    });
}

fn run_server(stats: Arc<Mutex<Stats>>) {
    let socket_dir = std::path::Path::new(SOCKET_PATH).parent().unwrap();
    if let Err(e) = std::fs::create_dir_all(socket_dir) {
        error!("Failed to create socket dir: {}", e);
        return;
    }
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
        let _ = std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o666));
    }
    
    info!("IPC server listening on {}", SOCKET_PATH);
    listener.set_nonblocking(true).ok();
    
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                info!("GUI connected!");
                let stats_clone = stats.clone();
                thread::spawn(move || {
                    handle_gui_connection(stream, stats_clone);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                error!("Accept error: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn handle_gui_connection(mut stream: UnixStream, stats: Arc<Mutex<Stats>>) {
    stream.set_read_timeout(Some(Duration::from_millis(100))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader_stream);
    
    loop {
        // Send stats every 2 seconds
        let s = stats.lock();
        let update = StatsUpdate {
            msg_type: "stats_update".to_string(),
            stats: StatsData {
                total_connections: s.total_connections,
                allowed_connections: s.allowed_connections,
                blocked_connections: s.blocked_connections,
                pending_gui: 0, // default until pending count is implemented
            },
        };
        drop(s);
        
        if let Ok(json) = serde_json::to_string(&update) {
            if stream.write_all((json + "\n").as_bytes()).is_err() {
                break;
            }
        }
        
        // Check for incoming messages (for future popup support)
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                debug!("Received from GUI: {}", line.trim());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        
        thread::sleep(Duration::from_secs(2));
    }
    
    info!("GUI disconnected");
}
