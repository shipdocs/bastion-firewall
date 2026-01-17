//! Bastion Firewall Daemon - Rust Edition
//! Handles packet filtering, GUI interaction, and rule enforcement.

mod config;
mod dns_snooper;
mod ebpf_loader;
mod gui;
mod proc_parser;
mod process;
mod rules;
mod whitelist;

use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};
use nfq::{Queue, Verdict};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};
use parking_lot::Mutex;
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use std::thread;

use bastion_rs::protocol::ConnectionRequest;
use config::ConfigManager;
use dns_snooper::DnsSnooper;
use gui::{run_socket_server, GuiState, Stats};
use process::ProcessCache;
use rules::RuleManager;
use whitelist::should_auto_allow;

const QUEUE_NUM: u16 = 1;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Bastion Firewall Daemon v2.0.29 starting...");

    let config = Arc::new(ConfigManager::new());
    let rules = Arc::new(RuleManager::new());
    let learning_mode = config.is_learning_mode();
    let stats = Arc::new(Mutex::new(Stats {
        learning_mode,
        ..Stats::default()
    }));

    info!(
        "Mode: {}",
        if learning_mode {
            "Learning"
        } else {
            "Enforcement"
        }
    );

    // Shared GUI state
    let gui_state = Arc::new(Mutex::new(GuiState::new()));

    // Start socket server for GUI connections
    let gui_state_server = gui_state.clone();
    let stats_server = stats.clone();
    let config_server = config.clone();
    let rules_server = rules.clone();
    thread::spawn(move || {
        run_socket_server(gui_state_server, stats_server, config_server, rules_server);
    });

    // Open NFQUEUE
    let mut queue = Queue::open()?;
    queue.bind(QUEUE_NUM)?;

    info!("Listening on NFQUEUE {}", QUEUE_NUM);
    info!("Ready for packets!");

    // Stats printer
    let stats_clone = stats.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));
        let s = stats_clone.lock();
        let mode = if s.learning_mode {
            "learning"
        } else {
            "enforcement"
        };
        info!(
            "Stats: {} total, {} allowed, {} blocked ({})",
            s.total_connections, s.allowed_connections, s.blocked_connections, mode
        );
    });

    // SIGHUP handler - reload config, clear pending cache, reload rules
    let gui_state_sighup = gui_state.clone();
    let rules_sighup = rules.clone();
    let config_sighup = config.clone();
    thread::spawn(move || {
        let mut signals = match Signals::new([SIGHUP]) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to register SIGHUP handler: {}", e);
                return;
            }
        };

        for sig in signals.forever() {
            if sig == SIGHUP {
                info!("Received SIGHUP - reloading config and rules");
                if let Err(e) = config_sighup.load() {
                    error!("Failed to reload config: {}", e);
                }
                gui_state_sighup.lock().pending_cache.clear();
                rules_sighup.reload();
                let mode = if config_sighup.is_learning_mode() {
                    "learning"
                } else {
                    "enforcement"
                };
                info!(
                    "Config reloaded: mode={}, rules reloaded, cache cleared",
                    mode
                );
            }
        }
    });

    // Process cache
    let process_cache = Arc::new(Mutex::new(ProcessCache::new(120)));

    // DNS snooper thread - requires shared eBPF manager and DNS cache
    // Extract eBPF manager and DNS cache from ProcessCache for sharing
    let ebpf_manager = {
        let cache = process_cache.lock();
        cache.get_ebpf_manager()
    };

    let dns_cache = {
        let cache = process_cache.lock();
        cache.get_dns_cache()
    };

    if let (Some(ebpf_mgr), Some(dns_c)) = (ebpf_manager, dns_cache) {
        thread::spawn(move || {
            match DnsSnooper::new(ebpf_mgr, dns_c) {
                Ok(mut snooper) => {
                    info!("DNS snooper thread started");
                    if let Err(e) = snooper.run() {
                        error!("DNS snooper error: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to start DNS snooper: {} (DNS tracking disabled)", e);
                }
            }
        });
    } else {
        warn!("DNS snooper not started (eBPF not available)");
    }

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
        let verdict = process_packet(payload, &rules, &process_cache, &config, &gui_state);

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

fn process_packet(
    payload: &[u8],
    rules: &RuleManager,
    process_cache: &Mutex<ProcessCache>,
    config: &Arc<ConfigManager>,
    gui_state: &Arc<Mutex<GuiState>>,
) -> Verdict {
    let learning_mode = config.is_learning_mode();
    
    // Detect IP version from first byte (version is in high nibble)
    if payload.is_empty() {
        return Verdict::Accept;
    }
    
    let ip_version = (payload[0] >> 4) & 0x0F;
    
    // Parse IP header and extract addresses, protocol, and transport offset
    let (src_ip_str, dst_ip_str, proto, transport_offset) = match ip_version {
        4 => {
            // IPv4
            let ip_header = match Ipv4HeaderSlice::from_slice(payload) {
                Ok(h) => h,
                Err(_) => return Verdict::Accept,
            };
            
            let src_ip = ip_header.source_addr();
            let dst_ip = ip_header.destination_addr();
            let proto = ip_header.protocol();
            let ip_len = ip_header.slice().len();
            
            (format!("{}", src_ip), format!("{}", dst_ip), proto, ip_len)
        }
        6 => {
            // IPv6
            let ip_header = match Ipv6HeaderSlice::from_slice(payload) {
                Ok(h) => h,
                Err(_) => return Verdict::Accept,
            };
            
            let src_ip = ip_header.source_addr();
            let dst_ip = ip_header.destination_addr();
            let proto = ip_header.next_header();
            let ip_len = ip_header.slice().len();
            
            (format!("{}", src_ip), format!("{}", dst_ip), proto, ip_len)
        }
        _ => {
            // Unknown IP version, accept
            return Verdict::Accept;
        }
    };

    if payload.len() <= transport_offset {
        return Verdict::Accept;
    }

    let transport_slice = &payload[transport_offset..];

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

    // Identify process
    let mut cache = process_cache.lock();
    let process_info =
        cache.find_process_by_socket(&src_ip_str, src_port, &dst_ip_str, dst_port, protocol_str);
    drop(cache);

    let (app_name, app_path, app_uid, domain_name) = match &process_info {
        Some(info) => (info.name.clone(), info.exe_path.clone(), info.uid, info.domain_name.clone()),
        None => ("unknown".to_string(), "unknown".to_string(), 0, None),
    };

    let display_name = if let Some(domain) = &domain_name {
        format!("{} ({})", app_name, domain)
    } else {
        app_name.clone()
    };

    // Check whitelist
    let (auto_allow, reason) = should_auto_allow(&app_path, &app_name, dst_port, &dst_ip_str);
    if auto_allow {
        info!("[AUTO] {} - {}", app_name, reason);
        return Verdict::Accept;
    }

    // Check path-based rules first
    if app_path != "unknown" && !app_path.is_empty() {
        if let Some(allow) = rules.get_decision(&app_path, dst_port) {
            if allow {
                info!(
                    "[RULE:ALLOW] app=\"{}\" dst=\"{}:{}\" user={}",
                    display_name, dst_ip_str, dst_port, app_uid
                );
                return Verdict::Accept;
            } else if !learning_mode {
                info!(
                    "[RULE:BLOCK] app=\"{}\" dst=\"{}:{}\" user={}",
                    display_name, dst_ip_str, dst_port, app_uid
                );
                return Verdict::Drop;
            } else {
                info!("[LEARN:RULE-DENIED-BUT-ALLOWED] app=\"{}\" dst=\"{}:{}\" (would block in enforcement)", display_name, dst_ip_str, dst_port);
            }
        }
    }

    // Check name-based rules as fallback (skip unknown - use @dest rules instead for security)
    if app_name != "unknown" && !app_name.is_empty() {
        let name_based_key = format!("@name:{}", app_name);
        if let Some(allow) = rules.get_decision(&name_based_key, dst_port) {
            if allow {
                info!(
                    "[RULE:ALLOW:NAME] app=\"{}\" dst=\"{}:{}\" user={}",
                    app_name, dst_ip_str, dst_port, app_uid
                );
                return Verdict::Accept;
            } else if !learning_mode {
                info!(
                    "[RULE:BLOCK:NAME] app=\"{}\" dst=\"{}:{}\" user={}",
                    app_name, dst_ip_str, dst_port, app_uid
                );
                return Verdict::Drop;
            } else {
                info!("[LEARN:RULE-DENIED-BUT-ALLOWED] app=\"@name:{}\" dst=\"{}:{}\" (would block in enforcement)", app_name, dst_ip_str, dst_port);
            }
        }
    }

    // For unknown apps: check destination-based rules (@dest:IP:PORT)
    // This is more secure than @name:unknown which would allow any unknown app
    if app_name == "unknown" || app_path == "unknown" {
        let dest_key = format!("@dest:{}:{}", dst_ip_str, dst_port);
        if let Some(allow) = rules.get_decision(&dest_key, 0) {
            if allow {
                info!(
                    "[RULE:ALLOW:DEST] dst=\"{}:{}\" (unknown app)",
                    dst_ip_str, dst_port
                );
                return Verdict::Accept;
            } else if !learning_mode {
                info!(
                    "[RULE:BLOCK:DEST] dst=\"{}:{}\" (unknown app)",
                    dst_ip_str, dst_port
                );
                return Verdict::Drop;
            }
        }
    }

    // No rule found - check session cache first, then ask user
    let session_cache_key = if app_path.is_empty() || app_path == "unknown" {
        format!("@name:{}:{}", app_name, dst_port)
    } else {
        format!("{}:{}", app_path, dst_port)
    };

    let mut gui = gui_state.lock();

    // Check session decision cache first
    if let Some(cached_allow) = gui.get_session_decision(&session_cache_key) {
        if cached_allow {
            drop(gui);
            info!(
                "[SESSION:ALLOW] app=\"{}\" dst=\"{}:{}\"",
                app_name, dst_ip_str, dst_port
            );
            return Verdict::Accept;
        } else if !learning_mode {
            drop(gui);
            info!(
                "[SESSION:BLOCK] app=\"{}\" dst=\"{}:{}\"",
                app_name, dst_ip_str, dst_port
            );
            return Verdict::Drop;
        } else {
            info!(
                "[LEARN:SESSION-DENIED-BUT-ALLOWED] app=\"{}\" dst=\"{}:{}\" (cached deny ignored)",
                app_name, dst_ip_str, dst_port
            );
        }
    }

    // For unknown apps, also check legacy destination-based cache
    if app_name == "unknown" || app_path == "unknown" {
        if let Some(cached_decision) = gui.check_unknown_decision(&dst_ip_str, dst_port) {
            if cached_decision {
                drop(gui);
                info!("[CACHED:ALLOW] unknown app dst=\"{}:{}\"", dst_ip_str, dst_port);
                return Verdict::Accept;
            } else if !learning_mode {
                drop(gui);
                info!("[CACHED:BLOCK] unknown app dst=\"{}:{}\"", dst_ip_str, dst_port);
                return Verdict::Drop;
            } else {
                info!(
                    "[LEARN:UNKNOWN-DENIED-BUT-ALLOWED] dst=\"{}:{}\" (cached deny ignored)",
                    dst_ip_str, dst_port
                );
            }
        }
    }

    let request_id = format!("{}-{}", app_name, uuid_simple());
    let request = ConnectionRequest {
        msg_type: "connection_request".to_string(),
        request_id: request_id.clone(),
        app_name: display_name.clone(),
        app_path: app_path.clone(),
        app_category: "unknown".to_string(),
        dest_ip: dst_ip_str.clone(),
        dest_port: dst_port,
        protocol: protocol_str.to_string(),
        learning_mode,
    };

    if gui.is_connected() {
        // Send the popup request
        let sent_request = gui.ask_gui(&request);
        drop(gui);  // Release lock before waiting for response!

        if sent_request.is_some() {
            // Response was immediately available (learning mode or cached)
            // This shouldn't happen in normal flow, but handle it
            return if learning_mode {
                Verdict::Accept
            } else {
                Verdict::Drop
            };
        }

        // Poll for response WITHOUT holding the lock (prevents deadlock)
        let start = Instant::now();
        let timeout = Duration::from_secs(60);  // Match GUI dialog timeout
        let mut response = None;

        while start.elapsed() < timeout {
            // briefly check rules first - another thread might have added a rule
            if let Some(allow) = rules.get_decision(&app_path, dst_port) {
                info!("[DAEMON:RACE] Another thread added rule for {}: allow={}", app_name, allow);
                // Try to cancel OUR popup if it's still pending
                let mut gui = gui_state.lock();
                gui.cancel_popup(&request_id);
                drop(gui);
                return if allow { Verdict::Accept } else { Verdict::Drop };
            }

            // Briefly acquire lock just to check cache
            let mut gui = gui_state.lock();
            // Check session decision for this app:port specifically (might have been added by another thread)
            if let Some(cached_allow) = gui.get_session_decision(&session_cache_key) {
                info!("[DAEMON:RACE] Another thread added session decision for {}: allow={}", app_name, cached_allow);
                gui.cancel_popup(&request_id);
                drop(gui);
                return if cached_allow { Verdict::Accept } else { Verdict::Drop };
            }

            response = gui.check_response_cache(&request_id);
            drop(gui);

            if response.is_some() {
                break;
            }
            // Sleep briefly to avoid busy-waiting
            std::thread::sleep(Duration::from_millis(50));
        }

        if let Some(resp) = response {
            let mut gui = gui_state.lock();
            gui.cache_session_decision(&session_cache_key, resp.allow);
            info!(
                "[SESSION] Cached decision for {} (allow: {})",
                session_cache_key, resp.allow
            );

            if app_name == "unknown" || app_path == "unknown" {
                gui.cache_unknown_decision(&dst_ip_str, dst_port, resp.allow);
            }

            if resp.permanent && app_name != "unknown" && !app_name.is_empty() {
                let rule_key = if !app_path.is_empty() && app_path != "unknown" {
                    app_path.clone()
                } else {
                    let name_based_key = format!("@name:{}", app_name);
                    warn!(
                        "[SECURITY] Creating name-based rule (no path): {} -> port {}",
                        app_name, dst_port
                    );
                    name_based_key
                };
                rules.add_rule(
                    &rule_key,
                    Some(dst_port),
                    resp.allow,
                    resp.all_ports,
                );
                let port_display = if resp.all_ports {
                    "*".to_string()
                } else {
                    dst_port.to_string()
                };
                info!(
                    "[RULE] Created permanent rule: {} -> port {}",
                    rule_key, port_display
                );
            } else if resp.permanent {
                warn!("[SECURITY] Cannot create permanent rule for unidentified process");
            }

            drop(gui);
            return if resp.allow {
                info!(
                    "[USER:ALLOW] app=\"{}\" dst=\"{}:{}\" user={}",
                    display_name, dst_ip_str, dst_port, app_uid
                );
                Verdict::Accept
            } else {
                info!(
                    "[USER:BLOCK] app=\"{}\" dst=\"{}:{}\" user={}",
                    display_name, dst_ip_str, dst_port, app_uid
                );
                Verdict::Drop
            };
        } else {
            info!("[GUI:TIMEOUT] No response received after 30s");
        }
    } else {
        drop(gui);
    }

    if learning_mode {
        Verdict::Accept
    } else {
        Verdict::Drop
    }
}

/// Simple unique ID generator since we don't want a heavy UUID dependency
fn uuid_simple() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    format!("{:x}{:x}", now.as_secs(), now.subsec_nanos())
}
