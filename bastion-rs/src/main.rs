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

use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};
use nfq::{Queue, Verdict};
use std::sync::Arc;
use std::time::Duration;

use log::{debug, error, info, warn};
use parking_lot::Mutex;
use signal_hook::consts::SIGHUP;
use signal_hook::iterator::Signals;
use std::thread;

use config::ConfigManager;
use dns_snooper::DnsSnooper;
use gui::{run_socket_server, ConnectionRequest, GuiState, Stats};
use process::ProcessCache;
use rules::RuleManager;
use whitelist::should_auto_allow;

const QUEUE_NUM: u16 = 1;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Bastion Firewall Daemon v2.0.28 starting...");

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
        debug!("[AUTO] {} - {}", app_name, reason);
        return Verdict::Accept;
    }

    // Check path-based rules first
    if app_path != "unknown" && !app_path.is_empty() {
        if let Some(allow) = rules.get_decision(&app_path, dst_port) {
            if allow {
                debug!(
                    "[RULE:ALLOW] app=\"{}\" dst=\"{}:{}\" user={}",
                    display_name, dst_ip, dst_port, app_uid
                );
                return Verdict::Accept;
            } else if !learning_mode {
                info!(
                    "[RULE:BLOCK] app=\"{}\" dst=\"{}:{}\" user={}",
                    display_name, dst_ip, dst_port, app_uid
                );
                return Verdict::Drop;
            } else {
                info!("[LEARN:RULE-DENIED-BUT-ALLOWED] app=\"{}\" dst=\"{}:{}\" (would block in enforcement)", display_name, dst_ip, dst_port);
            }
        }
    }

    // Check name-based rules as fallback (skip unknown - use @dest rules instead for security)
    if app_name != "unknown" && !app_name.is_empty() {
        let name_based_key = format!("@name:{}", app_name);
        if let Some(allow) = rules.get_decision(&name_based_key, dst_port) {
            if allow {
                debug!(
                    "[RULE:ALLOW:NAME] app=\"{}\" dst=\"{}:{}\" user={}",
                    app_name, dst_ip, dst_port, app_uid
                );
                return Verdict::Accept;
            } else if !learning_mode {
                info!(
                    "[RULE:BLOCK:NAME] app=\"{}\" dst=\"{}:{}\" user={}",
                    app_name, dst_ip, dst_port, app_uid
                );
                return Verdict::Drop;
            } else {
                info!("[LEARN:RULE-DENIED-BUT-ALLOWED] app=\"@name:{}\" dst=\"{}:{}\" (would block in enforcement)", app_name, dst_ip, dst_port);
            }
        }
    }

    // For unknown apps: check destination-based rules (@dest:IP:PORT)
    // This is more secure than @name:unknown which would allow any unknown app
    if app_name == "unknown" || app_path == "unknown" {
        let dest_key = format!("@dest:{}:{}", dst_ip, dst_port);
        if let Some(allow) = rules.get_decision(&dest_key, 0) {
            if allow {
                debug!(
                    "[RULE:ALLOW:DEST] dst=\"{}:{}\" (unknown app)",
                    dst_ip, dst_port
                );
                return Verdict::Accept;
            } else if !learning_mode {
                info!(
                    "[RULE:BLOCK:DEST] dst=\"{}:{}\" (unknown app)",
                    dst_ip, dst_port
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
            debug!(
                "[SESSION:ALLOW] app=\"{}\" dst=\"{}:{}\"",
                app_name, dst_ip, dst_port
            );
            return Verdict::Accept;
        } else if !learning_mode {
            drop(gui);
            debug!(
                "[SESSION:BLOCK] app=\"{}\" dst=\"{}:{}\"",
                app_name, dst_ip, dst_port
            );
            return Verdict::Drop;
        } else {
            info!(
                "[LEARN:SESSION-DENIED-BUT-ALLOWED] app=\"{}\" dst=\"{}:{}\" (cached deny ignored)",
                app_name, dst_ip, dst_port
            );
        }
    }

    // For unknown apps, also check legacy destination-based cache
    if app_name == "unknown" || app_path == "unknown" {
        if let Some(cached_decision) = gui.check_unknown_decision(&dst_ip_str, dst_port) {
            if cached_decision {
                drop(gui);
                debug!("[CACHED:ALLOW] unknown app dst=\"{}:{}\"", dst_ip, dst_port);
                return Verdict::Accept;
            } else if !learning_mode {
                drop(gui);
                debug!("[CACHED:BLOCK] unknown app dst=\"{}:{}\"", dst_ip, dst_port);
                return Verdict::Drop;
            } else {
                info!(
                    "[LEARN:UNKNOWN-DENIED-BUT-ALLOWED] dst=\"{}:{}\" (cached deny ignored)",
                    dst_ip, dst_port
                );
            }
        }
    }

    let request = ConnectionRequest {
        msg_type: "connection_request".to_string(),
        app_name: display_name.clone(),
        app_path: app_path.clone(),
        app_category: "unknown".to_string(),
        dest_ip: dst_ip_str.clone(),
        dest_port: dst_port,
        protocol: protocol_str.to_string(),
        learning_mode,
    };

    if gui.is_connected() {
        if let Some(response) = gui.ask_gui(&request) {
            gui.cache_session_decision(&session_cache_key, response.allow);
            debug!(
                "[SESSION] Cached decision for {} (allow: {})",
                session_cache_key, response.allow
            );

            if app_name == "unknown" || app_path == "unknown" {
                gui.cache_unknown_decision(&dst_ip_str, dst_port, response.allow);
            }

            if response.permanent && app_name != "unknown" && !app_name.is_empty() {
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
                    response.allow,
                    response.all_ports,
                );
                let port_display = if response.all_ports {
                    "*".to_string()
                } else {
                    dst_port.to_string()
                };
                info!(
                    "[RULE] Created permanent rule: {} -> port {}",
                    rule_key, port_display
                );
            } else if response.permanent {
                warn!("[SECURITY] Cannot create permanent rule for unidentified process");
            }

            drop(gui);
            return if response.allow {
                info!(
                    "[USER:ALLOW] app=\"{}\" dst=\"{}:{}\" user={}",
                    display_name, dst_ip, dst_port, app_uid
                );
                Verdict::Accept
            } else {
                info!(
                    "[USER:BLOCK] app=\"{}\" dst=\"{}:{}\" user={}",
                    display_name, dst_ip, dst_port, app_uid
                );
                Verdict::Drop
            };
        }
    }
    drop(gui);

    if learning_mode {
        Verdict::Accept
    } else {
        Verdict::Drop
    }
}
