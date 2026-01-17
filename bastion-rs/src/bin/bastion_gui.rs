//! Bastion Firewall GUI - Rust Edition
//! 
//! Proof-of-concept: Tray icon + popup dialog
//! Tests Wayland/X11 compatibility before full implementation

use iced::widget::{button, column, container, row, text};
use iced::{Element, Length, Subscription, Task, Theme}; 
use iced::futures::{stream, Stream}; 
use std::sync::mpsc;
use std::thread;

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

// Icon as embedded bytes (simple 32x32 red circle for PoC)
fn create_test_icon() -> Icon {
    // Create a simple 32x32 RGBA icon (red circle on transparent background)
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    
    let center = size as f32 / 2.0;
    let radius = 12.0f32;
    
    for y in 0..size {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();
            
            if dist <= radius {
                // Red color for connected status
                rgba[idx] = 0x98;     // R 
                rgba[idx + 1] = 0xC3; // G
                rgba[idx + 2] = 0x79; // B (green-ish)
                rgba[idx + 3] = 255;  // A
            }
        }
    }
    
    Icon::from_rgba(rgba, size, size).expect("Failed to create icon")
}

use bastion_rs::protocol::*;
use tokio::net::UnixStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::OwnedWriteHalf;
use serde_json::Value;

// ...

#[derive(Debug, Clone)]
enum Message {
    /// Show popup dialog
    ShowPopup,
    /// Allow button clicked
    Allow,
    /// Deny button clicked  
    Deny,
    /// Close popup without decision
    ClosePopup,
    /// Tray menu event
    TrayEvent(TrayEventMessage),
    /// Quit application
    Quit,
    /// Daemon connection established
    DaemonConnected(Arc<tokio::sync::Mutex<OwnedWriteHalf>>),
    /// Daemon disconnected
    DaemonDisconnected,
    /// Incoming connection request from daemon
    DaemonRequest(ConnectionRequest),
    /// Incoming stats update from daemon
    StatsUpdate(StatsData),
    /// Notification (ignore or log)
    DaemonNotification(String),
}

// ...

#[derive(Debug, Clone)]
enum TrayEventMessage {
    MenuEvent(String),
    IconClick,
}

use std::sync::{Arc, Mutex};

/// Main GUI application state
struct BastionGui {
    /// Whether popup is currently shown
    popup_visible: bool,
    /// Channel receiver for tray events (Thread-safe)
    tray_rx: Option<Arc<Mutex<mpsc::Receiver<TrayEventMessage>>>>,
    /// Writer for sending commands to daemon
    daemon_writer: Option<Arc<tokio::sync::Mutex<OwnedWriteHalf>>>,
    /// Current request being displayed
    current_request: Option<ConnectionRequest>,
    /// Latest stats
    stats: Option<StatsData>,
    /// Tray sender for updates
    tray_tx: Option<gtk::glib::Sender<String>>,
}

impl BastionGui {
    fn new() -> (Self, Task<Message>) {
        // Initialize tray icon here
        println!("🏰 Bastion Firewall GUI - Rust PoC");
        println!("Testing tray icon and popup dialog...\n");

        // Channel to pass menu IDs and TrayIcon back to main thread
        let (init_tx, init_rx) = mpsc::channel();

        // Spawn thread to run GTK event loop and manage tray icon
        thread::spawn(move || {
            #[cfg(target_os = "linux")]
            if let Err(e) = gtk::init() {
                eprintln!("Failed to initialize GTK in background thread: {}", e);
                return;
            }

            // Create tray icon menu
            let menu = Menu::new();
            
            // Items need unique IDs
            let show_item = MenuItem::new("Show Popup", true, None);
            let quit_item = MenuItem::new("Quit", true, None);
            let separator = PredefinedMenuItem::separator();
            
            let show_id = show_item.id().clone();
            let quit_id = quit_item.id().clone();
            
            menu.append(&show_item).unwrap();
            menu.append(&separator).unwrap();
            menu.append(&quit_item).unwrap();

            // Create tray icon
            let icon = create_test_icon();
            let tray_icon = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("Bastion Firewall - Connected")
                .with_icon(icon)
                .build()
                .expect("Failed to create tray icon");

            println!("[TRAY] Tray icon created successfully in background thread");
            
            // Create glib channel for updates
            let (tray_tx, tray_rx) = gtk::glib::MainContext::channel(gtk::glib::Priority::default());
            
            // Attach receiver to the default main context (which gtk::main uses)
            tray_rx.attach(None, move |tooltip: String| {
                let _ = tray_icon.set_tooltip(Some(tooltip));
                gtk::glib::ControlFlow::Continue
            });

            // Send IDs and Sender back to main thread
            let _ = init_tx.send((show_id, quit_id, tray_tx));
            
            // On Linux, we need to run the GTK loop for the tray to work
            #[cfg(target_os = "linux")]
            gtk::main();
        });
        
        // Wait for IDs and TraySender
        let (show_id, quit_id, tray_tx) = init_rx.recv().expect("Failed to receive tray init data");

        println!("[TRAY] Menu IDs and Sender received");

        // Channel for tray events
        let (tx, rx) = mpsc::channel();

        // Spawn thread to handle tray menu events  
        let tx_menu = tx.clone();
        let show_id_clone = show_id.clone();
        let quit_id_clone = quit_id.clone();
        
        thread::spawn(move || {
            let menu_rx = MenuEvent::receiver();
            loop {
                if let Ok(event) = menu_rx.recv() {
                    let id_str = if event.id == show_id_clone {
                        "show_popup"
                    } else if event.id == quit_id_clone {
                        "quit"
                    } else {
                        "unknown"
                    };
                    let _ = tx_menu.send(TrayEventMessage::MenuEvent(id_str.to_string()));
                }
            }
        });

        // Spawn thread to handle tray icon click events
        let tx_icon = tx;
        thread::spawn(move || {
            let icon_rx = TrayIconEvent::receiver();
            loop {
                if let Ok(_event) = icon_rx.recv() {
                    let _ = tx_icon.send(TrayEventMessage::IconClick);
                }
            }
        });

        println!("[GUI] Starting iced application...");
        println!("[GUI] Right-click tray icon for menu, or click 'Test Popup' button\n");

        (
            BastionGui {
                popup_visible: false,
                tray_rx: Some(Arc::new(Mutex::new(rx))),
                daemon_writer: None,
                current_request: None,
                stats: None,
                tray_tx: Some(tray_tx),
            },
            Task::none(),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ShowPopup => {
                self.popup_visible = true;
                Task::none()
            }
            Message::Allow => {
                println!("[GUI] User clicked ALLOW");
                self.popup_visible = false;
                if let Some(req) = &self.current_request {
                    self.send_response(true, req.app_name == "unknown")
                } else {
                    Task::none()
                }
            }
            Message::Deny => {
                println!("[GUI] User clicked DENY");
                self.popup_visible = false;
                if let Some(req) = &self.current_request {
                    // Default to non-persistent deny for now unless user selected options (TODO)
                    self.send_response(false, false)
                } else {
                    Task::none()
                }
            }
            Message::ClosePopup => {
                self.popup_visible = false;
                Task::none()
            }
            Message::TrayEvent(event) => {
                match event {
                    TrayEventMessage::MenuEvent(id) => {
                        println!("[TRAY] Menu event: {}", id);
                        if id == "quit" {
                            std::process::exit(0);
                        } else if id == "show_popup" {
                            self.popup_visible = true;
                        }
                    }
                    TrayEventMessage::IconClick => {
                        println!("[TRAY] Icon clicked");
                        self.popup_visible = true;
                    }
                }
                Task::none()
            }
            Message::Quit => {
                std::process::exit(0);
            }
            Message::DaemonConnected(writer) => {
                println!("[GUI] Connected to daemon");
                self.daemon_writer = Some(writer);
                Task::none()
            }
            Message::DaemonDisconnected => {
                println!("[GUI] Disconnected from daemon");
                self.daemon_writer = None;
                Task::none()
            }
            Message::DaemonRequest(req) => {
                println!("[GUI] Received request: {} -> {}", req.app_name, req.dest_ip);
                self.current_request = Some(req);
                self.popup_visible = true;
                // Bring window to front/focus logic would go here
                Task::none()
            }
            Message::StatsUpdate(stats) => {
                if let Some(tx) = &self.tray_tx {
                    let _ = tx.send(format!(
                        "Bastion Firewall\nAllowed: {}\nBlocked: {}", 
                        stats.allowed_connections, 
                        stats.blocked_connections
                    ));
                }
                self.stats = Some(stats);
                Task::none()
            }
            Message::DaemonNotification(msg) => {
                // Ignore verbose connection logs?
                // println!("[GUI] Notification: {}", msg);
                Task::none()
            }
        }
    }
    
    fn send_response(&self, allow: bool, permanent: bool) -> Task<Message> {
        if let Some(writer) = &self.daemon_writer {
            let response = GuiCommand::Response(GuiResponse {
                request_id: self.current_request.as_ref().map(|r| r.request_id.clone()).unwrap_or_default(),
                allow,
                permanent,
                all_ports: false,
                duration: "".to_string(),
            });
            
            if let Ok(json) = serde_json::to_string(&response) {
                let writer = writer.clone();
                let json = json + "\n";
                
                return Task::perform(async move {
                    let mut writer = writer.lock().await;
                    if let Err(e) = writer.write_all(json.as_bytes()).await {
                        Message::DaemonNotification(format!("Write error: {}", e))
                    } else {
                        Message::DaemonNotification("Response sent".into())
                    }
                }, |msg| msg);
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<Message> {
        if self.popup_visible {
            // Popup dialog view
            let title = text("🏰 Bastion Firewall")
                .size(24);
            
            let subtitle = text("Connection Request")
                .size(18);

            let app_info = column![
                text("Application: firefox").size(14),
                text("Path: /usr/lib/firefox/firefox").size(12),
                text("Destination: 142.250.185.206:443").size(12),
                text("Protocol: TCP").size(12),
            ]
            .spacing(4);

            let info_container = container(app_info)
                .padding(15)
                .style(|_theme: &Theme| {
                    container::Style {
                        background: Some(iced::Color::from_rgb(0.15, 0.15, 0.18).into()),
                        border: iced::Border {
                            color: iced::Color::from_rgb(0.3, 0.3, 0.35),
                            width: 1.0,
                            radius: 8.0.into(),
                        },
                        ..Default::default()
                    }
                });

            let allow_btn = button(text("Allow").size(14))
                .padding([10, 30])
                .on_press(Message::Allow)
                .style(|_theme: &Theme, status| {
                    let base = button::Style {
                        background: Some(iced::Color::from_rgb(0.15, 0.65, 0.35).into()),
                        text_color: iced::Color::WHITE,
                        border: iced::Border {
                            radius: 6.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    match status {
                        button::Status::Hovered => button::Style {
                            background: Some(iced::Color::from_rgb(0.2, 0.75, 0.4).into()),
                            ..base
                        },
                        _ => base,
                    }
                });

            let deny_btn = button(text("Deny").size(14))
                .padding([10, 30])
                .on_press(Message::Deny)
                .style(|_theme: &Theme, status| {
                    let base = button::Style {
                        background: Some(iced::Color::from_rgb(0.8, 0.25, 0.25).into()),
                        text_color: iced::Color::WHITE,
                        border: iced::Border {
                            radius: 6.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    match status {
                        button::Status::Hovered => button::Style {
                            background: Some(iced::Color::from_rgb(0.9, 0.3, 0.3).into()),
                            ..base
                        },
                        _ => base,
                    }
                });

            let buttons = row![allow_btn, deny_btn].spacing(15);

            let content = column![
                title,
                subtitle,
                info_container,
                buttons,
            ]
            .spacing(20)
            .padding(25)
            .width(Length::Fill);

            container(content)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .style(|_theme: &Theme| container::Style {
                    background: Some(iced::Color::from_rgb(0.12, 0.12, 0.14).into()),
                    ..Default::default()
                })
                .into()
        } else {
            // Hidden/minimized state - show minimal UI
            let content = column![
                text("Bastion Firewall").size(16),
                text("Running in system tray").size(12),
                button(text("Test Popup")).on_press(Message::ShowPopup),
                button(text("Quit")).on_press(Message::Quit),
            ]
            .spacing(10)
            .padding(20);

            container(content)
                .width(Length::Fill)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .into()
        }
    }


    fn subscription(&self) -> Subscription<Message> {
        let tray_rx = self.tray_rx.clone();
        struct TrayId;
        
        let tray_sub = if let Some(rx) = tray_rx {
            Subscription::run_with_id(
                std::any::TypeId::of::<TrayId>(),
                tray_stream(&rx)
            )
        } else {
            Subscription::none()
        };

        let daemon_sub = Subscription::run(daemon_stream);

        Subscription::batch(vec![tray_sub, daemon_sub])
    }
    
    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

fn tray_stream(rx: &Arc<Mutex<mpsc::Receiver<TrayEventMessage>>>) -> impl Stream<Item = Message> {
    let rx = rx.clone();
    stream::unfold(rx, |rx| async move {
        loop {
            // Scope the lock to ensure it is dropped before moving rx
            let msg = {
                if let Ok(guard) = rx.try_lock() {
                    guard.try_recv().ok()
                } else {
                    None
                }
            };
            
            if let Some(msg) = msg {
                return Some((Message::TrayEvent(msg), rx));
            }
            
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
}

pub fn main() -> iced::Result {
    // GTK init moved to background thread

    // Note: window settings are now part of application run configuration
    // or set via initialization flags/settings if needed.
    // For iced 0.13, we use iced::application
    
    iced::application("Bastion Firewall", BastionGui::update, BastionGui::view)
        .subscription(BastionGui::subscription)
        .theme(BastionGui::theme)
        .window_size(iced::Size::new(450.0, 350.0))
        .centered()
        .run_with(|| BastionGui::new())
}

enum ConnectionState {
    Connecting,
    Connected(BufReader<tokio::net::unix::OwnedReadHalf>),
}

fn daemon_stream() -> impl Stream<Item = Message> {
    stream::unfold(ConnectionState::Connecting, |state| async move {
        match state {
            ConnectionState::Connecting => {
                match UnixStream::connect("/var/run/bastion/bastion-daemon.sock").await {
                    Ok(s) => {
                         let (reader, writer) = s.into_split();
                         let msg = Message::DaemonConnected(Arc::new(tokio::sync::Mutex::new(writer)));
                         let buf_reader = BufReader::new(reader);
                         Some((msg, ConnectionState::Connected(buf_reader)))
                    }
                    Err(_) => {
                         tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                         Some((Message::DaemonNotification("Connecting...".into()), ConnectionState::Connecting))
                    }
                }
            }
            ConnectionState::Connected(mut reader) => {
                 let mut line = String::new();
                 match reader.read_line(&mut line).await {
                     Ok(0) => {
                         Some((Message::DaemonDisconnected, ConnectionState::Connecting))
                     }
                     Ok(_) => {
                         let msg = if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                             if let Some(msg_type) = val.get("type").and_then(|v| v.as_str()) {
                                 match msg_type {
                                     "connection_request" => {
                                         if let Ok(req) = serde_json::from_value(val) {
                                             Message::DaemonRequest(req)
                                         } else {
                                             Message::DaemonNotification("Invalid request format".into())
                                         }
                                     }
                                     "stats_update" => {
                                         if let Ok(stats_update) = serde_json::from_value::<StatsUpdate>(val) {
                                             Message::StatsUpdate(stats_update.stats)
                                         } else {
                                             Message::DaemonNotification("Invalid stats format".into())
                                         }
                                     }
                                     _ => Message::DaemonNotification("Unknown message type".into())
                                 }
                             } else {
                                 Message::DaemonNotification("Missing message type".into())
                             }
                         } else {
                             Message::DaemonNotification("JSON parse error".into())
                         };
                         Some((msg, ConnectionState::Connected(reader)))
                     }
                     Err(_) => {
                         Some((Message::DaemonDisconnected, ConnectionState::Connecting))
                     }
                 }
            }
        }
    })
}
