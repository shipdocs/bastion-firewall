use nfqueue::{Queue, Verdict, CopyMode, Message};
use etherparse::{Ipv4HeaderSlice, TcpHeaderSlice, UdpHeaderSlice};

fn main() {
    // Initialize logging
    env_logger::init();
    
    println!("Bastion (Rust) initializing...");

    let mut queue = Queue::new(());

    queue.open();
    
    // Unbind/Bind to AF_INET
    if queue.unbind(libc::AF_INET) != 0 {
        println!("Warning: Unbind returned non-zero (first run?)");
    }
    if queue.bind(libc::AF_INET) != 0 {
        panic!("Failed to bind AF_INET");
    }

    // Register callback function
    queue.create_queue(1, packet_handler);

    // Set copy mode to Packet (full packet)
    queue.set_mode(CopyMode::CopyPacket, 0xFFFF);

    println!("Listening on NFQUEUE 1. Triggers valid if traffic is outbound.");

    queue.run_loop();
    
    queue.close();
}

// Callback must be specific signature: fn(&Message, &mut T)
fn packet_handler(msg: &Message, _: &mut ()) {
    let payload = msg.get_payload();
    let verdict = inspect_packet(payload);
    msg.set_verdict(verdict);
}

fn inspect_packet(payload: &[u8]) -> Verdict {
    // Attempt to parse IPv4
    if let Ok(ip_header) = Ipv4HeaderSlice::from_slice(payload) {
        let src = ip_header.source_addr();
        let dst = ip_header.destination_addr();
        let proto = ip_header.protocol();
        
        // Calculate header length to jump to transport
        let ip_len = ip_header.slice().len();
        
        if payload.len() > ip_len {
            let transport_slice = &payload[ip_len..];
            
            let info = match proto {
                6 => { // TCP
                   if let Ok(tcp) = TcpHeaderSlice::from_slice(transport_slice) {
                       format!("TCP {} -> {}", tcp.source_port(), tcp.destination_port())
                   } else { "TCP (Unknown)".to_string() }
                },
                17 => { // UDP
                   if let Ok(udp) = UdpHeaderSlice::from_slice(transport_slice) {
                       format!("UDP {} -> {}", udp.source_port(), udp.destination_port())
                   } else { "UDP (Unknown)".to_string() }
                },
                _ => format!("Proto {}", proto)
            };
            
            println!("[RUST] Packet: {} -> {} | {} | {} bytes", src, dst, info, payload.len());
        }
    }
    
    // Default Policy: ACCEPT
    Verdict::Accept
}
