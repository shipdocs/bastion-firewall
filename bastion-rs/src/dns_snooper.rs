use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::RData;
use log::{debug, error, info};
use pcap::{Active, Capture, Device};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::ebpf_loader::EbpfManager;
use crate::process::DnsCache;

/// DNS Snooper - captures and parses DNS responses to correlate IPs with processes
/// True for a response (QR bit set) to a standard query (opcode QUERY).
fn is_standard_response(msg: &Message) -> bool {
    msg.metadata.message_type == MessageType::Response && msg.metadata.op_code == OpCode::Query
}

pub struct DnsSnooper {
    capture: Capture<Active>,
    ebpf_manager: Arc<parking_lot::Mutex<EbpfManager>>,
    dns_cache: Arc<parking_lot::Mutex<DnsCache>>,
    correlation_window_ns: u64,
}

impl DnsSnooper {
    /// Create a new DNS snooper
    pub fn new(
        ebpf_manager: Arc<parking_lot::Mutex<EbpfManager>>,
        dns_cache: Arc<parking_lot::Mutex<DnsCache>>,
    ) -> Result<Self> {
        info!("Initializing DNS snooper...");

        // Find the default device or use "any"
        let device = Device::lookup()
            .ok()
            .flatten()
            .unwrap_or_else(|| Device {
                name: "any".to_string(),
                desc: None,
                addresses: vec![],
                flags: pcap::DeviceFlags::empty(),
            });

        info!("DNS snooper using device: {}", device.name);

        // Open capture device
        let mut capture = Capture::from_device(device)
            .context("Failed to open capture device")?
            .promisc(true)
            .snaplen(65535)
            .buffer_size(10_000_000)
            .timeout(100) // 100ms timeout for next_packet()
            .open()
            .context("Failed to activate capture")?;

        // Set BPF filter for DNS traffic (UDP port 53)
        capture
            .filter("udp port 53", true)
            .context("Failed to set BPF filter")?;

        info!("DNS snooper initialized successfully");

        Ok(Self {
            capture,
            ebpf_manager,
            dns_cache,
            correlation_window_ns: 100_000_000, // 100ms default
        })
    }

    /// Main loop - capture and process DNS responses
    pub fn run(&mut self) -> Result<()> {
        info!("DNS snooper thread started");

        loop {
            match self.capture.next_packet() {
                Ok(packet) => {
                    // Clone packet data to avoid borrow checker issues
                    let packet_data = packet.data.to_vec();
                    if let Err(e) = self.process_packet(&packet_data) {
                        debug!("Failed to process DNS packet: {}", e);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue
                    continue;
                }
                Err(e) => {
                    error!("pcap error: {}", e);
                    // Sleep briefly before retrying
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// Process a captured packet
    fn process_packet(&self, data: &[u8]) -> Result<()> {
        // Parse Ethernet + IP + UDP headers to get to DNS payload
        let dns_payload = self.extract_dns_payload(data)?;

        // Parse DNS message
        let dns_msg = Message::from_vec(dns_payload)
            .context("Failed to parse DNS message")?;

        // Only process responses to standard queries: skip queries, and skip UPDATE/NOTIFY/etc.
        // messages, whose sections don't mean what an ordinary answer section does.
        if !is_standard_response(&dns_msg) {
            return Ok(());
        }

        // Extract DNS server IP from packet
        let dns_server_ip = self.extract_source_ip(data)?;

        info!(
            "DNS response: ID {} from {} ({} answers)",
            dns_msg.metadata.id,
            dns_server_ip,
            dns_msg.answers.len()
        );

        // Correlate with recent eBPF queries
        self.correlate_and_cache(dns_server_ip, &dns_msg)?;

        Ok(())
    }

    /// Extract DNS payload from Ethernet/IP/UDP packet
    fn extract_dns_payload<'a>(&self, data: &'a [u8]) -> Result<&'a [u8]> {
        use etherparse::{PacketHeaders, TransportHeader};

        let headers = PacketHeaders::from_ethernet_slice(data)
            .context("Failed to parse packet headers")?;

        match headers.transport {
            Some(TransportHeader::Udp(_udp_header)) => {
                let payload_offset = headers.payload.as_ptr() as usize - data.as_ptr() as usize;
                Ok(&data[payload_offset..])
            }
            _ => Err(anyhow!("Not a UDP packet")),
        }
    }

    /// Extract source IP address from packet
    fn extract_source_ip(&self, data: &[u8]) -> Result<Ipv4Addr> {
        use etherparse::{IpHeader, PacketHeaders};

        let headers = PacketHeaders::from_ethernet_slice(data)
            .context("Failed to parse packet headers")?;

        match headers.ip {
            Some(IpHeader::Version4(ipv4_header, _)) => {
                Ok(Ipv4Addr::from(ipv4_header.source))
            }
            _ => Err(anyhow!("Not an IPv4 packet")),
        }
    }

    /// Correlate DNS response with recent queries and update cache
    fn correlate_and_cache(&self, dns_server_ip: Ipv4Addr, dns_msg: &Message) -> Result<()> {
        let dns_server_ip_u32 = u32::from_be_bytes(dns_server_ip.octets());
        let now_ns = crate::ebpf_loader::get_monotonic_ns();

        // Query eBPF for recent DNS queries to this server
        let recent_queries = {
            let ebpf = self.ebpf_manager.lock();
            ebpf.poll_dns_queries_by_dest_ip(dns_server_ip_u32, self.correlation_window_ns)
        };

        if recent_queries.is_empty() {
            info!("No matching eBPF queries for DNS server {} (checked {} recent queries)", 
                dns_server_ip, recent_queries.len());
            return Ok(());
        }

        info!("Found {} potential matches for DNS server {} response", recent_queries.len(), dns_server_ip);

        // Find the most recent query (closest timestamp)
        let best_match = recent_queries
            .iter()
            .min_by_key(|q| {
                
                now_ns.saturating_sub(q.timestamp_ns)
            });

        let Some(query) = best_match else {
            return Ok(());
        };

        let process_name = String::from_utf8_lossy(&query.comm)
            .trim_end_matches('\0')
            .to_string();

        // Extract domain from DNS question section
        let domain = dns_msg
            .queries
            .first()
            .map(|q| q.name.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());

        // Process all answers
        let mut ip_count = 0;
        for answer in dns_msg.answers.iter() {
            match &answer.data {
                RData::A(addr) => {
                    let ip = IpAddr::V4(**addr);
                    let ttl = answer.ttl;

                    // Store in DNS cache
                    let mut cache = self.dns_cache.lock();
                    cache.insert_ip_mapping(
                        ip.to_string(),
                        query.pid,
                        process_name.clone(),
                        domain.clone(),
                        ttl,
                    );

                    ip_count += 1;
                    info!(
                        "DNS cache: {} -> {} (PID {}, domain: {}, TTL: {}s)",
                        ip, process_name, query.pid, domain, ttl
                    );
                }
                RData::AAAA(addr) => {
                    let ip = IpAddr::V6(**addr);
                    let ttl = answer.ttl;

                    // Store in DNS cache
                    let mut cache = self.dns_cache.lock();
                    cache.insert_ip_mapping(
                        ip.to_string(),
                        query.pid,
                        process_name.clone(),
                        domain.clone(),
                        ttl,
                    );

                    ip_count += 1;
                    info!(
                        "DNS cache: {} -> {} (PID {}, domain: {}, TTL: {}s)",
                        ip, process_name, query.pid, domain, ttl
                    );
                }
                RData::CNAME(cname) => {
                    debug!("CNAME record: {} → {}", answer.name, cname);
                }
                _ => {}
            }
        }

        if ip_count > 0 {
            debug!(
                "Correlated {} IPs for domain {} to PID {} ({})",
                ip_count, domain, query.pid, process_name
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_standard_response;
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::RData;
    use std::net::Ipv4Addr;

    /// A hand-built DNS response for `www.example.com A`, answering 93.184.216.34.
    /// Reads it the same way `process_packet`/`correlate_and_cache` do, so a change
    /// in the hickory-proto API or decoding shows up here.
    fn response() -> Vec<u8> {
        let mut m = vec![
            0x12, 0x34, // id
            0x81, 0x80, // response, RD, RA
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 1 question, 1 answer
        ];
        for label in ["www", "example", "com"] {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // end of name, type A, class IN
        m.extend_from_slice(&[0xc0, 0x0c]); // answer name: pointer to the question name
        m.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04]); // A IN ttl 60 len 4
        m.extend_from_slice(&[93, 184, 216, 34]);
        m
    }

    #[test]
    fn parses_a_response_with_the_fields_the_snooper_reads() {
        let msg = Message::from_vec(&response()).expect("valid response");
        assert_eq!(msg.metadata.id, 0x1234);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.queries.first().unwrap().name.to_string(), "www.example.com.");
        assert_eq!(msg.answers.len(), 1);
        let answer = &msg.answers[0];
        assert_eq!(answer.ttl, 60);
        assert_eq!(answer.name.to_string(), "www.example.com.");
        match &answer.data {
            RData::A(a) => assert_eq!(**a, Ipv4Addr::new(93, 184, 216, 34)),
            other => panic!("expected an A record, got {:?}", other),
        }
    }

    #[test]
    fn only_standard_query_responses_are_processed() {
        let mut bytes = response();
        assert!(is_standard_response(&Message::from_vec(&bytes).unwrap()));

        // Same packet but with the QR bit cleared: a query, not a response.
        bytes[2] &= 0x7f;
        let query = Message::from_vec(&bytes).unwrap();
        assert_eq!(query.metadata.message_type, MessageType::Query);
        assert!(!is_standard_response(&query));

        // A response whose opcode is NOTIFY (4) or UPDATE (5), not QUERY.
        for opcode in [4u8, 5u8] {
            let mut bytes = response();
            bytes[2] = 0x80 | (opcode << 3);
            let msg = Message::from_vec(&bytes).unwrap();
            assert_eq!(msg.metadata.message_type, MessageType::Response);
            assert_ne!(msg.metadata.op_code, OpCode::Query);
            assert!(!is_standard_response(&msg), "opcode {opcode}");
        }
    }

    #[test]
    fn rejects_garbage_and_truncated_messages() {
        assert!(Message::from_vec(&[]).is_err());
        assert!(Message::from_vec(&[0xff; 7]).is_err());
        let full = response();
        assert!(Message::from_vec(&full[..full.len() - 3]).is_err());
    }
}
