use anyhow::{anyhow, Context, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use log::{debug, error, info};
use pcap::{Active, Capture, Device};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::ebpf_loader::EbpfManager;
use crate::process::DnsCache;

/// DNS Snooper - captures and parses DNS responses to correlate IPs with processes
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

        // Only process responses (check if message type is Response)
        if dns_msg.message_type() == hickory_proto::op::MessageType::Query {
            return Ok(()); // Skip queries
        }

        // Extract DNS server IP from packet
        let dns_server_ip = self.extract_source_ip(data)?;

        info!(
            "DNS response: ID {} from {} ({} answers)",
            dns_msg.id(),
            dns_server_ip,
            dns_msg.answers().len()
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
                let age_ns = now_ns.saturating_sub(q.timestamp_ns);
                age_ns
            });

        let Some(query) = best_match else {
            return Ok(());
        };

        let process_name = String::from_utf8_lossy(&query.comm)
            .trim_end_matches('\0')
            .to_string();

        // Extract domain from DNS question section
        let domain = dns_msg
            .queries()
            .first()
            .map(|q| q.name().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());

        // Process all answers
        let mut ip_count = 0;
        for answer in dns_msg.answers() {
            match answer.data() {
                Some(RData::A(addr)) => {
                    let ip = IpAddr::V4(**addr);
                    let ttl = answer.ttl();

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
                Some(RData::AAAA(addr)) => {
                    let ip = IpAddr::V6(**addr);
                    let ttl = answer.ttl();

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
                Some(RData::CNAME(cname)) => {
                    debug!("CNAME record: {} → {}", answer.name(), cname);
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
