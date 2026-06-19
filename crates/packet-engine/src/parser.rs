use etherparse::{PacketHeaders, NetHeaders, TransportHeader};
use crate::tcp::TcpParser;
use crate::udp::UdpParser;
use crate::dns::DnsParser;
use crate::models::{NetworkEvent, Protocol};
use std::net::IpAddr;
use chrono::Utc;
use uuid::Uuid;

pub struct PacketParser {
    tcp_parser: TcpParser,
    udp_parser: UdpParser,
    dns_parser: DnsParser,
}

impl PacketParser {
    pub fn new() -> Self {
        Self {
            tcp_parser: TcpParser,
            udp_parser: UdpParser,
            dns_parser: DnsParser,
        }
    }

    pub fn parse(&self, data: &[u8]) -> Option<NetworkEvent> {
        let headers = match PacketHeaders::from_ethernet_slice(data) {
            Ok(h) => h,
            Err(_) => return None,
        };

        let (src_ip, dst_ip, protocol) = match headers.net {
            Some(NetHeaders::Ipv4(ipv4, _)) => (
                IpAddr::from(ipv4.source),
                IpAddr::from(ipv4.destination),
                Protocol::from(u8::from(ipv4.protocol)),
            ),
            Some(NetHeaders::Ipv6(ipv6, _)) => (
                IpAddr::from(ipv6.source),
                IpAddr::from(ipv6.destination),
                Protocol::from(u8::from(ipv6.next_header)),
            ),
            Some(NetHeaders::Arp(_)) => return None,
            None => return None,
        };

        let (src_port, dst_port) = match headers.transport {
            Some(TransportHeader::Tcp(tcp)) => {
                (tcp.source_port, tcp.destination_port)
            }
            Some(TransportHeader::Udp(udp)) => {
                (udp.source_port, udp.destination_port)
            }
            Some(TransportHeader::Icmpv4(_)) | Some(TransportHeader::Icmpv6(_)) => {
                (0, 0)
            }
            None => return None,
        };

        let payload = headers.payload.slice();

        let mut event = NetworkEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source_ip: src_ip,
            destination_ip: dst_ip,
            source_port: src_port,
            destination_port: dst_port,
            protocol,
            packet_size: data.len(),
            process_id: None,
            process_name: None,
            dns_query_domain: None,
            dns_response_ips: Vec::new(),
            dns_response_code: None,
        };

        match protocol {
            Protocol::TCP => self.tcp_parser.enrich(&mut event, payload),
            Protocol::UDP => {
                self.udp_parser.enrich(&mut event, payload);
                if src_port == 53 || dst_port == 53 {
                    if let Some(dns) = DnsParser::parse(payload) {
                        if !dns.query_domain.is_empty() {
                            event.dns_query_domain = Some(dns.query_domain);
                        }
                        event.dns_response_ips = dns.response_ips;
                        event.dns_response_code = Some(dns.response_code);
                    }
                }
            }
            _ => {}
        }

        Some(event)
    }
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for PacketParser {
    fn clone(&self) -> Self {
        Self {
            tcp_parser: self.tcp_parser,
            udp_parser: self.udp_parser,
            dns_parser: self.dns_parser,
        }
    }
}
