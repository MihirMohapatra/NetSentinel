use crate::models::NetworkEvent;
use crate::dns::DnsParser;

#[derive(Clone, Copy)]
pub struct UdpParser;

impl UdpParser {
    pub fn enrich(&self, event: &mut NetworkEvent, payload: &[u8]) {
        if event.destination_port == 53 || event.source_port == 53 {
            let _ = DnsParser::parse(payload);
        }

        if Self::is_streaming_port(event.destination_port) || Self::is_streaming_port(event.source_port) {
        }
    }

    fn is_streaming_port(port: u16) -> bool {
        matches!(port, 1935 | 5004 | 5005 | 8000 | 8080 | 8888)
    }

    pub fn classify_udp_traffic(&self, src_port: u16, dst_port: u16) -> UdpTrafficType {
        match (src_port, dst_port) {
            (53, _) | (_, 53) => UdpTrafficType::Dns,
            (67, 68) | (68, 67) => UdpTrafficType::Dhcp,
            (123, 123) => UdpTrafficType::Ntp,
            (161, 162) | (162, 161) => UdpTrafficType::Snmp,
            (500, 4500) | (4500, 500) => UdpTrafficType::Ipsec,
            (1900, _) => UdpTrafficType::Ssdp,
            _ if Self::is_streaming_port(src_port) || Self::is_streaming_port(dst_port) => UdpTrafficType::Streaming,
            _ => UdpTrafficType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpTrafficType {
    Dns,
    Dhcp,
    Ntp,
    Snmp,
    Ipsec,
    Ssdp,
    Streaming,
    Unknown,
}