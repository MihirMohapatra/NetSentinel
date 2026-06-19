use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: Protocol,
    pub packet_size: usize,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub dns_query_domain: Option<String>,
    pub dns_response_ips: Vec<IpAddr>,
    pub dns_response_code: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            other => Protocol::Other(other),
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::Other(n) => write!(f, "OTHER({})", n),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub query_domain: String,
    pub query_type: u16,
    pub response_ips: Vec<IpAddr>,
    pub response_code: u16,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
}
