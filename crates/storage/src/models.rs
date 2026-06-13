use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub id: String,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub created_at: String,
    pub closed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub process_name: Option<String>,
    pub created_at: String,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub domain: String,
    pub query_type: u16,
    pub response_ips: Vec<String>,
    pub response_code: u16,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBaseline {
    pub id: String,
    pub process_name: String,
    pub avg_bytes_per_hour: f64,
    pub std_dev_bytes: f64,
    pub avg_connections_per_hour: f64,
    pub last_updated: String,
}