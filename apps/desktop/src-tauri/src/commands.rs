use crate::state::AppState;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub is_capturing: bool,
    pub connections_seen: u64,
    pub alert_count: usize,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertResponse {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub timestamp: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionResponse {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: String,
    pub process_name: Option<String>,
    pub packet_size: usize,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHistoryResponse {
    pub domain: String,
    pub risk_score: f64,
    pub risk_factors: Vec<String>,
    pub timestamp: String,
}

#[tauri::command]
pub fn get_status(state: State<AppState>) -> StatusResponse {
    let is_capturing = *state.is_capturing.read();
    let alert_count = state.alerts.read().len();
    StatusResponse {
        is_capturing,
        connections_seen: 0,
        alert_count,
        uptime_secs: 0,
    }
}

#[tauri::command]
pub fn get_alerts(state: State<AppState>) -> Vec<AlertResponse> {
    state.alerts.read().iter().map(|a| AlertResponse {
        id: a.id.to_string(),
        severity: a.severity.to_string(),
        title: a.title.clone(),
        description: a.description.clone(),
        timestamp: a.timestamp.to_rfc3339(),
        source_ip: a.source_ip.map(|ip| ip.to_string()),
        destination_ip: a.destination_ip.map(|ip| ip.to_string()),
        port: a.port,
        protocol: a.protocol.clone(),
        process_name: a.process_name.clone(),
    }).collect()
}

#[tauri::command]
pub fn get_connections() -> Vec<ConnectionResponse> {
    Vec::new()
}

#[tauri::command]
pub fn get_dns_history() -> Vec<DnsHistoryResponse> {
    Vec::new()
}

#[tauri::command]
pub fn get_port_scan_candidates(state: State<AppState>) -> Vec<String> {
    if let Some(ref detector) = *state.detector.read() {
        detector.get_port_scan_candidates()
            .into_iter()
            .map(|(ip, count)| format!("{}: {} ports", ip, count))
            .collect()
    } else {
        Vec::new()
    }
}

#[tauri::command]
pub async fn start_capture(state: State<'_, AppState>) -> Result<String, String> {
    let mut capturing = state.is_capturing.write();
    if *capturing {
        return Err("Already capturing".to_string());
    }
    *capturing = true;
    Ok("Capture started".to_string())
}

#[tauri::command]
pub async fn stop_capture(state: State<'_, AppState>) -> Result<String, String> {
    let mut capturing = state.is_capturing.write();
    if !*capturing {
        return Err("Not capturing".to_string());
    }
    *capturing = false;
    Ok("Capture stopped".to_string())
}