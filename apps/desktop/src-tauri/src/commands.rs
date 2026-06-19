use crate::state::AppState;
use chrono::Utc;
use packet_engine::capture::PacketCapture;
use serde::{Deserialize, Serialize};
use tauri::State;
use threat_engine::ThreatDetector;
use tracing::{error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub is_capturing: bool,
    pub connections_seen: u64,
    pub alert_count: usize,
    pub uptime_secs: u64,
    pub selected_interface: Option<String>,
    pub last_message: Option<String>,
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
    pub resolver: String,
    pub response_ips: Vec<String>,
    pub response_code: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceListResponse {
    pub interfaces: Vec<String>,
    pub selected: Option<String>,
}

#[tauri::command]
pub fn get_status(state: State<AppState>) -> StatusResponse {
    let runtime = state.capture_runtime.read();
    let is_capturing = runtime.is_some();
    let alert_count = state.alerts.read().len();
    let connections_seen = state.detector.read()
        .as_ref()
        .map(|detector| detector.connections_seen())
        .unwrap_or_else(|| state.connections.read().len() as u64);
    let uptime_secs = runtime.as_ref()
        .map(|runtime| (Utc::now() - runtime.started_at).num_seconds().max(0) as u64)
        .unwrap_or(0);

    StatusResponse {
        is_capturing,
        connections_seen,
        alert_count,
        uptime_secs,
        selected_interface: state.selected_interface.read().clone(),
        last_message: state.last_message.read().clone(),
    }
}

#[tauri::command]
pub fn list_interfaces(state: State<AppState>) -> Result<InterfaceListResponse, String> {
    let interfaces = PacketCapture::list_interfaces()
        .map_err(|e| format!("Failed to list interfaces: {e}"))?;

    Ok(InterfaceListResponse {
        interfaces,
        selected: state.selected_interface.read().clone(),
    })
}

#[tauri::command]
pub fn select_interface(state: State<AppState>, interface: String) -> Result<String, String> {
    let interfaces = PacketCapture::list_interfaces()
        .map_err(|e| format!("Failed to list interfaces: {e}"))?;

    if !interfaces.iter().any(|name| name == &interface) {
        return Err(format!("Interface not found: {interface}"));
    }

    *state.selected_interface.write() = Some(interface.clone());
    let message = format!("Selected interface: {interface}");
    state.set_message(message.clone());
    Ok(message)
}

#[tauri::command]
pub fn get_alerts(state: State<AppState>) -> Vec<AlertResponse> {
    state.alerts.read().iter().rev().map(|a| AlertResponse {
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
pub fn get_connections(state: State<AppState>) -> Vec<ConnectionResponse> {
    state.connections.read().iter().rev().map(|event| ConnectionResponse {
        source_ip: event.source_ip.to_string(),
        destination_ip: event.destination_ip.to_string(),
        source_port: event.source_port,
        destination_port: event.destination_port,
        protocol: event.protocol.to_string(),
        process_name: event.process_name.clone(),
        packet_size: event.packet_size,
        timestamp: event.timestamp.to_rfc3339(),
    }).collect()
}

#[tauri::command]
pub fn get_dns_history(state: State<AppState>) -> Vec<DnsHistoryResponse> {
    state.connections.read().iter().rev().filter_map(|event| {
        let domain = event.dns_query_domain.clone()?;
        if event.destination_port != 53 && event.source_port != 53 {
            return None;
        }

        Some(DnsHistoryResponse {
            domain,
            risk_score: 0.0,
            risk_factors: if event.dns_response_code == Some(0) {
                vec!["Observed live DNS query/response".to_string()]
            } else {
                vec!["Observed DNS packet with non-zero response code".to_string()]
            },
            timestamp: event.timestamp.to_rfc3339(),
            resolver: event.destination_ip.to_string(),
            response_ips: event.dns_response_ips.iter().map(|ip| ip.to_string()).collect(),
            response_code: event.dns_response_code,
        })
    }).collect()
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
    if state.capture_runtime.read().is_some() {
        return Err("Already capturing".to_string());
    }

    let interface = selected_or_default_interface(&state)?;
    let mut capture = PacketCapture::new(&interface)
        .map_err(|e| {
            let message = format!("Failed to start capture on {interface}: {e}");
            state.set_message(message.clone());
            message
        })?;
    let stop_requested = capture.stop_handle();
    let (detector, _alert_rx) = ThreatDetector::new();
    let detector = std::sync::Arc::new(detector);

    state.clear_runtime_data();
    *state.detector.write() = Some(detector.clone());
    *state.selected_interface.write() = Some(interface.clone());

    let app_state = state.inner().clone();
    let started_at = Utc::now();
    let task = tokio::spawn(async move {
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        let capture_task = tokio::spawn(async move {
            if let Err(err) = capture.start(event_tx).await {
                error!("Desktop packet capture stopped with error: {err}");
            }
        });

        while let Some(event) = event_rx.recv().await {
            app_state.push_connection(event.clone());
            for alert in detector.analyze(&event) {
                app_state.push_alert(alert);
            }
        }

        if let Err(err) = capture_task.await {
            warn!("Capture task join error: {err}");
        }
    });

    *state.capture_runtime.write() = Some(crate::state::CaptureRuntime {
        stop_requested,
        task,
        started_at,
    });

    let message = format!("Capture started on {interface}");
    state.set_message(message.clone());
    Ok(message)
}

#[tauri::command]
pub async fn stop_capture(state: State<'_, AppState>) -> Result<String, String> {
    let runtime = state.capture_runtime.write().take();
    let Some(runtime) = runtime else {
        return Err("Not capturing".to_string());
    };

    runtime.stop_requested.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Err(err) = runtime.task.await {
        warn!("Capture shutdown join error: {err}");
    }
    *state.detector.write() = None;

    let message = "Capture stopped".to_string();
    state.set_message(message.clone());
    Ok(message)
}

fn selected_or_default_interface(state: &State<'_, AppState>) -> Result<String, String> {
    if let Some(selected) = state.selected_interface.read().clone() {
        return Ok(selected);
    }
    select_default_interface()
}

fn select_default_interface() -> Result<String, String> {
    let interfaces = PacketCapture::list_interfaces()
        .map_err(|e| format!("Failed to list interfaces: {e}"))?;

    if interfaces.is_empty() {
        return Err("No network interfaces found. On Windows, make sure Npcap is installed.".to_string());
    }

    let preferred = interfaces.iter()
        .find(|name| {
            let lower = name.to_ascii_lowercase();
            !lower.contains("loopback") && !lower.contains("bluetooth")
        })
        .cloned();

    Ok(preferred.unwrap_or_else(|| interfaces[0].clone()))
}
