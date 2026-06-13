use crate::rules::RuleEngine;
use crate::alerts::Alert;
use packet_engine::NetworkEvent;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{info, warn};
use std::collections::HashMap;
use std::net::IpAddr;

pub struct ThreatDetector {
    rule_engine: Arc<RwLock<RuleEngine>>,
    alert_tx: mpsc::UnboundedSender<Alert>,
    state: Arc<RwLock<DetectorState>>,
}

struct DetectorState {
    port_scan_tracker: Vec<PortScanAttempt>,
    data_transfer_tracker: Vec<DataTransferRecord>,
    connections_seen: u64,
    known_processes: HashMap<String, ProcessBaseline>,
}

struct PortScanAttempt {
    source_ip: IpAddr,
    target_ports: Vec<u16>,
    first_seen: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
    alert_sent: bool,
}

struct DataTransferRecord {
    process_name: String,
    bytes_sent: u64,
    bytes_received: u64,
    packet_count: u64,
    _window_start: chrono::DateTime<chrono::Utc>,
}

struct ProcessBaseline {
    avg_bytes_per_session: f64,
    _avg_connections_per_min: f64,
    samples: u32,
}

impl ThreatDetector {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Alert>) {
        let (alert_tx, alert_rx) = mpsc::unbounded_channel();
        let rule_engine = RuleEngine::new();

        let detector = Self {
            rule_engine: Arc::new(RwLock::new(rule_engine)),
            alert_tx,
            state: Arc::new(RwLock::new(DetectorState {
                port_scan_tracker: Vec::new(),
                data_transfer_tracker: Vec::new(),
                connections_seen: 0,
                known_processes: HashMap::new(),
            })),
        };

        (detector, alert_rx)
    }

    pub fn analyze(&self, event: &NetworkEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        let port_scan_alert = {
            let mut state = self.state.write();
            state.connections_seen += 1;
            self.check_port_scan(&mut state, event)
        };
        if let Some(alert) = port_scan_alert {
            alerts.push(alert);
        }

        let data_leak_alert = {
            let mut state = self.state.write();
            self.check_data_leak(&mut state, event)
        };
        if let Some(alert) = data_leak_alert {
            alerts.push(alert);
        }

        let guard = self.rule_engine.read();
        let rules = guard.get_rules();
        for rule in rules {
            if let Some(rule_match) = rule.evaluate(event) {
                let alert = Alert {
                    id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    severity: rule_match.severity,
                    title: rule.name().to_string(),
                    description: rule_match.description,
                    source_ip: Some(event.source_ip),
                    destination_ip: Some(event.destination_ip),
                    port: Some(event.destination_port),
                    protocol: Some(event.protocol.to_string()),
                    process_name: event.process_name.clone(),
                    raw_event: serde_json::to_string(event).ok(),
                    acknowledged: false,
                };
                info!(alert = ?alert.title, "Threat detected");
                if self.alert_tx.send(alert.clone()).is_err() {
                    warn!("Alert channel closed");
                }
                alerts.push(alert);
            }
        }

        alerts
    }

    fn check_port_scan(&self, state: &mut DetectorState, event: &NetworkEvent) -> Option<Alert> {
        let existing = state.port_scan_tracker.iter_mut().find(|p| p.source_ip == event.source_ip);

        match existing {
            Some(scan) => {
                if !scan.target_ports.contains(&event.destination_port) {
                    scan.target_ports.push(event.destination_port);
                }
                scan.last_seen = event.timestamp;

                let window_secs = (scan.last_seen - scan.first_seen).num_seconds();
                if scan.target_ports.len() >= 100 && window_secs <= 60 && !scan.alert_sent {
                    scan.alert_sent = true;
                    return Some(Alert {
                        id: uuid::Uuid::new_v4(),
                        timestamp: chrono::Utc::now(),
                        severity: crate::alerts::AlertSeverity::Critical,
                        title: "Port Scan Detected".to_string(),
                        description: format!("IP {} scanned {} ports in {} seconds — possible port scan",
                            event.source_ip, scan.target_ports.len(), window_secs),
                        source_ip: Some(event.source_ip),
                        destination_ip: None,
                        port: None,
                        protocol: Some(event.protocol.to_string()),
                        process_name: None,
                        raw_event: None,
                        acknowledged: false,
                    });
                }
            }
            None => {
                state.port_scan_tracker.push(PortScanAttempt {
                    source_ip: event.source_ip,
                    target_ports: vec![event.destination_port],
                    first_seen: event.timestamp,
                    last_seen: event.timestamp,
                    alert_sent: false,
                });
            }
        }

        state.port_scan_tracker.retain(|p| {
            (chrono::Utc::now() - p.first_seen).num_seconds() < 60
        });

        None
    }

    fn check_data_leak(&self, state: &mut DetectorState, event: &NetworkEvent) -> Option<Alert> {
        let process = event.process_name.as_deref()?;

        let record = if let Some(existing) = state.data_transfer_tracker.iter_mut().find(|d| d.process_name == process) {
            existing.bytes_sent += event.packet_size as u64;
            existing.bytes_received += event.packet_size as u64;
            existing.packet_count += 1;
            existing
        } else {
            state.data_transfer_tracker.push(DataTransferRecord {
                process_name: process.to_string(),
                bytes_sent: event.packet_size as u64,
                bytes_received: event.packet_size as u64,
                packet_count: 1,
                _window_start: chrono::Utc::now(),
            });
            return None;
        };

        let baseline = state.known_processes.entry(process.to_string()).or_insert(ProcessBaseline {
            avg_bytes_per_session: 0.0,
            _avg_connections_per_min: 0.0,
            samples: 0,
        });

        let total_bytes = record.bytes_sent + record.bytes_received;
        if baseline.samples >= 5 {
            let deviation = total_bytes as f64 / baseline.avg_bytes_per_session.max(1.0);
            if deviation > 10.0 {
                return Some(Alert {
                    id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    severity: crate::alerts::AlertSeverity::High,
                    title: "Possible Data Leak".to_string(),
                    description: format!("{} uploaded/downloaded {} bytes — {}x above normal baseline of {:.0} bytes",
                        process, total_bytes, deviation as u64, baseline.avg_bytes_per_session),
                    source_ip: Some(event.source_ip),
                    destination_ip: Some(event.destination_ip),
                    port: Some(event.destination_port),
                    protocol: Some(event.protocol.to_string()),
                    process_name: Some(process.to_string()),
                    raw_event: None,
                    acknowledged: false,
                });
            }
        }

        baseline.samples += 1;
        let n = baseline.samples as f64;
        baseline.avg_bytes_per_session = baseline.avg_bytes_per_session + (total_bytes as f64 - baseline.avg_bytes_per_session) / n;

        None
    }

    pub fn get_port_scan_candidates(&self) -> Vec<(IpAddr, usize)> {
        let state = self.state.read();
        state.port_scan_tracker.iter()
            .filter(|p| p.target_ports.len() >= 10)
            .map(|p| (p.source_ip, p.target_ports.len()))
            .collect()
    }

    pub fn connections_seen(&self) -> u64 {
        self.state.read().connections_seen
    }
}