use crate::rules::RuleEngine;
use crate::alerts::Alert;
use packet_engine::NetworkEvent;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct ThreatDetector {
    rule_engine: Arc<RwLock<RuleEngine>>,
    alert_tx: mpsc::UnboundedSender<Alert>,
    state: Arc<RwLock<DetectorState>>,
}

struct DetectorState {
    port_scan_tracker: Vec<PortScanAttempt>,
    data_transfer_tracker: Vec<DataTransferRecord>,
    connections_seen: u64,
}

struct PortScanAttempt {
    source_ip: std::net::IpAddr,
    target_ports: Vec<u16>,
    first_seen: chrono::DateTime<chrono::Utc>,
    last_seen: chrono::DateTime<chrono::Utc>,
}

struct DataTransferRecord {
    process_name: String,
    bytes_sent: u64,
    bytes_received: u64,
    _window_start: chrono::DateTime<chrono::Utc>,
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
            })),
        };

        (detector, alert_rx)
    }

    pub fn analyze(&self, event: &NetworkEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();

        {
            let mut state = self.state.write();
            state.connections_seen += 1;
            self.track_port_scan(&mut state, event);
            self.track_data_transfer(&mut state, event);
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

    fn track_port_scan(&self, state: &mut DetectorState, event: &NetworkEvent) {
        let existing = state.port_scan_tracker.iter_mut().find(|p: &&mut PortScanAttempt| {
            p.source_ip == event.source_ip
        });

        match existing {
            Some(scan) => {
                if !scan.target_ports.contains(&event.destination_port) {
                    scan.target_ports.push(event.destination_port);
                }
                scan.last_seen = event.timestamp;
            }
            None => {
                state.port_scan_tracker.push(PortScanAttempt {
                    source_ip: event.source_ip,
                    target_ports: vec![event.destination_port],
                    first_seen: event.timestamp,
                    last_seen: event.timestamp,
                });
            }
        }

        state.port_scan_tracker.retain(|p| {
            (chrono::Utc::now() - p.first_seen).num_seconds() < 60
        });
    }

    fn track_data_transfer(&self, state: &mut DetectorState, event: &NetworkEvent) {
        if let Some(ref process) = event.process_name {
            let existing = state.data_transfer_tracker.iter_mut().find(|d| d.process_name == *process);
            match existing {
                Some(record) => {
                    record.bytes_sent += event.packet_size as u64;
                    record.bytes_received += event.packet_size as u64;
                }
                None => {
                    state.data_transfer_tracker.push(DataTransferRecord {
                        process_name: process.clone(),
                        bytes_sent: event.packet_size as u64,
                        bytes_received: event.packet_size as u64,
                        _window_start: chrono::Utc::now(),
                    });
                }
            }
        }
    }

    pub fn get_port_scan_candidates(&self) -> Vec<(std::net::IpAddr, usize)> {
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