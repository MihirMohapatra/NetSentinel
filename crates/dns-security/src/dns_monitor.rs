use crate::reputation::{DomainReputation, DomainRisk};
use packet_engine::NetworkEvent;
use threat_engine::alerts::{Alert, AlertSeverity};
use std::sync::Arc;
use tracing::{info, warn};

pub struct DnsMonitor {
    reputation: Arc<DomainReputation>,
    alert_tx: tokio::sync::mpsc::UnboundedSender<Alert>,
}

impl DnsMonitor {
    pub fn new(reputation: Arc<DomainReputation>) -> (Self, tokio::sync::mpsc::UnboundedReceiver<Alert>) {
        let (alert_tx, alert_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                reputation,
                alert_tx,
            },
            alert_rx,
        )
    }

    pub fn analyze_dns_traffic(&self, event: &NetworkEvent) {
        let is_dns = event.destination_port == 53 || event.source_port == 53;
        if !is_dns {
            return;
        }

        if let Some(process) = &event.process_name
            && (process == "svchost.exe" || process == "systemd-resolve" || process == "dnscache" || process == "systemd")
        {
            return;
        }

        let alert = Alert {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            severity: AlertSeverity::Low,
            title: "DNS Traffic".to_string(),
            description: format!("DNS query from {}:{} to {}:{} (protocol: {})",
                event.source_ip, event.source_port,
                event.destination_ip, event.destination_port,
                event.protocol),
            source_ip: Some(event.source_ip),
            destination_ip: Some(event.destination_ip),
            port: Some(event.destination_port),
            protocol: Some("DNS".to_string()),
            process_name: event.process_name.clone(),
            raw_event: Some(serde_json::to_string(event).unwrap_or_default()),
            acknowledged: false,
        };

        if self.alert_tx.send(alert).is_err() {
            warn!("DNS monitor alert channel closed");
        }
    }

    pub fn check_domain(&self, domain: &str) -> DomainRisk {
        self.reputation.check(domain)
    }

    pub fn record_domain(&self, domain: &str) {
        self.reputation.record_query(domain);
        let risk = self.reputation.check(domain);
        match risk {
            DomainRisk::Malware => {
                let alert = Alert {
                    id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    severity: AlertSeverity::Critical,
                    title: "Malware Domain Detected".to_string(),
                    description: format!("DNS query to known malware domain: {}", domain),
                    source_ip: None,
                    destination_ip: None,
                    port: Some(53),
                    protocol: Some("DNS".to_string()),
                    process_name: None,
                    raw_event: None,
                    acknowledged: false,
                };
                info!("Malware domain detected: {}", domain);
                if self.alert_tx.send(alert).is_err() {
                    warn!("DNS monitor alert channel closed");
                }
            }
            DomainRisk::Suspicious(score, ref factors) => {
                let alert = Alert {
                    id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    severity: AlertSeverity::High,
                    title: "Suspicious Domain".to_string(),
                    description: format!("Suspicious DNS query: {} (risk score: {:.0}) — {}",
                        domain, score, factors.join("; ")),
                    source_ip: None,
                    destination_ip: None,
                    port: Some(53),
                    protocol: Some("DNS".to_string()),
                    process_name: None,
                    raw_event: None,
                    acknowledged: false,
                };
                if self.alert_tx.send(alert).is_err() {
                    warn!("DNS monitor alert channel closed");
                }
            }
            _ => {}
        }
    }

    pub fn reputation(&self) -> &Arc<DomainReputation> {
        &self.reputation
    }
}
