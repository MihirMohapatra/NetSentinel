use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Low => write!(f, "LOW"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl AlertSeverity {
    pub fn score(&self) -> u8 {
        match self {
            AlertSeverity::Low => 1,
            AlertSeverity::Medium => 3,
            AlertSeverity::High => 7,
            AlertSeverity::Critical => 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub process_name: Option<String>,
    pub raw_event: Option<String>,
    pub acknowledged: bool,
}

impl Alert {
    pub fn new(
        severity: AlertSeverity,
        title: &str,
        description: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            severity,
            title: title.to_string(),
            description: description.to_string(),
            source_ip: None,
            destination_ip: None,
            port: None,
            protocol: None,
            process_name: None,
            raw_event: None,
            acknowledged: false,
        }
    }

    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
    }
}

pub struct AlertManager {
    alerts: Vec<Alert>,
    max_alerts: usize,
}

impl AlertManager {
    pub fn new(max_alerts: usize) -> Self {
        Self {
            alerts: Vec::new(),
            max_alerts,
        }
    }

    pub fn push(&mut self, alert: Alert) {
        if self.alerts.len() >= self.max_alerts {
            self.alerts.remove(0);
        }
        self.alerts.push(alert);
    }

    pub fn get_alerts(&self) -> &[Alert] {
        &self.alerts
    }

    pub fn get_unacknowledged(&self) -> Vec<&Alert> {
        self.alerts.iter().filter(|a| !a.acknowledged).collect()
    }

    pub fn acknowledge(&mut self, id: &uuid::Uuid) -> bool {
        if let Some(alert) = self.alerts.iter_mut().find(|a| a.id == *id) {
            alert.acknowledge();
            true
        } else {
            false
        }
    }

    pub fn clear(&mut self) {
        self.alerts.clear();
    }
}