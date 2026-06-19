use chrono::{DateTime, Utc};
use packet_engine::NetworkEvent;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use threat_engine::ThreatDetector;
use threat_engine::alerts::Alert;
use tokio::task::JoinHandle;

pub struct CaptureRuntime {
    pub stop_requested: Arc<AtomicBool>,
    pub task: JoinHandle<()>,
    pub started_at: DateTime<Utc>,
}

pub struct AppState {
    pub detector: Arc<RwLock<Option<Arc<ThreatDetector>>>>,
    pub alerts: Arc<RwLock<VecDeque<Alert>>>,
    pub connections: Arc<RwLock<VecDeque<NetworkEvent>>>,
    pub capture_runtime: Arc<RwLock<Option<CaptureRuntime>>>,
    pub selected_interface: Arc<RwLock<Option<String>>>,
    pub last_message: Arc<RwLock<Option<String>>>,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            detector: self.detector.clone(),
            alerts: self.alerts.clone(),
            connections: self.connections.clone(),
            capture_runtime: self.capture_runtime.clone(),
            selected_interface: self.selected_interface.clone(),
            last_message: self.last_message.clone(),
        }
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            detector: Arc::new(RwLock::new(None)),
            alerts: Arc::new(RwLock::new(VecDeque::new())),
            connections: Arc::new(RwLock::new(VecDeque::new())),
            capture_runtime: Arc::new(RwLock::new(None)),
            selected_interface: Arc::new(RwLock::new(None)),
            last_message: Arc::new(RwLock::new(None)),
        }
    }

    pub fn push_connection(&self, event: NetworkEvent) {
        let mut connections = self.connections.write();
        if connections.len() >= 500 {
            connections.pop_front();
        }
        connections.push_back(event);
    }

    pub fn push_alert(&self, alert: Alert) {
        let mut alerts = self.alerts.write();
        if alerts.len() >= 200 {
            alerts.pop_front();
        }
        alerts.push_back(alert);
    }

    pub fn clear_runtime_data(&self) {
        self.connections.write().clear();
        self.alerts.write().clear();
    }

    pub fn set_message(&self, message: impl Into<String>) {
        *self.last_message.write() = Some(message.into());
    }
}
