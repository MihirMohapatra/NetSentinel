use parking_lot::RwLock;
use std::sync::Arc;
use threat_engine::alerts::Alert;
use threat_engine::ThreatDetector;

pub struct AppState {
    pub detector: Arc<RwLock<Option<ThreatDetector>>>,
    pub alerts: Arc<RwLock<Vec<Alert>>>,
    pub is_capturing: Arc<RwLock<bool>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            detector: Arc::new(RwLock::new(None)),
            alerts: Arc::new(RwLock::new(Vec::new())),
            is_capturing: Arc::new(RwLock::new(false)),
        }
    }
}