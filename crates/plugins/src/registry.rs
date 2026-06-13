use crate::traits::SecurityPlugin;
use packet_engine::NetworkEvent;
use threat_engine::alerts::Alert;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn};

pub struct PluginRegistry {
    plugins: Arc<RwLock<Vec<Box<dyn SecurityPlugin>>>>,
    alert_tx: tokio::sync::mpsc::UnboundedSender<Alert>,
}

impl PluginRegistry {
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<Alert>) {
        let (alert_tx, alert_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                plugins: Arc::new(RwLock::new(Vec::new())),
                alert_tx,
            },
            alert_rx,
        )
    }

    pub fn register(&self, plugin: Box<dyn SecurityPlugin>) {
        let name = plugin.name().to_string();
        if let Err(e) = plugin.on_startup() {
            warn!("Plugin '{}' startup failed: {}", name, e);
        }
        info!("Registered plugin: {} v{}", name, plugin.version());
        self.plugins.write().push(plugin);
    }

    pub fn unregister(&self, name: &str) {
        let mut plugins = self.plugins.write();
        if let Some(pos) = plugins.iter().position(|p| p.name() == name) {
            let plugin = plugins.remove(pos);
            if let Err(e) = plugin.on_shutdown() {
                warn!("Plugin '{}' shutdown failed: {}", name, e);
            }
            info!("Unregistered plugin: {}", name);
        }
    }

    pub fn analyze(&self, event: &NetworkEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let plugins = self.plugins.read();
        for plugin in plugins.iter() {
            match plugin.analyze(event) {
                Some(alert) => {
                    info!("Plugin '{}' generated alert: {}", plugin.name(), alert.title);
                    if self.alert_tx.send(alert.clone()).is_err() {
                        warn!("Plugin alert channel closed");
                    }
                    alerts.push(alert);
                }
                None => {}
            }
        }
        alerts
    }

    pub fn list_plugins(&self) -> Vec<(String, String)> {
        self.plugins.read().iter()
            .map(|p| (p.name().to_string(), p.version().to_string()))
            .collect()
    }
}