use packet_engine::NetworkEvent;
use threat_engine::alerts::Alert;

pub trait SecurityPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str {
        "0.1.0"
    }
    fn description(&self) -> &str {
        ""
    }
    fn analyze(&self, event: &NetworkEvent) -> Option<Alert>;
    fn on_startup(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn on_shutdown(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
}