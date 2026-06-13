use packet_engine::NetworkEvent;
use anyhow::Result;
use std::sync::Arc;

pub type EventHandlerFn = Arc<dyn Fn(NetworkEvent) -> Result<()> + Send + Sync>;

pub struct EventHandler {
    pub name: String,
    pub handler: EventHandlerFn,
}

impl EventHandler {
    pub fn new(name: &str, handler: EventHandlerFn) -> Self {
        Self {
            name: name.to_string(),
            handler,
        }
    }
}