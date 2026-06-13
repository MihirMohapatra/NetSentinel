pub mod capture;
pub mod parser;
pub mod tcp;
pub mod udp;
pub mod dns;
pub mod models;

use capture::PacketCapture;
use tokio::sync::mpsc;
use anyhow::Result;

pub struct PacketEngine {
    capture: PacketCapture,
    event_tx: mpsc::UnboundedSender<models::NetworkEvent>,
}

impl PacketEngine {
    pub fn new(interface: &str) -> Result<(Self, mpsc::UnboundedReceiver<models::NetworkEvent>)> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let capture = PacketCapture::new(interface)?;
        
        Ok((
            Self { capture, event_tx },
            event_rx,
        ))
    }

    pub async fn run(&mut self) -> Result<()> {
        self.capture.start(self.event_tx.clone()).await
    }
}

pub use models::*;