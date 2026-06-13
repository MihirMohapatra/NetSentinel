use pcap::{Capture, Device, Active};
use crate::parser::PacketParser;
use crate::models::NetworkEvent;
use tokio::sync::mpsc;
use anyhow::Result;
use parking_lot::Mutex;
use std::sync::Arc;
use tracing::{info, error, warn};

pub struct PacketCapture {
    capture: Arc<Mutex<Capture<Active>>>,
    parser: PacketParser,
}

impl PacketCapture {
    pub fn new(interface: &str) -> Result<Self> {
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == interface || d.desc.as_ref().map_or(false, |desc| desc == interface))
            .ok_or_else(|| anyhow::anyhow!("Interface not found: {}", interface))?;

        let cap = Capture::from_device(device)?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        info!("Started capture on interface: {}", interface);

        Ok(Self {
            capture: Arc::new(Mutex::new(cap)),
            parser: PacketParser::new(),
        })
    }

    pub async fn start(&mut self, event_tx: mpsc::UnboundedSender<NetworkEvent>) -> Result<()> {
        let capture = self.capture.clone();
        let parser = self.parser.clone();

        tokio::task::spawn_blocking(move || {
            let mut cap = capture.lock();
            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(event) = parser.parse(packet.data) {
                            if event_tx.send(event).is_err() {
                                warn!("Event channel closed, stopping capture");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Packet capture error: {}", e);
                        break;
                    }
                }
            }
        }).await?;

        Ok(())
    }

    pub fn list_interfaces() -> Result<Vec<String>> {
        let devices = Device::list()?;
        Ok(devices.into_iter()
            .map(|d| d.name)
            .collect())
    }
}