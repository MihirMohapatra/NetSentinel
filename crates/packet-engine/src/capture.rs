use crate::models::NetworkEvent;
use crate::parser::PacketParser;
use anyhow::Result;
use parking_lot::Mutex;
use pcap::{Active, Capture, Device};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub struct PacketCapture {
    capture: Arc<Mutex<Capture<Active>>>,
    parser: PacketParser,
    stop_requested: Arc<AtomicBool>,
}

impl PacketCapture {
    pub fn new(interface: &str) -> Result<Self> {
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == interface || d.desc.as_ref().is_some_and(|desc| desc == interface))
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
            stop_requested: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn start(&mut self, event_tx: mpsc::UnboundedSender<NetworkEvent>) -> Result<()> {
        let capture = self.capture.clone();
        let parser = self.parser.clone();
        let stop_requested = self.stop_requested.clone();

        tokio::task::spawn_blocking(move || {
            let mut cap = capture.lock();
            loop {
                if stop_requested.load(Ordering::Relaxed) {
                    info!("Stop requested for packet capture");
                    break;
                }

                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(event) = parser.parse(packet.data)
                            && event_tx.send(event).is_err()
                        {
                            warn!("Event channel closed, stopping capture");
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => continue,
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
        Ok(devices.into_iter().map(|d| d.name).collect())
    }

    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.stop_requested.clone()
    }
}
