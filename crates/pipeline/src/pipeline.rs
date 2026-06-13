use crate::worker::EventHandler;
use packet_engine::NetworkEvent;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use std::sync::Arc;

pub struct FanOutPipeline {
    event_tx: mpsc::Sender<NetworkEvent>,
    handlers: Vec<EventHandler>,
    worker_count: usize,
    channel_capacity: usize,
}

impl FanOutPipeline {
    pub fn new(channel_capacity: usize, worker_count: usize) -> (Self, mpsc::Receiver<NetworkEvent>) {
        let (event_tx, event_rx) = mpsc::channel(channel_capacity);
        (
            Self {
                event_tx,
                handlers: Vec::new(),
                worker_count,
                channel_capacity,
            },
            event_rx,
        )
    }

    pub fn sender(&self) -> mpsc::Sender<NetworkEvent> {
        self.event_tx.clone()
    }

    pub fn add_handler(&mut self, handler: EventHandler) {
        self.handlers.push(handler);
    }

    pub async fn run(self, mut event_rx: mpsc::Receiver<NetworkEvent>) {
        let handlers = Arc::new(self.handlers);
        let mut worker_txs = Vec::new();
        let mut worker_handles = Vec::new();

        for worker_id in 0..self.worker_count {
            let (worker_tx, mut worker_rx) = mpsc::channel::<NetworkEvent>(self.channel_capacity);
            let handlers = handlers.clone();

            let handle = tokio::spawn(async move {
                info!("Pipeline worker {} started ({} handlers)", worker_id, handlers.len());
                while let Some(event) = worker_rx.recv().await {
                    for handler in handlers.iter() {
                        if let Err(e) = (handler.handler)(event.clone()) {
                            error!("Handler '{}' (worker {}) failed: {}", handler.name, worker_id, e);
                        }
                    }
                }
                info!("Pipeline worker {} stopped", worker_id);
            });

            worker_txs.push(worker_tx);
            worker_handles.push(handle);
        }

        let worker_txs = Arc::new(worker_txs);
        let mut round_robin = 0usize;

        while let Some(event) = event_rx.recv().await {
            if let Some(tx) = worker_txs.get(round_robin) {
                if tx.send(event).await.is_err() {
                    warn!("Pipeline worker {} channel closed", round_robin);
                }
            } else {
                warn!("No worker available, dropping event");
            }
            round_robin = (round_robin + 1) % self.worker_count;
        }

        drop(worker_txs);
        for handle in worker_handles {
            let _ = handle.await;
        }
        info!("Pipeline shut down");
    }
}