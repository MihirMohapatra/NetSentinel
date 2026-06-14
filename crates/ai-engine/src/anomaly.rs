use crate::model::{AnomalyModel, IsolationForestModel, BaselineModel, AnomalyScore, FlowFeatures};
use packet_engine::NetworkEvent;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use chrono::{DateTime, Utc};

pub struct AnomalyDetector {
    models: Vec<Box<dyn AnomalyModel>>,
    baseline: Arc<RwLock<BaselineModel>>,
    event_history: Arc<RwLock<EventHistory>>,
}

struct EventHistory {
    events: Vec<(DateTime<Utc>, NetworkEvent)>,
    per_process: HashMap<String, Vec<(DateTime<Utc>, usize)>>,
    max_events: usize,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        let models: Vec<Box<dyn AnomalyModel>> = vec![Box::new(IsolationForestModel::new(0.6))];

        Self {
            models,
            baseline: Arc::new(RwLock::new(BaselineModel::new())),
            event_history: Arc::new(RwLock::new(EventHistory {
                events: Vec::new(),
                per_process: HashMap::new(),
                max_events: 10000,
            })),
        }
    }

    pub fn analyze(&self, event: &NetworkEvent) -> Option<AnomalyScore> {
        let now = Utc::now();

        {
            let mut history = self.event_history.write();
            while history.events.len() >= history.max_events {
                history.events.remove(0);
            }
            history.events.push((now, event.clone()));

            if let Some(ref process) = event.process_name {
                let proc_events = history.per_process.entry(process.clone()).or_default();
                while proc_events.len() >= 1000 {
                    proc_events.remove(0);
                }
                proc_events.push((now, event.packet_size));
            }
        }

        let features = self.extract_features(event);
        let mut overall_score = AnomalyScore {
            score: 0.0,
            is_anomaly: false,
            contributors: Vec::new(),
        };

        for model in &self.models {
            let result = model.predict(&self.features_to_vec(&features));
            if result.is_anomaly {
                overall_score.is_anomaly = true;
                overall_score.contributors.push(model.name().to_string());
            }
            overall_score.score = overall_score.score.max(result.score);
        }

        if let Some(ref process) = event.process_name {
            let bytes_per_sec = {
                let history = self.event_history.read();
                Self::rate_for_process(&history, process, now)
            };
            let connections_per_min = {
                let history = self.event_history.read();
                Self::connection_rate_for_process(&history, process, now)
            };

            let mut bl = self.baseline.write();
            bl.record_observation(process, bytes_per_sec, connections_per_min);

            if let Some(baseline_score) = bl.anomaly_score(process, bytes_per_sec, connections_per_min)
                && baseline_score > 2.0
            {
                overall_score.is_anomaly = true;
                overall_score.score = overall_score.score.max(baseline_score);
                overall_score.contributors.push("baseline_deviation".to_string());
            }
        }

        if overall_score.is_anomaly {
            Some(overall_score)
        } else {
            None
        }
    }

    fn extract_features(&self, _event: &NetworkEvent) -> FlowFeatures {
        FlowFeatures {
            bytes_per_second: 0.0,
            packets_per_second: 0.0,
            avg_packet_size: 0.0,
            port_entropy: 0.0,
            unique_destinations: 0,
            connection_duration_secs: 0.0,
        }
    }

    fn features_to_vec(&self, features: &FlowFeatures) -> Vec<f64> {
        vec![
            features.bytes_per_second,
            features.packets_per_second,
            features.avg_packet_size,
            features.port_entropy,
            features.unique_destinations as f64,
            features.connection_duration_secs,
        ]
    }

    fn rate_for_process(history: &EventHistory, process: &str, now: DateTime<Utc>) -> f64 {
        if let Some(events) = history.per_process.get(process) {
            let recent: Vec<_> = events.iter()
                .filter(|(t, _)| (now - *t).num_seconds() < 60)
                .collect();
            let total_bytes: usize = recent.iter().map(|(_, s)| s).sum();
            total_bytes as f64 / 60.0
        } else {
            0.0
        }
    }

    fn connection_rate_for_process(history: &EventHistory, process: &str, now: DateTime<Utc>) -> f64 {
        if let Some(events) = history.per_process.get(process) {
            let count = events.iter()
                .filter(|(t, _)| (now - *t).num_seconds() < 60)
                .count();
            count as f64
        } else {
            0.0
        }
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}
