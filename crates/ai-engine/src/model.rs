use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    pub bytes_per_second: f64,
    pub packets_per_second: f64,
    pub avg_packet_size: f64,
    pub port_entropy: f64,
    pub unique_destinations: u32,
    pub connection_duration_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub score: f64,
    pub is_anomaly: bool,
    pub contributors: Vec<String>,
}

pub trait AnomalyModel: Send + Sync {
    fn predict(&self, features: &[f64]) -> AnomalyScore;
    fn train(&mut self, data: &[Vec<f64>]) -> anyhow::Result<()>;
    fn name(&self) -> &str;
}

pub struct IsolationForestModel {
    threshold: f64,
    trees: usize,
    sample_size: usize,
}

impl IsolationForestModel {
    pub fn new(threshold: f64) -> Self {
        Self {
            threshold,
            trees: 100,
            sample_size: 256,
        }
    }

    fn isolation_score(&self, point: &[f64]) -> f64 {
        let n = point.len() as f64;
        let path_length = n.ln() + 0.577;
        2.0_f64.powf(-path_length / self.trees as f64)
    }
}

impl AnomalyModel for IsolationForestModel {
    fn predict(&self, features: &[f64]) -> AnomalyScore {
        let score = self.isolation_score(features);
        AnomalyScore {
            score,
            is_anomaly: score > self.threshold,
            contributors: vec![],
        }
    }

    fn train(&mut self, data: &[Vec<f64>]) -> anyhow::Result<()> {
        self.sample_size = data.len().min(self.sample_size);
        Ok(())
    }

    fn name(&self) -> &str {
        "Isolation Forest"
    }
}

pub struct BaselineModel {
    baselines: HashMap<String, ProcessBaseline>,
}

#[derive(Debug, Clone)]
pub struct ProcessBaseline {
    pub mean_bytes_per_sec: f64,
    pub std_bytes_per_sec: f64,
    pub mean_connections_per_min: f64,
    pub std_connections_per_min: f64,
    pub samples: usize,
}

impl BaselineModel {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
        }
    }

    pub fn record_observation(&mut self, process: &str, bytes_per_sec: f64, connections_per_min: f64) {
        let entry = self.baselines.entry(process.to_string()).or_insert(ProcessBaseline {
            mean_bytes_per_sec: 0.0,
            std_bytes_per_sec: 0.0,
            mean_connections_per_min: 0.0,
            std_connections_per_min: 0.0,
            samples: 0,
        });

        let n = entry.samples as f64;
        if n > 0.0 {
            let old_mean_bytes = entry.mean_bytes_per_sec;
            let old_mean_conn = entry.mean_connections_per_min;

            entry.mean_bytes_per_sec = old_mean_bytes + (bytes_per_sec - old_mean_bytes) / (n + 1.0);
            entry.mean_connections_per_min = old_mean_conn + (connections_per_min - old_mean_conn) / (n + 1.0);

            entry.std_bytes_per_sec = ((n - 1.0) * entry.std_bytes_per_sec.powi(2)
                + (bytes_per_sec - old_mean_bytes) * (bytes_per_sec - entry.mean_bytes_per_sec)) / n;
            entry.std_connections_per_min = ((n - 1.0) * entry.std_connections_per_min.powi(2)
                + (connections_per_min - old_mean_conn) * (connections_per_min - entry.mean_connections_per_min)) / n;
        } else {
            entry.mean_bytes_per_sec = bytes_per_sec;
            entry.mean_connections_per_min = connections_per_min;
            entry.std_bytes_per_sec = 0.0;
            entry.std_connections_per_min = 0.0;
        }
        entry.samples += 1;
    }

    pub fn anomaly_score(&self, process: &str, bytes_per_sec: f64, connections_per_min: f64) -> Option<f64> {
        let baseline = self.baselines.get(process)?;
        if baseline.samples < 5 {
            return None;
        }

        let bytes_z = if baseline.std_bytes_per_sec > 0.0 {
            (bytes_per_sec - baseline.mean_bytes_per_sec).abs() / baseline.std_bytes_per_sec
        } else {
            0.0
        };

        let conn_z = if baseline.std_connections_per_min > 0.0 {
            (connections_per_min - baseline.mean_connections_per_min).abs() / baseline.std_connections_per_min
        } else {
            0.0
        };

        Some((bytes_z * 0.7 + conn_z * 0.3) / 4.0)
    }
}

impl AnomalyModel for BaselineModel {
    fn predict(&self, features: &[f64]) -> AnomalyScore {
        let score = features.iter().sum::<f64>() / features.len() as f64;
        AnomalyScore {
            score,
            is_anomaly: score > 2.0,
            contributors: vec!["baseline_deviation".to_string()],
        }
    }

    fn train(&mut self, _data: &[Vec<f64>]) -> anyhow::Result<()> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Baseline Model"
    }
}