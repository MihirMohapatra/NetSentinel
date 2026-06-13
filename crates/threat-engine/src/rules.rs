use crate::alerts::AlertSeverity;
use packet_engine::NetworkEvent;
use std::net::IpAddr;

pub struct RuleEngine {
    rules: Vec<Box<dyn DetectionRule + Send + Sync>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn DetectionRule + Send + Sync>> = vec![
            Box::new(SuspiciousPortRule),
            Box::new(PrivateIpEgressRule),
            Box::new(HighPortTrafficRule),
        ];

        Self { rules }
    }

    pub fn add_rule(&mut self, rule: Box<dyn DetectionRule + Send + Sync>) {
        self.rules.push(rule);
    }

    pub fn get_rules(&self) -> &[Box<dyn DetectionRule + Send + Sync>] {
        &self.rules
    }
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub description: String,
}

pub trait DetectionRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, event: &NetworkEvent) -> Option<RuleMatch>;
}

pub struct SuspiciousPortRule;

impl DetectionRule for SuspiciousPortRule {
    fn name(&self) -> &str {
        "Suspicious Port"
    }

    fn evaluate(&self, event: &NetworkEvent) -> Option<RuleMatch> {
        let suspicious_ports = [22, 23, 135, 445, 1433, 3389, 4444, 5555, 6666, 6667, 1337, 31337];
        if suspicious_ports.contains(&event.destination_port) || suspicious_ports.contains(&event.source_port) {
            Some(RuleMatch {
                rule_name: self.name().to_string(),
                severity: AlertSeverity::Medium,
                description: format!("Connection on suspicious port {}", event.destination_port),
            })
        } else {
            None
        }
    }
}

pub struct PrivateIpEgressRule;

impl DetectionRule for PrivateIpEgressRule {
    fn name(&self) -> &str {
        "Private IP Egress"
    }

    fn evaluate(&self, event: &NetworkEvent) -> Option<RuleMatch> {
        let is_private = |ip: IpAddr| -> bool {
            match ip {
                IpAddr::V4(v4) => {
                    v4.is_private() || v4.is_loopback() || v4.is_link_local()
                }
                IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
            }
        };

        if !is_private(event.destination_ip) && is_private(event.source_ip) {
            match (event.source_port, event.destination_port) {
                (_, 25) | (_, 587) | (25, _) | (587, _) => Some(RuleMatch {
                    rule_name: self.name().to_string(),
                    severity: AlertSeverity::High,
                    description: format!("Email traffic detected on non-standard port: {} -> {}:{}",
                        event.source_ip, event.destination_ip, event.destination_port),
                }),
                _ => None,
            }
        } else {
            None
        }
    }
}

pub struct HighPortTrafficRule;

impl DetectionRule for HighPortTrafficRule {
    fn name(&self) -> &str {
        "High Port Traffic"
    }

    fn evaluate(&self, event: &NetworkEvent) -> Option<RuleMatch> {
        let is_ephemeral = |port: u16| port >= 49152;

        if is_ephemeral(event.source_port) && is_ephemeral(event.destination_port)
        {
            Some(RuleMatch {
                rule_name: self.name().to_string(),
                severity: AlertSeverity::Low,
                description: format!("Traffic between ephemeral ports: {}:{} -> {}:{}",
                    event.source_ip, event.source_port,
                    event.destination_ip, event.destination_port),
            })
        } else {
            None
        }
    }
}

pub struct CustomRule {
    name: String,
    severity: AlertSeverity,
    condition: Box<dyn Fn(&NetworkEvent) -> bool + Send + Sync>,
}

impl CustomRule {
    pub fn new(name: &str, severity: AlertSeverity, condition: Box<dyn Fn(&NetworkEvent) -> bool + Send + Sync>) -> Self {
        Self {
            name: name.to_string(),
            severity,
            condition,
        }
    }
}

impl DetectionRule for CustomRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, event: &NetworkEvent) -> Option<RuleMatch> {
        if (self.condition)(event) {
            Some(RuleMatch {
                rule_name: self.name.clone(),
                severity: self.severity.clone(),
                description: format!("Rule '{}' triggered", self.name),
            })
        } else {
            None
        }
    }
}