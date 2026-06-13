use std::collections::HashSet;
use parking_lot::RwLock;
use std::sync::Arc;

static KNOWN_MALWARE_DOMAINS: &[&str] = &[
    "malware.test.xyz",
    "phishing.example.com",
    "botnet.c2.server",
    "ransomware.pay.xyz",
    "dataexfil.evil.com",
    "cryptominer.pool.xyz",
    "driveby.download.cc",
    "tracker.evil.tk",
    "maldoc.attach.xyz",
    "phish.login.cc",
];

static SUSPICIOUS_TLDS: &[&str] = &[
    ".xyz", ".top", ".gq", ".ml", ".cf", ".tk", ".ga",
    ".cam", ".work", ".download", ".review", ".trade",
    ".bid", ".loan", ".date", ".racing", ".accountant",
];

static KNOWN_SAFE_DOMAINS: &[&str] = &[
    "google.com", "github.com", "microsoft.com", "apple.com",
    "amazon.com", "cloudflare.com", "fastly.com", "akamai.com",
    "rust-lang.org", "crates.io", "docs.rs",
];

pub struct DomainReputation {
    malware_domains: Arc<RwLock<HashSet<String>>>,
    safe_domains: Arc<RwLock<HashSet<String>>>,
    suspicious_tlds: Arc<RwLock<HashSet<String>>>,
    query_history: Arc<RwLock<Vec<DomainQuery>>>,
}

#[derive(Debug, Clone)]
pub struct DomainQuery {
    pub domain: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub risk_score: f64,
    pub risk_factors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DomainRisk {
    Safe,
    Unknown(f64),
    Suspicious(f64, Vec<String>),
    Malware,
}

impl DomainReputation {
    pub fn new() -> Self {
        let malware: HashSet<String> = KNOWN_MALWARE_DOMAINS.iter().map(|s| s.to_string()).collect();
        let safe: HashSet<String> = KNOWN_SAFE_DOMAINS.iter().map(|s| s.to_string()).collect();
        let tlds: HashSet<String> = SUSPICIOUS_TLDS.iter().map(|s| s.to_string()).collect();

        Self {
            malware_domains: Arc::new(RwLock::new(malware)),
            safe_domains: Arc::new(RwLock::new(safe)),
            suspicious_tlds: Arc::new(RwLock::new(tlds)),
            query_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn check(&self, domain: &str) -> DomainRisk {
        let domain_lower = domain.to_lowercase();

        if self.malware_domains.read().contains(&domain_lower) {
            return DomainRisk::Malware;
        }

        if self.safe_domains.read().contains(&domain_lower) {
            return DomainRisk::Safe;
        }

        let mut risk_factors = Vec::new();
        let mut score = 0.0;

        for tld in self.suspicious_tlds.read().iter() {
            if domain_lower.ends_with(tld) {
                risk_factors.push(format!("Suspicious TLD: {}", tld));
                score += 30.0;
            }
        }

        let parts: Vec<&str> = domain_lower.split('.').collect();
        if parts.len() > 3 {
            risk_factors.push("Excessive subdomains".to_string());
            score += 15.0;
        }

        if domain_lower.len() > 50 {
            risk_factors.push("Unusually long domain".to_string());
            score += 10.0;
        }

        let entropy = Self::entropy(domain_lower.as_bytes());
        if entropy > 3.5 {
            risk_factors.push(format!("High entropy domain name ({:.2})", entropy));
            score += 20.0;
        }

        if score >= 30.0 {
            DomainRisk::Suspicious(score, risk_factors)
        } else if score > 0.0 {
            DomainRisk::Unknown(score)
        } else {
            DomainRisk::Unknown(0.0)
        }
    }

    pub fn record_query(&self, domain: &str) {
        let risk = self.check(domain);
        let risk_score = match &risk {
            DomainRisk::Safe => 0.0,
            DomainRisk::Unknown(s) => *s,
            DomainRisk::Suspicious(s, _) => *s,
            DomainRisk::Malware => 100.0,
        };
        let risk_factors = match &risk {
            DomainRisk::Suspicious(_, factors) => factors.clone(),
            DomainRisk::Malware => vec!["Known malware domain".to_string()],
            _ => Vec::new(),
        };

        let mut history = self.query_history.write();
        history.push(DomainQuery {
            domain: domain.to_string(),
            timestamp: chrono::Utc::now(),
            risk_score,
            risk_factors,
        });
        if history.len() > 10000 {
            history.remove(0);
        }
    }

    pub fn get_history(&self) -> Vec<DomainQuery> {
        self.query_history.read().clone()
    }

    pub fn add_malware_domain(&self, domain: &str) {
        self.malware_domains.write().insert(domain.to_lowercase());
    }

    pub fn add_safe_domain(&self, domain: &str) {
        self.safe_domains.write().insert(domain.to_lowercase());
    }

    fn entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in freq.iter() {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}