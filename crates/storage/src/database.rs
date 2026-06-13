use crate::models::{ConnectionRecord, AlertRecord, DnsRecord, ThreatBaseline};
use anyhow::Result;
use rusqlite::{Connection, params};
use std::sync::Arc;
use parking_lot::Mutex;
use tracing::info;

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.initialize_tables()?;
        info!("Database initialized at: {}", path);
        Ok(db)
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.initialize_tables()?;
        Ok(db)
    }

    fn initialize_tables(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY,
                process_name TEXT,
                process_id INTEGER,
                local_ip TEXT NOT NULL,
                local_port INTEGER NOT NULL,
                remote_ip TEXT NOT NULL,
                remote_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                closed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                port INTEGER,
                protocol TEXT,
                process_name TEXT,
                created_at TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS dns_history (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                query_type INTEGER,
                response_ips TEXT,
                response_code INTEGER,
                process_id INTEGER,
                process_name TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS baselines (
                id TEXT PRIMARY KEY,
                process_name TEXT NOT NULL,
                avg_bytes_per_hour REAL,
                std_dev_bytes REAL,
                avg_connections_per_hour REAL,
                last_updated TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_connections_remote_ip ON connections(remote_ip);
            CREATE INDEX IF NOT EXISTS idx_connections_created_at ON connections(created_at);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
            CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_history(domain);
        ")?;
        Ok(())
    }

    pub fn insert_connection(&self, record: &ConnectionRecord) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO connections (id, process_name, process_id, local_ip, local_port, remote_ip, remote_port, protocol, bytes_sent, bytes_received, created_at, closed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                record.id, record.process_name, record.process_id,
                record.local_ip, record.local_port, record.remote_ip, record.remote_port,
                record.protocol, record.bytes_sent, record.bytes_received,
                record.created_at, record.closed_at
            ],
        )?;
        Ok(())
    }

    pub fn insert_alert(&self, record: &AlertRecord) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO alerts (id, severity, title, description, source_ip, destination_ip, port, protocol, process_name, created_at, acknowledged)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.id, record.severity, record.title, record.description,
                record.source_ip, record.destination_ip, record.port, record.protocol,
                record.process_name, record.created_at, record.acknowledged as i32
            ],
        )?;
        Ok(())
    }

    pub fn insert_dns(&self, record: &DnsRecord) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO dns_history (id, domain, query_type, response_ips, response_code, process_id, process_name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.id, record.domain, record.query_type,
                record.response_ips.join(","), record.response_code,
                record.process_id, record.process_name, record.created_at
            ],
        )?;
        Ok(())
    }

    pub fn insert_baseline(&self, record: &ThreatBaseline) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO baselines (id, process_name, avg_bytes_per_hour, std_dev_bytes, avg_connections_per_hour, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.id, record.process_name, record.avg_bytes_per_hour,
                record.std_dev_bytes, record.avg_connections_per_hour, record.last_updated
            ],
        )?;
        Ok(())
    }

    pub fn get_recent_alerts(&self, limit: usize) -> Result<Vec<AlertRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, severity, title, description, source_ip, destination_ip, port, protocol, process_name, created_at, acknowledged
             FROM alerts ORDER BY created_at DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AlertRecord {
                id: row.get(0)?,
                severity: row.get(1)?,
                title: row.get(2)?,
                description: row.get(3)?,
                source_ip: row.get(4)?,
                destination_ip: row.get(5)?,
                port: row.get(6)?,
                protocol: row.get(7)?,
                process_name: row.get(8)?,
                created_at: row.get(9)?,
                acknowledged: row.get::<_, i32>(10)? != 0,
            })
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    pub fn get_baseline(&self, process_name: &str) -> Result<Option<ThreatBaseline>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, process_name, avg_bytes_per_hour, std_dev_bytes, avg_connections_per_hour, last_updated
             FROM baselines WHERE process_name = ?1"
        )?;
        let mut rows = stmt.query_map(params![process_name], |row| {
            Ok(ThreatBaseline {
                id: row.get(0)?,
                process_name: row.get(1)?,
                avg_bytes_per_hour: row.get(2)?,
                std_dev_bytes: row.get(3)?,
                avg_connections_per_hour: row.get(4)?,
                last_updated: row.get(5)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }
}