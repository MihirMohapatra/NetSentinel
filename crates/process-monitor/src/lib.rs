pub mod windows;
pub mod linux;
pub mod mac;

use packet_engine::NetworkEvent;
use anyhow::Result;
use std::net::IpAddr;

pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub user: String,
}

pub trait ProcessMapper {
    fn find_process_for_connection(&self, event: &NetworkEvent) -> Result<Option<ProcessInfo>>;
    fn get_active_connections(&self) -> Result<Vec<ProcessConnection>>;
}

pub struct ProcessConnection {
    pub pid: u32,
    pub process_name: String,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub protocol: String,
}

pub use windows::WindowsProcessMonitor;
pub use linux::LinuxProcessMonitor;
pub use mac::MacProcessMonitor;