use crate::{ProcessInfo, ProcessMapper, ProcessConnection};
use packet_engine::NetworkEvent;
use anyhow::Result;
use std::path::Path;
use std::fs;

pub struct LinuxProcessMonitor;

impl LinuxProcessMonitor {
    pub fn new() -> Self {
        Self
    }

    fn read_socket_inode(port: u16, protocol: &str) -> Option<u32> {
        let proc_file = match protocol {
            "TCP" => "/proc/net/tcp",
            "UDP" => "/proc/net/udp",
            _ => return None,
        };

        let content = fs::read_to_string(proc_file).ok()?;

        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            if let Some(local_addr) = parts.get(1) {
                let addr_parts: Vec<&str> = local_addr.split(':').collect();
                if let Some(port_hex) = addr_parts.get(1) {
                    if let Ok(p) = u16::from_str_radix(port_hex, 16) {
                        if p == port {
                            if let Some(inode_str) = parts.get(9) {
                                return inode_str.parse::<u32>().ok();
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn find_process_by_inode(inode: u32) -> Option<(u32, String)> {
        let proc_dir = Path::new("/proc");
        for entry in fs::read_dir(proc_dir).ok()? {
            if let Ok(entry) = entry {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                let pid: u32 = pid_str.parse().ok()?;

                let fd_dir = entry.path().join("fd");
                if let Ok(fd_entries) = fs::read_dir(fd_dir) {
                    for fd_entry in fd_entries.flatten() {
                        if let Ok(target) = fs::read_link(fd_entry.path()) {
                            let target_str = target.to_string_lossy().to_string();
                            if target_str.contains(&format!("socket:[{}]", inode)) {
                                let cmdline_path = entry.path().join("cmdline");
                                if let Ok(cmdline) = fs::read_to_string(cmdline_path) {
                                    let name = cmdline.trim_matches('\0').to_string();
                                    return Some((pid, name));
                                }
                                return Some((pid, format!("pid_{}", pid)));
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

impl ProcessMapper for LinuxProcessMonitor {
    fn find_process_for_connection(&self, event: &NetworkEvent) -> Result<Option<ProcessInfo>> {
        let protocol = match event.protocol {
            packet_engine::Protocol::TCP => "TCP",
            packet_engine::Protocol::UDP => "UDP",
            _ => return Ok(None),
        };

        if let Some(inode) = Self::read_socket_inode(event.destination_port, protocol) {
            if let Some((pid, name)) = Self::find_process_by_inode(inode) {
                return Ok(Some(ProcessInfo {
                    pid,
                    name,
                    path: format!("/proc/{}/exe", pid),
                    user: String::new(),
                }));
            }
        }

        if let Some(pid) = event.process_id {
            Ok(Some(ProcessInfo {
                pid,
                name: format!("pid_{}", pid),
                path: format!("/proc/{}/exe", pid),
                user: String::new(),
            }))
        } else {
            Ok(None)
        }
    }

    fn get_active_connections(&self) -> Result<Vec<ProcessConnection>> {
        Ok(Vec::new())
    }
}