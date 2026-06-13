use crate::{ProcessInfo, ProcessMapper, ProcessConnection};
use packet_engine::NetworkEvent;
use anyhow::Result;
use sysinfo::{System, Pid};

pub struct WindowsProcessMonitor {
    system: System,
}

impl WindowsProcessMonitor {
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
        }
    }

    pub fn refresh(&mut self) {
        self.system.refresh_all();
    }
}

impl ProcessMapper for WindowsProcessMonitor {
    fn find_process_for_connection(&self, event: &NetworkEvent) -> Result<Option<ProcessInfo>> {
        self.get_process_by_pid(event.process_id.unwrap_or(0))
    }

    fn get_active_connections(&self) -> Result<Vec<ProcessConnection>> {
        Ok(Vec::new())
    }
}

impl WindowsProcessMonitor {
    pub fn get_process_by_pid(&self, pid: u32) -> Result<Option<ProcessInfo>> {
        if pid == 0 {
            return Ok(None);
        }
        match self.system.process(Pid::from(pid as usize)) {
            Some(p) => Ok(Some(ProcessInfo {
                pid: p.pid().as_u32() as u32,
                name: p.name().to_string_lossy().to_string(),
                path: p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default(),
                user: String::new(),
            })),
            None => Ok(None),
        }
    }
}