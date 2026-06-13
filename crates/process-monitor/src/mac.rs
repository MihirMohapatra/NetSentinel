use crate::{ProcessInfo, ProcessMapper, ProcessConnection};
use packet_engine::NetworkEvent;
use anyhow::Result;
use sysinfo::{System, Pid};

pub struct MacProcessMonitor {
    system: System,
}

impl MacProcessMonitor {
    pub fn new() -> Self {
        Self {
            system: System::new_all(),
        }
    }

    pub fn refresh(&mut self) {
        self.system.refresh_all();
    }
}

impl ProcessMapper for MacProcessMonitor {
    fn find_process_for_connection(&self, event: &NetworkEvent) -> Result<Option<ProcessInfo>> {
        if let Some(pid) = event.process_id {
            match self.system.process(Pid::from(pid as usize)) {
                Some(p) => Ok(Some(ProcessInfo {
                    pid: p.pid().as_u32() as u32,
                    name: p.name().to_string_lossy().to_string(),
                    path: p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default(),
                    user: String::new(),
                })),
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    fn get_active_connections(&self) -> Result<Vec<ProcessConnection>> {
        Ok(Vec::new())
    }
}