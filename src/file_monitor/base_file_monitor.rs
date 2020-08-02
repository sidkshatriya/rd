use super::{FileMonitor, FileMonitorType};

pub struct BaseFileMonitor;

impl FileMonitor for BaseFileMonitor {
    fn file_monitor_type(&self) -> FileMonitorType {
        FileMonitorType::Base
    }
}

impl BaseFileMonitor {
    pub fn new() -> BaseFileMonitor {
        BaseFileMonitor
    }
}
