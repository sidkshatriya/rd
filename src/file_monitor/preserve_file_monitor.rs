use crate::file_monitor::{FileMonitor, FileMonitorType};

/// A FileMonitor that does no monitoring of I/O itself, but prevents the file
/// descriptor from being closed (except via privileged syscalls made by
/// preload.c) or seen in /proc/pid/fd/.
///
/// The mere existence of this monitor disables syscall buffering for the fd, so
/// we get syscall traps for close() etc on the fd. Then
/// rec_prepare_syscall_arch calls allow_close() to check whether closing is
/// allowed.
pub struct PreserveFileMonitor;

impl FileMonitor for PreserveFileMonitor {
    fn file_monitor_type(&self) -> FileMonitorType {
        FileMonitorType::Preserve
    }

    fn is_rd_fd(&self) -> bool {
        true
    }
}

impl PreserveFileMonitor {
    pub fn new() -> PreserveFileMonitor {
        PreserveFileMonitor
    }
}
