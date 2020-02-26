use crate::event::Switchable;
use crate::file_monitor::{FileMonitorInterface, FileMonitorSharedPtr, LazyOffset, Range};
use crate::replay_task::ReplayTask;
use crate::task_interface::record_task::record_task::RecordTask;
use crate::task_interface::task::task::Task;
use crate::task_interface::TaskInterface;
use crate::task_set::TaskSet;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub type FdTableSharedPtr = Rc<RefCell<FdTable>>;

#[derive(Clone)]
pub struct FdTable {
    tasks: TaskSet,
    fds: HashMap<i32, FileMonitorSharedPtr>,
    /// Number of elements of `fds` that are >= SYSCALLBUF_FDS_DISABLED_SIZE
    fd_count_beyond_limit: u32,
}

impl FdTable {
    pub fn add_monitor(&self, t: &dyn TaskInterface, fd: i32, monitor: &dyn FileMonitorInterface) {
        unimplemented!()
    }
    pub fn emulate_ioctl(&self, fd: i32, t: &RecordTask, result: &mut u64) -> bool {
        unimplemented!()
    }
    pub fn emulate_fcntl(&self, fd: i32, t: &RecordTask, result: &mut u64) -> bool {
        unimplemented!()
    }
    pub fn emulate_read(
        &self,
        fd: i32,
        t: &RecordTask,
        ranges: &Vec<Range>,
        offset: &LazyOffset,
        result: &mut i64,
    ) -> bool {
        unimplemented!()
    }
    pub fn filter_getdents(&self, fd: i32, t: &RecordTask) {
        unimplemented!()
    }
    pub fn is_rd_fd(&self, fd: i32) {
        unimplemented!()
    }
    pub fn will_write(&self, t: &Task, fd: i32) -> Switchable {
        unimplemented!()
    }
    pub fn did_write(&self, t: &Task, fd: i32, ranges: Vec<Range>, offset: LazyOffset) {
        unimplemented!()
    }
    pub fn did_dup(&self, from: i32, to: i32) {
        unimplemented!()
    }
    pub fn did_close(&self, fd: i32) {
        unimplemented!()
    }

    pub fn clone(&self, t: &Task) -> FileMonitorSharedPtr {
        unimplemented!()
    }
    pub fn create(t: &Task) -> FileMonitorSharedPtr {
        unimplemented!()
    }

    pub fn is_monitoring(&self, fd: i32) -> bool {
        unimplemented!()
    }
    pub fn count_beyond_limit(&self) -> u32 {
        unimplemented!()
    }

    pub fn get_monitor(&self, fd: i32) -> &dyn FileMonitorInterface {
        unimplemented!()
    }

    /**
     * Regenerate syscallbuf_fds_disabled in task |t|.
     * Called during initialization of the preload library.
     */
    pub fn init_syscallbuf_fds_disabled(&self, t: &Task) {
        unimplemented!()
    }

    /**
     * Get list of fds that have been closed after |t| has done an execve.
     * Rather than tracking CLOEXEC flags (which would be complicated), we just
     * scan /proc/<pid>/fd during recording and note any monitored fds that have
     * been closed.
     * This also updates our table to match reality.
     */
    pub fn fds_to_close_after_exec(&self, t: &RecordTask) -> Vec<i32> {
        unimplemented!()
    }

    /**
     * Close fds in list after an exec.
     */
    pub fn close_after_exec(&self, t: &ReplayTask, fds_to_close: &Vec<i32>) {
        unimplemented!()
    }

    fn new() -> FdTable {
        unimplemented!()
    }

    fn update_syscallbuf_fds_disabled(&self, fd: i32) {
        unimplemented!()
    }
}
