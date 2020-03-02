use crate::event::Switchable;
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::task_interface::record_task::record_task::RecordTask;
use crate::task_interface::TaskInterface;
use std::cell::RefCell;
use std::rc::Rc;

pub type FileMonitorSharedPtr = Rc<RefCell<dyn FileMonitorInterface>>;

pub struct FileMonitor;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum FileMonitorType {
    Base,
    MagicSaveData,
    Mmapped,
    Preserve,
    ProcFd,
    ProcMem,
    Stdio,
    VirtualPerfCounter,
}

/// Notification that task |t| wrote to the file descriptor.
/// Due to races, if will_write did not return PREVENT_SWITCH, it's possible
/// that the data in the buffers is not what was actually written.
#[derive(Copy, Clone)]
pub struct Range {
    pub data: RemotePtr<Void>,
    pub length: usize,
}

impl Range {
    pub fn new(data: RemotePtr<Void>, length: usize) -> Range {
        Range { data, length }
    }
}

/// Encapsulates the offset at which to read or write. Computing this may be
/// an expensive operation if the offset is implicit (i.e. is taken from the
/// file descriptor), so we only do it if we actually need to look at the
/// offset.
pub struct LazyOffset<'a> {
    t: &'a dyn TaskInterface,
    regs: &'a Registers,
    syscallno: i64,
}

impl<'a> LazyOffset<'a> {
    pub fn new(t: &'a dyn TaskInterface, regs: &'a Registers, syscallno: i64) -> LazyOffset<'a> {
        LazyOffset { t, regs, syscallno }
    }
    pub fn retrieve(needed_for_replay: bool) -> i64 {
        unimplemented!()
    }
}

pub trait FileMonitorInterface {
    fn file_monitor_type(&self) -> FileMonitorType {
        FileMonitorType::Base
    }

    /// Overriding this to return true will cause close() (and related fd-smashing
    /// operations such as dup2) to return EBADF, and hide it from the tracee's
    /// /proc/pid/fd/
    fn is_rd_fd(&self) -> bool {
        false
    }

    /// Notification that task |t| is about to write |data| bytes of length
    /// |length| to the file.
    /// In general writes can block, and concurrent blocking writes to the same
    /// file may race so that the kernel performs writes out of order
    /// with respect to will_write notifications.
    /// If it is known that the write cannot block (or that blocking all of rr
    /// on it is OK), this notification can return PREVENT_SWITCH to make the
    /// write a blocking write. This ensures that writes are performed in the order
    /// of will_write notifications.
    fn will_write(&self, t: &dyn TaskInterface) -> Switchable {
        Switchable::AllowSwitch
    }

    fn did_write(&self, t: &dyn TaskInterface, rv: Vec<Range>, l: &LazyOffset) {}

    /// Return true if the ioctl should be fully emulated. If so the result
    /// is stored in the last parameter.
    /// Only called during recording.
    fn emulate_ioctl(&self, t: &RecordTask, r: &mut u64) -> bool {
        false
    }

    /// Return true if the fcntl should should be fully emulated. If so the
    /// result is stored in the last parameter.
    /// Only called during recording.
    fn emulate_fcntl(&self, t: &RecordTask, r: &mut u64) -> bool {
        false
    }

    /// Return true if the read should should be fully emulated. If so the
    /// result is stored in the last parameter. The emulation should write to the
    /// task's memory ranges.
    /// Only called during recording.
    fn emulate_read(&self, t: &RecordTask, vr: &Vec<Range>, o: &LazyOffset, l: &mut u64) -> bool {
        false
    }

    /// Allows the FileMonitor to rewrite the output of a getdents/getdents64 call
    /// if desired.
    fn filter_getdents(&self, t: &RecordTask) {}
}