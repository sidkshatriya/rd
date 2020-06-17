//! Support tracees that share memory read-only with a non-tracee that
//! writes to the memory. Currently this just supports limited cases that
//! suffice for dconf: no remapping, coalescing or splitting of the memory is
//! allowed (`subrange` below just asserts). It doesn't handle mappings where
//! the mapping has more pages than the file.
//!
//! After such memory is mapped in the tracee, we also map it in rd at `real_mem`
//! and replace the tracee's mapping with a "shadow buffer" that's only shared
//! with rd. Then periodically rd reads the real memory, and if it doesn't match
//! the shadow buffer, we update the shadow buffer with the new values and
//! record that we did so.
//!
//! Currently we check the real memory after each syscall exit. This ensures
//! that if the tracee is woken up by some IPC mechanism (or after sched_yield),
//! it will get a chance to see updated memory values.

use crate::session::{address_space::address_space, task::record_task::record_task::RecordTask};
use std::{
    cell::RefCell,
    rc::{Rc, Weak},
};

pub type MonitoredSharedMemorySharedPtr = Rc<RefCell<MonitoredSharedMemory>>;
pub type MonitoredSharedMemorySharedWeakPtr = Weak<RefCell<MonitoredSharedMemory>>;

pub struct MonitoredSharedMemory {
    real_mem: *mut [u8],
}

impl MonitoredSharedMemory {
    pub fn maybe_monitor(
        _t: &RecordTask,
        _filename: &str,
        _m: &address_space::Mapping,
        _tracee_fd: i32,
        _offset: usize,
    ) {
        unimplemented!()
    }

    pub fn check_all(_t: &RecordTask) {
        unimplemented!()
    }

    /// This feature is currently unsupported
    pub fn subrange(&self, _start: usize, _size: usize) -> MonitoredSharedMemorySharedPtr {
        assert!(
            false,
            "Subranges in monitored shared memory not supported yet!"
        );
        unimplemented!()
    }

    fn check_for_changes(&self, _t: &RecordTask, _m: &address_space::Mapping) {
        unimplemented!()
    }

    /// real_mem is pointer within rd's address space to the memory shared between
    /// the tracee (which just becomes a "shadow buffer") and the non-rd process.
    /// See description above.
    fn new(real_mem: *mut [u8]) -> MonitoredSharedMemory {
        MonitoredSharedMemory { real_mem }
    }
}
