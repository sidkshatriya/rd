use crate::task_set::*;
use std::ops::{Deref, DerefMut};
pub mod kernel_mapping;
pub mod memory_range;
use crate::remote_ptr::RemotePtr;

#[derive(Copy, Clone)]
pub enum BreakpointType {
    BkptNone = 0,
    /// Trap for internal rr purposes, f.e. replaying async
    /// signals.
    BkptInternal = 1,
    /// Trap on behalf of a debugger user.
    BkptUser = 2,
}

/// NB: these random-looking enumeration values are chosen to
/// match the numbers programmed into x86 debug registers.
#[derive(Copy, Clone)]
pub enum WatchType {
    WatchExec = 0x00,
    WatchWrite = 0x01,
    WatchReadWrite = 0x03,
}

#[derive(Copy, Clone)]
pub enum DebugStatus {
    DsWatchpointAny = 0xf,
    DsSingleStep = 1 << 14,
}

#[derive(Copy, Clone)]
pub enum MappingFlags {
    FlagNone = 0x0,
    /// This mapping represents a syscallbuf. It needs to handled specially
    /// during checksumming since its contents are not fully restored by the
    /// replay.
    IsSyscallbuf = 0x1,
    /// This mapping is used as our thread-local variable area for this
    /// address space
    IsThreadLocals = 0x2,
    /// This mapping is used for syscallbuf patch stubs
    IsPatchStubs = 0x4,
    /// This mapping is the rd page
    IsRdPage = 0x8,
}

pub enum Traced {
    Traced,
    Untraced,
}
pub enum Privileged {
    Privileged,
    Unpriviledged,
}
pub enum Enabled {
    RecordingOnly,
    ReplayOnly,
    RecordingAndReplay,
}

pub struct SyscallType {
    traced: Traced,
    priviledged: Privileged,
    enabled: Enabled,
}

pub struct AddressSpace<'a> {
    task_set: TaskSet<'a>,
}

/// A distinct watchpoint, corresponding to the information needed to
/// program a single x86 debug register.
pub struct WatchConfig {
    pub addr: RemotePtr<u8>,
    pub num_bytes: usize,
    pub type_: WatchType,
}

impl WatchConfig {
    pub fn new(addr: RemotePtr<u8>, num_bytes: usize, type_: WatchType) -> WatchConfig {
        WatchConfig {
            addr,
            num_bytes,
            type_,
        }
    }
}

impl<'a> AddressSpace<'a> {
    pub fn new() -> AddressSpace<'a> {
        AddressSpace {
            task_set: TaskSet::new(),
        }
    }
}

impl<'a> Deref for AddressSpace<'a> {
    type Target = TaskSet<'a>;
    fn deref(&self) -> &Self::Target {
        &self.task_set
    }
}

impl<'a> DerefMut for AddressSpace<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.task_set
    }
}

#[cfg(test)]
mod test {
    use super::AddressSpace;
    use crate::task_trait::TaskTrait;

    struct Task(u32);
    impl TaskTrait for Task {}

    #[test]
    fn basic_test() {
        let mut addr_space = AddressSpace::new();
        let t1 = Task(1);
        let t2 = Task(2);
        assert!(addr_space.insert_task(&t1));
        assert!(addr_space.has_task(&t1));
        assert!(!addr_space.insert_task(&t1));
        assert!(addr_space.insert_task(&t2));
        assert!(addr_space.has_task(&t2));
        assert!(addr_space.erase_task(&t1));
        assert!(!addr_space.erase_task(&t1));
        assert!(!addr_space.has_task(&t1));
    }
}
