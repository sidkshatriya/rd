use libc::pid_t;
use std::marker::PhantomData;
use std::ops::Deref;

#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct TaskishUid<T> {
    tid_: pid_t,
    serial_: u32,
    phantom_data: PhantomData<T>,
}

/// An ID that's unique within a Session (but consistent across
/// multiple ReplaySessions for the same trace), used by Tasks, ThreadGroups
/// and AddressSpaces.
/// This is needed because tids can be recycled during a long-running session.
impl<T> TaskishUid<T> {
    pub fn new() -> TaskishUid<T> {
        TaskishUid {
            tid_: 0,
            serial_: 0,
            phantom_data: PhantomData,
        }
    }

    pub fn new_with(tid: pid_t, serial: u32) -> TaskishUid<T> {
        TaskishUid {
            tid_: tid,
            serial_: serial,
            phantom_data: PhantomData,
        }
    }

    pub fn tid(&self) -> pid_t {
        self.tid_
    }

    pub fn serial(&self) -> u32 {
        self.serial_
    }
}

#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Ord)]
pub struct AddressSpaceStandIn {
    // this is empty
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AddressSpaceUid {
    /// Note that this is a parameterized by placeholder type AddressSpaceStandIn instead of
    /// AddressSpace to deal with Rust quirkiness with automatically deriving traits from structs
    /// with PhantomData in them.
    taskish: TaskishUid<AddressSpaceStandIn>,
    exec_count: u32,
}

impl AddressSpaceUid {
    pub fn new() -> AddressSpaceUid {
        AddressSpaceUid {
            taskish: TaskishUid::new(),
            exec_count: 0,
        }
    }

    pub fn new_with(tid: pid_t, serial: u32, exec_count: u32) -> AddressSpaceUid {
        AddressSpaceUid {
            taskish: TaskishUid::new_with(tid, serial),
            exec_count,
        }
    }

    pub fn exec_count(&self) -> u32 {
        self.exec_count
    }
}

impl Deref for AddressSpaceUid {
    type Target = TaskishUid<AddressSpaceStandIn>;

    fn deref(&self) -> &Self::Target {
        &self.taskish
    }
}

#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Ord)]
pub struct TaskStandIn {
    // this is empty
}

#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Ord)]
pub struct ThreadGroupStandIn {
    // this is empty
}

/// Note the use of placeholder "...StandIn" types to deal with quirkiness in deriving traits from
/// structs with PhantomData in them.
pub type TaskUid = TaskishUid<TaskStandIn>;
pub type ThreadGroupUid = TaskishUid<ThreadGroupStandIn>;

#[cfg(test)]
mod test {
    use crate::taskish_uid::{AddressSpaceUid, TaskUid};

    #[test]
    pub fn compare_taskish_addr_space_uid() {
        let auid1 = AddressSpaceUid::new_with(1, 1, 2);
        let auid2 = AddressSpaceUid::new_with(0, 2, 3);
        let auid3 = AddressSpaceUid::new_with(0, 1, 4);
        let auid4 = AddressSpaceUid::new_with(0, 0, 9);
        assert!(auid1 > auid2);
        assert!(auid2 > auid3);
        assert!(auid3 > auid4);

        assert!(auid1 > auid3);
        assert!(auid1 > auid4);

        assert!(auid2 > auid4);

        // Test the deref here
        assert_eq!(auid2.tid(), auid3.tid());
    }

    #[test]
    pub fn compare_taskish() {
        let tuid1 = TaskUid::new_with(1, 1);
        let tuid2 = TaskUid::new_with(0, 9);
        let tuid3 = TaskUid::new_with(0, 7);
        assert!(tuid1 > tuid2);
        assert!(tuid2 > tuid3);

        assert!(tuid1 > tuid3);
    }
}
