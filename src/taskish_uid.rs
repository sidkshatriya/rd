use crate::address_space::address_space::AddressSpace;
use crate::task::Task;
use crate::thread_group::ThreadGroup;
use libc::pid_t;
use std::cmp::Ordering;
use std::marker::PhantomData;
use std::ops::Deref;

/// Need to manually derive Eq, PartialEq, Ord, PartialOrd due to quirks with PhantomData
pub struct TaskishUid<T> {
    tid_: pid_t,
    serial_: u32,
    phantom_data: PhantomData<T>,
}

impl<T> Clone for TaskishUid<T> {
    fn clone(&self) -> Self {
        TaskishUid {
            tid_: self.tid_,
            serial_: self.serial_,
            phantom_data: PhantomData,
        }
    }
}

impl<T> PartialEq for TaskishUid<T> {
    fn eq(&self, other: &Self) -> bool {
        self.tid_ == other.tid_ && self.serial_ == other.serial_
    }
}

impl<T> Eq for TaskishUid<T> {}

impl<T> Ord for TaskishUid<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.tid_ < other.tid_ {
            Ordering::Less
        } else if self.tid_ == other.tid_ {
            if self.serial_ < other.serial_ {
                Ordering::Less
            } else if self.serial_ == other.serial_ {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        } else {
            Ordering::Greater
        }
    }
}

impl<T> PartialOrd for TaskishUid<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Copy for TaskishUid<T> {}

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

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AddressSpaceUid {
    taskish: TaskishUid<AddressSpace>,
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
    type Target = TaskishUid<AddressSpace>;

    fn deref(&self) -> &Self::Target {
        &self.taskish
    }
}

pub type TaskUid = TaskishUid<Box<dyn Task>>;
pub type ThreadGroupUid = TaskishUid<ThreadGroup>;

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
