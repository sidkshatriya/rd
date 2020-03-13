use crate::task::task_inner::task_inner::TaskInner;
use crate::thread_group::ThreadGroup;
use libc::pid_t;
use std::marker::PhantomData;

pub struct AddressSpaceUid {}

pub struct TaskishUid<T> {
    tid_: pid_t,
    serial_: u32,
    phantom_data: PhantomData<T>,
}

impl<T> TaskishUid<T> {
    pub fn new() -> TaskishUid<T> {
        TaskishUid {
            tid_: 0,
            serial_: 0,
            phantom_data: PhantomData,
        }
    }
}

/// Note that this is TaskInner and not dyn Task
pub type TaskUid = TaskishUid<TaskInner>;
pub type ThreadGroupUid = TaskishUid<ThreadGroup>;
