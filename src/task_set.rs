use crate::task_interface::*;
use std::collections::HashSet;
use std::ops::Deref;

#[derive(Clone)]
pub struct TaskSet(HashSet<TaskInterfaceRawPtr>);

impl TaskSet {
    pub fn new() -> TaskSet {
        TaskSet(HashSet::new())
    }
    pub fn task_set(&self) -> &HashSet<TaskInterfaceRawPtr> {
        &self.0
    }
    pub fn insert_task(&mut self, t: *mut dyn TaskInterface) -> bool {
        self.0.insert(TaskInterfaceRawPtr(t))
    }
    pub fn erase_task(&mut self, t: *mut dyn TaskInterface) -> bool {
        self.0.remove(&TaskInterfaceRawPtr(t))
    }
    pub fn has_task(&self, t: *mut dyn TaskInterface) -> bool {
        self.0.contains(&TaskInterfaceRawPtr(t))
    }
}

impl Deref for TaskSet {
    type Target = HashSet<TaskInterfaceRawPtr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
