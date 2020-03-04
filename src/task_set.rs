use crate::task::*;
use std::collections::HashSet;
use std::ops::Deref;

#[derive(Clone)]
pub struct TaskSet(HashSet<TaskRawPtr>);

impl TaskSet {
    pub fn new() -> TaskSet {
        TaskSet(HashSet::new())
    }
    pub fn task_set(&self) -> &HashSet<TaskRawPtr> {
        &self.0
    }
    pub fn insert_task(&mut self, t: *mut dyn Task) -> bool {
        self.0.insert(TaskRawPtr(t))
    }
    pub fn erase_task(&mut self, t: *mut dyn Task) -> bool {
        self.0.remove(&TaskRawPtr(t))
    }
    pub fn has_task(&self, t: *mut dyn Task) -> bool {
        self.0.contains(&TaskRawPtr(t))
    }
}

impl Deref for TaskSet {
    type Target = HashSet<TaskRawPtr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
