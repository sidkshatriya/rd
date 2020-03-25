use crate::task::*;
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};

#[derive(Clone)]
pub struct TaskSet(HashSet<TaskPtr>);

impl TaskSet {
    pub fn new() -> TaskSet {
        TaskSet(HashSet::new())
    }
    pub fn task_set(&self) -> &HashSet<TaskPtr> {
        &self.0
    }
    pub fn insert_task(&mut self, t: TaskSharedWeakPtr) -> bool {
        self.0.insert(TaskPtr(t))
    }
    pub fn erase_task(&mut self, t: TaskSharedWeakPtr) -> bool {
        self.0.remove(&TaskPtr(t))
    }
    pub fn has_task(&self, t: TaskSharedWeakPtr) -> bool {
        self.0.contains(&TaskPtr(t))
    }
}

impl Deref for TaskSet {
    type Target = HashSet<TaskPtr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TaskSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
