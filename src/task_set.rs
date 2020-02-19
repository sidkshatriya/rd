use crate::task_trait::*;
use std::collections::HashSet;
use std::ops::Deref;

pub struct TaskSet(HashSet<TaskTraitRawPtr>);

impl TaskSet {
    pub fn new() -> TaskSet {
        TaskSet(HashSet::new())
    }
    pub fn task_set(&self) -> &HashSet<TaskTraitRawPtr> {
        &self.0
    }
    pub fn insert_task(&mut self, t: *mut dyn TaskTrait) -> bool {
        self.0.insert(TaskTraitRawPtr(t))
    }
    pub fn erase_task(&mut self, t: *mut dyn TaskTrait) -> bool {
        self.0.remove(&TaskTraitRawPtr(t))
    }
    pub fn has_task(&self, t: *mut dyn TaskTrait) -> bool {
        self.0.contains(&TaskTraitRawPtr(t))
    }
}

impl Deref for TaskSet {
    type Target = HashSet<TaskTraitRawPtr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
