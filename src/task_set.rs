use crate::task_trait::*;
use std::collections::HashSet;

pub struct TaskSet<'a>(HashSet<RefTaskTrait<'a>>);

impl<'a> TaskSet<'a> {
    pub fn new() -> TaskSet<'a> {
        TaskSet(HashSet::new())
    }
    pub fn task_set(&self) -> &TaskSet {
        self
    }
    pub fn insert_task(&mut self, t: &'a dyn TaskTrait) -> bool {
        self.0.insert(RefTaskTrait::<'a>(t))
    }
    pub fn erase_task(&mut self, t: &'a dyn TaskTrait) -> bool {
        self.0.remove(&RefTaskTrait::<'a>(t))
    }
    pub fn has_task(&self, t: &'a dyn TaskTrait) -> bool {
        self.0.contains(&RefTaskTrait::<'a>(t))
    }
}
