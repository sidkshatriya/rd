use crate::task::*;
use std::collections::hash_set::Iter;
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};

#[derive(Clone)]
pub struct TaskSet(HashSet<TaskPtr>);

impl TaskSet {
    pub fn new() -> TaskSet {
        TaskSet(HashSet::new())
    }
    pub fn task_hashset(&self) -> &HashSet<TaskPtr> {
        &self.0
    }
    pub fn task_set_iter(&self) -> TaskSetIterator {
        self.into_iter()
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

impl<'a> IntoIterator for &'a TaskSet {
    type Item = TaskSharedPtr;
    type IntoIter = TaskSetIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        TaskSetIterator {
            hash_set_iterator: self.0.iter(),
        }
    }
}

pub struct TaskSetIterator<'a> {
    hash_set_iterator: Iter<'a, TaskPtr>,
}

impl Iterator for TaskSetIterator<'_> {
    type Item = TaskSharedPtr;

    fn next(&mut self) -> Option<Self::Item> {
        self.hash_set_iterator.next().map(|t| t.upgrade().unwrap())
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

impl Default for TaskSet {
    fn default() -> Self {
        TaskSet(Default::default())
    }
}
