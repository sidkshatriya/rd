use crate::task_set::*;
use std::ops::{Deref, DerefMut};
pub mod kernel_mapping;
pub mod memory_range;

pub struct AddressSpace<'a> {
    task_set: TaskSet<'a>,
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
    use super::address_space::AddressSpace;
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
