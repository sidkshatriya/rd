use crate::task_set::*;
use std::ops::{Deref, DerefMut};
pub mod memory_range;

mod kernel_mapping {
    use super::*;
    use libc::{dev_t, ino_t};
    use libc::{MAP_ANONYMOUS, MAP_GROWSDOWN, MAP_NORESERVE, MAP_PRIVATE, MAP_SHARED, MAP_STACK};
    use memory_range::MemoryRange;

    /// These are the flags we track internally to distinguish
    /// between adjacent segments.  For example, the kernel
    /// considers a NORESERVE anonynmous mapping that's adjacent to
    /// a non-NORESERVE mapping distinct, even if all other
    /// metadata are the same.  See |is_adjacent_mapping()|.
    pub const MAP_FLAGS_MASK: i32 =
        MAP_ANONYMOUS | MAP_NORESERVE | MAP_PRIVATE | MAP_SHARED | MAP_STACK | MAP_GROWSDOWN;
    pub const CHECKABLE_FLAGS_MASK: i32 = MAP_PRIVATE | MAP_SHARED;
    pub const NO_DEVICE: dev_t = 0;
    pub const NO_INODE: ino_t = 0;

    pub struct KernelMapping {
        mr: MemoryRange,
    }

    impl KernelMapping {}

    impl<'a> Deref for KernelMapping {
        type Target = MemoryRange;
        fn deref(&self) -> &Self::Target {
            &self.mr
        }
    }

    impl<'a> DerefMut for KernelMapping {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.mr
        }
    }
}

mod address_space {
    use super::*;

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
