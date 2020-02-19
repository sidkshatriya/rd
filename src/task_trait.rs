use std::hash::{Hash, Hasher};

/// @TODO should we store *const dyn TaskTrait?
#[derive(Copy, Clone)]
pub struct TaskTraitRawPtr(pub *mut dyn TaskTrait);

impl PartialEq for TaskTraitRawPtr {
    fn eq(&self, other: &Self) -> bool {
        // If the addresses of the dyn TaskTrait ptrs are same then they are the same task.
        self.0 as *const u8 as usize == other.0 as *const u8 as usize
    }
}

impl Eq for TaskTraitRawPtr {}

impl Hash for TaskTraitRawPtr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let addr = self.0 as *const u8 as usize;
        // The hash is the hash of the address of the task (dyn TaskTrait).
        addr.hash(state);
    }
}

pub trait TaskTrait {}
