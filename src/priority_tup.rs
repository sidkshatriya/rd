use crate::session::task::TaskSharedWeakPtr;
use std::cmp::Ordering;

#[derive(Clone)]
/// priority, task `stable_serial` (not `serial` which is slightly different) and task weak ptr
pub struct PriorityTup(pub i32, pub u32, pub TaskSharedWeakPtr);

impl PartialOrd for PriorityTup {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl PartialEq for PriorityTup {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl Eq for PriorityTup {}

impl Ord for PriorityTup {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.0 < other.0 {
            Ordering::Less
        } else if self.0 == other.0 {
            if self.1 < other.1 {
                Ordering::Less
            } else if self.1 > other.1 {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        } else {
            Ordering::Greater
        }
    }
}
