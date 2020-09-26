use crate::session::task::TaskSharedWeakPtr;
use std::cmp::Ordering;

#[derive(Clone)]
pub struct PriorityPair(pub i32, pub TaskSharedWeakPtr);

impl PartialOrd for PriorityPair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl PartialEq for PriorityPair {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && (self.1.as_ptr() as usize) == (other.1.as_ptr() as usize)
    }
}

impl Eq for PriorityPair {}

impl Ord for PriorityPair {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.0 < other.0 {
            Ordering::Less
        } else if self.0 == other.0 {
            if (self.1.as_ptr() as usize) < (other.1.as_ptr() as usize) {
                Ordering::Less
            } else if self.1.as_ptr() as usize > other.1.as_ptr() as usize {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        } else {
            Ordering::Greater
        }
    }
}
