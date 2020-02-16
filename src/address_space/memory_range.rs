use crate::remote_ptr::RemotePtr;
use std::cmp::{max, min};
use std::convert::TryInto;
use std::fmt::{Display, Formatter, Result};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct MemoryRange {
    pub(super) start_: RemotePtr<u8>,
    pub(super) end_: RemotePtr<u8>,
}

/// Note: The end point (end_) is implicitly NOT included in the MemoryRange
impl MemoryRange {
    pub fn new() -> MemoryRange {
        MemoryRange {
            start_: RemotePtr::new(),
            end_: RemotePtr::new(),
        }
    }

    pub fn new_range(addr: RemotePtr<u8>, num_bytes: usize) -> MemoryRange {
        // If there is an overflow in addition, rust should panic in debug mode.
        // So no need for debug_assert!(result.start_ <= result.end_).
        MemoryRange {
            start_: addr,
            end_: addr + num_bytes,
        }
    }

    pub fn from_range(addr: RemotePtr<u8>, end: RemotePtr<u8>) -> MemoryRange {
        let result = MemoryRange {
            start_: addr,
            end_: end,
        };
        debug_assert!(result.start_ <= result.end_);
        result
    }

    /// Avoid implementing this logic in an Ord.
    pub fn less_than(&self, other: &Self) -> bool {
        if self.start_ != other.start_ {
            self.start_ < other.start_
        } else {
            self.end_ < other.end_
        }
    }

    // Return true iff |other| is an address range fully contained by self.
    pub fn contains(&self, other: &Self) -> bool {
        self.start_ <= other.start_ && other.end_ <= self.end_
    }

    // @TODO Note that we have p < self.end_ and not p <= self.end here.
    pub fn contains_ptr(&self, p: RemotePtr<u8>) -> bool {
        self.start_ <= p && p < self.end_
    }

    pub fn intersect(&self, other: &MemoryRange) -> MemoryRange {
        let s = max(self.start_, other.start_);
        let e = min(self.end_, other.end_);
        MemoryRange {
            start_: s,
            end_: max(s, e),
        }
    }

    pub fn start(&self) -> RemotePtr<u8> {
        self.start_
    }
    pub fn end(&self) -> RemotePtr<u8> {
        self.end_
    }
    pub fn size(&self) -> usize {
        (self.end_ - self.start_).try_into().unwrap()
    }
}

impl Display for MemoryRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}-{}", self.start_, self.end_)
    }
}
