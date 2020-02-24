use crate::remote_ptr::RemotePtr;
use core::cmp::Ordering;
use std::cmp::{max, min};
use std::convert::TryInto;
use std::fmt::{Display, Formatter, Result};
use std::ops::{Deref, DerefMut};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
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

    /// Operator < (basically lexicographic comparison) and == automatically derived

    /// Return true iff |other| is an address range fully contained by self.
    pub fn contains(&self, other: &Self) -> bool {
        self.start_ <= other.start_ && other.end_ <= self.end_
    }

    /// Note that we have p < self.end_ and not p <= self.end here.
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

    pub fn intersects(&self, other: &MemoryRange) -> bool {
        let s = max(self.start_, other.start_);
        let e = min(self.end_, other.end_);
        s < e
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

/// This wrapper type is needed for special ordering requirements
/// Traits PartialOrd, Ord, PartialEq, Eq are manually derived (see below).
#[derive(Copy, Clone)]
pub struct MemoryRangeKey(pub MemoryRange);

impl PartialOrd for MemoryRangeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemoryRangeKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if !self.0.intersects(&other.0) {
            if self.0.start_ < other.0.start_ {
                Ordering::Less
            } else if self.0.start_ > other.0.start_ {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        } else {
            Ordering::Equal
        }
    }
}

impl PartialEq for MemoryRangeKey {
    fn eq(&self, other: &Self) -> bool {
        if !self.0.intersects(&other.0) {
            self.0.start_ == other.0.start_
        } else {
            true
        }
    }
}

impl Eq for MemoryRangeKey {}

impl Deref for MemoryRangeKey {
    type Target = MemoryRange;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MemoryRangeKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
