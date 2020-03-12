use crate::remote_ptr::RemotePtr;
use crate::remote_ptr::Void;
use core::cmp::Ordering;
use std::cmp::{max, min};
use std::fmt::{Display, Formatter, Result};
use std::ops::{Deref, DerefMut};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct MemoryRange {
    pub(super) start_: RemotePtr<Void>,
    pub(super) end_: RemotePtr<Void>,
}

/// Note: The end point (end_) is implicitly NOT included in the MemoryRange
impl MemoryRange {
    pub fn new() -> MemoryRange {
        MemoryRange {
            start_: RemotePtr::new(),
            end_: RemotePtr::new(),
        }
    }

    pub fn new_range(addr: RemotePtr<Void>, num_bytes: usize) -> MemoryRange {
        // If there is an overflow in addition, rust should panic in debug mode.
        // So no need for debug_assert!(result.start_ <= result.end_).
        MemoryRange {
            start_: addr,
            end_: addr + num_bytes,
        }
    }

    pub fn from_range(addr: RemotePtr<Void>, end: RemotePtr<Void>) -> MemoryRange {
        let result = MemoryRange {
            start_: addr,
            end_: end,
        };
        debug_assert!(result.start_ <= result.end_);
        result
    }

    /// Operator < (basically lexicographic comparison) and == automatically derived

    /// Return true iff `other` is an address range fully contained by self.
    pub fn contains(&self, other: &Self) -> bool {
        self.start_ <= other.start_ && other.end_ <= self.end_
    }

    /// Note that we have p < self.end_ and not p <= self.end here.
    pub fn contains_ptr(&self, p: RemotePtr<Void>) -> bool {
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

    pub fn start(&self) -> RemotePtr<Void> {
        self.start_
    }
    pub fn end(&self) -> RemotePtr<Void> {
        self.end_
    }
    pub fn size(&self) -> usize {
        // Should automatically flag an error in debug mode if size() is negative
        self.end_ - self.start_
    }
}

impl Display for MemoryRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}-{}", self.start_, self.end_)
    }
}

/// This wrapper type is needed for special ordering requirements
/// Traits PartialOrd, Ord, PartialEq, Eq are manually derived (see below).
#[derive(Copy, Clone, Debug)]
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

impl From<MemoryRange> for MemoryRangeKey {
    fn from(r: MemoryRange) -> Self {
        MemoryRangeKey(r)
    }
}

#[cfg(test)]
mod test {
    use crate::address_space::memory_range::{MemoryRange, MemoryRangeKey};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ops::Bound::{Included, Unbounded};

    #[test]
    pub fn test_overlapping_and_iter() {
        let mut m: BTreeSet<MemoryRangeKey> = BTreeSet::new();
        let k1 = MemoryRangeKey(MemoryRange::from_range(0.into(), 10.into()));
        let k2 = MemoryRangeKey(MemoryRange::from_range(10.into(), 15.into()));
        let k4 = MemoryRangeKey(MemoryRange::from_range(1.into(), 10.into()));
        m.insert(k1);
        m.insert(k2);
        let r0 = m.insert(k4);
        assert_eq!(m.len(), 2);
        assert_eq!(r0, false);

        let mut found = 0;
        let mut range = m.range((
            Unbounded,
            Included(MemoryRangeKey(MemoryRange::from_range(9.into(), 11.into()))),
        ));

        while range.next().is_some() {
            found = found + 1;
        }
        assert_eq!(found, 1);
        let k3 = MemoryRangeKey(MemoryRange::from_range(3.into(), 11.into()));
        let r1 = m.remove(&k3);
        assert_eq!(r1, true);
        assert_eq!(m.len(), 1);
        let r2 = m.remove(&k3);
        assert_eq!(r2, true);
        assert_eq!(m.len(), 0);
        let r3 = m.remove(&k3);
        assert_eq!(m.len(), 0);
        assert_eq!(r3, false);
    }

    #[test]
    pub fn test_remove() {
        let mut m: BTreeSet<MemoryRangeKey> = BTreeSet::new();
        let k1 = MemoryRangeKey(MemoryRange::from_range(0.into(), 10.into()));
        let k2 = MemoryRangeKey(MemoryRange::from_range(10.into(), 15.into()));
        m.insert(k1);
        m.insert(k2);
        assert_eq!(m.len(), 2);

        let k3 = MemoryRangeKey(MemoryRange::from_range(3.into(), 11.into()));

        let k1_prime = m.get(&k3).unwrap();
        assert_eq!(k1_prime.start(), k1.start());
        assert_eq!(k1_prime.end(), k1.end());
        m.remove(&k3);

        let k2_prime = m.get(&k3).unwrap();
        assert_eq!(k2_prime.start(), k2.start());
        assert_eq!(k2_prime.end(), k2.end());
    }

    #[test]
    pub fn test_map_iter() {
        let mut m: BTreeMap<MemoryRangeKey, usize> = BTreeMap::new();
        let k1 = MemoryRangeKey(MemoryRange::from_range(0.into(), 10.into()));
        let k2 = MemoryRangeKey(MemoryRange::from_range(10.into(), 15.into()));
        m.insert(k1, 1);
        m.insert(k2, 1);
        assert_eq!(m.len(), 2);

        let mut found = 0;
        let mut range = m.range((
            Unbounded,
            Included(MemoryRangeKey(MemoryRange::from_range(9.into(), 11.into()))),
        ));

        while range.next().is_some() {
            found = found + 1;
        }
        assert_eq!(found, 1);
    }
}
