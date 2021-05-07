use crate::remote_ptr::{RemotePtr, Void};
use core::cmp::Ordering;
use std::{
    cmp::{max, min},
    fmt::{Display, Formatter, Result},
    ops::{Deref, DerefMut},
};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct MemoryRange {
    pub(super) start_: RemotePtr<Void>,
    pub(super) end_: RemotePtr<Void>,
}

impl Default for MemoryRange {
    fn default() -> Self {
        MemoryRange {
            start_: RemotePtr::null(),
            end_: RemotePtr::null(),
        }
    }
}

/// Note: The end point (end_) is implicitly NOT included in the MemoryRange
impl MemoryRange {
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

    pub fn intersect(&self, other: MemoryRange) -> MemoryRange {
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
            // Note: The Ordering::Equal case in the below cmp is used
            // for single point comparison with starting of interval
            // e.g. MemoryRange::from_addr(addr, addr).
            self.0.start_.cmp(&other.0.start_)
        } else {
            Ordering::Equal
        }
    }
}

impl PartialEq for MemoryRangeKey {
    fn eq(&self, other: &Self) -> bool {
        if !self.0.intersects(&other.0) {
            // Tricky
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
    use crate::session::address_space::memory_range::{MemoryRange, MemoryRangeKey};
    use std::{
        collections::{BTreeMap, BTreeSet},
        ops::Bound::{Included, Unbounded},
    };

    #[test]
    pub fn test_overlapping_and_iter() {
        let mut m: BTreeMap<MemoryRangeKey, u32> = BTreeMap::new();
        let k1 = MemoryRangeKey(MemoryRange::from_range(0usize.into(), 10usize.into()));
        let k4 = MemoryRangeKey(MemoryRange::from_range(1usize.into(), 10usize.into()));

        let k2 = MemoryRangeKey(MemoryRange::from_range(10usize.into(), 15usize.into()));
        let k5 = MemoryRangeKey(MemoryRange::from_range(15usize.into(), 20usize.into()));
        m.insert(k2, 0);
        m.insert(k1, 1);
        m.insert(k5, 5);
        let r0 = m.insert(k4, 4);
        assert_eq!(m.len(), 3);
        match m.get(&k4) {
            Some(&v) => {
                assert_eq!(v, 4);
            }
            None => assert!(false),
        };
        assert!(r0.is_some());

        let mut found = 0;

        // MemoryRangeKeys that are less than or equal to [9, 11).
        let mrk_9to11 = MemoryRangeKey(MemoryRange::from_range(9usize.into(), 11usize.into()));

        let mut range = m.range((Unbounded, Included(mrk_9to11)));
        while range.next().is_some() {
            found += 1;
        }
        assert_eq!(found, 1);
        let mut range2 = m.range((Unbounded, Included(mrk_9to11)));

        match range2.next() {
            Some((found_r, _)) => {
                assert_eq!(found_r.end(), 10usize.into());
                assert_eq!(found_r.start(), 0usize.into());
            }
            None => assert!(false),
        };

        // MemoryRangeKeys that are greater than or equal to [9, 11).
        let mut range3 = m.range((Included(mrk_9to11), Unbounded));

        match range3.next() {
            Some((found_r, _)) => {
                assert_eq!(found_r.end(), 10usize.into());
                assert_eq!(found_r.start(), 0usize.into());
            }
            None => assert!(false),
        };

        match range3.next() {
            Some((found_r, _)) => {
                assert_eq!(found_r.end(), 15usize.into());
                assert_eq!(found_r.start(), 10usize.into());
            }
            None => assert!(false),
        };

        match range3.next() {
            Some((found_r, _)) => {
                assert_eq!(found_r.end(), 20usize.into());
                assert_eq!(found_r.start(), 15usize.into());
            }
            None => assert!(false),
        };

        // Iterate in interval in both items are Included and the same.
        // This is a tricky case. Only 1 element will be found even though 2 may qualify
        // (i.e. [0, 10) and [10, 15) )
        // In this case it will be [0, 10) but it can be [10, 15) in larger BTreeSets.
        // Because of this the interval length is only 0 or 1 in Maps/MapsMut
        let mut range4 = m.range((Included(mrk_9to11), Included(mrk_9to11)));

        match range4.next() {
            Some((found_r, _)) => {
                // In this case it will be [0,10) but it can be [10, 15) also in larger BTreeSets
                assert_eq!(mrk_9to11, *found_r);
                assert_eq!(found_r.end(), 10usize.into());
                assert_eq!(found_r.start(), 0usize.into());
            }
            None => assert!(false, "Iterator does not have 1st element"),
        };

        match range4.next() {
            Some((_found_r, _)) => assert!(false, "Unexpected - Iterator has a 2nd element"),
            None => (),
        };

        let k3 = MemoryRangeKey(MemoryRange::from_range(3usize.into(), 11usize.into()));
        let r1 = m.remove(&k3);
        assert!(r1.is_some());
        assert_eq!(m.len(), 2);
        let r2 = m.remove(&k3);
        assert!(r2.is_some());
        assert_eq!(m.len(), 1);
        let r3 = m.remove(&k3);
        assert_eq!(m.len(), 1);
        assert!(r3.is_none());
    }

    #[test]
    pub fn test_remove() {
        let mut m: BTreeSet<MemoryRangeKey> = BTreeSet::new();
        let k1 = MemoryRangeKey(MemoryRange::from_range(0usize.into(), 10usize.into()));
        let k2 = MemoryRangeKey(MemoryRange::from_range(10usize.into(), 15usize.into()));
        m.insert(k1);
        m.insert(k2);
        assert_eq!(m.len(), 2);

        let k3 = MemoryRangeKey(MemoryRange::from_range(3usize.into(), 11usize.into()));

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
        let k1 = MemoryRangeKey(MemoryRange::from_range(0usize.into(), 10usize.into()));
        let k2 = MemoryRangeKey(MemoryRange::from_range(10usize.into(), 15usize.into()));
        m.insert(k1, 1);
        m.insert(k2, 1);
        assert_eq!(m.len(), 2);

        let mut found = 0;
        let mut range = m.range((
            Unbounded,
            Included(MemoryRangeKey(MemoryRange::from_range(
                9usize.into(),
                11usize.into(),
            ))),
        ));

        while range.next().is_some() {
            found += 1;
        }
        assert_eq!(found, 1);
    }
}
