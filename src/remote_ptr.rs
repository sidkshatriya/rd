use std::cmp::Ordering;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::marker::PhantomData;
use std::ops::Sub;
use std::ops::{Add, AddAssign, SubAssign};

/// Useful alias.
pub type Void = u8;

#[derive(Copy, Clone, Hash, Debug)]
pub struct RemotePtr<T> {
    ptr: usize,
    phantom: PhantomData<T>,
}

impl<T> Default for RemotePtr<T> {
    fn default() -> Self {
        RemotePtr {
            ptr: 0,
            phantom: PhantomData,
        }
    }
}

impl<T> RemotePtr<T> {
    pub fn new() -> RemotePtr<T> {
        RemotePtr {
            ptr: 0,
            phantom: PhantomData,
        }
    }

    pub fn new_from_val(val: usize) -> RemotePtr<T> {
        RemotePtr {
            ptr: val,
            phantom: PhantomData,
        }
    }

    pub fn as_usize(&self) -> usize {
        self.ptr
    }

    /// As the name indicates this is just a cast. No try_into().unwrap() here!
    pub fn as_isize(&self) -> isize {
        self.ptr as isize
    }

    pub fn is_null(&self) -> bool {
        self.ptr == 0
    }

    pub fn referent_size(&self) -> usize {
        std::mem::size_of::<T>()
    }

    pub fn cast<U>(r: RemotePtr<U>) -> RemotePtr<T> {
        RemotePtr::<T>::new_from_val(r.ptr)
    }
}

impl<T> Display for RemotePtr<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:#x}", self.ptr)
    }
}

impl<T> Add<usize> for RemotePtr<T> {
    type Output = Self;

    fn add(self, delta: usize) -> Self::Output {
        // Will automatically deal with underflow in debug mode.
        let result: usize = self.as_usize() + delta * std::mem::size_of::<T>();
        Self::new_from_val(result)
    }
}

impl<T> Sub<usize> for RemotePtr<T> {
    type Output = Self;

    fn sub(self, delta: usize) -> Self::Output {
        // Will automatically deal with underflow in debug mode.
        let result: usize = self.as_usize() - delta * std::mem::size_of::<T>();
        Self::new_from_val(result)
    }
}

// ! Note that there is NO impl Add<isize> for RemotePtr<T> and impl Sub<isize> for RemotePtr<T> !

/// Note that the other RemotePtr must have SAME referent type.
impl<T> Sub<RemotePtr<T>> for RemotePtr<T> {
    type Output = usize;

    fn sub(self, rhs: RemotePtr<T>) -> Self::Output {
        // Will automatically deal with underflow in debug mode.
        let delta: usize = self.as_usize() - rhs.as_usize();
        delta / std::mem::size_of::<T>()
    }
}

impl<T> PartialOrd for RemotePtr<T> {
    fn partial_cmp(&self, other: &RemotePtr<T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for RemotePtr<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.ptr < other.ptr {
            Ordering::Less
        } else if self.ptr == other.ptr {
            Ordering::Equal
        } else {
            Ordering::Greater
        }
    }
}

impl<T> PartialEq for RemotePtr<T> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl<T> Eq for RemotePtr<T> {}

impl<T> From<usize> for RemotePtr<T> {
    fn from(addr: usize) -> Self {
        RemotePtr::<T>::new_from_val(addr)
    }
}

impl<T> Into<usize> for RemotePtr<T> {
    fn into(self) -> usize {
        self.as_usize()
    }
}

impl<T> SubAssign<usize> for RemotePtr<T> {
    fn sub_assign(&mut self, rhs: usize) {
        self.ptr = self.ptr - rhs * std::mem::size_of::<T>();
    }
}

impl<T> AddAssign<usize> for RemotePtr<T> {
    fn add_assign(&mut self, rhs: usize) {
        self.ptr = self.ptr + rhs * std::mem::size_of::<T>();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_test() {
        let a = RemotePtr::<u64>::new();
        assert_eq!(0, a.as_usize());
    }

    #[test]
    fn add_test() {
        let a = RemotePtr::<u64>::new();
        let b = a + 1 as usize;
        assert_eq!(8, b.as_usize());
    }

    #[test]
    fn add_test_with_custom_struct() {
        struct S(u64, u64);
        let a = RemotePtr::<S>::new();
        let b = a + 1 as usize;
        assert_eq!(16, b.as_usize());
    }

    #[test]
    fn referent_size_custom_struct() {
        struct S(u64, u64);
        let a = RemotePtr::<S>::new();
        assert_eq!(16, a.referent_size());
    }

    #[test]
    fn add_sub_test() {
        let a = RemotePtr::<u64>::new();
        let b = a + 1 as usize;
        let c = b - 1 as usize;
        assert_eq!(0, c.as_usize());
    }

    #[test]
    fn cast_test() {
        struct S(u64, u64);
        let a = RemotePtr::<u64>::new_from_val(8);
        let b = RemotePtr::<S>::cast(a);
        assert_eq!(16, b.referent_size());
        assert_eq!(8, a.referent_size());
    }

    #[test]
    fn comparison_test() {
        struct S(u64, u64);
        let a = RemotePtr::<u64>::new_from_val(8);
        let c = RemotePtr::<S>::new_from_val(0);
        let d = RemotePtr::<S>::new_from_val(16);
        assert_eq!(a, a);
        assert_eq!(a, a.clone());
        assert!(c < d);
        assert!(d > c);
        assert!(c != d);
    }
}
