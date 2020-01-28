use std::cmp::Ordering;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::marker::PhantomData;
use std::ops::Add;
use std::ops::Sub;

#[derive(Copy, Clone)]
struct RemotePtr<T> {
    ptr: usize,
    phantom: PhantomData<T>,
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

    /// as_int() in rr
    pub fn as_uint(&self) -> usize {
        self.ptr
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
        let result = self.as_uint() + delta * std::mem::size_of::<T>();
        Self::new_from_val(result)
    }
}

impl<T> Sub<usize> for RemotePtr<T> {
    type Output = Self;

    fn sub(self, delta: usize) -> Self::Output {
        let result = self.as_uint() - delta * std::mem::size_of::<T>();
        Self::new_from_val(result)
    }
}

impl<T, U> Sub<RemotePtr<U>> for RemotePtr<T> {
    type Output = isize;

    fn sub(self, rhs: RemotePtr<U>) -> Self::Output {
        let delta: isize = (self.as_uint() - rhs.as_uint()) as isize;
        delta / std::mem::size_of::<usize>() as isize
    }
}

impl<T> PartialOrd for RemotePtr<T> {
    fn partial_cmp(&self, other: &RemotePtr<T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for RemotePtr<T> {
    fn cmp(&self, other: &RemotePtr<T>) -> Ordering {
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
    fn eq(&self, other: &RemotePtr<T>) -> bool {
        self.ptr == other.ptr
    }
}

impl<T> Eq for RemotePtr<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_test() {
        let a = RemotePtr::<u64>::new();
        assert_eq!(0, a.as_uint());
    }

    #[test]
    fn add_test() {
        let a = RemotePtr::<u64>::new();
        let b = a + 1;
        assert_eq!(8, b.as_uint());
    }

    #[test]
    fn add_test_with_custom_struct() {
        struct S(u64, u64);
        let a = RemotePtr::<S>::new();
        let b = a + 1;
        assert_eq!(16, b.as_uint());
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
        let b = a + 1;
        let c = b - 1;
        assert_eq!(0, c.as_uint());
    }

    #[test]
    fn sub_with_different_test() {
        struct S(u64, u64);
        let a = RemotePtr::<u64>::new_from_val(8);
        let b = RemotePtr::<S>::new_from_val(96);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(11, b - a);
        #[cfg(target_arch = "x86")]
        assert_eq!(22, b - a);
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
        assert!(a == a);
        assert!(a == a.clone());
        assert!(c < d);
        assert!(d > c);
        assert!(c != d);
    }
}
