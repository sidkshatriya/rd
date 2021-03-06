use crate::remote_code_ptr::RemoteCodePtr;
use std::{
    cmp::Ordering,
    convert::TryInto,
    fmt::{Display, Formatter, Result},
    marker::PhantomData,
    num::Wrapping,
    ops::{Add, AddAssign, Sub, SubAssign},
};

/// Useful alias.
pub type Void = u8;

macro_rules! remote_ptr_field {
    ($remote_ptr:expr, $struct_name:path, $struct_member:ident) => {
        $remote_ptr.as_rptr_u8() + offset_of!($struct_name, $struct_member)
    };
}

/// Most operations in RemotePtr are Wrapping.
///
/// This is because many of these operations indirectly originate in the program being
/// recorded/replayed so we must allow overflow/underflow to take place.
///
/// If we don't have Wrapping operations then some tests would fail in rd
/// e.g. clone_bad_stack in debug mode
///
/// Note: This issue is relevant only for debug mode in Rust where operations are checked
/// for overflow/underflow by default. In release mode the operations are unchecked
/// by default so we don't need Wrapping.
///
/// @TODO Clippy complains about Hash been automatically derived while PartialEq
/// being manually defined
#[derive(Hash, Debug)]
/// Manually derive Copy, Clone due to quirks with PhantomData
pub struct RemotePtr<T> {
    ptr: Wrapping<usize>,
    /// Since this struct does not "own" a `T`, upon recommendation of the Rust PhantomData docs,
    /// there is a `PhantomData<*const T>` here and not simply a `PhantomData<T>`.
    /// This also makes sense because this struct is a kind of pointer to `T`.
    phantom: PhantomData<*const T>,
}

impl<T> Clone for RemotePtr<T> {
    fn clone(&self) -> Self {
        RemotePtr {
            ptr: self.ptr,
            phantom: PhantomData,
        }
    }
}

impl<T> Copy for RemotePtr<T> {}

impl<T> Default for RemotePtr<T> {
    fn default() -> Self {
        RemotePtr {
            ptr: Wrapping(0),
            phantom: PhantomData,
        }
    }
}

impl<T> RemotePtr<T> {
    #[inline]
    pub fn null() -> RemotePtr<T> {
        RemotePtr {
            ptr: Wrapping(0),
            phantom: PhantomData,
        }
    }

    #[inline]
    pub fn new(val: usize) -> RemotePtr<T> {
        RemotePtr {
            ptr: Wrapping(val),
            phantom: PhantomData,
        }
    }

    #[inline]
    pub fn as_usize(&self) -> usize {
        self.ptr.0
    }

    /// As the name indicates this is just a cast. No try_into().unwrap() here!
    pub fn as_isize(&self) -> isize {
        self.ptr.0 as isize
    }

    pub fn is_null(&self) -> bool {
        self.ptr.0 == 0
    }

    pub fn referent_size(&self) -> usize {
        std::mem::size_of::<T>()
    }

    pub fn cast<U>(r: RemotePtr<U>) -> RemotePtr<T> {
        Self {
            ptr: r.ptr,
            phantom: PhantomData,
        }
    }

    pub fn to_code_ptr(self) -> RemoteCodePtr {
        RemoteCodePtr::from_val(self.ptr.0)
    }

    pub fn as_rptr_u8(self) -> RemotePtr<u8> {
        RemotePtr::<u8>::new(self.ptr.0)
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
        let result = self.ptr + Wrapping(delta) * Wrapping(std::mem::size_of::<T>());
        Self {
            ptr: result,
            phantom: PhantomData,
        }
    }
}

impl<T> Add<u32> for RemotePtr<T> {
    type Output = Self;

    fn add(self, delta: u32) -> Self::Output {
        let result = self.ptr + Wrapping(delta as usize) * Wrapping(std::mem::size_of::<T>());
        Self {
            ptr: result,
            phantom: PhantomData,
        }
    }
}

impl<T> Add<isize> for RemotePtr<T> {
    type Output = Self;

    fn add(self, delta: isize) -> Self::Output {
        if delta < 0 {
            return Sub::<usize>::sub(self, delta.abs() as usize);
        }
        let result = self.ptr + Wrapping(delta as usize) * Wrapping(std::mem::size_of::<T>());
        Self {
            ptr: result,
            phantom: PhantomData,
        }
    }
}

impl<T> Sub<usize> for RemotePtr<T> {
    type Output = Self;

    fn sub(self, delta: usize) -> Self::Output {
        let result = self.ptr - Wrapping(delta) * Wrapping(std::mem::size_of::<T>());
        Self {
            ptr: result,
            phantom: PhantomData,
        }
    }
}

impl<T> Sub<u32> for RemotePtr<T> {
    type Output = Self;

    fn sub(self, delta: u32) -> Self::Output {
        let result = self.ptr - Wrapping(delta as usize) * Wrapping(std::mem::size_of::<T>());
        Self {
            ptr: result,
            phantom: PhantomData,
        }
    }
}

// ! Note that there is NO impl Add<isize> for RemotePtr<T> and impl Sub<isize> for RemotePtr<T> !

/// Note that the other RemotePtr must have SAME referent type.
impl<T> Sub<RemotePtr<T>> for RemotePtr<T> {
    type Output = usize;

    fn sub(self, rhs: RemotePtr<T>) -> Self::Output {
        let delta = self.ptr - rhs.ptr;
        (delta / Wrapping(std::mem::size_of::<T>())).0
    }
}

impl<T> PartialOrd for RemotePtr<T> {
    fn partial_cmp(&self, other: &RemotePtr<T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for RemotePtr<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ptr.cmp(&other.ptr)
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
        RemotePtr::<T>::new(addr)
    }
}

/// NOTE: This method can fail due to the try_into().
/// However this should be OK in almost all cases.
impl<T> From<u64> for RemotePtr<T> {
    fn from(addr: u64) -> Self {
        RemotePtr::<T>::new(addr.try_into().unwrap())
    }
}

impl<T> From<RemotePtr<T>> for usize {
    fn from(p: RemotePtr<T>) -> Self {
        p.as_usize()
    }
}

impl<T> SubAssign<usize> for RemotePtr<T> {
    fn sub_assign(&mut self, rhs: usize) {
        self.ptr = self.ptr - Wrapping(rhs) * Wrapping(std::mem::size_of::<T>());
    }
}

impl<T> AddAssign<usize> for RemotePtr<T> {
    fn add_assign(&mut self, rhs: usize) {
        self.ptr = self.ptr + Wrapping(rhs) * Wrapping(std::mem::size_of::<T>());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_test() {
        let a = RemotePtr::<u64>::null();
        assert_eq!(0, a.as_usize());
    }

    #[test]
    fn add_test() {
        let a = RemotePtr::<u64>::null();
        let b = a + 1 as usize;
        assert_eq!(8, b.as_usize());
    }

    #[test]
    fn add_test_with_custom_struct() {
        struct S(u64, u64);
        let a = RemotePtr::<S>::null();
        let b = a + 1 as usize;
        assert_eq!(16, b.as_usize());
    }

    #[test]
    fn referent_size_custom_struct() {
        struct S(u64, u64);
        let a = RemotePtr::<S>::null();
        assert_eq!(16, a.referent_size());
    }

    #[test]
    fn add_sub_test() {
        let a = RemotePtr::<u64>::null();
        let b = a + 1 as usize;
        let c = b - 1 as usize;
        assert_eq!(0, c.as_usize());
    }

    #[test]
    fn cast_test() {
        struct S(u64, u64);
        let a = RemotePtr::<u64>::new(8);
        let b = RemotePtr::<S>::cast(a);
        assert_eq!(16, b.referent_size());
        assert_eq!(8, a.referent_size());
    }

    #[test]
    fn comparison_test() {
        struct S(u64, u64);
        let a = RemotePtr::<u64>::new(8);
        let c = RemotePtr::<S>::new(0);
        let d = RemotePtr::<S>::new(16);
        assert_eq!(a, a);
        assert_eq!(a, a.clone());
        assert!(c < d);
        assert!(d > c);
        assert!(c != d);
    }
}
