use crate::remote_code_ptr::RemoteCodePtr;
use std::{
    cmp::Ordering,
    convert::TryInto,
    fmt::{Display, Formatter, Result},
    marker::PhantomData,
    ops::{Add, AddAssign, Sub, SubAssign},
};

/// Useful alias.
pub type Void = u8;

macro_rules! remote_ptr_field {
    ($remote_ptr:expr, $struct_name:path, $struct_member:ident) => {
        $remote_ptr.as_rptr_u8() + offset_of!($struct_name, $struct_member)
    };
}

#[derive(Hash, Debug)]
/// Manually derive Copy, Clone due to quirks with PhantomData
pub struct RemotePtr<T> {
    ptr: usize,
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
            ptr: 0,
            phantom: PhantomData,
        }
    }
}

impl<T> RemotePtr<T> {
    pub fn null() -> RemotePtr<T> {
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

    pub fn to_code_ptr(self) -> RemoteCodePtr {
        RemoteCodePtr::from_val(self.ptr)
    }

    pub fn as_rptr_u8(self) -> RemotePtr<u8> {
        RemotePtr::<u8>::new_from_val(self.ptr)
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

impl<T> Add<u32> for RemotePtr<T> {
    type Output = Self;

    fn add(self, delta: u32) -> Self::Output {
        // Will automatically deal with overflow in debug mode.
        let result: usize = self.as_usize() + (delta as usize) * std::mem::size_of::<T>();
        Self::new_from_val(result)
    }
}

impl<T> Add<isize> for RemotePtr<T> {
    type Output = Self;

    fn add(self, delta: isize) -> Self::Output {
        if delta < 0 {
            return Sub::<usize>::sub(self, delta.abs() as usize);
        }
        let result: usize = self.as_usize() + (delta as usize) * std::mem::size_of::<T>();
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

impl<T> Sub<u32> for RemotePtr<T> {
    type Output = Self;

    fn sub(self, delta: u32) -> Self::Output {
        // Will automatically deal with underflow in debug mode.
        let result: usize = self.as_usize() - (delta as usize) * std::mem::size_of::<T>();
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

/// NOTE: This method can fail due to the try_into().
/// However this should be OK in almost all cases.
impl<T> From<u64> for RemotePtr<T> {
    fn from(addr: u64) -> Self {
        RemotePtr::<T>::new_from_val(addr.try_into().unwrap())
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
