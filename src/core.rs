use memchr::memchr;
use std::mem::{size_of, zeroed};
use std::ptr::copy_nonoverlapping;
use std::slice::from_raw_parts;

pub fn return_dummy_value<T: Copy>() -> T {
    let mut v: T = unsafe { zeroed() };
    let buf: Vec<u8> = vec![1u8; size_of::<T>()];
    unsafe {
        copy_nonoverlapping(buf.as_ptr(), &mut v as *mut _ as *mut u8, size_of::<T>());
    }
    v
}

pub fn check_type_has_no_holes<T: Copy>() -> bool {
    let mut v: T = unsafe { zeroed() };
    let buf: Vec<u8> = vec![2u8; size_of::<T>()];
    unsafe {
        copy_nonoverlapping(buf.as_ptr(), &mut v as *mut _ as *mut u8, size_of::<T>());
    }
    v = return_dummy_value::<T>();

    let s = unsafe { from_raw_parts(&v as *const _ as *const u8, size_of::<T>()) };
    memchr(2, s).is_none()
}

/// Returns true when type T has no holes. Preferably should not be defined
/// at all otherwise.
/// This is not 100% reliable since the check_type_has_no_holes may be
/// compiled to copy holes. However, it has detected at least two bugs.
pub fn type_has_no_holes<T: Copy>() -> bool {
    unimplemented!()
}

#[cfg(test)]
mod test {
    use crate::core::check_type_has_no_holes;

    #[derive(Copy, Clone)]
    struct S1 {
        a: u16,
        b: u32,
    }
    #[derive(Copy, Clone)]
    struct S2 {
        a: u32,
        b: u32,
    }

    #[test]
    fn check_for_holes() {
        assert!(!check_type_has_no_holes::<S1>());
        assert!(check_type_has_no_holes::<S2>());
    }
}
