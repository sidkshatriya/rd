use memchr::memchr;
use std::any::TypeId;
use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::ptr::copy_nonoverlapping;
use std::slice::from_raw_parts;
use std::sync::Mutex;

lazy_static! {
    static ref CHECK_TYPE_FOR_HOLES: Mutex<HashMap<TypeId, bool>> = Mutex::new(HashMap::new());
}

pub fn return_dummy_value<T>() -> T {
    let mut v: T = unsafe { zeroed() };
    let buf: Vec<u8> = vec![1u8; size_of::<T>()];
    unsafe {
        copy_nonoverlapping(buf.as_ptr(), &raw mut v as *mut u8, size_of::<T>());
    }
    v
}

pub fn check_type_has_no_holes<T>() -> bool {
    let mut v: T = unsafe { zeroed() };
    let buf: Vec<u8> = vec![2u8; size_of::<T>()];
    unsafe {
        copy_nonoverlapping(buf.as_ptr(), &raw mut v as *mut u8, size_of::<T>());
    }
    v = return_dummy_value::<T>();

    let s = unsafe { from_raw_parts(&raw const v as *const u8, size_of::<T>()) };
    memchr(2, s).is_none()
}

/// Returns true when type T has no holes. Preferably should not be defined
/// at all otherwise.
/// This is not 100% reliable since the check_type_has_no_holes may be
/// compiled to copy holes. However, it has detected at least two bugs.
/// @TODO We _could_ require T: Copy also here but it does not seem necessary.
pub fn type_has_no_holes<T: 'static>() -> bool {
    let mut map = CHECK_TYPE_FOR_HOLES.lock().unwrap();
    let result = map.get(&TypeId::of::<T>());
    match result {
        Some(has_hole) => *has_hole,
        None => {
            let result = check_type_has_no_holes::<T>();
            map.insert(TypeId::of::<T>(), result);
            result
        }
    }
}

#[cfg(test)]
mod test {
    use crate::core::{check_type_has_no_holes, type_has_no_holes};

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

    struct S3 {
        a: u16,
        b: u32,
    }
    struct S4 {
        a: u32,
        b: u32,
    }

    #[test]
    fn check_for_holes() {
        assert!(!check_type_has_no_holes::<S1>());
        assert!(check_type_has_no_holes::<S2>());
        assert!(!check_type_has_no_holes::<S3>());
        assert!(check_type_has_no_holes::<S4>());
    }

    #[test]
    fn cached_check_for_holes() {
        assert!(!type_has_no_holes::<S1>());
        assert!(type_has_no_holes::<S2>());
        assert!(!type_has_no_holes::<S1>());
        assert!(type_has_no_holes::<S2>());

        assert!(!type_has_no_holes::<S3>());
        assert!(type_has_no_holes::<S4>());
        assert!(!type_has_no_holes::<S3>());
        assert!(type_has_no_holes::<S4>());
    }
}
