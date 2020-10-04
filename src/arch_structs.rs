#![allow(non_camel_case_types)]

use crate::{
    arch::{Architecture, NativeArch},
    bindings::{kernel, kernel::sock_filter},
};

pub struct robust_list<Arch: Architecture> {
    pub next: Arch::ptr<robust_list<Arch>>,
}

/// Had to manually derive Copy and Clone
/// Would not work otherwise
impl<Arch: Architecture> Clone for robust_list<Arch> {
    fn clone(&self) -> Self {
        robust_list { next: self.next }
    }
}

impl<Arch: Architecture> Copy for robust_list<Arch> {}

assert_eq_size!(kernel::robust_list, robust_list<NativeArch>);
assert_eq_align!(kernel::robust_list, robust_list<NativeArch>);

pub struct robust_list_head<Arch: Architecture> {
    pub list: robust_list<Arch>,
    pub futex_offset: Arch::signed_long,
    pub list_op_pending: Arch::ptr<robust_list<Arch>>,
}

/// Had to manually derive Copy and Clone
/// Would not work otherwise
impl<Arch: Architecture> Clone for robust_list_head<Arch> {
    fn clone(&self) -> Self {
        robust_list_head {
            list: self.list,
            futex_offset: self.futex_offset,
            list_op_pending: self.list_op_pending,
        }
    }
}

impl<Arch: Architecture> Copy for robust_list_head<Arch> {}

assert_eq_size!(kernel::robust_list_head, robust_list_head<NativeArch>);
assert_eq_align!(kernel::robust_list_head, robust_list_head<NativeArch>);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sock_fprog<Arch: Architecture> {
    pub len: u16,
    pub _padding: Arch::STD_PAD_ARR,
    pub filter: Arch::ptr<sock_filter>,
}

assert_eq_size!(kernel::sock_fprog, sock_fprog<NativeArch>);
assert_eq_align!(kernel::sock_fprog, sock_fprog<NativeArch>);
