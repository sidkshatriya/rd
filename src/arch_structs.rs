#![allow(non_camel_case_types)]

use crate::{
    arch::{Architecture, NativeArch},
    bindings::kernel,
};

#[derive(Copy, Clone)]
pub struct robust_list<Arch: Architecture> {
    pub next: Arch::ptr<robust_list<Arch>>,
}

assert_eq_size!(kernel::robust_list, robust_list<NativeArch>);
assert_eq_align!(kernel::robust_list, robust_list<NativeArch>);

#[derive(Copy, Clone)]
pub struct robust_list_head<Arch: Architecture> {
    pub list: robust_list<Arch>,
    pub futex_offset: Arch::signed_long,
    pub list_op_pending: Arch::ptr<robust_list<Arch>>,
}

assert_eq_size!(kernel::robust_list_head, robust_list_head<NativeArch>);
assert_eq_align!(kernel::robust_list_head, robust_list_head<NativeArch>);
