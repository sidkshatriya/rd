#![allow(non_camel_case_types)]

use crate::bindings::kernel;

#[derive(Copy, Clone)]
pub enum SupportedArch {
    X86,
    X86_64,
    // @TODO
    // What about SupportArch_Max?
}

include!(concat!(
    env!("OUT_DIR"),
    "/syscall_helper_functions_generated.rs"
));

#[cfg(target_arch = "x86_64")]
pub const RR_NATIVE_ARCH: SupportedArch = SupportedArch::X86_64;

#[cfg(target_arch = "x86")]
pub const RR_NATIVE_ARCH: SupportedArch = SupportedArch::X86;

macro_rules! rr_arch_function {
    ($func_name:ident, $arch:expr) => {
        match $arch {
            SupportedArch::X86 => crate::x86_arch::$func_name(),
            SupportedArch::X86_64 => crate::x64_arch::$func_name(),
        }
    };
    ($func_name:ident, $arch:expr, $($exp:expr),+) => {
        match $arch {
            SupportedArch::X86 => crate::x86_arch::$func_name($($exp),+),
            SupportedArch::X86_64 => crate::x64_arch::$func_name($($exp),+),
        }
    };
}

pub fn syscall_instruction_length(arch: SupportedArch) -> usize {
    match arch {
        SupportedArch::X86 => 2,
        SupportedArch::X86_64 => 2,
    }
}

const MSGHDR_PADDING_X86: usize = 0;
const MSGHDR_PADDING_X86_64: usize = 4;

#[repr(C)]
pub struct msghdr<ULongT, const MSGHDR_PADDING: usize> {
    pub msg_name: ULongT,
    pub msg_namelen: u32,
    pub _padding: [u8; MSGHDR_PADDING],
    pub msg_iov: ULongT,
    pub msg_iovlen: ULongT,
    pub msg_control: ULongT,
    pub msg_controllen: ULongT,
    pub msg_flags: i32,
}

#[repr(C)]
pub struct cmsghdr<ULongT> {
    pub cmsg_len: ULongT,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}

pub type msghdr_x86 = msghdr<u32, MSGHDR_PADDING_X86>;

#[cfg(target_arch = "x86_64")]
pub type msghdr_x86_64 = msghdr<u64, MSGHDR_PADDING_X86_64>;

#[cfg(target_arch = "x86_64")]
assert_eq_align!(kernel::msghdr, msghdr_x86_64);
#[cfg(target_arch = "x86_64")]
assert_eq_size!(kernel::msghdr, msghdr_x86_64);

#[cfg(target_arch = "x86")]
assert_eq_align!(kernel::msghdr, msghdr_x86);
#[cfg(target_arch = "x86")]
assert_eq_size!(kernel::msghdr, msghdr_x86);
