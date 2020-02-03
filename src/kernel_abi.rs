#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use crate::bindings::kernel;
use crate::remote_ptr::RemotePtr;
use std::convert::TryInto;
use std::marker::PhantomData;

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

struct X86Arch;
#[cfg(target_arch = "x86_64")]
struct X8664Arch;

trait Architecture {}

impl Architecture for X86Arch {}

#[cfg(target_arch = "x86_64")]
impl Architecture for X8664Arch {}

///////////////////// Ptr
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Ptr<ValT: Copy + Clone + Default, ReferentT> {
    val: ValT,
    referent: PhantomData<ReferentT>,
}

impl<ValT: Copy + Clone + Default, ReferentT> Ptr<ValT, ReferentT> {
    pub fn referent_size(&self) -> usize {
        std::mem::size_of::<ReferentT>()
    }
}

impl<ReferentT> Ptr<u32, ReferentT> {
    pub fn rptr(&self) -> RemotePtr<ReferentT> {
        RemotePtr::new_from_val(self.val as usize)
    }

    pub fn new_from_remote_ptr<T>(r: RemotePtr<T>) -> Ptr<u32, T> {
        let addr = r.as_usize();
        Ptr {
            val: addr.try_into().unwrap(),
            referent: PhantomData,
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl<ReferentT> Ptr<u64, ReferentT> {
    pub fn rptr(&self) -> RemotePtr<ReferentT> {
        RemotePtr::new_from_val(self.val as usize)
    }

    pub fn new_from_remote_ptr<T>(r: RemotePtr<T>) -> Ptr<u64, T> {
        let addr = r.as_usize();
        Ptr {
            val: addr as u64,
            referent: PhantomData,
        }
    }
}

pub type PtrX8664<T> = Ptr<u64, T>;
pub type PtrX86<T> = Ptr<u32, T>;

///////////////////// user_regs_struct
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct user_regs_struct_x86_64 {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    // Unsigned type matches <sys/user.h>, but we need to treat this as
    // signed in practice.
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    // These _base registers are architecturally defined MSRs and really do
    // need to be 64-bit.
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct user_regs_struct_x86 {
    ebx: i32,
    ecx: i32,
    edx: i32,
    esi: i32,
    edi: i32,
    ebp: i32,
    eax: i32,
    xds: i32,
    xes: i32,
    xfs: i32,
    xgs: i32,
    orig_eax: i32,
    eip: i32,
    xcs: i32,
    eflags: i32,
    esp: i32,
    xss: i32,
}

#[cfg(target_arch = "x86_64")]
assert_eq_align!(kernel::user_regs_struct, user_regs_struct_x86_64);
#[cfg(target_arch = "x86_64")]
assert_eq_size!(kernel::user_regs_struct, user_regs_struct_x86_64);

#[cfg(target_arch = "x86")]
assert_eq_align!(kernel::user_regs_struct, user_regs_struct_x86);
#[cfg(target_arch = "x86")]
assert_eq_size!(kernel::user_regs_struct, user_regs_struct_x86);

///////////////////// sigcontext
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct sigcontext_x86_64 {
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    di: u64,
    si: u64,
    bp: u64,
    bx: u64,
    dx: u64,
    ax: u64,
    cx: u64,
    sp: u64,
    ip: u64,
    flags: u64,
    cs: u16,
    gs: u16,
    fs: u16,
    __pad0: u16,
    err: u64,
    trapno: u64,
    oldmask: u64,
    cr2: u64,
    fpstate: u64,
    reserved: [u64; 8],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct sigcontext_x86 {
    gs: u16,
    __gsh: u16,
    fs: u16,
    __fsh: u16,
    es: u16,
    __esh: u16,
    ds: u16,
    __dsh: u16,
    di: u32,
    si: u32,
    bp: u32,
    sp: u32,
    bx: u32,
    dx: u32,
    cx: u32,
    ax: u32,
    trapno: u32,
    err: u32,
    ip: u32,
    cs: u16,
    __csh: u16,
    flags: u16,
    sp_at_signal: u32,
    ss: u16,
    __ssh: u16,
    fpstate: u32,
    oldmask: u32,
    cr2: u32,
}

#[cfg(target_arch = "x86_64")]
assert_eq_align!(kernel::sigcontext, sigcontext_x86_64);
#[cfg(target_arch = "x86_64")]
assert_eq_size!(kernel::sigcontext, sigcontext_x86_64);

#[cfg(target_arch = "x86")]
assert_eq_align!(kernel::sigcontext, sigcontext_x86);
#[cfg(target_arch = "x86")]
assert_eq_size!(kernel::sigcontext, sigcontext_x86);

///////////////////// sigcontext
// @TODO this is packed struct in rr but this causes static assertion issues.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct stat64_x86_64 {
    st_dev: u64,
    __pad1: u32,
    __st_ino: u64,
    st_mode: u32,
    st_nlink: u64,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    __pad2: u32,
    st_size: u64,
    st_blksize: i64,
    st_blocks: i64,
    st_atim: timespec<i64>,
    st_mtim: timespec<i64>,
    st_ctim: timespec<i64>,
    st_ino: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct timespec<SLongT: Copy + Clone> {
    tv_sec: SLongT,
    tv_nsec: SLongT,
}

#[cfg(target_arch = "x86_64")]
assert_eq_align!(kernel::stat64, stat64_x86_64);
#[cfg(target_arch = "x86_64")]
assert_eq_size!(kernel::stat64, stat64_x86_64);

mod common {
    pub type int16_t = i16;
    pub type int32_t = i32;
    pub type int64_t = i64;
    pub type uint8_t = u8;
    pub type uint16_t = u16;
    pub type uint32_t = u32;
    pub type uint64_t = u64;
    pub type __u32 = uint32_t;
    pub type __u64 = uint64_t;
    pub type pid_t = int32_t;
    pub type uid_t = uint32_t;
    pub type gid_t = uint32_t;
    pub type socklen_t = uint32_t;
    pub type dev_t = uint64_t;
    pub type mode_t = uint32_t;
    pub type __kernel_timer_t = int32_t;
    pub type cc_t = u8;
}

mod x86_64 {
    pub use super::common::*;
    use std::marker::PhantomData;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct ptr<T: Copy + Clone> {
        w: usize,
        r: PhantomData<T>,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct ptr64<T: Copy + Clone> {
        w: u64,
        r: PhantomData<T>,
    }

    //////////////////////////////////
    pub type speed_t = unsigned_int;
    pub type tcflag_t = unsigned_int;
    /////////////////////////////////

    pub type signed_short = int16_t;
    pub type unsigned_short = uint16_t;

    pub type signed_int = int32_t;
    pub type unsigned_int = uint32_t;
    pub type int = int32_t;

    pub type signed_long = int64_t;
    pub type unsigned_long = uint64_t;

    pub type signed_word = int64_t;
    pub type unsigned_word = uint64_t;

    pub type size_t = uint64_t;
    pub type ssize_t = int64_t;

    // These really only exist as proper abstractions so that adding x32
    // (x86-64's ILP32 ABI) support is relatively easy.
    pub type syscall_slong_t = int64_t;
    pub type syscall_ulong_t = uint64_t;
    pub type sigchld_clock_t = int64_t;
    pub type __statfs_word = signed_long;

    pub type time_t = syscall_slong_t;
    pub type off_t = syscall_slong_t;
    pub type blkcnt_t = syscall_slong_t;
    pub type blksize_t = syscall_slong_t;
    pub type rlim_t = syscall_ulong_t;
    pub type fsblkcnt_t = syscall_ulong_t;
    pub type fsfilcnt_t = syscall_ulong_t;
    pub type ino_t = syscall_ulong_t;
    pub type nlink_t = syscall_ulong_t;

    pub type off64_t = int64_t;
    pub type loff_t = int64_t;
    pub type rlim64_t = uint64_t;
    pub type ino64_t = uint64_t;
    pub type blkcnt64_t = int64_t;

    pub type clock_t = syscall_slong_t;
    pub type __kernel_key_t = signed_int;
    pub type __kernel_uid32_t = signed_int;
    pub type __kernel_gid32_t = signed_int;
    pub type __kernel_mode_t = unsigned_int;
    pub type __kernel_ulong_t = unsigned_long;
    pub type __kernel_long_t = signed_long;
    pub type __kernel_time_t = __kernel_long_t;
    pub type __kernel_suseconds_t = __kernel_long_t;
    pub type __kernel_pid_t = signed_int;
    pub type __kernel_loff_t = int64_t;

    include!("include/struct_defns.rs");
}
