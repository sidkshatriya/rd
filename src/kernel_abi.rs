#![allow(non_camel_case_types)]

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

trait Architecture {
    type msghdr: Default + Copy + Clone;
    type cmsghdr: Default + Copy + Clone;
    type iovec: Default + Copy + Clone;
    type siginfo_t: Copy + Clone;
}

impl Architecture for X86Arch {
    type msghdr = msghdr_x86;
    type cmsghdr = cmsghdr_x86;
    type iovec = iovec_x86;
    type siginfo_t = siginfo_t_x86;
}

#[cfg(target_arch = "x86_64")]
impl Architecture for X8664Arch {
    type msghdr = msghdr_x86_64;
    type cmsghdr = cmsghdr_x86_64;
    type iovec = iovec_x86_64;
    type siginfo_t = siginfo_t_x86_64;
}

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

///////////////////// msghdr
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct msghdr_x86 {
    pub msg_name: PtrX86<u8>,
    pub msg_namelen: u32,
    pub _padding: [u8; 0],
    pub msg_iov: PtrX86<iovec_x86>,
    pub msg_iovlen: u32,
    pub msg_control: PtrX86<u8>,
    pub msg_controllen: u32,
    pub msg_flags: i32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct msghdr_x86_64 {
    pub msg_name: PtrX8664<u8>,
    pub msg_namelen: u32,
    pub _padding: [u8; 4],
    pub msg_iov: PtrX8664<iovec_x86_64>,
    pub msg_iovlen: u64,
    pub msg_control: PtrX8664<u8>,
    pub msg_controllen: u64,
    pub msg_flags: i32,
}

#[cfg(target_arch = "x86_64")]
assert_eq_align!(kernel::msghdr, msghdr_x86_64);
#[cfg(target_arch = "x86_64")]
assert_eq_size!(kernel::msghdr, msghdr_x86_64);

#[cfg(target_arch = "x86")]
assert_eq_align!(kernel::msghdr, msghdr_x86);
#[cfg(target_arch = "x86")]
assert_eq_size!(kernel::msghdr, msghdr_x86);

///////////////////// cmsghdr
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct cmsghdr<ULongT: Copy + Clone + Default> {
    pub cmsg_len: ULongT,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}

pub type cmsghdr_x86 = cmsghdr<u32>;

#[cfg(target_arch = "x86_64")]
pub type cmsghdr_x86_64 = cmsghdr<u64>;

#[cfg(target_arch = "x86_64")]
assert_eq_align!(kernel::cmsghdr, cmsghdr_x86_64);
#[cfg(target_arch = "x86_64")]
assert_eq_size!(kernel::cmsghdr, cmsghdr_x86_64);

#[cfg(target_arch = "x86")]
assert_eq_align!(kernel::cmsghdr, cmsghdr_x86);
#[cfg(target_arch = "x86")]
assert_eq_size!(kernel::cmsghdr, cmsghdr_x86);

///////////////////// iovec
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct iovec<P: Copy + Clone + Default, ULongT: Copy + Clone + Default> {
    iov_base: P,
    iov_len: ULongT,
}

pub type iovec_x86 = iovec<Ptr<u32, u8>, u32>;

#[cfg(target_arch = "x86_64")]
pub type iovec_x86_64 = iovec<Ptr<u64, u8>, u64>;

#[cfg(target_arch = "x86_64")]
assert_eq_align!(kernel::iovec, iovec_x86_64);
#[cfg(target_arch = "x86_64")]
assert_eq_size!(kernel::iovec, iovec_x86_64);

#[cfg(target_arch = "x86")]
assert_eq_align!(kernel::iovec, iovec_x86);
#[cfg(target_arch = "x86")]
assert_eq_size!(kernel::iovec, iovec_x86);

///////////////////// siginfo_t
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kill {
    si_pid_: i32,
    si_uid_: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct timer<P: Copy + Clone> {
    si_tid_: i32,
    si_overrun_: i32,
    si_sigval_: sigval_t<P>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union sigval_t<P: Copy + Clone> {
    sival_int: i32,
    sival_ptr: P,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct rt<P: Copy + Clone> {
    si_pid_: i32,
    si_uid_: u32,
    si_sigval_: sigval_t<P>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sigchld<SLongT: Copy + Clone> {
    si_pid_: i32,
    si_uid_: u32,
    si_status_: i32,
    si_utime_: SLongT,
    si_stime_: SLongT,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sigfault<P: Copy + Clone> {
    si_addr_: P,
    si_addr_lsb_: i16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sigpoll<SLongT: Copy + Clone> {
    si_band_: SLongT,
    si_fd_: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sigsys<P: Copy + Clone> {
    _call_addr: P,
    _syscall: i32,
    _arch: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union sifields_x86 {
    padding: [i32; 29], // 32: 128/4 - 3 = 29,
    _kill: kill,
    _timer: timer<PtrX86<u8>>,
    _rt: rt<PtrX86<u8>>,
    _sigchld: sigchld<i32>,
    _sigfault: sigfault<PtrX86<u8>>,
    _sigpoll: sigpoll<i32>,
    _sigsys: sigsys<PtrX86<u8>>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union sifields_x86_64 {
    padding: [i32; 28], // 64: 128/4 - 4 = 28
    _kill: kill,
    _timer: timer<PtrX8664<u8>>,
    _rt: rt<PtrX8664<u8>>,
    _sigchld: sigchld<i64>,
    _sigfault: sigfault<PtrX8664<u8>>,
    _sigpoll: sigpoll<i64>,
    _sigsys: sigsys<PtrX8664<u8>>,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct siginfo_t_x86 {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _sifields: sifields_x86,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone)]
struct siginfo_t_x86_64 {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _sifields: sifields_x86_64,
}

#[cfg(target_arch = "x86_64")]
assert_eq_align!(kernel::siginfo_t, siginfo_t_x86_64);
#[cfg(target_arch = "x86_64")]
assert_eq_size!(kernel::siginfo_t, siginfo_t_x86_64);

#[cfg(target_arch = "x86")]
assert_eq_align!(kernel::siginfo_t, siginfo_t_x86);
#[cfg(target_arch = "x86")]
assert_eq_size!(kernel::siginfo_t, siginfo_t_x86);
