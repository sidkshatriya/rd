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

///////////////////// user_regs_struct
#[cfg(target_arch = "x86_64")]
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
