#![allow(non_camel_case_types)]

use crate::{
    arch::{Architecture, NativeArch},
    bindings::{kernel, kernel::sock_filter, signal},
    kernel_abi::{common, Ptr},
};
use std::mem::size_of;

#[repr(C)]
pub struct robust_list<Arch: Architecture> {
    pub next: Ptr<Arch::unsigned_word, robust_list<Arch>>,
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

#[repr(C)]
pub struct robust_list_head<Arch: Architecture> {
    pub list: robust_list<Arch>,
    pub futex_offset: Arch::signed_long,
    pub list_op_pending: Ptr<Arch::unsigned_word, robust_list<Arch>>,
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
    pub _padding: Arch::FPROG_PAD_ARR,
    pub filter: Ptr<Arch::unsigned_word, sock_filter>,
}

assert_eq_size!(kernel::sock_fprog, sock_fprog<NativeArch>);
assert_eq_align!(kernel::sock_fprog, sock_fprog<NativeArch>);

#[repr(C)]
#[derive(Copy, Clone, Default)]
/// @TODO Any align and size asserts?
pub struct kernel_sigaction<Arch: Architecture> {
    pub k_sa_handler: Ptr<Arch::unsigned_word, u8>,
    pub sa_flags: Arch::unsigned_long,
    pub sa_restorer: Ptr<Arch::unsigned_word, u8>,
    /// This is what it is for x86 and x64 to make things simple
    /// Might this definition cause problems elsewhere e.g. for AArch64?
    pub sa_mask: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
/// @TODO Any align and size asserts?
pub struct mmap_args<Arch: Architecture> {
    pub addr: Ptr<Arch::unsigned_word, u8>,
    pub len: Arch::size_t,
    pub prot: i32,
    pub flags: i32,
    pub fd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub offset: Arch::off_t,
}

#[repr(C)]
pub union sigval_t<Arch: Architecture> {
    pub sival_int: i32,
    pub sival_ptr: Ptr<Arch::unsigned_word, u8>,
}

impl<Arch: Architecture> Clone for sigval_t<Arch> {
    fn clone(&self) -> Self {
        unsafe {
            sigval_t {
                sival_ptr: self.sival_ptr,
            }
        }
    }
}

impl<Arch: Architecture> Copy for sigval_t<Arch> {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct siginfo_kill {
    pub si_pid_: common::pid_t,
    pub si_uid_: common::uid_t,
}

#[repr(C)]
pub struct siginfo_timer<Arch: Architecture> {
    pub si_tid_: i32,
    pub si_overrun_: i32,
    pub si_sigval_: sigval_t<Arch>,
}

impl<Arch: Architecture> Clone for siginfo_timer<Arch> {
    fn clone(&self) -> Self {
        siginfo_timer {
            si_tid_: self.si_tid_,
            si_overrun_: self.si_overrun_,
            si_sigval_: self.si_sigval_,
        }
    }
}

impl<Arch: Architecture> Copy for siginfo_timer<Arch> {}

#[repr(C)]
pub struct siginfo_rt<Arch: Architecture> {
    pub si_pid_: common::pid_t,
    pub si_uid_: common::uid_t,
    pub si_sigval_: sigval_t<Arch>,
}

impl<Arch: Architecture> Clone for siginfo_rt<Arch> {
    fn clone(&self) -> Self {
        siginfo_rt {
            si_pid_: self.si_pid_,
            si_uid_: self.si_uid_,
            si_sigval_: self.si_sigval_,
        }
    }
}

impl<Arch: Architecture> Copy for siginfo_rt<Arch> {}

#[repr(C)]
#[derive(Default)]
pub struct siginfo_sigchld<Arch: Architecture> {
    pub si_pid_: common::pid_t,
    pub si_uid_: common::uid_t,
    pub si_status_: i32,
    pub si_utime_: Arch::sigchld_clock_t,
    pub si_stime_: Arch::sigchld_clock_t,
}

impl<Arch: Architecture> Clone for siginfo_sigchld<Arch> {
    fn clone(&self) -> Self {
        siginfo_sigchld {
            si_pid_: self.si_pid_,
            si_uid_: self.si_uid_,
            si_status_: self.si_status_,
            si_utime_: self.si_utime_,
            si_stime_: self.si_stime_,
        }
    }
}

impl<Arch: Architecture> Copy for siginfo_sigchld<Arch> {}

#[repr(C)]
#[derive(Default)]
pub struct siginfo_sigfault<Arch: Architecture> {
    pub si_addr_: Ptr<Arch::unsigned_word, u8>,
    pub si_addr_lsb_: Arch::signed_short,
}

impl<Arch: Architecture> Clone for siginfo_sigfault<Arch> {
    fn clone(&self) -> Self {
        siginfo_sigfault {
            si_addr_: self.si_addr_,
            si_addr_lsb_: self.si_addr_lsb_,
        }
    }
}

impl<Arch: Architecture> Copy for siginfo_sigfault<Arch> {}

#[repr(C)]
#[derive(Default)]
pub struct siginfo_sigpoll<Arch: Architecture> {
    pub si_band_: Arch::signed_long,
    pub si_fd_: i32,
}

impl<Arch: Architecture> Clone for siginfo_sigpoll<Arch> {
    fn clone(&self) -> Self {
        siginfo_sigpoll {
            si_band_: self.si_band_,
            si_fd_: self.si_fd_,
        }
    }
}

impl<Arch: Architecture> Copy for siginfo_sigpoll<Arch> {}

#[repr(C)]
#[derive(Default)]
pub struct siginfo_sigsys<Arch: Architecture> {
    pub _call_addr: Ptr<Arch::unsigned_word, u8>,
    pub _syscall: i32,
    pub _arch: u32,
}

impl<Arch: Architecture> Clone for siginfo_sigsys<Arch> {
    fn clone(&self) -> Self {
        siginfo_sigsys {
            _call_addr: self._call_addr,
            _syscall: self._syscall,
            _arch: self._arch,
        }
    }
}

impl<Arch: Architecture> Copy for siginfo_sigsys<Arch> {}

#[repr(C)]
pub union siginfo_sifields<Arch: Architecture> {
    pub padding: Arch::SIGINFO_PADDING_ARR,
    pub _kill: siginfo_kill,
    pub _timer: siginfo_timer<Arch>,
    pub _rt: siginfo_rt<Arch>,
    pub _sigchld: siginfo_sigchld<Arch>,
    pub _sigfault: siginfo_sigfault<Arch>,
    pub _sigpoll: siginfo_sigpoll<Arch>,
    pub _sigsys: siginfo_sigsys<Arch>,
}

impl<Arch: Architecture> Clone for siginfo_sifields<Arch> {
    fn clone(&self) -> Self {
        unsafe {
            siginfo_sifields {
                padding: self.padding,
            }
        }
    }
}

impl<Arch: Architecture> Copy for siginfo_sifields<Arch> {}

#[repr(C)]
pub struct siginfo_t<Arch: Architecture> {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _sifields: siginfo_sifields<Arch>,
}

impl<Arch: Architecture> Clone for siginfo_t<Arch> {
    fn clone(&self) -> Self {
        siginfo_t {
            si_signo: self.si_signo,
            si_errno: self.si_errno,
            si_code: self.si_code,
            _sifields: self._sifields,
        }
    }
}

impl<Arch: Architecture> Copy for siginfo_t<Arch> {}

assert_eq_size!(kernel::siginfo_t, siginfo_t<NativeArch>);
assert_eq_align!(kernel::siginfo_t, siginfo_t<NativeArch>);

// Not necessary as these are also generated by bindgen but just to be safe
assert_eq_size!(signal::siginfo_t, siginfo_t<NativeArch>);
assert_eq_align!(signal::siginfo_t, siginfo_t<NativeArch>);

#[repr(C)]
#[derive(Copy, Default)]
pub struct iovec<Arch: Architecture> {
    pub iov_base: Ptr<Arch::unsigned_word, u8>,
    pub iov_len: Arch::size_t,
}

impl<Arch: Architecture> Clone for iovec<Arch> {
    fn clone(&self) -> Self {
        Self {
            iov_base: self.iov_base,
            iov_len: self.iov_len,
        }
    }
}

assert_eq_size!(kernel::iovec, iovec<NativeArch>);
assert_eq_align!(kernel::iovec, iovec<NativeArch>);

#[repr(C)]
#[derive(Copy, Default)]
pub struct msghdr<Arch: Architecture> {
    pub msg_name: Ptr<Arch::unsigned_word, u8>,
    pub msg_namelen: common::socklen_t,
    pub _padding: Arch::STD_PAD_ARR,

    pub msg_iov: Ptr<Arch::unsigned_word, iovec<Arch>>,
    pub msg_iovlen: Arch::size_t,

    pub msg_control: Ptr<Arch::unsigned_word, u8>,
    pub msg_controllen: Arch::size_t,

    pub msg_flags: i32,
}

impl<Arch: Architecture> Clone for msghdr<Arch> {
    fn clone(&self) -> Self {
        Self {
            msg_name: self.msg_name,
            msg_namelen: self.msg_namelen,
            _padding: self._padding,
            msg_iov: self.msg_iov,
            msg_iovlen: self.msg_iovlen,
            msg_control: self.msg_control,
            msg_controllen: self.msg_controllen,
            msg_flags: self.msg_flags,
        }
    }
}

assert_eq_size!(kernel::msghdr, msghdr<NativeArch>);
assert_eq_align!(kernel::msghdr, msghdr<NativeArch>);

#[repr(C)]
#[derive(Copy, Default)]
pub struct mmsghdr<Arch: Architecture> {
    pub msg_hdr: msghdr<Arch>,
    pub msg_len: u32,
}

impl<Arch: Architecture> Clone for mmsghdr<Arch> {
    fn clone(&self) -> Self {
        Self {
            msg_hdr: self.msg_hdr.clone(),
            msg_len: self.msg_len,
        }
    }
}

assert_eq_size!(kernel::mmsghdr, mmsghdr<NativeArch>);
assert_eq_align!(kernel::mmsghdr, mmsghdr<NativeArch>);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct cmsghdr<Arch: Architecture> {
    pub cmsg_len: Arch::size_t,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}

assert_eq_size!(kernel::cmsghdr, cmsghdr<NativeArch>);
assert_eq_align!(kernel::cmsghdr, cmsghdr<NativeArch>);

pub fn cmsg_data_offset<Arch: Architecture>() -> usize {
    cmsg_align::<Arch>(size_of::<cmsghdr<Arch>>())
}

pub fn cmsg_align<Arch: Architecture>(len: usize) -> usize {
    (len + size_of::<Arch::size_t>() - 1) & !(size_of::<Arch::size_t>() - 1)
}

pub fn cmsg_space<Arch: Architecture>(len: usize) -> usize {
    cmsg_align::<Arch>(size_of::<cmsghdr<Arch>>()) + cmsg_align::<Arch>(len)
}

pub fn cmsg_len<Arch: Architecture>(len: usize) -> usize {
    cmsg_align::<Arch>(size_of::<cmsghdr<Arch>>()) + len
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct pselect6_arg6<Arch: Architecture> {
    pub ss: Ptr<Arch::unsigned_word, Arch::kernel_sigset_t>,
    pub ss_len: Arch::size_t,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct select_args<Arch: Architecture> {
    pub n_fds: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub read_fds: Ptr<Arch::unsigned_word, Arch::fd_set>,
    pub write_fds: Ptr<Arch::unsigned_word, Arch::fd_set>,
    pub except_fds: Ptr<Arch::unsigned_word, Arch::fd_set>,
    pub timeout: Ptr<Arch::unsigned_word, Arch::timeval>,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct __user_cap_header_struct {
    pub version: u32,
    pub pid: i32,
}

assert_eq_size!(kernel::__user_cap_header_struct, __user_cap_header_struct);
assert_eq_align!(kernel::__user_cap_header_struct, __user_cap_header_struct);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct __user_cap_data_struct {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

assert_eq_size!(kernel::__user_cap_data_struct, __user_cap_data_struct);
assert_eq_align!(kernel::__user_cap_data_struct, __user_cap_data_struct);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct xt_counters {
    pub pcnt: u64,
    pub bcnt: u64,
}

assert_eq_size!(kernel::xt_counters, xt_counters);
assert_eq_align!(kernel::xt_counters, xt_counters);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct setsockopt_args<Arch: Architecture> {
    pub sockfd: Arch::signed_long,
    pub level: Arch::signed_long,
    pub optname: Arch::signed_long,
    pub optval: Ptr<Arch::unsigned_word, u8>,
    pub optlen: Arch::signed_long,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct ipt_replace<Arch: Architecture> {
    pub name: [u8; 32],
    pub valid_hook: u32,
    pub num_entries: u32,
    pub size: u32,
    pub hook_entry: [u32; 5],
    pub underflow: [u32; 5],
    pub num_counters: u32,
    pub counters: Ptr<Arch::unsigned_word, xt_counters>,
    // Plus hangoff here
}
