#![allow(non_camel_case_types)]

use crate::{
    arch,
    arch::{Architecture, NativeArch},
    bindings::{kernel, kernel::sock_filter, signal},
    kernel_abi::{common, Ptr},
};
use std::mem::{self, size_of};

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

impl<Arch: Architecture> Default for siginfo_t<Arch> {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

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

// @TODO: "The corresponding header requires -fpermissive, which we don't pass. Skip this check"
// assert_eq_size!(kernel::ipt_replace, ipt_replace<NativeArch>);
// assert_eq_align!(kernel::ipt_replace, ipt_replace<NativeArch>);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct __sysctl_args<Arch: Architecture> {
    pub name: Ptr<Arch::unsigned_word, i32>,
    pub nlen: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub oldval: Ptr<Arch::unsigned_word, u8>,
    pub oldlenp: Ptr<Arch::unsigned_word, Arch::size_t>,
    pub newval: Ptr<Arch::unsigned_word, u8>,
    pub newlen: Ptr<Arch::unsigned_word, Arch::size_t>,
    pub __rd_unused: [Arch::unsigned_long; 4],
}

assert_eq_size!(kernel::__sysctl_args, __sysctl_args<NativeArch>);
assert_eq_align!(kernel::__sysctl_args, __sysctl_args<NativeArch>);

#[repr(C)]
pub struct sockaddr<Arch: Architecture> {
    pub sa_family: Arch::unsigned_short,
    pub sa_data: [u8; 14],
}

assert_eq_size!(kernel::sockaddr, sockaddr<NativeArch>);
assert_eq_align!(kernel::sockaddr, sockaddr<NativeArch>);

impl<Arch: Architecture> Clone for sockaddr<Arch> {
    fn clone(&self) -> Self {
        Self {
            sa_family: self.sa_family,
            sa_data: self.sa_data,
        }
    }
}

impl<Arch: Architecture> Copy for sockaddr<Arch> {}

#[repr(C)]
pub struct ifmap<Arch: Architecture> {
    pub mem_start: Arch::unsigned_long,
    pub mem_end: Arch::unsigned_long,
    pub base_addr: Arch::unsigned_short,
    pub irq: u8,
    pub dma: u8,
    pub port: u8,
}

assert_eq_size!(kernel::ifmap, ifmap<NativeArch>);
assert_eq_align!(kernel::ifmap, ifmap<NativeArch>);

impl<Arch: Architecture> Clone for ifmap<Arch> {
    fn clone(&self) -> Self {
        Self {
            mem_start: self.mem_start,
            mem_end: self.mem_end,
            base_addr: self.base_addr,
            irq: self.irq,
            dma: self.dma,
            port: self.dma,
        }
    }
}

impl<Arch: Architecture> Copy for ifmap<Arch> {}

#[repr(C)]
pub union ifs_ifsu<Arch: Architecture> {
    pub raw_hdlc: Ptr<Arch::unsigned_word, u8>,
    pub cisco: Ptr<Arch::unsigned_word, u8>,
    pub fr: Ptr<Arch::unsigned_word, u8>,
    pub fr_pvc: Ptr<Arch::unsigned_word, u8>,
    pub fr_pvc_info: Ptr<Arch::unsigned_word, u8>,
    pub sync: Ptr<Arch::unsigned_word, u8>,
    pub tel: Ptr<Arch::unsigned_word, u8>,
}

impl<Arch: Architecture> Clone for ifs_ifsu<Arch> {
    fn clone(&self) -> Self {
        Self {
            tel: unsafe { self.tel },
        }
    }
}

impl<Arch: Architecture> Copy for ifs_ifsu<Arch> {}

#[repr(C)]
pub struct if_settings<Arch: Architecture> {
    pub type_: u32,
    pub size: u32,
    pub ifs_ifsu: ifs_ifsu<Arch>,
}

assert_eq_size!(kernel::if_settings, if_settings<NativeArch>);
assert_eq_align!(kernel::if_settings, if_settings<NativeArch>);

impl<Arch: Architecture> Clone for if_settings<Arch> {
    fn clone(&self) -> Self {
        Self {
            type_: self.type_,
            size: self.size,
            ifs_ifsu: self.ifs_ifsu,
        }
    }
}

impl<Arch: Architecture> Copy for if_settings<Arch> {}

#[repr(C)]
pub union ifr_ifru<Arch: Architecture> {
    pub ifru_addr: sockaddr<Arch>,
    pub ifru_dstaddr: sockaddr<Arch>,
    pub ifru_broadaddr: sockaddr<Arch>,
    pub ifru_netmask: sockaddr<Arch>,
    pub ifru_hwaddr: sockaddr<Arch>,
    pub ifru_flags: Arch::signed_short,
    pub ifru_ivalue: i32,
    pub ifru_mtu: i32,
    pub ifru_map: ifmap<Arch>,
    pub ifru_slave: [u8; 16],
    pub ifru_newname: [u8; 16],
    pub ifru_data: Ptr<Arch::unsigned_word, u8>,
    pub ifru_settings: if_settings<Arch>,
}

impl<Arch: Architecture> Clone for ifr_ifru<Arch> {
    fn clone(&self) -> Self {
        Self {
            ifru_slave: unsafe { self.ifru_slave },
        }
    }
}

impl<Arch: Architecture> Copy for ifr_ifru<Arch> {}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifr_ifrn {
    pub ifrn_name: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq<Arch: Architecture> {
    pub ifr_ifrn: ifr_ifrn,
    pub ifr_ifru: ifr_ifru<Arch>,
}

assert_eq_size!(kernel::ifreq, ifreq<NativeArch>);
assert_eq_align!(kernel::ifreq, ifreq<NativeArch>);

#[repr(C)]
pub union ifc_ifcu<Arch: Architecture> {
    pub ifcu_buf: Ptr<Arch::unsigned_word, u8>,
    pub ifcu_req: Ptr<Arch::unsigned_word, ifreq<Arch>>,
}

impl<Arch: Architecture> Clone for ifc_ifcu<Arch> {
    fn clone(&self) -> Self {
        Self {
            ifcu_buf: unsafe { self.ifcu_buf },
        }
    }
}

impl<Arch: Architecture> Copy for ifc_ifcu<Arch> {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifconf<Arch: Architecture> {
    pub ifc_len: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub ifc_ifcu: ifc_ifcu<Arch>,
}

assert_eq_size!(kernel::ifconf, ifconf<NativeArch>);
assert_eq_align!(kernel::ifconf, ifconf<NativeArch>);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct sg_io_hdr<Arch: Architecture> {
    pub interface_id: i32,
    pub dxfer_direction: i32,
    pub cmd_len: u8,
    pub mx_sb_len: u8,
    pub iovec_count: Arch::unsigned_short,
    pub dxfer_len: u32,
    pub dxferp: Ptr<Arch::unsigned_word, u8>,
    pub cmdp: Ptr<Arch::unsigned_word, u8>,
    pub sbp: Ptr<Arch::unsigned_word, u8>,
    pub timeout: u32,
    pub flags: u32,
    pub pack_id: i32,
    pub usr_ptr: Ptr<Arch::unsigned_word, u8>,
    pub status: u8,
    pub masked_status: u8,
    pub msg_status: u8,
    pub sb_len_wr: u8,
    pub host_status: Arch::unsigned_short,
    pub driver_status: Arch::unsigned_short,
    pub resid: i32,
    pub duration: u32,
    pub info: u32,
}

assert_eq_size!(kernel::sg_io_hdr, sg_io_hdr<NativeArch>);
assert_eq_align!(kernel::sg_io_hdr, sg_io_hdr<NativeArch>);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iw_param {
    pub value: i32,
    pub fixed: u8,
    pub disabled: u8,
    pub flags: u16,
}

assert_eq_size!(kernel::iw_param, iw_param);
assert_eq_align!(kernel::iw_param, iw_param);

#[repr(C)]
pub struct iw_point<Arch: Architecture> {
    pub pointer: Ptr<Arch::unsigned_word, u8>,
    pub length: u16,
    pub flags: u16,
}

assert_eq_size!(kernel::iw_point, iw_point<NativeArch>);
assert_eq_align!(kernel::iw_point, iw_point<NativeArch>);

impl<Arch: Architecture> Clone for iw_point<Arch> {
    fn clone(&self) -> Self {
        Self {
            pointer: self.pointer,
            length: self.length,
            flags: self.flags,
        }
    }
}

impl<Arch: Architecture> Copy for iw_point<Arch> {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iw_freq {
    pub m: i32,
    pub e: i16,
    pub i: u8,
    pub flags: u8,
}

assert_eq_size!(kernel::iw_freq, iw_freq);
assert_eq_align!(kernel::iw_freq, iw_freq);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iw_quality {
    pub qual: u8,
    pub level: u8,
    pub noise: u8,
    pub updated: u8,
}
assert_eq_size!(kernel::iw_quality, iw_quality);
assert_eq_align!(kernel::iw_quality, iw_quality);

#[repr(C)]
pub union iwreq_data<Arch: Architecture> {
    pub name: [u8; 16],
    pub essid: iw_point<Arch>,
    pub nwid: iw_param,
    pub freq: iw_freq,
    pub sens: iw_param,
    pub bitrate: iw_param,
    pub txpower: iw_param,
    pub rts: iw_param,
    pub frag: iw_param,
    pub mode: u32,
    pub retry: iw_param,
    pub encoding: iw_point<Arch>,
    pub power: iw_param,
    pub qual: iw_quality,
    pub ap_addr: sockaddr<Arch>,
    pub addr: sockaddr<Arch>,
    pub param: iw_param,
    pub data: iw_point<Arch>,
}

assert_eq_size!(kernel::iwreq_data, iwreq_data<NativeArch>);
assert_eq_align!(kernel::iwreq_data, iwreq_data<NativeArch>);

impl<Arch: Architecture> Clone for iwreq_data<Arch> {
    fn clone(&self) -> Self {
        Self {
            name: unsafe { self.name },
        }
    }
}

impl<Arch: Architecture> Copy for iwreq_data<Arch> {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct iwreq<Arch: Architecture> {
    pub ifr_ifrn: ifr_ifrn,
    pub u: iwreq_data<Arch>,
}

assert_eq_size!(kernel::iwreq, iwreq<NativeArch>);
assert_eq_align!(kernel::iwreq, iwreq<NativeArch>);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct linux_dirent<Arch: Architecture> {
    pub d_ino: Arch::ino_t,
    pub d_off: Arch::off_t,
    pub d_reclen: u16,
    /// Variable length
    pub d_name: [u8; 1],
    // Other stuff like d_type and pad
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct linux_dirent64 {
    pub d_ino: arch::ino64_t,
    pub d_off: arch::off64_t,
    pub d_reclen: u16,
    pub d_type: u8,
    /// Variable length
    pub d_name: [u8; 1],
}

#[repr(C)]
pub struct connect_args<Arch: Architecture> {
    pub sockfd: Arch::signed_long,
    pub addr: Ptr<Arch::unsigned_word, u8>,
    pub addrlen: common::socklen_t,
}

#[repr(C)]
pub struct getsockopt_args<Arch: Architecture> {
    pub sockfd: i32,
    pub level: i32,
    pub optname: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub optval: Ptr<Arch::unsigned_word, u8>,
    pub optlen: Ptr<Arch::unsigned_word, common::socklen_t>,
}

#[repr(C)]
pub struct socketpair_args<Arch: Architecture> {
    pub domain: i32,
    pub type_: i32,
    pub protocol: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub sv: Ptr<Arch::unsigned_word, i32>, // int sv[2]
}

#[repr(C)]
pub struct getsockname_args<Arch: Architecture> {
    pub sockfd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub addr: Ptr<Arch::unsigned_word, sockaddr<Arch>>,
    pub addrlen: Ptr<Arch::unsigned_word, common::socklen_t>,
}

#[repr(C)]
pub struct recv_args<Arch: Architecture> {
    pub sockfd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub buf: Ptr<Arch::unsigned_word, u8>,
    pub len: Arch::size_t,
    pub flags: i32,
}

#[repr(C)]
pub struct recvfrom_args<Arch: Architecture> {
    pub sockfd: Arch::signed_long,
    pub buf: Ptr<Arch::unsigned_word, u8>,
    pub len: Arch::size_t,
    pub flags: Arch::signed_long,
    pub src_addr: Ptr<Arch::unsigned_word, sockaddr<Arch>>,
    pub addrlen: Ptr<Arch::unsigned_word, common::socklen_t>,
}

#[repr(C)]
pub struct accept_args<Arch: Architecture> {
    pub sockfd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub addr: Ptr<Arch::unsigned_word, sockaddr<Arch>>,
    pub addrlen: Ptr<Arch::unsigned_word, common::socklen_t>,
}

#[repr(C)]
pub struct accept4_args<Arch: Architecture> {
    pub sockfd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub addr: Ptr<Arch::unsigned_word, sockaddr<Arch>>,
    pub addrlen: Ptr<Arch::unsigned_word, common::socklen_t>,
    pub flags: Arch::signed_long,
}

#[repr(C)]
pub struct sendmsg_args<Arch: Architecture> {
    pub fd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub msg: Ptr<Arch::unsigned_word, msghdr<Arch>>,
    pub flags: i32,
}

#[repr(C)]
pub struct sendmmsg_args<Arch: Architecture> {
    pub sockfd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub msgvec: Ptr<Arch::unsigned_word, mmsghdr<Arch>>,
    pub vlen: u32,
    pub flags: u32,
}

#[repr(C)]
pub struct recvmsg_args<Arch: Architecture> {
    pub fd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub msg: Ptr<Arch::unsigned_word, msghdr<Arch>>,
    pub flags: i32,
}

#[repr(C)]
pub struct recvmmsg_args<Arch: Architecture> {
    pub sockfd: i32,
    pub __pad: Arch::STD_PAD_ARR,
    pub msgvec: Ptr<Arch::unsigned_word, mmsghdr<Arch>>,
    pub vlen: u32,
    pub flags: u32,
    pub timeout: Ptr<Arch::unsigned_word, Arch::timespec>,
}

///  Some ipc calls require 7 params, so two of them are stashed into
///  one of these structs and a pointer to this is passed instead.
pub struct ipc_kludge_args<Arch: Architecture> {
    pub msgbuf: Ptr<Arch::unsigned_word, u8>,
    pub msgtype: Arch::signed_long,
}

#[repr(C)]
pub struct usbdevfs_ioctl<Arch: Architecture> {
    pub ifno: i32,
    pub ioctl_code: i32,
    pub data: Ptr<Arch::unsigned_word, u8>,
}

assert_eq_size!(kernel::usbdevfs_ioctl, usbdevfs_ioctl<NativeArch>);
assert_eq_align!(kernel::usbdevfs_ioctl, usbdevfs_ioctl<NativeArch>);

#[repr(C)]
#[allow(non_snake_case)]
pub struct usbdevfs_ctrltransfer<Arch: Architecture> {
    pub bRequestType: u8,
    pub bRequest: u8,
    pub wValue: u16,
    pub wIndex: u16,
    pub wLength: u16,
    pub timeout: u32,
    pub data: Ptr<Arch::unsigned_word, u8>,
}

assert_eq_size!(
    kernel::usbdevfs_ctrltransfer,
    usbdevfs_ctrltransfer<NativeArch>
);
assert_eq_align!(
    kernel::usbdevfs_ctrltransfer,
    usbdevfs_ctrltransfer<NativeArch>
);

#[repr(C)]
pub struct v4l2_timecode {
    pub type_: u32,
    pub flags: u32,
    pub frames: u8,
    pub seconds: u8,
    pub minutes: u8,
    pub hours: u8,
    pub userbits: [u8; 4],
}

assert_eq_size!(kernel::v4l2_timecode, v4l2_timecode);
assert_eq_align!(kernel::v4l2_timecode, v4l2_timecode);

#[repr(C)]
pub union v4l2_m<Arch: Architecture> {
    pub offset: u32,
    pub userptr: Arch::unsigned_long,
    pub planes: Ptr<Arch::unsigned_word, u8>,
    pub fd: i32,
}

#[repr(C)]
pub struct v4l2_buffer<Arch: Architecture> {
    pub index: u32,
    pub type_: u32,
    pub bytesused: u32,
    pub flags: u32,
    pub field: u32,
    pub __pad: Arch::STD_PAD_ARR,
    pub timestamp: Arch::timeval,
    pub timecode: v4l2_timecode,
    pub sequence: u32,
    pub memory: u32,
    pub m: v4l2_m<Arch>,
    pub length: u32,
    pub reserved2: u32,
    pub reserved: u32,
}

assert_eq_size!(kernel::v4l2_buffer, v4l2_buffer<NativeArch>);
assert_eq_align!(kernel::v4l2_buffer, v4l2_buffer<NativeArch>);

#[repr(C)]
pub struct usbdevfs_urb<Arch: Architecture> {
    pub type_: u8,
    pub endpoint: u8,
    pub status: i32,
    pub flags: u32,
    pub buffer: Ptr<Arch::unsigned_word, u8>,
    pub buffer_length: i32,
    pub actual_length: i32,
    pub start_frame: i32,
    pub usbdevfs_urb_u: usbdevfs_urb_u,
    pub error_count: i32,
    pub signr: u32,
    pub usercontext: Ptr<Arch::unsigned_word, u8>,
    pub iso_frame_desc: [usbdevfs_iso_packet_desc; 0],
}

assert_eq_size!(kernel::usbdevfs_urb, usbdevfs_urb<NativeArch>);
assert_eq_align!(kernel::usbdevfs_urb, usbdevfs_urb<NativeArch>);

#[repr(C)]
pub union usbdevfs_urb_u {
    pub number_of_packets: i32,
    pub stream_id: u32,
}

#[repr(C)]
#[derive(Clone)]
pub struct usbdevfs_iso_packet_desc {
    pub length: u32,
    pub actual_length: u32,
    pub status: u32,
}

assert_eq_size!(kernel::usbdevfs_iso_packet_desc, usbdevfs_iso_packet_desc);
assert_eq_align!(kernel::usbdevfs_iso_packet_desc, usbdevfs_iso_packet_desc);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct bpf_attr_u1 {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub inner_map_fd: u32,
    pub numa_node: u32,
    pub map_name: [u8; 16],
    pub map_ifindex: u32,
    pub btf_fd: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr_u2_u1 {
    pub value: common::ptr64<u8>,
    pub next_key: common::ptr64<u8>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_attr_u2 {
    pub map_fd: u32,
    pub key: common::ptr64<u8>,
    pub bpf_attr_u2_u1: bpf_attr_u2_u1,
    pub flags: u64,
}

#[repr(C, align(8))]
#[derive(Copy, Clone, Default)]
pub struct aligned_u64 {
    pub __val: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct bpf_attr_u3 {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: common::ptr64<u8>,
    pub license: common::ptr64<u8>,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: common::ptr64<char>,
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; 16],
    pub prog_ifindex: u32,
    pub expected_attach_type: u32,
    pub prog_btf_fd: u32,
    pub func_info_rec_size: u32,
    pub func_info: aligned_u64,
    pub func_info_cnt: u32,
    pub line_info_rec_size: u32,
    pub line_info: aligned_u64,
    pub line_info_cnt: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union bpf_attr {
    pub bpf_attr_u1: bpf_attr_u1,
    pub bpf_attr_u2: bpf_attr_u2,
    pub bpf_attr_u3: bpf_attr_u3,
}
