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
#[repr(C, align(8))]
#[derive(Copy, Clone)]
pub struct aligned_u64 {
    pub val: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Ptr<ValT: Copy + Clone, ReferentT> {
    val: ValT,
    referent: PhantomData<ReferentT>,
}

impl<ValT: Copy + Clone, ReferentT> Ptr<ValT, ReferentT> {
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

///////////////////// stat64
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

pub mod common {
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

    pub use super::aligned_u64;
    pub type ptr64<T> = super::Ptr<aligned_u64, T>;
}

pub mod w64 {
    pub use super::common::*;
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
}

#[cfg(target_arch = "x86_64")]
pub mod x86_64 {
    pub use super::w64::*;
    use crate::bindings::kernel;
    pub const SIGINFO_PADDING: usize = 28;

    pub type ptr<T> = super::Ptr<u64, T>;

    // IMPORTANT ! ////////////////////////
    include!("include/base_arch_defns.rs");

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct user_regs_struct {
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

    assert_eq_align!(kernel::user_regs_struct, user_regs_struct);
    assert_eq_size!(kernel::user_regs_struct, user_regs_struct);

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct sigcontext {
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

    assert_eq_align!(kernel::sigcontext, sigcontext);
    assert_eq_size!(kernel::sigcontext, sigcontext);

    assert_eq_size!(kernel::sockaddr, sockaddr);
    assert_eq_align!(kernel::sockaddr, sockaddr);

    assert_eq_size!(kernel::sockaddr_un, sockaddr_un);
    assert_eq_align!(kernel::sockaddr_un, sockaddr_un);

    assert_eq_size!(kernel::timeval, timeval);
    assert_eq_align!(kernel::timeval, timeval);

    assert_eq_size!(kernel::timespec, timespec);
    assert_eq_align!(kernel::timespec, timespec);

    assert_eq_size!(kernel::pollfd, pollfd);
    assert_eq_align!(kernel::pollfd, pollfd);

    assert_eq_size!(kernel::iovec, iovec);
    assert_eq_align!(kernel::iovec, iovec);

    assert_eq_size!(kernel::msghdr, msghdr);
    assert_eq_align!(kernel::msghdr, msghdr);

    assert_eq_size!(kernel::cmsghdr, cmsghdr);
    assert_eq_align!(kernel::cmsghdr, cmsghdr);

    assert_eq_size!(kernel::mmsghdr, mmsghdr);
    assert_eq_align!(kernel::mmsghdr, mmsghdr);

    assert_eq_size!(kernel::rusage, rusage);
    assert_eq_align!(kernel::rusage, rusage);

    assert_eq_size!(kernel::siginfo_t, siginfo_t);
    assert_eq_align!(kernel::siginfo_t, siginfo_t);

    assert_eq_size!(kernel::termios, termios);
    assert_eq_align!(kernel::termios, termios);

    assert_eq_size!(kernel::termio, termio);
    assert_eq_align!(kernel::termio, termio);

    assert_eq_size!(kernel::winsize, winsize);
    assert_eq_align!(kernel::winsize, winsize);

    assert_eq_size!(kernel::ipc64_perm, ipc64_perm);
    assert_eq_align!(kernel::ipc64_perm, ipc64_perm);

    assert_eq_size!(kernel::msqid64_ds, msqid64_ds);
    assert_eq_align!(kernel::msqid64_ds, msqid64_ds);

    assert_eq_size!(kernel::msginfo, msginfo);
    assert_eq_align!(kernel::msginfo, msginfo);

    assert_eq_size!(kernel::shmid64_ds, shmid64_ds);
    // @TODO
    // assert_eq_align!(kernel::shmid64_ds, shmid64_ds);

    assert_eq_size!(kernel::shminfo64, shminfo64);
    assert_eq_align!(kernel::shminfo64, shminfo64);

    assert_eq_size!(kernel::shm_info, shm_info);
    assert_eq_align!(kernel::shm_info, shm_info);

    assert_eq_size!(kernel::semid64_ds, semid64_ds);
    assert_eq_align!(kernel::semid64_ds, semid64_ds);

    assert_eq_size!(kernel::seminfo, seminfo);
    assert_eq_align!(kernel::seminfo, seminfo);

    // @TODO.
    // assert_eq_size!(kernel::user_desc, user_desc);
    // assert_eq_align!(kernel::user_desc, user_desc);

    assert_eq_size!(kernel::__user_cap_header_struct, __user_cap_header_struct);
    assert_eq_align!(kernel::__user_cap_header_struct, __user_cap_header_struct);

    assert_eq_size!(kernel::__user_cap_data_struct, __user_cap_data_struct);
    assert_eq_align!(kernel::__user_cap_data_struct, __user_cap_data_struct);

    assert_eq_size!(kernel::dqblk, dqblk);
    assert_eq_align!(kernel::dqblk, dqblk);

    assert_eq_size!(kernel::dqinfo, dqinfo);
    assert_eq_align!(kernel::dqinfo, dqinfo);

    assert_eq_size!(kernel::ifmap, ifmap);
    assert_eq_align!(kernel::ifmap, ifmap);

    assert_eq_size!(kernel::if_settings, if_settings);
    assert_eq_align!(kernel::if_settings, if_settings);

    assert_eq_size!(kernel::ifreq, ifreq);
    assert_eq_align!(kernel::ifreq, ifreq);

    assert_eq_size!(kernel::ifconf, ifconf);
    assert_eq_align!(kernel::ifconf, ifconf);

    assert_eq_size!(kernel::iw_param, iw_param);
    assert_eq_align!(kernel::iw_param, iw_param);

    assert_eq_size!(kernel::iw_point, iw_point);
    assert_eq_align!(kernel::iw_point, iw_point);

    assert_eq_size!(kernel::iw_freq, iw_freq);
    assert_eq_align!(kernel::iw_freq, iw_freq);

    assert_eq_size!(kernel::iw_quality, iw_quality);
    assert_eq_align!(kernel::iw_quality, iw_quality);

    assert_eq_size!(kernel::iwreq_data, iwreq_data);
    assert_eq_align!(kernel::iwreq_data, iwreq_data);

    assert_eq_size!(kernel::iwreq, iwreq);
    assert_eq_align!(kernel::iwreq, iwreq);

    assert_eq_size!(kernel::ethtool_cmd, ethtool_cmd);
    assert_eq_align!(kernel::ethtool_cmd, ethtool_cmd);

    assert_eq_size!(kernel::flock, _flock);
    assert_eq_align!(kernel::flock, _flock);

    assert_eq_size!(kernel::flock64, flock64);
    assert_eq_align!(kernel::flock64, flock64);

    assert_eq_size!(kernel::f_owner_ex, f_owner_ex);
    assert_eq_align!(kernel::f_owner_ex, f_owner_ex);

    assert_eq_size!(kernel::__sysctl_args, __sysctl_args);
    assert_eq_align!(kernel::__sysctl_args, __sysctl_args);

    assert_eq_size!(kernel::sigset_t, sigset_t);
    assert_eq_align!(kernel::sigset_t, sigset_t);

    assert_eq_size!(kernel::tms, tms);
    assert_eq_align!(kernel::tms, tms);

    assert_eq_size!(kernel::rlimit, rlimit);
    assert_eq_align!(kernel::rlimit, rlimit);

    assert_eq_size!(kernel::rlimit64, rlimit64);
    assert_eq_align!(kernel::rlimit64, rlimit64);

    assert_eq_size!(kernel::timezone, timezone);
    assert_eq_align!(kernel::timezone, timezone);

    assert_eq_size!(kernel::statfs, statfs);
    assert_eq_align!(kernel::statfs, statfs);

    assert_eq_size!(kernel::statfs64, statfs64);
    assert_eq_align!(kernel::statfs64, statfs64);

    assert_eq_size!(kernel::itimerval, itimerval);
    assert_eq_align!(kernel::itimerval, itimerval);

    assert_eq_size!(kernel::itimerspec, itimerspec);
    assert_eq_align!(kernel::itimerspec, itimerspec);

    assert_eq_size!(kernel::stack_t, stack_t);
    assert_eq_align!(kernel::stack_t, stack_t);

    assert_eq_size!(kernel::sysinfo, sysinfo);
    assert_eq_align!(kernel::sysinfo, sysinfo);

    assert_eq_size!(kernel::utsname, utsname);
    assert_eq_align!(kernel::utsname, utsname);

    // @TODO.
    // assert_eq_size!(kernel::sched_param, sched_param);
    // assert_eq_align!(kernel::sched_param, sched_param);

    assert_eq_size!(kernel::v4l2_timecode, v4l2_timecode);
    assert_eq_align!(kernel::v4l2_timecode, v4l2_timecode);

    assert_eq_size!(kernel::v4l2_buffer, v4l2_buffer);
    assert_eq_align!(kernel::v4l2_buffer, v4l2_buffer);

    assert_eq_size!(kernel::sock_filter, sock_filter);
    assert_eq_align!(kernel::sock_filter, sock_filter);

    assert_eq_size!(kernel::sock_fprog, sock_fprog);
    assert_eq_align!(kernel::sock_fprog, sock_fprog);

    assert_eq_size!(kernel::robust_list, robust_list);
    assert_eq_align!(kernel::robust_list, robust_list);

    assert_eq_size!(kernel::robust_list_head, robust_list_head);
    assert_eq_align!(kernel::robust_list_head, robust_list_head);

    assert_eq_size!(kernel::snd_ctl_card_info, snd_ctl_card_info);
    assert_eq_align!(kernel::snd_ctl_card_info, snd_ctl_card_info);

    assert_eq_size!(kernel::usbdevfs_iso_packet_desc, usbdevfs_iso_packet_desc);
    assert_eq_align!(kernel::usbdevfs_iso_packet_desc, usbdevfs_iso_packet_desc);

    assert_eq_size!(kernel::usbdevfs_urb, usbdevfs_urb);
    assert_eq_align!(kernel::usbdevfs_urb, usbdevfs_urb);

    assert_eq_size!(kernel::usbdevfs_ioctl, usbdevfs_ioctl);
    assert_eq_align!(kernel::usbdevfs_ioctl, usbdevfs_ioctl);

    assert_eq_size!(kernel::usbdevfs_ctrltransfer, usbdevfs_ctrltransfer);
    assert_eq_align!(kernel::usbdevfs_ctrltransfer, usbdevfs_ctrltransfer);

    assert_eq_size!(kernel::dirent, dirent);
    assert_eq_align!(kernel::dirent, dirent);

    assert_eq_size!(kernel::dirent64, dirent64);
    assert_eq_align!(kernel::dirent64, dirent64);

    assert_eq_size!(kernel::mq_attr, mq_attr);
    assert_eq_align!(kernel::mq_attr, mq_attr);

    assert_eq_size!(kernel::xt_counters, xt_counters);
    assert_eq_align!(kernel::xt_counters, xt_counters);

    // @TODO
    // assert_eq_size!(kernel::ipt_replace, ipt_replace);
    // assert_eq_align!(kernel::ipt_replace, ipt_replace);

    assert_eq_size!(kernel::ifbond, ifbond);
    assert_eq_align!(kernel::ifbond, ifbond);

    assert_eq_size!(kernel::timex, timex);
    assert_eq_align!(kernel::timex, timex);

    assert_eq_size!(kernel::statx_timestamp, statx_timestamp);
    assert_eq_align!(kernel::statx_timestamp, statx_timestamp);

    assert_eq_size!(kernel::statx, statx);
    assert_eq_align!(kernel::statx, statx);

    assert_eq_size!(kernel::sg_io_hdr, sg_io_hdr);
    assert_eq_align!(kernel::sg_io_hdr, sg_io_hdr);
}

pub mod w32 {
    pub use super::common::*;
    pub type signed_short = int16_t;
    pub type unsigned_short = uint16_t;

    pub type signed_int = int32_t;
    pub type unsigned_int = uint32_t;
    pub type int = int32_t;

    pub type signed_long = int32_t;
    pub type unsigned_long = uint32_t;

    pub type signed_word = int32_t;
    pub type unsigned_word = uint32_t;

    pub type size_t = uint32_t;
    pub type ssize_t = int32_t;

    // These really only exist as proper abstractions so that adding x32
    // (x86-64's ILP32 ABI) support is relatively easy.
    pub type syscall_slong_t = int32_t;
    pub type syscall_ulong_t = uint32_t;
    pub type sigchld_clock_t = int32_t;
    pub type __statfs_word = uint32_t;
}

pub mod x86 {
    pub use super::w32::*;
    use crate::bindings::kernel;

    pub const SIGINFO_PADDING: usize = 29;
    pub type ptr<T> = super::Ptr<u32, T>;

    // IMPORTANT ! ////////////////////////
    include!("include/base_arch_defns.rs");

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct user_regs_struct {
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

    #[cfg(target_arch = "x86")]
    assert_eq_align!(kernel::user_regs_struct, user_regs_struct);
    #[cfg(target_arch = "x86")]
    assert_eq_size!(kernel::user_regs_struct, user_regs_struct);

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct sigcontext {
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

    #[cfg(target_arch = "x86")]
    assert_eq_align!(kernel::sigcontext, sigcontext);
    #[cfg(target_arch = "x86")]
    assert_eq_size!(kernel::sigcontext, sigcontext);

    #[cfg(target_arch = "x86")]
    mod assert {
        use super::*;
        assert_eq_align!(kernel::sigcontext, sigcontext);
        assert_eq_size!(kernel::sigcontext, sigcontext);

        assert_eq_size!(kernel::sockaddr, sockaddr);
        assert_eq_align!(kernel::sockaddr, sockaddr);

        assert_eq_size!(kernel::sockaddr_un, sockaddr_un);
        assert_eq_align!(kernel::sockaddr_un, sockaddr_un);

        assert_eq_size!(kernel::timeval, timeval);
        assert_eq_align!(kernel::timeval, timeval);

        assert_eq_size!(kernel::timespec, timespec);
        assert_eq_align!(kernel::timespec, timespec);

        assert_eq_size!(kernel::pollfd, pollfd);
        assert_eq_align!(kernel::pollfd, pollfd);

        assert_eq_size!(kernel::iovec, iovec);
        assert_eq_align!(kernel::iovec, iovec);

        assert_eq_size!(kernel::msghdr, msghdr);
        assert_eq_align!(kernel::msghdr, msghdr);

        assert_eq_size!(kernel::cmsghdr, cmsghdr);
        assert_eq_align!(kernel::cmsghdr, cmsghdr);

        assert_eq_size!(kernel::mmsghdr, mmsghdr);
        assert_eq_align!(kernel::mmsghdr, mmsghdr);

        assert_eq_size!(kernel::rusage, rusage);
        assert_eq_align!(kernel::rusage, rusage);

        assert_eq_size!(kernel::siginfo_t, siginfo_t);
        assert_eq_align!(kernel::siginfo_t, siginfo_t);

        assert_eq_size!(kernel::termios, termios);
        assert_eq_align!(kernel::termios, termios);

        assert_eq_size!(kernel::termio, termio);
        assert_eq_align!(kernel::termio, termio);

        assert_eq_size!(kernel::winsize, winsize);
        assert_eq_align!(kernel::winsize, winsize);

        assert_eq_size!(kernel::ipc64_perm, ipc64_perm);
        assert_eq_align!(kernel::ipc64_perm, ipc64_perm);

        assert_eq_size!(kernel::msqid64_ds, msqid64_ds);
        assert_eq_align!(kernel::msqid64_ds, msqid64_ds);

        assert_eq_size!(kernel::msginfo, msginfo);
        assert_eq_align!(kernel::msginfo, msginfo);

        assert_eq_size!(kernel::shmid64_ds, shmid64_ds);
        // @TODO
        // assert_eq_align!(kernel::shmid64_ds, shmid64_ds);

        assert_eq_size!(kernel::shminfo64, shminfo64);
        assert_eq_align!(kernel::shminfo64, shminfo64);

        assert_eq_size!(kernel::shm_info, shm_info);
        assert_eq_align!(kernel::shm_info, shm_info);

        assert_eq_size!(kernel::semid64_ds, semid64_ds);
        assert_eq_align!(kernel::semid64_ds, semid64_ds);

        assert_eq_size!(kernel::seminfo, seminfo);
        assert_eq_align!(kernel::seminfo, seminfo);

        // @TODO.
        // assert_eq_size!(kernel::user_desc, user_desc);
        // assert_eq_align!(kernel::user_desc, user_desc);

        assert_eq_size!(kernel::__user_cap_header_struct, __user_cap_header_struct);
        assert_eq_align!(kernel::__user_cap_header_struct, __user_cap_header_struct);

        assert_eq_size!(kernel::__user_cap_data_struct, __user_cap_data_struct);
        assert_eq_align!(kernel::__user_cap_data_struct, __user_cap_data_struct);

        assert_eq_size!(kernel::dqblk, dqblk);
        assert_eq_align!(kernel::dqblk, dqblk);

        assert_eq_size!(kernel::dqinfo, dqinfo);
        assert_eq_align!(kernel::dqinfo, dqinfo);

        assert_eq_size!(kernel::ifmap, ifmap);
        assert_eq_align!(kernel::ifmap, ifmap);

        assert_eq_size!(kernel::if_settings, if_settings);
        assert_eq_align!(kernel::if_settings, if_settings);

        assert_eq_size!(kernel::ifreq, ifreq);
        assert_eq_align!(kernel::ifreq, ifreq);

        assert_eq_size!(kernel::ifconf, ifconf);
        assert_eq_align!(kernel::ifconf, ifconf);

        assert_eq_size!(kernel::iw_param, iw_param);
        assert_eq_align!(kernel::iw_param, iw_param);

        assert_eq_size!(kernel::iw_point, iw_point);
        assert_eq_align!(kernel::iw_point, iw_point);

        assert_eq_size!(kernel::iw_freq, iw_freq);
        assert_eq_align!(kernel::iw_freq, iw_freq);

        assert_eq_size!(kernel::iw_quality, iw_quality);
        assert_eq_align!(kernel::iw_quality, iw_quality);

        assert_eq_size!(kernel::iwreq_data, iwreq_data);
        assert_eq_align!(kernel::iwreq_data, iwreq_data);

        assert_eq_size!(kernel::iwreq, iwreq);
        assert_eq_align!(kernel::iwreq, iwreq);

        assert_eq_size!(kernel::ethtool_cmd, ethtool_cmd);
        assert_eq_align!(kernel::ethtool_cmd, ethtool_cmd);

        assert_eq_size!(kernel::flock, _flock);
        assert_eq_align!(kernel::flock, _flock);

        assert_eq_size!(kernel::flock64, flock64);
        assert_eq_align!(kernel::flock64, flock64);

        assert_eq_size!(kernel::f_owner_ex, f_owner_ex);
        assert_eq_align!(kernel::f_owner_ex, f_owner_ex);

        assert_eq_size!(kernel::__sysctl_args, __sysctl_args);
        assert_eq_align!(kernel::__sysctl_args, __sysctl_args);

        assert_eq_size!(kernel::sigset_t, sigset_t);
        assert_eq_align!(kernel::sigset_t, sigset_t);

        assert_eq_size!(kernel::tms, tms);
        assert_eq_align!(kernel::tms, tms);

        assert_eq_size!(kernel::rlimit, rlimit);
        assert_eq_align!(kernel::rlimit, rlimit);

        assert_eq_size!(kernel::rlimit64, rlimit64);
        assert_eq_align!(kernel::rlimit64, rlimit64);

        assert_eq_size!(kernel::timezone, timezone);
        assert_eq_align!(kernel::timezone, timezone);

        assert_eq_size!(kernel::statfs, statfs);
        assert_eq_align!(kernel::statfs, statfs);

        assert_eq_size!(kernel::statfs64, statfs64);
        assert_eq_align!(kernel::statfs64, statfs64);

        assert_eq_size!(kernel::itimerval, itimerval);
        assert_eq_align!(kernel::itimerval, itimerval);

        assert_eq_size!(kernel::itimerspec, itimerspec);
        assert_eq_align!(kernel::itimerspec, itimerspec);

        assert_eq_size!(kernel::stack_t, stack_t);
        assert_eq_align!(kernel::stack_t, stack_t);

        assert_eq_size!(kernel::sysinfo, sysinfo);
        assert_eq_align!(kernel::sysinfo, sysinfo);

        assert_eq_size!(kernel::utsname, utsname);
        assert_eq_align!(kernel::utsname, utsname);

        // @TODO.
        // assert_eq_size!(kernel::sched_param, sched_param);
        // assert_eq_align!(kernel::sched_param, sched_param);

        assert_eq_size!(kernel::v4l2_timecode, v4l2_timecode);
        assert_eq_align!(kernel::v4l2_timecode, v4l2_timecode);

        assert_eq_size!(kernel::v4l2_buffer, v4l2_buffer);
        assert_eq_align!(kernel::v4l2_buffer, v4l2_buffer);

        assert_eq_size!(kernel::sock_filter, sock_filter);
        assert_eq_align!(kernel::sock_filter, sock_filter);

        assert_eq_size!(kernel::sock_fprog, sock_fprog);
        assert_eq_align!(kernel::sock_fprog, sock_fprog);

        assert_eq_size!(kernel::robust_list, robust_list);
        assert_eq_align!(kernel::robust_list, robust_list);

        assert_eq_size!(kernel::robust_list_head, robust_list_head);
        assert_eq_align!(kernel::robust_list_head, robust_list_head);

        assert_eq_size!(kernel::snd_ctl_card_info, snd_ctl_card_info);
        assert_eq_align!(kernel::snd_ctl_card_info, snd_ctl_card_info);

        assert_eq_size!(kernel::usbdevfs_iso_packet_desc, usbdevfs_iso_packet_desc);
        assert_eq_align!(kernel::usbdevfs_iso_packet_desc, usbdevfs_iso_packet_desc);

        assert_eq_size!(kernel::usbdevfs_urb, usbdevfs_urb);
        assert_eq_align!(kernel::usbdevfs_urb, usbdevfs_urb);

        assert_eq_size!(kernel::usbdevfs_ioctl, usbdevfs_ioctl);
        assert_eq_align!(kernel::usbdevfs_ioctl, usbdevfs_ioctl);

        assert_eq_size!(kernel::usbdevfs_ctrltransfer, usbdevfs_ctrltransfer);
        assert_eq_align!(kernel::usbdevfs_ctrltransfer, usbdevfs_ctrltransfer);

        assert_eq_size!(kernel::dirent, dirent);
        assert_eq_align!(kernel::dirent, dirent);

        assert_eq_size!(kernel::dirent64, dirent64);
        assert_eq_align!(kernel::dirent64, dirent64);

        assert_eq_size!(kernel::mq_attr, mq_attr);
        assert_eq_align!(kernel::mq_attr, mq_attr);

        assert_eq_size!(kernel::xt_counters, xt_counters);
        assert_eq_align!(kernel::xt_counters, xt_counters);

        // @TODO
        // assert_eq_size!(kernel::ipt_replace, ipt_replace);
        // assert_eq_align!(kernel::ipt_replace, ipt_replace);

        assert_eq_size!(kernel::ifbond, ifbond);
        assert_eq_align!(kernel::ifbond, ifbond);

        assert_eq_size!(kernel::timex, timex);
        assert_eq_align!(kernel::timex, timex);

        assert_eq_size!(kernel::statx_timestamp, statx_timestamp);
        assert_eq_align!(kernel::statx_timestamp, statx_timestamp);

        assert_eq_size!(kernel::statx, statx);
        assert_eq_align!(kernel::statx, statx);

        assert_eq_size!(kernel::sg_io_hdr, sg_io_hdr);
        assert_eq_align!(kernel::sg_io_hdr, sg_io_hdr);
    }
}
