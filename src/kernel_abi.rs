#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use crate::{
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::RemotePtr,
    session::{
        address_space::{address_space::AddressSpace, Enabled},
        task::{task_common::read_mem, Task},
    },
};
use libc::memcmp;
use std::{
    convert::TryInto,
    fmt::{Display, Formatter, LowerHex, Result},
    marker::PhantomData,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SupportedArch {
    X86,
    X64,
}

impl Default for SupportedArch {
    fn default() -> Self {
        Self::X64
    }
}

// All architectures have an mmap syscall, but it has architecture-specific
// calling semantics. We describe those here, and specializations need to
// indicate which semantics they use.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MmapCallingSemantics {
    /// x86-ish, packaged into mmap_args, below
    StructArguments,
    /// arguments passed in registers, the offset
    /// is assumed to be in bytes, not in pages.
    RegisterArguments,
}

/// Despite the clone(2) manpage describing the clone syscall as taking a
/// pointer to `struct user_desc*`, the actual kernel interface treats the
/// TLS value as a opaque cookie, which architectures are then free to do
/// whatever they like with.  See for instance the definition of TLS_VALUE
/// in nptl/sysdeps/pthread/createthread.c in the glibc source.  We need to
/// describe what the architecture uses so we can record things accurately.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CloneTLSType {
    /// `struct user_desc*`
    UserDescPointer,
    /// This is the default choice for TLS_VALUE in the glibc source.
    PthreadStructurePointer,
}

// All architectures have a select syscall, but like mmap, there are two
// different calling styles: one that packages the args into a structure,
// and one that handles the args in registers.  (Architectures using the
// first style, like the x86, sometimes support the register-args version
// as a separate syscall.)
//
// (Yes, we'd like to call these StructArguments and RegisterArguments, but
// that would conflict with MmapCallingSemantics, above.)
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SelectCallingSemantics {
    SelectStructArguments,
    SelectRegisterArguments,
}

/// The clone(2) syscall has four (!) different calling conventions,
/// depending on what architecture it's being compiled for.  We describe
/// the orderings for x86oids here.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CloneParameterOrdering {
    FlagsStackParentTLSChild,
    FlagsStackParentChildTLS,
}

// IMPORTANT //
include!(concat!(
    env!("OUT_DIR"),
    "/syscall_helper_functions_generated.rs"
));

#[cfg(target_arch = "x86_64")]
pub const RD_NATIVE_ARCH: SupportedArch = SupportedArch::X64;

#[cfg(target_arch = "x86")]
pub const RD_NATIVE_ARCH: SupportedArch = SupportedArch::X86;

macro_rules! rd_kernel_abi_arch_function {
    ($func_name:ident, $arch:expr) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => crate::kernel_abi::x86::$func_name(),
            crate::kernel_abi::SupportedArch::X64 => crate::kernel_abi::x64::$func_name(),
        }
    };
    ($func_name:ident, $arch:expr, $($exp:expr),+) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => crate::kernel_abi::x86::$func_name($($exp),+),
            crate::kernel_abi::SupportedArch::X64 => crate::kernel_abi::x64::$func_name($($exp),+),
        }
    };
}

const INT80_INSN: [u8; 2] = [0xcd, 0x80];
const SYSENTER_INSN: [u8; 2] = [0x0f, 0x34];
const SYSCALL_INSN: [u8; 2] = [0x0f, 0x05];
fn get_syscall_instruction_arch(
    t: &mut dyn Task,
    ptr: RemoteCodePtr,
    arch: &mut SupportedArch,
) -> bool {
    // Lots of syscalls occur in the rr page and we know what it contains without
    // looking at it.
    // (Without this optimization we spend a few % of all CPU time in this
    // function in a syscall-dominated trace.)i
    if t.vm().has_rd_page() {
        let maybe_type = AddressSpace::rd_page_syscall_from_entry_point(ptr);

        match maybe_type {
            Some(type_) => {
                if type_.enabled == Enabled::RecordingAndReplay
                    || type_.enabled
                        == (if t.session().is_recording() {
                            Enabled::RecordingOnly
                        } else {
                            Enabled::ReplayOnly
                        })
                {
                    // rd-page syscalls are always the task's arch
                    *arch = t.arch();
                    return true;
                }
            }
            None => (),
        }
    }

    let mut ok = true;
    let code: Vec<u8> = read_mem(t, ptr.to_data_ptr::<u8>(), 2, Some(&mut ok));
    if !ok {
        return false;
    }
    match t.arch() {
        // Compatibility mode switch can happen in user space (but even without
        // such tricks, int80, which uses the 32bit syscall table, can be invoked
        // from 64bit processes).
        SupportedArch::X86 | SupportedArch::X64 => {
            if unsafe {
                memcmp(
                    code.as_ptr().cast(),
                    INT80_INSN.as_ptr().cast(),
                    INT80_INSN.len(),
                ) == 0
                    || memcmp(
                        code.as_ptr().cast(),
                        SYSENTER_INSN.as_ptr().cast(),
                        SYSENTER_INSN.len(),
                    ) == 0
            } {
                *arch = SupportedArch::X86;
            } else if unsafe {
                memcmp(
                    code.as_ptr().cast(),
                    SYSCALL_INSN.as_ptr().cast(),
                    SYSCALL_INSN.len(),
                ) == 0
            } {
                *arch = SupportedArch::X64;
            } else {
                return false;
            }
            return true;
        }
    }
}

pub fn is_at_syscall_instruction(t: &mut dyn Task, ptr: RemoteCodePtr) -> bool {
    let mut arch = SupportedArch::X64;
    get_syscall_instruction_arch(t, ptr, &mut arch)
}

/// Return the code bytes of an invoke-syscall instruction. The vector must
/// have the length given by `syscall_instruction_length`.
pub fn syscall_instruction(arch: SupportedArch) -> &'static [u8] {
    match arch {
        SupportedArch::X86 => &INT80_INSN,
        SupportedArch::X64 => &SYSCALL_INSN,
    }
}

/// Return the length of all invoke-syscall instructions. Currently,
/// they must all have the same length!
pub fn syscall_instruction_length(arch: SupportedArch) -> usize {
    match arch {
        SupportedArch::X86 => 2,
        SupportedArch::X64 => 2,
    }
}

///////////////////// Ptr
#[repr(C, align(8))]
#[derive(Copy, Clone, Default)]
pub struct aligned_u64 {
    pub val: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Ptr<ValT: Copy, ReferentT> {
    val: ValT,
    referent: PhantomData<ReferentT>,
}

impl<ValT: Copy, ReferentT> Ptr<ValT, ReferentT> {
    pub fn referent_size(&self) -> usize {
        std::mem::size_of::<ReferentT>()
    }
}

impl<ReferentT> Ptr<u32, ReferentT> {
    pub fn rptr(&self) -> RemotePtr<ReferentT> {
        RemotePtr::new_from_val(self.val as usize)
    }

    pub fn from_remote_ptr<T>(r: RemotePtr<T>) -> Ptr<u32, T> {
        let addr = r.as_usize();
        Ptr {
            val: addr.try_into().unwrap(),
            referent: PhantomData,
        }
    }
}

impl<T> From<RemotePtr<T>> for Ptr<u32, T> {
    fn from(r: RemotePtr<T>) -> Self {
        Ptr::<u32, T>::from_remote_ptr(r)
    }
}

impl<T> From<RemotePtr<T>> for Ptr<u64, T> {
    fn from(r: RemotePtr<T>) -> Self {
        Ptr::<u64, T>::from_remote_ptr(r)
    }
}

impl<ReferentT> Ptr<u64, ReferentT> {
    pub fn rptr(&self) -> RemotePtr<ReferentT> {
        RemotePtr::new_from_val(self.val as usize)
    }

    pub fn from_remote_ptr<T>(r: RemotePtr<T>) -> Ptr<u64, T> {
        let addr = r.as_usize();
        Ptr {
            val: addr as u64,
            referent: PhantomData,
        }
    }
}

impl<ValT: Copy + LowerHex, ReferenT> Display for Ptr<ValT, ReferenT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:#x}", self.val)
    }
}

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
    pub type int = int32_t;
    pub type signed_int = int32_t;
    pub type unsigned_int = uint32_t;

    pub use super::aligned_u64;
    pub type ptr64<T> = super::Ptr<aligned_u64, T>;

    // IMPORTANT ! ////////////////////////
    pub mod preload_interface {
        use super::*;
        include!("include/preload_interface.rs");
    }
}

pub mod w64 {
    pub use super::common::*;
    pub type signed_short = int16_t;
    pub type unsigned_short = uint16_t;

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

pub mod x64 {
    pub use super::w64::*;
    use crate::kernel_abi::{
        CloneParameterOrdering,
        CloneTLSType,
        MmapCallingSemantics,
        SelectCallingSemantics,
    };

    pub const SIGINFO_PADDING: usize = 28;

    pub type ptr<T> = super::Ptr<u64, T>;

    pub const MMAP_SEMANTICS: MmapCallingSemantics = MmapCallingSemantics::RegisterArguments;
    pub const CLONE_TLS_TYPE: CloneTLSType = CloneTLSType::PthreadStructurePointer;
    pub const CLONE_PARAMETER_ORDERING: CloneParameterOrdering =
        CloneParameterOrdering::FlagsStackParentChildTLS;
    pub const SELECT_SEMANTICS: SelectCallingSemantics =
        SelectCallingSemantics::SelectRegisterArguments;

    // syscall_consts_x64_generated.rs is generated by scripts/generate_syscall.py
    include!(concat!(env!("OUT_DIR"), "/syscall_consts_x64_generated.rs"));
    // End Generated by scripts/generate_syscall.py

    // syscall_name_arch_x64_generated.rs is generated by scripts/generate_syscall.py
    include!(concat!(
        env!("OUT_DIR"),
        "/syscall_name_arch_x64_generated.rs"
    ));

    // IMPORTANT ! ////////////////////////
    include!("include/base_arch_defns.rs");

    // IMPORTANT ! ////////////////////////
    pub mod preload_interface {
        use super::*;
        include!("include/preload_interface_arch.rs");
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct stat64 {
        pub st_dev: dev_t,
        pub st_ino: ino_t,
        pub st_nlink: nlink_t,
        pub st_mode: mode_t,
        pub st_uid: uid_t,
        pub st_gid: gid_t,
        pub __pad0: int,
        pub st_rdev: dev_t,
        pub st_size: off_t,
        pub st_blksize: blksize_t,
        pub st_blocks: blkcnt_t,
        pub st_atim: timespec,
        pub st_mtim: timespec,
        pub st_ctim: timespec,
        pub __rd_unused: [syscall_slong_t; 3],
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct user_regs_struct {
        pub r15: u64,
        pub r14: u64,
        pub r13: u64,
        pub r12: u64,
        pub rbp: u64,
        pub rbx: u64,
        pub r11: u64,
        pub r10: u64,
        pub r9: u64,
        pub r8: u64,
        pub rax: u64,
        pub rcx: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        // Unsigned type matches <sys/user.h>, but we need to treat this as
        // signed in practice.
        pub orig_rax: u64,
        pub rip: u64,
        pub cs: u64,
        pub eflags: u64,
        pub rsp: u64,
        pub ss: u64,
        // These _base registers are architecturally defined MSRs and really do
        // need to be 64-bit.
        pub fs_base: u64,
        pub gs_base: u64,
        pub ds: u64,
        pub es: u64,
        pub fs: u64,
        pub gs: u64,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct sigcontext {
        pub r8: u64,
        pub r9: u64,
        pub r10: u64,
        pub r11: u64,
        pub r12: u64,
        pub r13: u64,
        pub r14: u64,
        pub r15: u64,
        pub di: u64,
        pub si: u64,
        pub bp: u64,
        pub bx: u64,
        pub dx: u64,
        pub ax: u64,
        pub cx: u64,
        pub sp: u64,
        pub ip: u64,
        pub flags: u64,
        pub cs: u16,
        pub gs: u16,
        pub fs: u16,
        pub __pad0: u16,
        pub err: u64,
        pub trapno: u64,
        pub oldmask: u64,
        pub cr2: u64,
        pub fpstate: u64,
        pub reserved: [u64; 8],
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct user_fpregs_struct {
        pub cwd: uint16_t,
        pub swd: uint16_t,
        pub ftw: uint16_t,
        pub fop: uint16_t,
        pub rip: uint64_t,
        pub rdp: uint64_t,
        pub mxcsr: uint32_t,
        pub mxcr_mask: uint32_t,
        pub st_space: [uint32_t; 32],
        pub xmm_space: [uint32_t; 64],
        pub padding: [uint32_t; 24],
    }

    #[cfg(target_arch = "x86_64")]
    mod assert {
        use super::*;
        use crate::bindings::kernel;

        assert_eq_align!(kernel::stat64, stat64);
        assert_eq_size!(kernel::stat64, stat64);

        assert_eq_align!(kernel::user_fpregs_struct, user_fpregs_struct);
        assert_eq_size!(kernel::user_fpregs_struct, user_fpregs_struct);

        assert_eq_align!(kernel::user_regs_struct, user_regs_struct);
        assert_eq_size!(kernel::user_regs_struct, user_regs_struct);

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

        assert_eq_size!(kernel::epoll_event, epoll_event);
        assert_eq_align!(kernel::epoll_event, epoll_event);
    }
}

pub mod w32 {
    pub use super::common::*;
    pub type signed_short = int16_t;
    pub type unsigned_short = uint16_t;

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
    use crate::kernel_abi::{
        CloneParameterOrdering,
        CloneTLSType,
        MmapCallingSemantics,
        SelectCallingSemantics,
    };

    pub const SIGINFO_PADDING: usize = 29;
    pub type ptr<T> = super::Ptr<u32, T>;

    pub const MMAP_SEMANTICS: MmapCallingSemantics = MmapCallingSemantics::StructArguments;
    pub const CLONE_TLS_TYPE: CloneTLSType = CloneTLSType::UserDescPointer;
    pub const CLONE_PARAMETER_ORDERING: CloneParameterOrdering =
        CloneParameterOrdering::FlagsStackParentTLSChild;
    pub const SELECT_SEMANTICS: SelectCallingSemantics =
        SelectCallingSemantics::SelectStructArguments;

    // syscall_consts_x86_generated.rs is generated by scripts/generate_syscall.py
    include!(concat!(env!("OUT_DIR"), "/syscall_consts_x86_generated.rs"));

    // syscall_name_arch_x86_generated.rs is generated by scripts/generate_syscall.py
    include!(concat!(
        env!("OUT_DIR"),
        "/syscall_name_arch_x86_generated.rs"
    ));

    // IMPORTANT ! ////////////////////////
    include!("include/base_arch_defns.rs");

    // IMPORTANT ! ////////////////////////
    pub mod preload_interface {
        use super::*;
        include!("include/preload_interface_arch.rs");
    }

    /// @TODO Check this in x86
    #[repr(C, packed)]
    pub struct stat64 {
        pub st_dev: dev_t,
        pub __pad1: unsigned_int,
        pub __st_ino: ino_t,
        pub st_mode: mode_t,
        pub st_nlink: nlink_t,
        pub st_uid: uid_t,
        pub st_gid: gid_t,
        pub st_rdev: dev_t,
        pub __pad2: unsigned_int,
        pub st_size: off64_t,
        pub st_blksize: blksize_t,
        pub st_blocks: blkcnt64_t,
        pub st_atim: timespec,
        pub st_mtim: timespec,
        pub st_ctim: timespec,
        pub st_ino: ino64_t,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct user_regs_struct {
        pub ebx: i32,
        pub ecx: i32,
        pub edx: i32,
        pub esi: i32,
        pub edi: i32,
        pub ebp: i32,
        pub eax: i32,
        pub xds: i32,
        pub xes: i32,
        pub xfs: i32,
        pub xgs: i32,
        pub orig_eax: i32,
        pub eip: i32,
        pub xcs: i32,
        pub eflags: i32,
        pub esp: i32,
        pub xss: i32,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct sigcontext {
        pub gs: u16,
        pub __gsh: u16,
        pub fs: u16,
        pub __fsh: u16,
        pub es: u16,
        pub __esh: u16,
        pub ds: u16,
        pub __dsh: u16,
        pub di: u32,
        pub si: u32,
        pub bp: u32,
        pub sp: u32,
        pub bx: u32,
        pub dx: u32,
        pub cx: u32,
        pub ax: u32,
        pub trapno: u32,
        pub err: u32,
        pub ip: u32,
        pub cs: u16,
        pub __csh: u16,
        pub flags: u16,
        pub sp_at_signal: u32,
        pub ss: u16,
        pub __ssh: u16,
        pub fpstate: u32,
        pub oldmask: u32,
        pub cr2: u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct user_fpxregs_struct {
        pub cwd: uint16_t,
        pub swd: uint16_t,
        pub twd: uint16_t,
        pub fop: uint16_t,
        pub fip: int32_t,
        pub fcs: int32_t,
        pub foo: int32_t,
        pub fos: int32_t,
        pub mxcsr: int32_t,
        pub reserved: int32_t,
        pub st_space: [int32_t; 32],
        pub xmm_space: [int32_t; 32],
        // Break this up into padding_1 and padding_2
        // instead of a single `padding: [int32_t;56]`
        // so that we can #[derive(Default)]
        pub padding_1: [int32_t; 28],
        pub padding_2: [int32_t; 28],
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct user_fpregs_struct {
        pub cwd: int32_t,
        pub swd: int32_t,
        pub twd: int32_t,
        pub fip: int32_t,
        pub fcs: int32_t,
        pub foo: int32_t,
        pub fos: int32_t,
        pub st_space: [int32_t; 20],
    }

    #[cfg(target_arch = "x86")]
    mod assert {
        use super::*;
        use crate::bindings::kernel;

        assert_eq_align!(kernel::stat64, stat64);
        assert_eq_size!(kernel::stat64, stat64);

        assert_eq_align!(kernel::user_fpregs_struct, user_fpregs_struct);
        assert_eq_size!(kernel::user_fpregs_struct, user_fpregs_struct);

        assert_eq_align!(kernel::user_fpxregs_struct, user_fpxregs_struct);
        assert_eq_size!(kernel::user_fpxregs_struct, user_fpxregs_struct);

        assert_eq_align!(kernel::user_regs_struct, user_regs_struct);
        assert_eq_size!(kernel::user_regs_struct, user_regs_struct);

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

        assert_eq_size!(kernel::epoll_event, epoll_event);
        assert_eq_align!(kernel::epoll_event, epoll_event);
    }
}
