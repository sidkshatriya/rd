use crate::kernel_abi::{x64, x86, SupportedArch};
use crate::kernel_supplement::{CLD_STOPPED, CLD_TRAPPED};
use crate::remote_ptr::{RemotePtr, Void};
use crate::task::record_task::record_task::RecordTask;
use crate::task::record_task::EmulatedStopType;
use std::convert::TryInto;

pub struct X86Arch;
pub struct X64Arch;

#[cfg(target_arch = "x86_64")]
pub type NativeArch = X64Arch;

#[cfg(target_arch = "x86")]
pub type NativeArch = X86Arch;

macro_rules! rd_arch_function {
    ($slf:expr, $func_name:ident, $arch:expr) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $slf.$func_name::<crate::arch::X86Arch>(),
            crate::kernel_abi::SupportedArch::X64 => $slf.$func_name::<crate::arch::X64Arch>(),
        }
    };
    ($slf:expr, $func_name:ident, $arch:expr, $($exp:tt)*) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $slf.$func_name::<crate::arch::X86Arch>($($exp)*),
            crate::kernel_abi::SupportedArch::X64 => $slf.$func_name::<crate::arch::X64Arch>($($exp)*),
        }
    };
}

macro_rules! rd_arch_function_selfless {
    ($func_name:ident, $arch:expr) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $func_name::<crate::arch::X86Arch>(),
            crate::kernel_abi::SupportedArch::X64 => $func_name::<crate::arch::X64Arch>(),
        }
    };
    ($func_name:ident, $arch:expr, $($exp:tt)*) => {
        match $arch {
            crate::kernel_abi::SupportedArch::X86 => $func_name::<crate::arch::X86Arch>($($exp)*),
            crate::kernel_abi::SupportedArch::X64 => $func_name::<crate::arch::X64Arch>($($exp)*),
        }
    };
}

pub trait Architecture {
    #[allow(non_camel_case_types)]
    type kernel_sigaction: Default + Copy + 'static;

    #[allow(non_camel_case_types)]
    type signed_long: Copy + From<i32> + 'static;

    #[allow(non_camel_case_types)]
    type iovec: Copy + Default + 'static;

    #[allow(non_camel_case_types)]
    type msghdr: Copy + Default + 'static;

    #[allow(non_camel_case_types)]
    type cmsghdr: Copy + Default + 'static;

    #[allow(non_camel_case_types)]
    type siginfo_t: 'static;

    #[allow(non_camel_case_types)]
    type sockaddr_un: Copy + 'static;

    fn to_signed_long(val: usize) -> Self::signed_long;
    fn get_k_sa_handler(k: &Self::kernel_sigaction) -> RemotePtr<Void>;
    fn get_sa_flags(k: &Self::kernel_sigaction) -> usize;
    fn arch() -> SupportedArch;
    fn set_iovec(msgdata: &mut Self::iovec, iov_base: RemotePtr<Void>, iov_len: usize);
    fn set_msghdr(
        msg: &mut Self::msghdr,
        msg_control: RemotePtr<u8>,
        msg_controllen: usize,
        msg_iov: RemotePtr<Self::iovec>,
        msg_iovlen: usize,
    );

    fn set_csmsghdr(msg: &mut Self::cmsghdr, cmsg_len: usize, cmsg_level: i32, cmsg_type: i32);

    fn set_siginfo_for_waited_task(r: &RecordTask, si: &mut Self::siginfo_t);
}

impl Architecture for X86Arch {
    type kernel_sigaction = x86::kernel_sigaction;
    type signed_long = x86::signed_long;
    type iovec = x86::iovec;
    type msghdr = x86::msghdr;
    type cmsghdr = x86::cmsghdr;
    type siginfo_t = x86::siginfo_t;
    type sockaddr_un = x86::sockaddr_un;

    fn to_signed_long(val: usize) -> Self::signed_long {
        val.try_into().unwrap()
    }

    fn get_k_sa_handler(k: &Self::kernel_sigaction) -> RemotePtr<Void> {
        k.k_sa_handler.rptr()
    }

    fn get_sa_flags(k: &Self::kernel_sigaction) -> usize {
        k.sa_flags as usize
    }

    fn arch() -> SupportedArch {
        SupportedArch::X86
    }

    fn set_iovec(msgdata: &mut Self::iovec, iov_base: RemotePtr<u8>, iov_len: usize) {
        msgdata.iov_base = iov_base.into();
        msgdata.iov_len = iov_len.try_into().unwrap();
    }

    fn set_msghdr(
        msg: &mut Self::msghdr,
        msg_control: RemotePtr<u8>,
        msg_controllen: usize,
        msg_iov: RemotePtr<Self::iovec>,
        msg_iovlen: usize,
    ) {
        msg.msg_control = msg_control.into();
        msg.msg_controllen = msg_controllen.try_into().unwrap();
        msg.msg_iov = msg_iov.into();
        msg.msg_iovlen = msg_iovlen.try_into().unwrap();
    }

    fn set_csmsghdr(cmsghdr: &mut Self::cmsghdr, cmsg_len: usize, cmsg_level: i32, cmsg_type: i32) {
        cmsghdr.cmsg_len = cmsg_len.try_into().unwrap();
        cmsghdr.cmsg_level = cmsg_level;
        cmsghdr.cmsg_type = cmsg_type;
    }

    fn set_siginfo_for_waited_task(r: &RecordTask, si: &mut x86::siginfo_t) {
        // XXX handle CLD_EXITED here
        if r.emulated_stop_type == EmulatedStopType::GroupStop {
            si.si_code = CLD_STOPPED as _;
            // @TODO Is the unwrap fail safe?
            si._sifields._sigchld.si_status_ = r.emulated_stop_code.stop_sig().unwrap();
        } else {
            si.si_code = CLD_TRAPPED as _;
            // @TODO Is the unwrap fail safe?
            si._sifields._sigchld.si_status_ = r.emulated_stop_code.ptrace_signal().unwrap();
        }
        si._sifields._sigchld.si_pid_ = r.tgid();
        si._sifields._sigchld.si_uid_ = r.getuid();
    }
}

impl Architecture for X64Arch {
    type kernel_sigaction = x64::kernel_sigaction;
    type signed_long = x64::signed_long;
    type iovec = x64::iovec;
    type msghdr = x64::msghdr;
    type cmsghdr = x64::cmsghdr;
    type siginfo_t = x64::siginfo_t;
    type sockaddr_un = x64::sockaddr_un;

    fn to_signed_long(val: usize) -> Self::signed_long {
        val as Self::signed_long
    }

    fn get_k_sa_handler(k: &Self::kernel_sigaction) -> RemotePtr<Void> {
        k.k_sa_handler.rptr()
    }
    fn get_sa_flags(k: &Self::kernel_sigaction) -> usize {
        k.sa_flags as usize
    }
    fn arch() -> SupportedArch {
        SupportedArch::X64
    }

    fn set_iovec(msgdata: &mut Self::iovec, iov_base: RemotePtr<u8>, iov_len: usize) {
        msgdata.iov_base = iov_base.into();
        msgdata.iov_len = iov_len as _;
    }

    fn set_msghdr(
        msg: &mut Self::msghdr,
        msg_control: RemotePtr<u8>,
        msg_controllen: usize,
        msg_iov: RemotePtr<Self::iovec>,
        msg_iovlen: usize,
    ) {
        msg.msg_control = msg_control.into();
        msg.msg_controllen = msg_controllen as _;
        msg.msg_iov = msg_iov.into();
        msg.msg_iovlen = msg_iovlen as _;
    }

    fn set_csmsghdr(cmsghdr: &mut Self::cmsghdr, cmsg_len: usize, cmsg_level: i32, cmsg_type: i32) {
        cmsghdr.cmsg_len = cmsg_len as _;
        cmsghdr.cmsg_level = cmsg_level;
        cmsghdr.cmsg_type = cmsg_type;
    }

    fn set_siginfo_for_waited_task(r: &RecordTask, si: &mut x64::siginfo_t) {
        // XXX handle CLD_EXITED here
        if r.emulated_stop_type == EmulatedStopType::GroupStop {
            si.si_code = CLD_STOPPED as _;
            // @TODO Is the unwrap fail safe?
            si._sifields._sigchld.si_status_ = r.emulated_stop_code.stop_sig().unwrap();
        } else {
            si.si_code = CLD_TRAPPED as _;
            // @TODO Is the unwrap fail safe?
            si._sifields._sigchld.si_status_ = r.emulated_stop_code.ptrace_signal().unwrap();
        }
        si._sifields._sigchld.si_pid_ = r.tgid();
        si._sifields._sigchld.si_uid_ = r.getuid();
    }
}
