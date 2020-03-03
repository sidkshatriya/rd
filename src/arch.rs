use crate::kernel_abi::{x64, x86, SupportedArch};
use crate::remote_ptr::{RemotePtr, Void};
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
            SupportedArch::X86 => $slf.$func_name::<crate::arch::X86Arch>(),
            SupportedArch::X64 => $slf.$func_name::<crate::arch::X64Arch>(),
        }
    };
    ($slf:expr, $func_name:ident, $arch:expr, $($exp:tt)*) => {
        match $arch {
            SupportedArch::X86 => $slf.$func_name::<crate::arch::X86Arch>($($exp)*),
            SupportedArch::X64 => $slf.$func_name::<crate::arch::X64Arch>($($exp)*),
        }
    };
}

pub trait Architecture {
    type kernel_sigaction: Default + Copy;
    type signed_long: Copy + From<i32>;
    type iovec: Copy + Default;
    type msghdr: Copy + Default;
    type cmsghdr: Copy + Default;

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
}

impl Architecture for X86Arch {
    type kernel_sigaction = x86::kernel_sigaction;
    type signed_long = x86::signed_long;
    type iovec = x86::iovec;
    type msghdr = x86::msghdr;
    type cmsghdr = x86::cmsghdr;

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
}

impl Architecture for X64Arch {
    type kernel_sigaction = x64::kernel_sigaction;
    type signed_long = x64::signed_long;
    type iovec = x64::iovec;
    type msghdr = x64::msghdr;
    type cmsghdr = x64::cmsghdr;

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
}
