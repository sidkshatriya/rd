use crate::kernel_abi::{x64, x86, SupportedArch};
use crate::remote_ptr::{RemotePtr, Void};

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
    type kernel_sigaction: Default;
    fn get_k_sa_handler(k: &Self::kernel_sigaction) -> RemotePtr<Void>;
    fn get_sa_flags(k: &Self::kernel_sigaction) -> usize;
    fn arch() -> SupportedArch;
}

impl Architecture for X86Arch {
    type kernel_sigaction = x86::kernel_sigaction;

    fn get_k_sa_handler(k: &Self::kernel_sigaction) -> RemotePtr<Void> {
        k.k_sa_handler.rptr()
    }

    fn get_sa_flags(k: &Self::kernel_sigaction) -> usize {
        k.sa_flags as usize
    }

    fn arch() -> SupportedArch {
        SupportedArch::X86
    }
}

impl Architecture for X64Arch {
    type kernel_sigaction = x64::kernel_sigaction;
    fn get_k_sa_handler(k: &Self::kernel_sigaction) -> RemotePtr<Void> {
        k.k_sa_handler.rptr()
    }
    fn get_sa_flags(k: &Self::kernel_sigaction) -> usize {
        k.sa_flags as usize
    }
    fn arch() -> SupportedArch {
        SupportedArch::X64
    }
}
