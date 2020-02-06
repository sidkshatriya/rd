use crate::bindings::kernel::user_regs_struct as native_user_regs_struct;
use crate::kernel_abi::x64;
use crate::kernel_abi::x86;
use crate::kernel_abi::SupportedArch;
use crate::kernel_abi::RD_NATIVE_ARCH;

use SupportedArch::*;

macro_rules! rd_get_reg {
    ($slf:expr, $x86case:ident, $x64case:ident) => {
        unsafe {
            match $slf.arch_ {
                crate::kernel_abi::SupportedArch::X86 => $slf.u.x86.$x86case as usize,
                crate::kernel_abi::SupportedArch::X64 => $slf.u.x64.$x64case as usize,
            }
        }
    };
}

macro_rules! rd_set_reg {
    ($slf:expr, $x86case:ident, $x64case:ident, $val:expr) => {
        match $slf.arch_ {
            crate::kernel_abi::SupportedArch::X86 => {
                $slf.u.x86.$x86case = $val as i32;
            }
            crate::kernel_abi::SupportedArch::X64 => {
                $slf.u.x64.$x64case = $val as u64;
            }
        }
    };
}

macro_rules! rd_get_reg_signed {
    ($slf:expr, $x86case:ident, $x64case:ident) => {
        rd_get_reg!($slf, $x86case, $x64case) as isize
    };
}

pub enum MismatchBehavior {
    ExpectMismatches,
    LogMismatches,
    BailOnMismatch,
}

const X86_RESERVED_FLAG: usize = 1 << 1;
const X86_TF_FLAG: usize = 1 << 8;
const X86_IF_FLAG: usize = 1 << 9;
const X86_DF_FLAG: usize = 1 << 10;
const X86_RF_FLAG: usize = 1 << 16;
const X86_ID_FLAG: usize = 1 << 21;

#[repr(C)]
#[derive(Copy, Clone)]
pub union RegistersUnion {
    x86: x86::user_regs_struct,
    x64: x64::user_regs_struct,
}

impl RegistersUnion {
    pub fn default() -> RegistersUnion {
        RegistersUnion {
            x64: x64::user_regs_struct::default(),
        }
    }
}

impl RegistersNativeUnion {
    pub fn default() -> RegistersNativeUnion {
        RegistersNativeUnion {
            x64: x64::user_regs_struct::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union RegistersNativeUnion {
    native: native_user_regs_struct,
    x64: x64::user_regs_struct,
}

#[derive(Copy, Clone)]
pub struct Registers {
    arch_: SupportedArch,
    u: RegistersUnion,
}

impl Registers {
    pub fn new(arch: SupportedArch) -> Registers {
        let r = RegistersUnion {
            x64: x64::user_regs_struct::default(),
        };

        Registers { arch_: arch, u: r }
    }

    pub fn arch(&self) -> SupportedArch {
        self.arch_
    }

    pub fn set_arch(&mut self, arch: SupportedArch) {
        self.arch_ = arch;
    }

    pub fn set_from_ptrace(&mut self, ptrace_regs: &native_user_regs_struct) {
        let mut native = RegistersNativeUnion::default();
        native.native = *ptrace_regs;

        if self.arch() == RD_NATIVE_ARCH {
            unsafe {
                self.u = std::mem::transmute::<RegistersNativeUnion, RegistersUnion>(native);
            }
        } else {
            debug_assert!(self.arch() == X86 && RD_NATIVE_ARCH == X64);
            unsafe {
                let regs = std::mem::transmute::<RegistersNativeUnion, RegistersUnion>(native);

                convert_x86_narrow(&mut self.u.x86, &regs.x64, to_x86_narrow, to_x86_narrow);
            }
        }
    }

    pub fn get_ptrace(&self) -> native_user_regs_struct {
        if self.arch() == RD_NATIVE_ARCH {
            unsafe {
                let n = std::mem::transmute::<RegistersUnion, RegistersNativeUnion>(self.u);
                n.native
            }
        } else {
            debug_assert!(self.arch() == X86 && RD_NATIVE_ARCH == X64);
            let mut result = RegistersUnion::default();
            unsafe {
                convert_x86_widen(
                    &mut result.x64,
                    &self.u.x86,
                    from_x86_narrow,
                    from_x86_narrow_signed,
                );
                let n = std::mem::transmute::<RegistersUnion, RegistersNativeUnion>(result);
                n.native
            }
        }
    }

    pub fn get_ptrace_for_arch(arch: SupportedArch) -> Vec<u8> {
        unimplemented!()
    }

    // @TODO should this be signed or unsigned?
    pub fn syscallno(&self) -> isize {
        rd_get_reg_signed!(self, eax, rax)
    }

    pub fn set_syscallno(&mut self, syscallno: isize) {
        rd_set_reg!(self, eax, rax, syscallno)
    }

    pub fn syscall_result(&self) -> usize {
        rd_get_reg!(self, eax, rax)
    }

    pub fn syscall_result_signed(&self) -> isize {
        rd_get_reg_signed!(self, eax, rax)
    }

    pub fn flags(&self) -> usize {
        unsafe {
            match self.arch() {
                X86 => self.u.x86.eflags as usize,
                X64 => self.u.x64.eflags as usize,
            }
        }
    }

    pub fn set_flags(&mut self, value: usize) {
        match self.arch() {
            X86 => self.u.x86.eflags = value as i32,
            X64 => self.u.x64.eflags = value as u64,
        }
    }
}

fn to_x86_narrow(r32: &mut i32, r64: u64) {
    *r32 = r64 as i32;
}
// No signed extension
fn from_x86_narrow(r64: &mut u64, r32: i32) {
    *r64 = r32 as u32 as u64
}
// Signed extension
fn from_x86_narrow_signed(r64: &mut u64, r32: i32) {
    *r64 = r32 as i64 as u64;
}

fn convert_x86_widen<F1, F2>(
    x64: &mut x64::user_regs_struct,
    x86: &x86::user_regs_struct,
    widen: F1,
    widen_signed: F2,
) -> ()
where
    F1: Fn(&mut u64, i32),
    F2: Fn(&mut u64, i32),
{
    widen_signed(&mut x64.rax, x86.eax);
    widen(&mut x64.rbx, x86.ebx);
    widen(&mut x64.rcx, x86.ecx);
    widen(&mut x64.rdx, x86.edx);
    widen(&mut x64.rsi, x86.esi);
    widen(&mut x64.rdi, x86.edi);
    widen(&mut x64.rsp, x86.esp);
    widen(&mut x64.rbp, x86.ebp);
    widen(&mut x64.rip, x86.eip);
    widen(&mut x64.orig_rax, x86.orig_eax);
    widen(&mut x64.eflags, x86.eflags);
    widen(&mut x64.cs, x86.xcs);
    widen(&mut x64.ds, x86.xds);
    widen(&mut x64.es, x86.xes);
    widen(&mut x64.fs, x86.xfs);
    widen(&mut x64.gs, x86.xgs);
    widen(&mut x64.ss, x86.xss);
}

fn convert_x86_narrow<F1, F2>(
    x86: &mut x86::user_regs_struct,
    x64: &x64::user_regs_struct,
    narrow: F1,
    narrow_signed: F2,
) -> ()
where
    F1: Fn(&mut i32, u64),
    F2: Fn(&mut i32, u64),
{
    narrow_signed(&mut x86.eax, x64.rax);
    narrow(&mut x86.ebx, x64.rbx);
    narrow(&mut x86.ecx, x64.rcx);
    narrow(&mut x86.edx, x64.rdx);
    narrow(&mut x86.esi, x64.rsi);
    narrow(&mut x86.edi, x64.rdi);
    narrow(&mut x86.esp, x64.rsp);
    narrow(&mut x86.ebp, x64.rbp);
    narrow(&mut x86.eip, x64.rip);
    narrow(&mut x86.orig_eax, x64.orig_rax);
    narrow(&mut x86.eflags, x64.eflags);
    narrow(&mut x86.xcs, x64.cs);
    narrow(&mut x86.xds, x64.ds);
    narrow(&mut x86.xes, x64.es);
    narrow(&mut x86.xfs, x64.fs);
    narrow(&mut x86.xgs, x64.gs);
    narrow(&mut x86.xss, x64.ss);
}
