use crate::bindings::kernel::user_regs_struct as native_user_regs_struct;
use crate::gdb_register::*;
use crate::kernel_abi::x64;
use crate::kernel_abi::x86;
use crate::kernel_abi::SupportedArch;
use crate::kernel_abi::RD_NATIVE_ARCH;
use crate::kernel_supplement::{
    ERESTARTNOHAND, ERESTARTNOINTR, ERESTARTSYS, ERESTART_RESTARTBLOCK,
};
use crate::log::LogLevel::LogWarn;
use crate::remote_code_ptr::RemoteCodePtr;
use crate::remote_ptr::RemotePtr;
use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::num::Wrapping;
use SupportedArch::*;

pub struct X86Arch;
pub struct X64Arch;

pub trait Architecture {
    fn get_regs_info() -> &'static HashMap<u32, RegisterValue>;
    fn ignore_undefined_register(regno: GdbRegister) -> bool;
    fn num_registers() -> u32;
}

impl Architecture for X86Arch {
    fn get_regs_info() -> &'static HashMap<u32, RegisterValue> {
        &*REGISTERS_X86
    }

    fn ignore_undefined_register(regno: GdbRegister) -> bool {
        regno == DREG_FOSEG || regno == DREG_MXCSR
    }
    fn num_registers() -> u32 {
        DREG_NUM_LINUX_I386
    }
}

impl Architecture for X64Arch {
    fn get_regs_info() -> &'static HashMap<u32, RegisterValue> {
        &*REGISTERS_X64
    }

    fn ignore_undefined_register(regno: GdbRegister) -> bool {
        regno == DREG_64_FOSEG || regno == DREG_64_MXCSR
    }
    fn num_registers() -> u32 {
        DREG_NUM_LINUX_X86_64
    }
}

lazy_static! {
    static ref REGISTERS_X86: HashMap<u32, RegisterValue> = x86regs();
    static ref REGISTERS_X64: HashMap<u32, RegisterValue> = x64regs();
}

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
    pub fn read_registers_arch<Arch: Architecture>(
        &self,
        buf: &mut [u8],
        regno: GdbRegister,
    ) -> Option<usize> {
        let regs = Arch::get_regs_info();
        if let Some(rv) = regs.get(&regno) {
            if rv.nbytes == 0 {
                None
            } else {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        rv.pointer_into(&self.u),
                        buf.as_mut_ptr(),
                        rv.nbytes,
                    );
                };
                Some(rv.nbytes)
            }
        } else {
            None
        }
    }

    pub fn read_registers(&self, buf: &mut [u8], regno: GdbRegister) -> Option<usize> {
        rd_arch_function!(self, read_registers_arch, self.arch(), buf, regno)
    }

    pub fn write_register_arch<Arch: Architecture>(&mut self, value: &[u8], regno: GdbRegister) {
        let regs = Arch::get_regs_info();
        if let Some(rv) = regs.get(&regno) {
            if rv.nbytes == 0 {
                // TODO: can we get away with not writing these?
                if Arch::ignore_undefined_register(regno) {
                    return;
                }
                log!(LogWarn, "Unhandled register name {}", regno);
            } else {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        value.as_ptr(),
                        rv.mut_pointer_into(&mut self.u),
                        value.len(),
                    );
                };
            }
        }
    }

    pub fn write_register(&mut self, value: &[u8], regno: GdbRegister) {
        rd_arch_function!(self, write_register_arch, self.arch(), value, regno)
    }

    pub fn write_register_by_user_offset_arch<Arch: Architecture>(
        &mut self,
        offset: usize,
        value: usize,
    ) {
        let regs = Arch::get_regs_info();
        for (_, rv) in regs.iter() {
            if rv.offset == offset {
                debug_assert!(rv.nbytes <= std::mem::size_of::<usize>());
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &value as *const _ as *const u8,
                        rv.mut_pointer_into(&mut self.u),
                        rv.nbytes,
                    );
                };
                return;
            }
        }
    }

    pub fn write_register_by_user_offset(&mut self, offset: usize, value: usize) {
        rd_arch_function!(
            self,
            write_register_by_user_offset_arch,
            self.arch(),
            offset,
            value
        )
    }

    pub fn read_registers_by_user_offset_arch<Arch: Architecture>(
        &self,
        buf: &mut [u8],
        offset: usize,
        regno: GdbRegister,
    ) -> Option<usize> {
        let regs = Arch::get_regs_info();
        for (_, rv) in regs.iter() {
            if rv.offset == offset {
                return self.read_registers_arch::<Arch>(buf, regno);
            }
        }
        None
    }

    pub fn read_registers_by_user_offset(
        &self,
        buf: &mut [u8],
        offset: usize,
        regno: GdbRegister,
    ) -> Option<usize> {
        rd_arch_function!(
            self,
            read_registers_by_user_offset_arch,
            self.arch(),
            buf,
            offset,
            regno
        )
    }

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

    pub fn get_ptrace_for_self_arch(&self) -> &[u8] {
        match self.arch_ {
            X86 => {
                let l = std::mem::size_of::<x86::user_regs_struct>();
                unsafe {
                    std::slice::from_raw_parts(
                        &self.u.x86 as *const x86::user_regs_struct as *const u8,
                        l,
                    )
                }
            }
            X64 => {
                let l = std::mem::size_of::<x64::user_regs_struct>();
                unsafe {
                    std::slice::from_raw_parts(
                        &self.u.x64 as *const x64::user_regs_struct as *const u8,
                        l,
                    )
                }
            }
        }
    }

    pub fn get_ptrace_for_arch(&self, arch: SupportedArch) -> Vec<u8> {
        let mut tmp_regs = Registers::new(arch);
        tmp_regs.set_from_ptrace(&self.get_ptrace());
        let l = match arch {
            X86 => std::mem::size_of::<x86::user_regs_struct>(),
            X64 => std::mem::size_of::<x64::user_regs_struct>(),
        };

        let mut v: Vec<u8> = Vec::with_capacity(l);
        unsafe {
            std::ptr::copy_nonoverlapping(
                &tmp_regs as *const Registers as *const u8,
                v.as_mut_ptr(),
                l,
            );
        }
        v
    }

    pub fn set_from_ptrace_for_arch(&mut self, arch: SupportedArch, data: &[u8]) {
        if arch == RD_NATIVE_ARCH {
            debug_assert_eq!(data.len(), std::mem::size_of::<native_user_regs_struct>());
            let mut n = RegistersNativeUnion::default();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    &mut n.native as *mut native_user_regs_struct as *mut u8,
                    data.len(),
                );
                self.set_from_ptrace(&n.native);
            }
        } else {
            debug_assert!(arch == X86 && RD_NATIVE_ARCH == X64);
            debug_assert!(self.arch() == X86);
            debug_assert_eq!(data.len(), std::mem::size_of::<x86::user_regs_struct>());
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    &mut self.u.x86 as *mut x86::user_regs_struct as *mut u8,
                    std::mem::size_of::<x86::user_regs_struct>(),
                );
            }
        }
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

    pub fn set_syscall_result(&mut self, syscall_result: usize) {
        rd_set_reg!(self, eax, rax, syscall_result);
    }

    pub fn set_syscall_result_from_remote_ptr<T>(&mut self, syscall_result: RemotePtr<T>) {
        rd_set_reg!(self, eax, rax, syscall_result.as_usize());
    }

    pub fn flags(&self) -> usize {
        unsafe {
            match self.arch_ {
                X86 => self.u.x86.eflags as usize,
                X64 => self.u.x64.eflags as usize,
            }
        }
    }

    pub fn set_flags(&mut self, value: usize) {
        match self.arch_ {
            X86 => self.u.x86.eflags = value as i32,
            X64 => self.u.x64.eflags = value as u64,
        }
    }

    pub fn syscall_failed(&self) -> bool {
        let result = self.syscall_result_signed();
        -4096 < result && result < 0
    }

    pub fn syscall_may_restart(&self) -> bool {
        match -self.syscall_result_signed() as u32 {
            ERESTART_RESTARTBLOCK | ERESTARTNOINTR | ERESTARTNOHAND | ERESTARTSYS => true,
            _ => false,
        }
    }

    pub fn ip(&self) -> RemoteCodePtr {
        let addr = rd_get_reg!(self, eip, rip);
        RemoteCodePtr::new_from_val(addr)
    }

    pub fn set_ip(&mut self, addr: RemoteCodePtr) {
        rd_set_reg!(self, eip, rip, addr.as_usize());
    }

    pub fn sp(&self) -> RemotePtr<u8> {
        let addr = rd_get_reg!(self, esp, rsp);
        RemotePtr::<u8>::new_from_val(addr)
    }

    pub fn set_sp(&mut self, addr: RemotePtr<u8>) {
        rd_set_reg!(self, esp, rsp, addr.as_usize());
    }

    pub fn original_syscallno(&self) -> isize {
        rd_get_reg_signed!(self, orig_eax, orig_rax)
    }

    pub fn set_original_syscallno(&mut self, syscallno: usize) {
        rd_set_reg!(self, orig_eax, orig_rax, syscallno);
    }

    pub fn arg1(&self) -> usize {
        rd_get_reg!(self, ebx, rdi)
    }
    pub fn arg1_signed(&self) -> isize {
        rd_get_reg_signed!(self, ebx, rdi)
    }
    pub fn set_arg1(&mut self, value: usize) {
        rd_set_reg!(self, ebx, rdi, value);
    }
    pub fn set_arg1_from_remote_ptr<T>(&mut self, value: RemotePtr<T>) {
        rd_set_reg!(self, ebx, rdi, value.as_usize());
    }

    pub fn arg2(&self) -> usize {
        rd_get_reg!(self, ecx, rsi)
    }
    pub fn arg2_signed(&self) -> isize {
        rd_get_reg_signed!(self, ecx, rsi)
    }
    pub fn set_arg2(&mut self, value: usize) {
        rd_set_reg!(self, ecx, rsi, value);
    }
    pub fn set_arg2_from_remote_ptr<T>(&mut self, value: RemotePtr<T>) {
        rd_set_reg!(self, ecx, rsi, value.as_usize());
    }

    pub fn arg3(&self) -> usize {
        rd_get_reg!(self, edx, rdx)
    }
    pub fn arg3_signed(&self) -> isize {
        rd_get_reg_signed!(self, edx, rdx)
    }
    pub fn set_arg3(&mut self, value: usize) {
        rd_set_reg!(self, edx, rdx, value);
    }
    pub fn set_arg3_from_remote_ptr<T>(&mut self, value: RemotePtr<T>) {
        rd_set_reg!(self, edx, rdx, value.as_usize());
    }

    pub fn arg4(&self) -> usize {
        rd_get_reg!(self, esi, r10)
    }
    pub fn arg4_signed(&self) -> isize {
        rd_get_reg_signed!(self, esi, r10)
    }
    pub fn set_arg4(&mut self, value: usize) {
        rd_set_reg!(self, esi, r10, value);
    }
    pub fn set_arg4_from_remote_ptr<T>(&mut self, value: RemotePtr<T>) {
        rd_set_reg!(self, esi, r10, value.as_usize());
    }

    pub fn arg5(&self) -> usize {
        rd_get_reg!(self, edi, r8)
    }
    pub fn arg5_signed(&self) -> isize {
        rd_get_reg_signed!(self, edi, r8)
    }
    pub fn set_arg5(&mut self, value: usize) {
        rd_set_reg!(self, edi, r8, value);
    }
    pub fn set_arg5_from_remote_ptr<T>(&mut self, value: RemotePtr<T>) {
        rd_set_reg!(self, edi, r8, value.as_usize());
    }

    pub fn arg6(&self) -> usize {
        rd_get_reg!(self, ebp, r9)
    }
    pub fn arg6_signed(&self) -> isize {
        rd_get_reg_signed!(self, ebp, r9)
    }
    pub fn set_arg6(&mut self, value: usize) {
        rd_set_reg!(self, ebp, r9, value);
    }
    pub fn set_arg6_from_remote_ptr<T>(&mut self, value: RemotePtr<T>) {
        rd_set_reg!(self, ebp, r9, value.as_usize());
    }

    pub fn arg(&self, index: i32) -> usize {
        match index {
            1 => self.arg1(),
            2 => self.arg2(),
            3 => self.arg3(),
            4 => self.arg4(),
            5 => self.arg5(),
            6 => self.arg6(),
            _ => {
                debug_assert!(false, "Argument index out of range");
                0
            }
        }
    }

    pub fn set_arg(&mut self, index: i32, value: usize) {
        match index {
            1 => self.set_arg1(value),
            2 => self.set_arg2(value),
            3 => self.set_arg3(value),
            4 => self.set_arg4(value),
            5 => self.set_arg5(value),
            6 => self.set_arg6(value),
            _ => {
                debug_assert!(false, "Argument index out of range");
            }
        }
    }

    pub fn set_arg_from_remote_ptr<T>(&mut self, index: i32, value: RemotePtr<T>) {
        match index {
            1 => self.set_arg1_from_remote_ptr(value),
            2 => self.set_arg2_from_remote_ptr(value),
            3 => self.set_arg3_from_remote_ptr(value),
            4 => self.set_arg4_from_remote_ptr(value),
            5 => self.set_arg5_from_remote_ptr(value),
            6 => self.set_arg6_from_remote_ptr(value),
            _ => {
                debug_assert!(false, "Argument index out of range");
            }
        }
    }

    pub fn set_rdtsc_output(&mut self, value: u64) {
        rd_set_reg!(self, eax, rax, value & 0xffffffff);
        rd_set_reg!(self, edx, rdx, value >> 32);
    }

    pub fn set_cpuid_output(&mut self, eax: u32, ebx: u32, ecx: u32, edx: u32) {
        rd_set_reg!(self, eax, rax, eax);
        rd_set_reg!(self, ebx, rbx, ebx);
        rd_set_reg!(self, ecx, rcx, ecx);
        rd_set_reg!(self, edx, rdx, edx);
    }

    pub fn set_r8(&mut self, value: u64) {
        debug_assert!(self.arch() == X64);
        self.u.x64.r8 = value;
    }

    pub fn set_r9(&mut self, value: u64) {
        debug_assert!(self.arch() == X64);
        self.u.x64.r9 = value;
    }

    pub fn set_r10(&mut self, value: u64) {
        debug_assert!(self.arch() == X64);
        self.u.x64.r10 = value;
    }

    pub fn set_r11(&mut self, value: u64) {
        debug_assert!(self.arch() == X64);
        self.u.x64.r11 = value;
    }

    pub fn di(&self) -> usize {
        rd_get_reg!(self, edi, rdi)
    }
    pub fn set_di(&mut self, value: usize) {
        rd_set_reg!(self, edi, rdi, value);
    }

    pub fn si(&self) -> usize {
        rd_get_reg!(self, esi, rsi)
    }
    pub fn set_si(&mut self, value: usize) {
        rd_set_reg!(self, esi, rsi, value);
    }

    pub fn cx(&self) -> usize {
        rd_get_reg!(self, ecx, rcx)
    }
    pub fn set_cx(&mut self, value: usize) {
        rd_set_reg!(self, ecx, rcx, value);
    }

    pub fn ax(&self) -> usize {
        rd_get_reg!(self, eax, rax)
    }
    pub fn bp(&self) -> usize {
        rd_get_reg!(self, ebp, rbp)
    }

    pub fn singlestep_flag(&self) -> bool {
        self.flags() & X86_TF_FLAG == X86_TF_FLAG
    }
    pub fn clear_singlestep_flag(&mut self) {
        self.set_flags(self.flags() & !X86_TF_FLAG);
    }
    pub fn df_flag(&self) -> bool {
        self.flags() & X86_DF_FLAG == X86_DF_FLAG
    }

    pub fn fs_base(&self) -> u64 {
        debug_assert!(self.arch() == X64);
        unsafe { self.u.x64.fs_base }
    }
    pub fn gs_base(&self) -> u64 {
        debug_assert!(self.arch() == X64);
        unsafe { self.u.x64.gs_base }
    }

    pub fn set_fs_base(&mut self, fs_base: u64) {
        debug_assert!(self.arch() == X64);
        self.u.x64.fs_base = fs_base;
    }

    pub fn set_gs_base(&mut self, gs_base: u64) {
        debug_assert!(self.arch() == X64);
        self.u.x64.gs_base = gs_base;
    }

    pub fn cs(&self) -> usize {
        rd_get_reg!(self, xcs, cs)
    }
    pub fn ss(&self) -> usize {
        rd_get_reg!(self, xss, ss)
    }
    pub fn ds(&self) -> usize {
        rd_get_reg!(self, xds, ds)
    }
    pub fn es(&self) -> usize {
        rd_get_reg!(self, xes, es)
    }
    pub fn fs(&self) -> usize {
        rd_get_reg!(self, xfs, fs)
    }
    pub fn gs(&self) -> usize {
        rd_get_reg!(self, xgs, gs)
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

impl Display for Registers {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{{ args:({:#x},{:#x},{:#x},{:#x},{:#x},{:#x}) orig_syscall:{} }}",
            self.arg1(),
            self.arg2(),
            self.arg3(),
            self.arg4(),
            self.arg5(),
            self.arg6(),
            self.original_syscallno()
        )
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RegisterValue {
    /// The name of this register.
    pub name: &'static str,
    /// The offsetof the register in user_regs_struct.
    pub offset: usize,
    /// The size of the register.  0 means we cannot read it.
    pub nbytes: usize,
    /// Mask to be applied to register values prior to comparing them.  Will
    /// typically be ((1 << nbytes*8) - 1), but some registers may have special
    /// comparison semantics.
    pub comparison_mask: u64,
}

impl RegisterValue {
    pub fn new(name: &'static str, offset: usize, nbytes: usize) -> RegisterValue {
        let comparison_mask: u64 = RegisterValue::mask_for_nbytes(nbytes);
        RegisterValue {
            name,
            offset,
            comparison_mask,
            nbytes,
        }
    }

    pub fn new_with_mask(
        name: &'static str,
        offset: usize,
        nbytes: usize,
        comparison_mask: u64,
    ) -> RegisterValue {
        // Ensure no bits are set outside of the register's bitwidth.
        debug_assert!((comparison_mask & !RegisterValue::mask_for_nbytes(nbytes)) == 0);
        RegisterValue {
            name,
            offset,
            comparison_mask,
            nbytes,
        }
    }

    pub fn new_with_mask_with_size_override(
        name: &'static str,
        offset: usize,
        mut nbytes: usize,
        comparison_mask: u64,
        size_override: usize,
    ) -> RegisterValue {
        // Ensure no bits are set outside of the register's bitwidth.
        debug_assert!((comparison_mask & !RegisterValue::mask_for_nbytes(nbytes)) == 0);

        if size_override > 0 {
            nbytes = size_override;
        }
        RegisterValue {
            name,
            offset,
            comparison_mask,
            nbytes,
        }
    }

    pub fn mask_for_nbytes(nbytes: usize) -> u64 {
        debug_assert!(nbytes <= std::mem::size_of::<u64>());
        if nbytes == std::mem::size_of::<u64>() {
            -1i64 as u64
        } else {
            let minus_one = Wrapping(-1i64 as u64);
            let shifted = Wrapping(1u64 << (nbytes * 8));
            let result = minus_one + shifted;
            result.0
        }
    }

    pub fn pointer_into(&self, regs: &RegistersUnion) -> *const u8 {
        unsafe { (regs as *const _ as *const u8).add(self.offset) }
    }

    pub fn mut_pointer_into(&self, regs: &mut RegistersUnion) -> *mut u8 {
        unsafe { (regs as *mut _ as *mut u8).add(self.offset) }
    }
}

macro_rules! rv_arch {
    ($gdb_name:ident, $name:ident, $arch:ident) => {{
        let el = crate::kernel_abi::$arch::user_regs_struct::default();
        let nbytes = std::mem::size_of_val(&el.$name);
        (
            crate::gdb_register::$gdb_name,
            crate::registers::RegisterValue::new(
                stringify!($name),
                unsafe {
                    &(*(std::ptr::null::<crate::kernel_abi::$arch::user_regs_struct>())).$name
                        as *const _ as usize
                },
                nbytes,
            ),
        )
    }};
    ($gdb_name:ident, $name:ident, $arch:ident, $comparison_mask:expr) => {{
        let el = crate::kernel_abi::$arch::user_regs_struct::default();
        let nbytes = std::mem::size_of_val(&el.$name);
        (
            crate::gdb_register::$gdb_name,
            crate::registers::RegisterValue::new_with_mask(
                stringify!($name),
                unsafe {
                    &(*(std::ptr::null::<crate::kernel_abi::$arch::user_regs_struct>())).$name
                        as *const _ as usize
                },
                nbytes,
                $comparison_mask,
            ),
        )
    }};
    ($gdb_name:ident, $name:ident, $arch:ident, $comparison_mask:expr, $size_override:expr) => {{
        let el = crate::kernel_abi::$arch::user_regs_struct::default();
        let nbytes = std::mem::size_of_val(&el.$name);
        (
            crate::gdb_register::$gdb_name,
            crate::registers::RegisterValue::new_with_mask_with_size_override(
                stringify!($name),
                unsafe {
                    &(*(std::ptr::null::<crate::kernel_abi::$arch::user_regs_struct>())).$name
                        as *const _ as usize
                },
                nbytes,
                $comparison_mask,
                $size_override,
            ),
        )
    }};
}

macro_rules! rv_x86 {
    ($gdb_name:ident, $name:ident) => {
        rv_arch!($gdb_name, $name, x86)
    };
}

macro_rules! rv_x64 {
    ($gdb_name:ident, $name:ident) => {
        rv_arch!($gdb_name, $name, x64)
    };
}

macro_rules! rv_x64_with_mask_with_size {
    ($gdb_name:ident, $name:ident, $comparison_mask:expr, $size_override:expr) => {
        rv_arch!($gdb_name, $name, x64, $comparison_mask, $size_override)
    };
}

macro_rules! rv_x86_with_mask {
    ($gdb_name:ident, $name:ident, $comparison_mask:expr) => {
        rv_arch!($gdb_name, $name, x86, $comparison_mask)
    };
}

fn x86regs() -> HashMap<u32, RegisterValue> {
    let regs = [
        rv_x86!(DREG_EAX, eax),
        rv_x86!(DREG_ECX, ecx),
        rv_x86!(DREG_EDX, edx),
        rv_x86!(DREG_EBX, ebx),
        rv_x86!(DREG_ESP, esp),
        rv_x86!(DREG_EBP, ebp),
        rv_x86!(DREG_ESI, esi),
        rv_x86!(DREG_EDI, edi),
        rv_x86!(DREG_EIP, eip),
        rv_x86_with_mask!(DREG_EFLAGS, eflags, 0),
        rv_x86_with_mask!(DREG_CS, xcs, 0),
        rv_x86_with_mask!(DREG_SS, xss, 0),
        rv_x86_with_mask!(DREG_DS, xds, 0),
        rv_x86_with_mask!(DREG_ES, xes, 0),
        // Mask out the RPL from the fs and gs segment selectors. The kernel
        // unconditionally sets RPL=3 on sigreturn, but if the segment index is 0,
        // the RPL doesn't matter, and the CPU resets the entire register to 0,
        // so whether or not we see this depends on whether the value round-tripped
        // to the CPU yet.
        rv_x86_with_mask!(DREG_FS, xfs, !3u16 as u64),
        rv_x86_with_mask!(DREG_GS, xgs, !3u16 as u64),
        // The comparison for this is handled specially elsewhere.
        rv_x86_with_mask!(DREG_ORIG_EAX, orig_eax, 0),
    ];

    let mut map: HashMap<u32, RegisterValue> = HashMap::new();
    for reg in regs.iter() {
        map.insert(reg.0, reg.1);
    }

    map
}

fn x64regs() -> HashMap<u32, RegisterValue> {
    let regs = [
        rv_x64!(DREG_RAX, rax),
        rv_x64!(DREG_RCX, rcx),
        rv_x64!(DREG_RDX, rdx),
        rv_x64!(DREG_RBX, rbx),
        rv_x64_with_mask_with_size!(DREG_RSP, rsp, 0, 8),
        rv_x64!(DREG_RBP, rbp),
        rv_x64!(DREG_RSI, rsi),
        rv_x64!(DREG_RDI, rdi),
        rv_x64!(DREG_R8, r8),
        rv_x64!(DREG_R9, r9),
        rv_x64!(DREG_R10, r10),
        rv_x64!(DREG_R11, r11),
        rv_x64!(DREG_R12, r12),
        rv_x64!(DREG_R13, r13),
        rv_x64!(DREG_R14, r14),
        rv_x64!(DREG_R15, r15),
        rv_x64!(DREG_RIP, rip),
        rv_x64_with_mask_with_size!(DREG_64_EFLAGS, eflags, 0, 4),
        rv_x64_with_mask_with_size!(DREG_64_CS, cs, 0, 4),
        rv_x64_with_mask_with_size!(DREG_64_SS, ss, 0, 4),
        rv_x64_with_mask_with_size!(DREG_64_DS, ds, 0, 4),
        rv_x64_with_mask_with_size!(DREG_64_ES, es, 0, 4),
        rv_x64_with_mask_with_size!(DREG_64_FS, fs, 0xffffffff, 4),
        rv_x64_with_mask_with_size!(DREG_64_GS, gs, 0xffffffff, 4),
        // The comparison for this is handled specially
        // elsewhere.
        rv_x64_with_mask_with_size!(DREG_ORIG_RAX, orig_rax, 0, 8),
        rv_x64!(DREG_FS_BASE, fs_base),
        rv_x64!(DREG_GS_BASE, gs_base),
    ];

    let mut map: HashMap<u32, RegisterValue> = HashMap::new();
    for reg in regs.iter() {
        map.insert(reg.0, reg.1);
    }

    map
}
