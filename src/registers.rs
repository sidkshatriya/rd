use crate::bindings::kernel::user_regs_struct as native_user_regs_struct;
use crate::gdb_register::*;
use crate::kernel_abi::x64;
use crate::kernel_abi::x86;
use crate::kernel_abi::SupportedArch;
use crate::kernel_abi::RD_NATIVE_ARCH;
use crate::kernel_supplement::{
    ERESTARTNOHAND, ERESTARTNOINTR, ERESTARTSYS, ERESTART_RESTARTBLOCK,
};
use crate::log::LogLevel::{LogError, LogInfo, LogWarn};
use crate::remote_code_ptr::RemoteCodePtr;
use crate::remote_ptr::RemotePtr;
use crate::task_interface::task::task::Task;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::io;
use std::io::Write;
use std::mem::size_of;
use std::mem::zeroed;
use std::num::Wrapping;
use std::ptr::copy_nonoverlapping;

#[derive(Copy, Clone, PartialEq)]
enum TraceStyle {
    Annotated,
    Raw,
}

lazy_static! {
    static ref REGISTERS_X86: HashMap<u32, RegisterValue> = x86regs();
    static ref REGISTERS_X64: HashMap<u32, RegisterValue> = x64regs();
}

macro_rules! rd_get_reg {
    ($slf:expr, $x86case:ident, $x64case:ident) => {
        match $slf {
            X86(regs) => regs.$x86case as usize,
            X64(regs) => regs.$x64case as usize,
        }
    };
}

macro_rules! rd_set_reg {
    ($slf:expr, $x86case:ident, $x64case:ident, $val:expr) => {
        match $slf {
            X86(regs) => {
                regs.$x86case = $val as i32;
            }
            X64(regs) => {
                regs.$x64case = $val as u64;
            }
        }
    };
}

macro_rules! rd_get_reg_signed {
    ($slf:expr, $x86case:ident, $x64case:ident) => {
        rd_get_reg!($slf, $x86case, $x64case) as isize
    };
}

#[derive(Copy, Clone, PartialEq, PartialOrd)]
pub enum MismatchBehavior {
    ExpectMismatches = 1,
    LogMismatches = 2,
    BailOnMismatch = 3,
}

const X86_RESERVED_FLAG: usize = 1 << 1;
const X86_TF_FLAG: usize = 1 << 8;
const X86_IF_FLAG: usize = 1 << 9;
const X86_DF_FLAG: usize = 1 << 10;
const X86_RF_FLAG: usize = 1 << 16;
const X86_ID_FLAG: usize = 1 << 21;

#[derive(Copy, Clone)]
pub enum Registers {
    X64(x64::user_regs_struct),
    X86(x86::user_regs_struct),
}

use Registers::*;

/// A Registers object contains values for all general-purpose registers.
/// These must include all registers used to pass syscall parameters and return
/// syscall results.
///
/// When reading register values, be sure to cast the result to the correct
/// type according to the kernel docs. E.g. int values should be cast
/// to int explicitly (or implicitly, by assigning to an int-typed variable),
/// size_t should be cast to size_t, etc. If the type is signed, call the
/// _signed getter. This ensures that when building rr 64-bit we will use the
/// right number of register bits whether the tracee is 32-bit or 64-bit, and
/// get sign-extension right.
///
/// We have different register sets for different architectures. To ensure a
/// trace can be dumped/processed by an rr build on any platform, we allow
/// Registers to contain registers for any architecture. So we store them
/// in a union of Arch::user_regs_structs for each known Arch.
impl Registers {
    fn get_regs_info(&self) -> &'static HashMap<u32, RegisterValue> {
        match self {
            X86(_) => &*REGISTERS_X86,
            X64(_) => &*REGISTERS_X64,
        }
    }

    fn ignore_undefined_register(&self, regno: GdbRegister) -> bool {
        match self {
            X86(_) => regno == DREG_FOSEG || regno == DREG_MXCSR,
            X64(_) => regno == DREG_64_FOSEG || regno == DREG_64_MXCSR,
        }
    }
    fn num_registers(&self) -> u32 {
        match self {
            X86(_) => DREG_NUM_LINUX_I386,
            X64(_) => DREG_NUM_LINUX_X86_64,
        }
    }

    fn x86(&self) -> &x86::user_regs_struct {
        match self {
            X86(regs) => regs,
            X64(_) => panic!("Not an x86::user_regs_struct"),
        }
    }

    fn x86_mut(&mut self) -> &mut x86::user_regs_struct {
        match self {
            X86(regs) => regs,
            X64(_) => panic!("Not an x86::user_regs_struct"),
        }
    }

    fn x64(&self) -> &x64::user_regs_struct {
        match self {
            X64(regs) => regs,
            X86(_) => panic!("Not an x64::user_regs_struct"),
        }
    }

    fn x64_mut(&mut self) -> &mut x64::user_regs_struct {
        match self {
            X64(regs) => regs,
            X86(_) => panic!("Not an x64::user_regs_struct"),
        }
    }

    fn compare_registers_arch(
        name1: &str,
        name2: &str,
        regs1: &Registers,
        regs2: &Registers,
        mismatch_behavior: MismatchBehavior,
    ) -> bool {
        let mut match_ = true;
        debug_assert!(regs1.arch() == regs2.arch());
        let regs_info = regs1.get_regs_info();

        match regs1 {
            X86(regs1_x86) => {
                let regs2_x86 = regs2.x86();
                // When the kernel is entered via an interrupt, orig_rax is set to -IRQ.
                // We observe negative orig_eax values at SCHED events and signals and other
                // timer interrupts. These values are only really meaningful to compare when
                // they reflect original syscall numbers, in which case both will be positive.
                if regs1_x86.orig_eax >= 0 && regs2_x86.orig_eax > 0 {
                    if regs1_x86.orig_eax != regs2_x86.orig_eax {
                        maybe_log_reg_mismatch(
                            mismatch_behavior,
                            "orig_eax",
                            name1,
                            regs1_x86.orig_eax as u64,
                            name2,
                            regs2_x86.orig_eax as u64,
                        );
                        match_ = false;
                    }
                }
            }
            X64(regs1_x64) => {
                let regs2_x64 = regs2.x64();
                // See comment in the x86 case
                if (regs1_x64.orig_rax as i64) >= 0 && (regs2_x64.orig_rax as i64) > 0 {
                    if regs1_x64.orig_rax != regs2_x64.orig_rax {
                        maybe_log_reg_mismatch(
                            mismatch_behavior,
                            "orig_rax",
                            name1,
                            regs1_x64.orig_rax,
                            name2,
                            regs2_x64.orig_rax,
                        );
                        match_ = false;
                    }
                }
            }
        }

        let mut val1: u64;
        let mut val2: u64;
        for (_, rv) in regs_info.iter() {
            if rv.nbytes == 0 {
                continue;
            }

            // Disregard registers that will trivially compare equal.
            if rv.comparison_mask == 0 {
                continue;
            }

            match regs1 {
                X86(regs1_x86) => {
                    let regs2_x86 = regs2.x86();
                    debug_assert!(rv.nbytes == 4);
                    let val1_32 = rv.u32_into_x86(&regs1_x86);
                    let val2_32 = rv.u32_into_x86(&regs2_x86);

                    val1 = val1_32 as u64;
                    val2 = val2_32 as u64;
                }
                X64(regs1_x64) => {
                    let regs2_x64 = regs2.x64();
                    debug_assert!(rv.nbytes == 8);
                    val1 = rv.u64_into_x64(&regs1_x64);
                    val2 = rv.u64_into_x64(&regs2_x64);
                }
            }

            if val1 & rv.comparison_mask != val2 & rv.comparison_mask {
                maybe_log_reg_mismatch(mismatch_behavior, rv.name, name1, val1, name2, val2);
                match_ = false;
            }
        }

        match_
    }

    fn compare_register_files_internal(
        name1: &str,
        regs1: &Registers,
        name2: &str,
        regs2: &Registers,
        mismatch_behavior: MismatchBehavior,
    ) -> bool {
        debug_assert!(regs1.arch() == regs2.arch());
        Registers::compare_registers_arch(name1, name2, regs1, regs2, mismatch_behavior)
    }

    /// Return true if |regs1| matches |regs2|.  Passing EXPECT_MISMATCHES
    /// indicates that the caller is using this as a general register
    /// compare and nothing special should be done if the register files
    /// mismatch.  Passing LOG_MISMATCHES will log the registers that don't
    /// match.  Passing BAIL_ON_MISMATCH will additionally abort on
    /// mismatch.
    // @TODO the first param shold be Option<&ReplayTask>
    pub fn compare_register_files(
        maybe_t: Option<&Task>,
        name1: &str,
        regs1: &Registers,
        name2: &str,
        regs2: &Registers,
        mismatch_behavior: MismatchBehavior,
    ) -> bool {
        let bail_error = mismatch_behavior >= MismatchBehavior::BailOnMismatch;
        let match_ = Registers::compare_register_files_internal(
            name1,
            regs1,
            name2,
            regs2,
            mismatch_behavior,
        );
        if let Some(t) = maybe_t {
            // @TODO complete this.
            ed_assert!(
                t,
                !bail_error || match_,
                "Fatal register mismatch (ticks/rec:{}/{})",
                1,
                1
            );
        } else {
            debug_assert!(!bail_error || match_);
        }

        if match_ && mismatch_behavior == MismatchBehavior::LogMismatches {
            log!(
                LogInfo,
                "(register files are the same for {} and {})",
                name1,
                name2
            );
        }

        match_
    }

    pub fn matches(&self, other: &Registers) -> bool {
        Registers::compare_register_files(
            None,
            "",
            self,
            "",
            other,
            MismatchBehavior::ExpectMismatches,
        )
    }

    /// Write the value for register |regno| into |buf|, which should
    /// be large enough to hold any register supported by the target.
    /// Return the size of the register in bytes. If None is returned it
    /// indicates that no value was written to |buf|.
    fn read_register(&self, buf: &mut [u8], regno: GdbRegister) -> Option<usize> {
        let regs = self.get_regs_info();
        if let Some(rv) = regs.get(&regno) {
            match rv.nbytes {
                0 => None,
                4 => {
                    buf.get_mut(0..rv.nbytes)
                        .unwrap()
                        .copy_from_slice(&rv.u32_into_x86(self.x86()).to_le_bytes());
                    Some(rv.nbytes)
                }
                8 => {
                    buf.get_mut(0..rv.nbytes)
                        .unwrap()
                        .copy_from_slice(&rv.u64_into_x64(self.x64()).to_le_bytes());
                    Some(rv.nbytes)
                }
                _ => {
                    debug_assert!(false, format!("Unknown register size: {}", rv.nbytes));
                    None
                }
            }
        } else {
            None
        }
    }

    /// Update the register named |reg_name| to |value| with
    /// |value_size| number of bytes.
    pub fn write_register(&mut self, value: &[u8], regno: GdbRegister) {
        let regs = self.get_regs_info();
        if let Some(rv) = regs.get(&regno) {
            match rv.nbytes {
                0 => {
                    // TODO: can we get away with not writing these?
                    if self.ignore_undefined_register(regno) {
                        return;
                    }
                    log!(LogWarn, "Unhandled register name {}", regno);
                }
                4 => {
                    let rv_ref = rv.mut_u32_ref_into_x86(&mut self.x86_mut());
                    *rv_ref = u32::from_le_bytes(value.get(0..4).unwrap().try_into().unwrap());
                }
                8 => {
                    let rv_ref = rv.mut_u64_ref_into_x64(&mut self.x64_mut());
                    *rv_ref = u64::from_le_bytes(value.get(0..8).unwrap().try_into().unwrap());
                }
                _ => {
                    debug_assert!(false, format!("Unknown register size: {}", rv.nbytes));
                }
            }
        }
    }

    /// Update the register at user offset |offset| to |value|, taking the low
    /// bytes if necessary.
    pub fn write_register_by_user_offset(&mut self, offset: usize, value: usize) {
        let regs = self.get_regs_info();
        for (_, rv) in regs.iter() {
            if rv.offset == offset {
                debug_assert!(rv.nbytes <= size_of::<usize>());

                match self {
                    X86(regs_x86) => {
                        unsafe {
                            copy_nonoverlapping(
                                &value as *const _ as *const u8,
                                rv.mut_pointer_into_x86(regs_x86),
                                rv.nbytes,
                            );
                        };
                    }
                    X64(regs_x64) => {
                        unsafe {
                            copy_nonoverlapping(
                                &value as *const _ as *const u8,
                                rv.mut_pointer_into_x64(regs_x64),
                                rv.nbytes,
                            );
                        };
                    }
                }

                return;
            }
        }
    }

    /// Write the value for register |offset| into |buf|, which should
    /// be large enough to hold any register supported by the target.
    /// Return the size of the register in bytes as an Option. If None
    /// is returned it indicates that no value was written to |buf|.
    /// |offset| is the offset of the register within a user_regs_struct.
    pub fn read_registers_by_user_offset(&self, buf: &mut [u8], offset: usize) -> Option<usize> {
        let regs = self.get_regs_info();
        for (regno, rv) in regs.iter() {
            if rv.offset == offset {
                return self.read_register(buf, *regno);
            }
        }
        None
    }

    pub fn new(arch: SupportedArch) -> Registers {
        match arch {
            SupportedArch::X86 => Registers::X86(x86::user_regs_struct::default()),
            SupportedArch::X64 => Registers::X64(x64::user_regs_struct::default()),
        }
    }

    pub fn arch(&self) -> SupportedArch {
        match self {
            X86(_) => SupportedArch::X86,
            X64(_) => SupportedArch::X64,
        }
    }

    /// Copy a user_regs_struct into these Registers. If the tracee architecture
    /// is not rr's native architecture, then it must be a 32-bit tracee with a
    /// 64-bit rr. In that case the user_regs_struct is 64-bit and we extract
    /// the 32-bit register values from it into u.x86regs.
    /// It's invalid to call this when the Registers' arch is 64-bit and the
    /// rr build is 32-bit, or when the Registers' arch is completely different
    /// to the rr build (e.g. ARM vs x86).
    pub fn set_from_ptrace(&mut self, ptrace_regs: &native_user_regs_struct) {
        #[cfg(target_arch = "x86")]
        match self {
            X86(regs_x86) => unsafe {
                *regs_x86 = std::mem::transmute::<native_user_regs_struct, x86::user_regs_struct>(
                    *ptrace_regs,
                );
            },
            X64(regs_x64) => {
                panic!("Not possible to have 64 bit tracee in 32 bit rd.");
            }
        }

        #[cfg(target_arch = "x86_64")]
        match self {
            X86(regs_x86) => unsafe {
                let regs_x64_tmp = std::mem::transmute::<
                    native_user_regs_struct,
                    x64::user_regs_struct,
                >(*ptrace_regs);

                convert_x86_narrow(regs_x86, &regs_x64_tmp, to_x86_narrow, to_x86_narrow);
            },
            X64(regs_x64) => unsafe {
                *regs_x64 = std::mem::transmute::<native_user_regs_struct, x64::user_regs_struct>(
                    *ptrace_regs,
                );
            },
        }
    }

    /// Get a user_regs_struct from these Registers. If the tracee architecture
    /// is not rr's native architecture, then it must be a 32-bit tracee with a
    /// 64-bit rr. In that case the user_regs_struct is 64-bit and we copy
    /// the 32-bit register values from u.x86regs into it.
    /// It's invalid to call this when the Registers' arch is 64-bit and the
    /// rr build is 32-bit, or when the Registers' arch is completely different
    /// to the rr build (e.g. ARM vs x86).
    pub fn get_ptrace(&self) -> native_user_regs_struct {
        #[cfg(target_arch = "x86")]
        match self {
            X86(regs_x86) => unsafe {
                std::mem::transmute::<x86::user_regs_struct, native_user_regs_struct>(*regs_x86)
            },
            X64(regs_x64) => {
                panic!("Not possible to have 64 bit tracee in 32 bit rd.");
            }
        }

        #[cfg(target_arch = "x86_64")]
        match self {
            X86(regs_x86) => {
                let mut result_x64 = x64::user_regs_struct::default();
                convert_x86_widen(
                    &mut result_x64,
                    regs_x86,
                    from_x86_narrow,
                    from_x86_narrow_signed,
                );

                unsafe {
                    std::mem::transmute::<x64::user_regs_struct, native_user_regs_struct>(
                        result_x64,
                    )
                }
            }
            X64(regs_x64) => unsafe {
                std::mem::transmute::<x64::user_regs_struct, native_user_regs_struct>(*regs_x64)
            },
        }
    }

    /// Equivalent to get_ptrace_for_arch(arch()) but doesn't copy.
    pub fn get_ptrace_for_self_arch(&self) -> &[u8] {
        match self {
            X86(regs_x86) => {
                let l = size_of::<x86::user_regs_struct>();
                unsafe {
                    std::slice::from_raw_parts(
                        regs_x86 as *const x86::user_regs_struct as *const u8,
                        l,
                    )
                }
            }
            X64(regs_x64) => {
                let l = size_of::<x64::user_regs_struct>();
                unsafe {
                    std::slice::from_raw_parts(
                        regs_x64 as *const x64::user_regs_struct as *const u8,
                        l,
                    )
                }
            }
        }
    }

    /// Get a user_regs_struct for a particular Arch from these Registers.
    /// It's invalid to call this when 'arch' is 64-bit and the
    /// rr build is 32-bit, or when the Registers' arch is completely different
    /// to the rr build (e.g. ARM vs x86).
    pub fn get_ptrace_for_arch(&self, arch: SupportedArch) -> Vec<u8> {
        let mut tmp_regs = Registers::new(arch);
        tmp_regs.set_from_ptrace(&self.get_ptrace());
        let l = match self {
            X86(_) => size_of::<x86::user_regs_struct>(),
            X64(_) => size_of::<x64::user_regs_struct>(),
        };

        let mut v: Vec<u8> = Vec::with_capacity(l);
        v.resize(l, 0);
        unsafe {
            copy_nonoverlapping(
                &tmp_regs as *const Registers as *const u8,
                v.as_mut_ptr(),
                l,
            );
        }
        v
    }

    /// Copy an arch-specific user_regs_struct into these Registers.
    /// It's invalid to call this when 'arch' is 64-bit and the
    /// rr build is 32-bit, or when the Registers' arch is completely different
    /// to the rr build (e.g. ARM vs x86).
    pub fn set_from_ptrace_for_arch(&mut self, arch: SupportedArch, data: &[u8]) {
        if arch == RD_NATIVE_ARCH {
            debug_assert_eq!(data.len(), size_of::<native_user_regs_struct>());
            let mut n: native_user_regs_struct = unsafe { zeroed() };
            unsafe {
                copy_nonoverlapping(
                    data.as_ptr(),
                    &mut n as *mut native_user_regs_struct as *mut u8,
                    data.len(),
                );
                self.set_from_ptrace(&n);
            }
        } else {
            debug_assert!(arch == SupportedArch::X86 && RD_NATIVE_ARCH == SupportedArch::X64);
            debug_assert!(self.arch() == SupportedArch::X86);
            debug_assert_eq!(data.len(), size_of::<x86::user_regs_struct>());
            unsafe {
                copy_nonoverlapping(
                    data.as_ptr(),
                    self.x86_mut() as *mut x86::user_regs_struct as *mut u8,
                    size_of::<x86::user_regs_struct>(),
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
        match self {
            X86(regs_x86) => regs_x86.eflags as usize,
            X64(regs_x64) => regs_x64.eflags as usize,
        }
    }

    pub fn set_flags(&mut self, value: usize) {
        match self {
            X86(regs_x86) => regs_x86.eflags = value as i32,
            X64(regs_x64) => regs_x64.eflags = value as u64,
        }
    }

    /// Returns true if syscall_result() indicates failure.
    pub fn syscall_failed(&self) -> bool {
        let result = self.syscall_result_signed();
        -4096 < result && result < 0
    }

    /// Returns true if syscall_result() indicates a syscall restart.
    pub fn syscall_may_restart(&self) -> bool {
        match -self.syscall_result_signed() as u32 {
            ERESTART_RESTARTBLOCK | ERESTARTNOINTR | ERESTARTNOHAND | ERESTARTSYS => true,
            _ => false,
        }
    }

    pub fn ip(&self) -> RemoteCodePtr {
        let addr = rd_get_reg!(self, eip, rip);
        RemoteCodePtr::from_val(addr)
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

    /// This pseudo-register holds the system-call number when we get ptrace
    /// enter-system-call and exit-system-call events. Setting it changes
    /// the system-call executed when resuming after an enter-system-call
    /// event.
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

    /// Set the output registers of the |rdtsc| instruction.
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
        let mut x64 = self.x64_mut();
        x64.r8 = value;
    }

    pub fn set_r9(&mut self, value: u64) {
        let mut x64 = self.x64_mut();
        x64.r9 = value;
    }

    pub fn set_r10(&mut self, value: u64) {
        let mut x64 = self.x64_mut();
        x64.r10 = value;
    }

    pub fn set_r11(&mut self, value: u64) {
        let mut x64 = self.x64_mut();
        x64.r11 = value;
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
        let x64 = self.x64();
        x64.fs_base
    }
    pub fn gs_base(&self) -> u64 {
        let x64 = self.x64();
        x64.gs_base
    }

    pub fn set_fs_base(&mut self, fs_base: u64) {
        let mut x64 = self.x64_mut();
        x64.fs_base = fs_base;
    }

    pub fn set_gs_base(&mut self, gs_base: u64) {
        let mut x64 = self.x64_mut();
        x64.gs_base = gs_base;
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

    pub fn write_register_file_for_trace_raw(&self, f: &mut dyn Write) -> io::Result<()> {
        let x86 = self.x86();
        write!(
            f,
            " {} {} {} {} {} {} {} {} {} {} {}",
            x86.eax,
            x86.ebx,
            x86.ecx,
            x86.edx,
            x86.esi,
            x86.edi,
            x86.ebp,
            x86.orig_eax,
            x86.esp,
            x86.eip,
            x86.eflags
        )
    }

    fn write_register_file_for_trace(
        &self,
        f: &mut dyn Write,
        style: TraceStyle,
    ) -> io::Result<()> {
        let regs_info = self.get_regs_info();
        let mut first = true;
        for (_, rv) in regs_info {
            if rv.nbytes == 0 {
                continue;
            }

            if !first {
                write!(f, " ")?;
            }
            first = false;
            let name = match style {
                TraceStyle::Annotated => rv.name,
                _ => "",
            };

            match rv.nbytes {
                4 => {
                    self.write_single_register(f, name, rv.nbytes, rv.pointer_into_x86(self.x86()))?
                }
                8 => {
                    self.write_single_register(f, name, rv.nbytes, rv.pointer_into_x64(self.x64()))?
                }
                _ => debug_assert!(false, "bad register size"),
            }
        }

        Ok(())
    }

    pub fn write_register_file(&self, f: &mut dyn Write) -> io::Result<()> {
        write!(f, "Printing register file:\n")?;
        let regs_info = self.get_regs_info();
        for (_, rv) in regs_info {
            if rv.nbytes == 0 {
                continue;
            }

            match rv.nbytes {
                4 => self.write_single_register(
                    f,
                    rv.name,
                    rv.nbytes,
                    rv.pointer_into_x86(self.x86()),
                )?,
                8 => self.write_single_register(
                    f,
                    rv.name,
                    rv.nbytes,
                    rv.pointer_into_x64(self.x64()),
                )?,
                _ => debug_assert!(false, "bad register size"),
            }
            write!(f, "\n")?;
        }
        write!(f, "\n")?;

        Ok(())
    }

    pub fn write_register_file_compact(&self, f: &mut dyn Write) -> io::Result<()> {
        self.write_register_file_for_trace(f, TraceStyle::Annotated)
    }

    fn write_single_register(
        &self,
        f: &mut dyn Write,
        name: &str,
        nbytes: usize,
        register_ptr: *const u8,
    ) -> io::Result<()> {
        if name.len() > 0 {
            write!(f, "{}:", name)?
        } else {
            write!(f, " ")?
        }

        unsafe {
            match nbytes {
                4 => write!(f, "{:x}", *(register_ptr as *const u32)),
                8 => write!(f, "{:x}", *(register_ptr as *const u64)),
                _ => {
                    debug_assert!(false, "bad register size");
                    Ok(())
                }
            }
        }
    }
}

fn to_x86_narrow(r32: &mut i32, r64: u64) {
    *r32 = r64 as i32;
}
/// No signed extension
fn from_x86_narrow(r64: &mut u64, r32: i32) {
    *r64 = r32 as u32 as u64
}
/// Signed extension
fn from_x86_narrow_signed(r64: &mut u64, r32: i32) {
    *r64 = r32 as i64 as u64;
}

/// In theory it doesn't matter how 32-bit register values are sign extended
/// to 64 bits for PTRACE_SETREGS. However:
/// -- When setting up a signal handler frame, the kernel does some arithmetic
/// on the 64-bit SP value and validates that the result points to writeable
/// memory. This validation fails if SP has been sign-extended to point
/// outside the 32-bit address space.
/// -- Some kernels (e.g. 4.3.3-301.fc23.x86_64) with commmit
/// c5c46f59e4e7c1ab244b8d38f2b61d317df90bba have a bug where if you clear
/// the upper 32 bits of %rax while in the kernel, syscalls may fail to
/// restart. So sign-extension is necessary for %eax in this case. We may as
/// well sign-extend %eax in all cases.
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
        debug_assert!(nbytes <= size_of::<u64>());
        if nbytes == size_of::<u64>() {
            -1i64 as u64
        } else {
            let minus_one = Wrapping(-1i64 as u64);
            let shifted = Wrapping(1u64 << (nbytes * 8));
            let result = minus_one + shifted;
            result.0
        }
    }

    /// Returns a pointer to the register in |regs| represented by |offset|.
    pub fn pointer_into_x86(&self, regs: &x86::user_regs_struct) -> *const u8 {
        unsafe { (regs as *const _ as *const u8).add(self.offset) }
    }

    /// Returns a pointer to the register in |regs| represented by |offset|.
    pub fn pointer_into_x64(&self, regs: &x64::user_regs_struct) -> *const u8 {
        unsafe { (regs as *const _ as *const u8).add(self.offset) }
    }

    pub fn u32_into_x86(&self, regs: &x86::user_regs_struct) -> u32 {
        unsafe {
            *((self.pointer_into_x86(regs) as *const u32)
                .as_ref()
                .unwrap())
        }
    }

    pub fn u64_into_x64(&self, regs: &x64::user_regs_struct) -> u64 {
        unsafe {
            *((self.pointer_into_x64(regs) as *const u64)
                .as_ref()
                .unwrap())
        }
    }

    pub fn mut_u32_ref_into_x86(&self, regs: &mut x86::user_regs_struct) -> &mut u32 {
        unsafe {
            (self.mut_pointer_into_x86(regs) as *mut u32)
                .as_mut()
                .unwrap()
        }
    }

    pub fn mut_u64_ref_into_x64(&self, regs: &mut x64::user_regs_struct) -> &mut u64 {
        unsafe {
            (self.mut_pointer_into_x64(regs) as *mut u64)
                .as_mut()
                .unwrap()
        }
    }

    pub fn mut_pointer_into_x86(&self, regs: &mut x86::user_regs_struct) -> *mut u8 {
        unsafe { (regs as *mut _ as *mut u8).add(self.offset) }
    }

    pub fn mut_pointer_into_x64(&self, regs: &mut x64::user_regs_struct) -> *mut u8 {
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

fn maybe_log_reg_mismatch(
    mismatch_behavior: MismatchBehavior,
    regname: &str,
    label1: &str,
    val1: u64,
    label2: &str,
    val2: u64,
) {
    if mismatch_behavior >= MismatchBehavior::BailOnMismatch {
        log!(
            LogError,
            "{} {:x} != {:x} ({} vs. {})",
            regname,
            val1,
            val2,
            label1,
            label2
        )
    } else if mismatch_behavior >= MismatchBehavior::LogMismatches {
        log!(
            LogInfo,
            "{} {:x} != {:x} ({} vs. {})",
            regname,
            val1,
            val2,
            label1,
            label2
        )
    }
}

pub fn with_converted_registers<Ret, F: Fn(&Registers) -> Ret>(
    regs: &Registers,
    arch: SupportedArch,
    f: F,
) -> Ret {
    if regs.arch() != arch {
        let mut converted_regs = Registers::new(arch);
        let data = regs.get_ptrace_for_arch(arch);
        converted_regs.set_from_ptrace_for_arch(arch, &data);
        f(&converted_regs)
    } else {
        f(regs)
    }
}
