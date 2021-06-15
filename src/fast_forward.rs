use crate::{
    kernel_abi::SupportedArch,
    log::LogLevel::LogDebug,
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    session::{
        address_space::{BreakpointType, DebugStatus, WatchConfig},
        task::{
            task_inner::{ResumeRequest, TicksRequest, WaitRequest},
            Task,
        },
    },
};
use libc::SIGTRAP;
use std::{
    cmp::{max, min},
    ops::BitOr,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FastForwardStatus {
    pub did_fast_forward: bool,
    pub incomplete_fast_forward: bool,
}

impl BitOr for FastForwardStatus {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            did_fast_forward: self.did_fast_forward | rhs.did_fast_forward,
            incomplete_fast_forward: self.incomplete_fast_forward | rhs.incomplete_fast_forward,
        }
    }
}

impl Default for FastForwardStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl FastForwardStatus {
    pub fn new() -> FastForwardStatus {
        FastForwardStatus {
            did_fast_forward: false,
            incomplete_fast_forward: false,
        }
    }
}

/// Return true if the instruction at t.ip() is a string instruction
pub fn at_x86_string_instruction<T: Task>(t: &T) -> bool {
    if !is_x86ish(t) {
        return false;
    }

    is_string_instruction_at(t, t.ip())
}

/// Perform one or more synchronous singlesteps of `t`. Usually just does
/// one singlestep, except when a singlestep leaves the IP unchanged (i.e. a
/// single instruction represents a loop, such as an x86 REP-prefixed string
/// instruction).
///
/// `how` can be e.g. `ResumeSinglestep` or `ResumeSysemuSinglestep`.
///
/// We always perform at least one singlestep. We stop after a singlestep if
/// one of the following is true, or will be true after one more singlestep:
/// -- Any breakpoint or watchpoint has been triggered
/// -- IP has advanced to the next instruction
/// -- One of the register states in `states` has been reached.
///
/// Spurious returns after any singlestep are also allowed.
///
/// This will not add more than one tick to t->tick_count().
///
/// Returns true if we did a fast-forward, false if we just did one regular
/// singlestep.
///
/// DIFF NOTE: @TODO Performance?
/// In rr we're getting pointers to registers. Here we're getting a register copy
pub fn fast_forward_through_instruction<T: Task>(
    t: &T,
    how: ResumeRequest,
    states: &[Registers],
) -> FastForwardStatus {
    debug_assert!(how == ResumeRequest::Singlestep || how == ResumeRequest::SysemuSinglestep);
    let mut result = FastForwardStatus::new();

    let ip = t.ip();

    t.resume_execution(
        how,
        WaitRequest::ResumeWait,
        TicksRequest::ResumeUnlimitedTicks,
        None,
    );
    if t.maybe_stop_sig() != SIGTRAP {
        // we might have stepped into a system call...
        return result;
    }

    if t.ip() != ip {
        return result;
    }
    if t.vm().get_breakpoint_type_at_addr(ip) != BreakpointType::BkptNone {
        // breakpoint must have fired
        return result;
    }
    if t.vm()
        .notify_watchpoint_fired(t.debug_status(), t.last_execution_resume())
    {
        // watchpoint fired
        return result;
    }
    for state in states {
        if state.matches(&t.regs_ref()) {
            return result;
        }
    }
    if !is_x86ish(t) {
        return result;
    }

    let instruction_buf: InstructionBuf = match read_instruction(t, ip) {
        Ok(buf) => buf,
        Err(()) => return result,
    };

    let decoded = match decode_x86_string_instruction(&instruction_buf) {
        Ok(res) => res,
        Err(()) => {
            return result;
        }
    };

    if decoded.address_size != 8 {
        ed_assert!(
            t,
            false,
            "Address-size prefix on string instructions unsupported"
        );
    }

    let limit_ip = ip + decoded.length;

    // At this point we can be sure the instruction didn't trigger a syscall,
    // so we no longer care about the value of `how`.

    let mut extra_state_to_avoid: Option<Registers> = None;

    loop {
        // This string instruction should execute until CX reaches 0 and
        // we move to the next instruction, or we hit one of the states in
        // `states`, or the ZF flag changes so that the REP stops, or we hit
        // a watchpoint. (We can't hit a breakpoint during the loop since we
        // already verified there isn't one set here.)

        // We'll compute an upper bound on the number of string instruction
        // iterations to execute, and execute just that many iterations by
        // modifying CX, setting a breakpoint after the string instruction to catch it
        // ending.
        // Keep in mind that it's possible that states in `states` might
        // belong to multiple independent loops of this string instruction, with
        // registers reset in between the loops.

        let cur_cx: usize = t.regs_ref().cx();
        if cur_cx == 0 {
            // Fake singlestep status for trap diagnosis
            t.set_debug_status(DebugStatus::DsSingleStep as usize);
            // This instruction will be skipped entirely.
            return result;
        }
        // There is at least one more iteration to go.
        result.incomplete_fast_forward = true;

        // Don't execute the last iteration of the string instruction. That
        // simplifies code below that tries to emulate the register effects
        // of singlestepping to predict if the next singlestep would result in a
        // mark_vector state.
        let mut iterations: usize = cur_cx - 1;

        // Bound `iterations` to ensure we stop before reachng any `states`.
        let mut it = states.iter();
        let mut extra_state_iterated = false;
        loop {
            let state = match it.next() {
                Some(regs) => regs,
                None => match extra_state_to_avoid.as_ref() {
                    Some(regs) if !extra_state_iterated => {
                        extra_state_iterated = true;
                        regs
                    }
                    _ => break,
                },
            };
            if state.ip() == ip {
                let dest_cx: usize = state.cx();
                if dest_cx == 0 {
                    // This state represents entering the instruction with CX==0,
                    // so we can't reach this instruction state in the current loop.
                    continue;
                }
                if dest_cx >= cur_cx {
                    // This can't be reached in the current loop.
                    continue;
                }
                iterations = min(iterations, cur_cx - dest_cx - 1);
            } else if state.ip() == limit_ip {
                let dest_cx: usize = state.cx();
                if dest_cx >= cur_cx {
                    // This can't be reached in the current loop.
                    continue;
                }
                iterations = min(iterations, cur_cx - dest_cx - 1);
            }
        }

        // To stop before the ZF changes and we exit the loop, we don't bound
        // the iterations here. Instead we run the loop, observe the ZF change,
        // and then rerun the loop with the loop-exit state added to the `states`
        // list. See below.

        // A code watchpoint would already be hit if we're going to hit it.
        // Check for data watchpoints that we might hit when reading/writing
        // memory.
        // Make conservative assumptions about the watchpoint type. Applying
        // unnecessary watchpoints here will only result in a few more singlesteps.
        // We do have to ignore SI if the instruction doesn't use it; otherwise
        // a watchpoint which happens to match SI will appear to be hit on every
        // iteration of the string instruction, which would be devastating.
        for watch in t.vm().all_watchpoints() {
            if decoded.uses_si {
                bound_iterations_for_watchpoint(
                    t,
                    t.regs_ref().si().into(),
                    &decoded,
                    &watch,
                    &mut iterations,
                );
            }
            bound_iterations_for_watchpoint(
                t,
                t.regs_ref().di().into(),
                &decoded,
                &watch,
                &mut iterations,
            );
        }

        if iterations == 0 {
            // Fake singlestep status for trap diagnosis
            t.set_debug_status(DebugStatus::DsSingleStep as usize);
            return result;
        }

        log!(
            LogDebug,
            "x86-string fast-forward: {} iterations required (ip=={})",
            iterations,
            t.ip()
        );

        let r: Registers = t.regs_ref().clone();
        let mut tmp: Registers = r.clone();
        tmp.set_cx(iterations);
        t.set_regs(&tmp);
        let ok = t
            .vm()
            .add_breakpoint(limit_ip, BreakpointType::BkptInternal);
        ed_assert!(t, ok, "Failed to add breakpoint");
        // Watchpoints can fire spuriously because configure_watch_registers
        // can increase the size of the watched area to conserve watch registers.
        // So, disable watchpoints temporarily.
        t.vm().save_watchpoints();
        t.vm().remove_all_watchpoints();
        t.resume_execution(
            ResumeRequest::Cont,
            WaitRequest::ResumeWait,
            TicksRequest::ResumeUnlimitedTicks,
            None,
        );
        t.vm().restore_watchpoints();
        t.vm()
            .remove_breakpoint(limit_ip, BreakpointType::BkptInternal);
        result.did_fast_forward = true;
        // We should have reached the breakpoint
        ed_assert_eq!(t, t.maybe_stop_sig(), SIGTRAP);
        ed_assert_eq!(t, t.ip(), limit_ip.increment_by_bkpt_insn_length(t.arch()));
        let iterations_performed: usize = iterations - t.regs_ref().cx();
        // Overwrite the value of tmp
        tmp = t.regs_ref().clone();
        // Undo our change to CX value
        //
        // DIFF NOTE: Expression for set_cx() slightly refactored to prevent arithmetic overflow
        // which still gives the correct result but in rust would give an error as arithmetic
        // can be checked (e.g. in debug mode).
        tmp.set_cx(cur_cx - iterations_performed);
        if decoded.modifies_flags && t.regs_ref().cx() > 0 {
            // String instructions that modify flags don't have non-register side
            // effects, so we can reset registers to effectively unwind the loop.
            // Then we try rerunning the loop again, adding this state as one to
            // avoid stepping into. We shouldn't need to do this more than once!
            ed_assert!(t, extra_state_to_avoid.is_none());
            tmp.set_ip(limit_ip);
            extra_state_to_avoid = Some(tmp);
            t.set_regs(&r);
            continue;
        }
        // instructions that don't modify flags should not terminate too early.
        ed_assert_eq!(t, t.regs_ref().cx(), 0);
        ed_assert_eq!(t, iterations_performed, iterations);
        // We always end with at least one iteration to go in the string instruction,
        // so we must have the IP of the string instruction.
        tmp.set_ip(r.ip());
        t.set_regs(&tmp);

        log!(LogDebug, "x86-string fast-forward done; ip()=={}", t.ip());
        // Fake singlestep status for trap diagnosis
        t.set_debug_status(DebugStatus::DsSingleStep as usize);
        return result;
    }
}

/// Return true if the instruction at t->ip(), or the instruction immediately
/// before t->ip(), could be a REP-prefixed string instruction. It's OK to
/// return true if it's not really a string instruction (though for performance
/// reasons, this should be rare).
pub fn maybe_at_or_after_x86_string_instruction<T: Task>(t: &T) -> bool {
    if !is_x86ish(t) {
        return false;
    }

    is_string_instruction_at(t, t.ip()) || is_string_instruction_before(t, t.ip())
}

#[derive(Default)]
struct InstructionBuf {
    arch: SupportedArch,
    code_buf: [u8; 32],
    /// code_buf_len <= 32
    code_buf_len: usize,
}

fn read_instruction<T: Task>(t: &T, ip: RemoteCodePtr) -> Result<InstructionBuf, ()> {
    let mut result = InstructionBuf::default();
    result.arch = t.arch();
    result.code_buf_len = t.read_bytes_fallible(ip.to_data_ptr::<u8>(), &mut result.code_buf)?;

    Ok(result)
}

#[derive(Default)]
struct DecodedInstruction {
    operand_size: usize,
    address_size: usize,
    length: usize,
    modifies_flags: bool,
    uses_si: bool,
}

/// This can be conservative: for weird prefix combinations that make valid
///  string instructions, but aren't ever used in practice, we can return false.
fn decode_x86_string_instruction(code: &InstructionBuf) -> Result<DecodedInstruction, ()> {
    let mut found_operand_prefix = false;
    let mut found_address_prefix = false;
    #[allow(non_snake_case)]
    let mut found_REP_prefix = false;
    #[allow(non_snake_case)]
    let mut found_REXW_prefix = false;

    let mut decoded = DecodedInstruction {
        modifies_flags: false,
        uses_si: false,
        ..Default::default()
    };
    let mut done = false;
    let mut last_i: usize = 0;
    for i in 0..code.code_buf_len {
        last_i = i;
        match code.code_buf[i] {
            0x66 => {
                found_operand_prefix = true;
            }
            0x67 => {
                found_address_prefix = true;
            }
            0x48 => {
                if code.arch == SupportedArch::X64 {
                    found_REXW_prefix = true;
                } else {
                    return Err(());
                }
            }
            0xF2 | 0xF3 => {
                found_REP_prefix = true;
            }
            // MOVSB, MOVSW
            0xA4 | 0xA5 => {
                decoded.uses_si = true;
                done = true;
            }
            // STOSB, STOSW, LODSB, LODSW
            0xAA | 0xAB | 0xAC | 0xAD => {
                done = true;
            }
            // CMPSB, CMPSW
            0xA6 | 0xA7 => {
                decoded.modifies_flags = true;
                decoded.uses_si = true;
                done = true;
            }
            // SCASB, SCASW
            0xAE | 0xAF => {
                decoded.modifies_flags = true;
                done = true;
            }
            _ => return Err(()),
        }
        if done {
            break;
        }
    }

    if !found_REP_prefix {
        return Err(());
    }

    decoded.length = last_i + 1;
    if code.code_buf[last_i] & 1 != 0 {
        decoded.operand_size = if found_REXW_prefix {
            8
        } else if found_operand_prefix {
            2
        } else {
            4
        }
    } else {
        decoded.operand_size = 1;
    }
    decoded.address_size = if found_address_prefix { 4 } else { 8 };
    Ok(decoded)
}

fn mem_intersect(a1: RemotePtr<Void>, s1: usize, a2: RemotePtr<Void>, s2: usize) -> bool {
    debug_assert!(a1 + s1 > a1);
    debug_assert!(a2 + s2 > a2);
    max(a1, a2) < min(a1 + s1, a2 + s2)
}

fn bound_iterations_for_watchpoint<T: Task>(
    t: &T,
    reg: RemotePtr<Void>,
    decoded: &DecodedInstruction,
    watch: &WatchConfig,
    iterations: &mut usize,
) {
    if watch.num_bytes == 0 {
        // Ignore zero-sized watch. It can't ever trigger.
        return;
    }

    // Compute how many iterations it will take before we hit the watchpoint.
    // 0 means the first iteration will hit the watchpoint.
    let size = decoded.operand_size;
    let direction = if t.regs_ref().df_flag() { -1 } else { 1 };

    if mem_intersect(reg, size, watch.addr, watch.num_bytes) {
        *iterations = 0;
        return;
    }

    // Number of iterations we can perform without triggering the watchpoint
    let steps: usize;
    if direction > 0 {
        if watch.addr < reg {
            // We're assuming wraparound can't happpen!
            return;
        }
        // We'll hit the first byte of the watchpoint moving forward.
        steps = (watch.addr - reg) / size;
    } else {
        if watch.addr > reg {
            // We're assuming wraparound can't happpen!
            return;
        }
        // We'll hit the last byte of the watchpoint moving backward.
        steps = (reg - (watch.addr + watch.num_bytes)) / size + 1;
    }

    *iterations = min(*iterations, steps);
}

fn is_x86ish<T: Task>(t: &T) -> bool {
    t.arch() == SupportedArch::X86 || t.arch() == SupportedArch::X64
}

fn is_ignorable_prefix<T: Task>(t: &T, byte: u8) -> bool {
    if byte >= 0x40 && byte <= 0x4f {
        // REX prefix
        return t.arch() == SupportedArch::X64;
    }
    matches!(
        byte,
        0x26| // ES override
     0x2E| // CS override
     0x36| // SS override
     0x3E| // DS override
     0x64| // FS override
     0x65| // GS override
     0x66| // operand-size override
     0x67| // address-size override
     0xF0
    )
}

fn is_rep_prefix(byte: u8) -> bool {
    byte == 0xF2 || byte == 0xF3
}

fn is_string_instruction(byte: u8) -> bool {
    matches!(
        byte,
        0xA4| // MOVSB
     0xA5| // MOVSW
     0xA6| // CMPSB
     0xA7| // CMPSW
     0xAA| // STOSB
     0xAB| // STOSW
     0xAC| // LODSB
     0xAD| // LODSW
     0xAE| // SCASB
     0xAF
    )
}

fn fallible_read_byte<T: Task>(t: &T, ip: RemotePtr<u8>) -> Result<u8, ()> {
    let mut byte = [0u8; 1];
    match t.read_bytes_fallible(ip, &mut byte) {
        Ok(1) => Ok(byte[0]),
        _ => Err(()),
    }
}

fn is_string_instruction_at<T: Task>(t: &T, ip: RemoteCodePtr) -> bool {
    let mut found_rep = false;
    let mut bare_ip = ip.to_data_ptr::<u8>();
    loop {
        match fallible_read_byte(t, bare_ip) {
            Err(()) => {
                return false;
            }
            Ok(byte) if is_rep_prefix(byte) => {
                found_rep = true;
            }
            Ok(byte) if is_string_instruction(byte) => {
                return found_rep;
            }
            Ok(byte) if !is_ignorable_prefix(t, byte) => {
                return false;
            }
            // @TODO check this!
            Ok(_) => (),
        }
        bare_ip += 1usize;
    }
}

fn is_string_instruction_before<T: Task>(t: &T, ip: RemoteCodePtr) -> bool {
    let mut bare_ip = ip.to_data_ptr::<u8>();
    bare_ip -= 1usize;
    match fallible_read_byte(t, bare_ip) {
        Err(()) => return false,
        Ok(byte) if !is_string_instruction(byte) => return false,
        Ok(_) => (),
    }

    loop {
        bare_ip -= 1usize;
        match fallible_read_byte(t, bare_ip) {
            Err(()) => {
                return false;
            }
            Ok(byte) if is_rep_prefix(byte) => {
                return true;
            }
            Ok(byte) if !is_ignorable_prefix(t, byte) => {
                return false;
            }
            // @TODO Check this
            Ok(_) => (),
        }
    }
}
