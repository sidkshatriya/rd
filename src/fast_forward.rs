use crate::{
    kernel_abi::SupportedArch,
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    session::task::{
        task_inner::{ResumeRequest, TicksRequest, WaitRequest},
        Task,
    },
};
use libc::SIGTRAP;
use std::ops::BitOr;

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
pub fn at_x86_string_instruction<T: Task>(_t: &mut T) -> bool {
    unimplemented!()
}

/// Perform one or more synchronous singlesteps of |t|. Usually just does
/// one singlestep, except when a singlestep leaves the IP unchanged (i.e. a
/// single instruction represents a loop, such as an x86 REP-prefixed string
/// instruction).
///
/// |how| must be either RESUME_SINGLESTEP or RESUME_SYSEMU_SINGLESTEP.
///
/// We always perform at least one singlestep. We stop after a singlestep if
/// one of the following is true, or will be true after one more singlestep:
/// -- Any breakpoint or watchpoint has been triggered
/// -- IP has advanced to the next instruction
/// -- One of the register states in |states| (a null-terminated list)
/// has been reached.
///
/// Spurious returns after any singlestep are also allowed.
///
/// This will not add more than one tick to t->tick_count().
///
/// Returns true if we did a fast-forward, false if we just did one regular
/// singlestep.
///
/// DIFF NOTE: @TODO? In rr we're getting pointers to registers. Here we're getting a register copy
pub fn fast_forward_through_instruction<T: Task>(
    t: &mut T,
    how: ResumeRequest,
    _states: &[Registers],
) -> FastForwardStatus {
    debug_assert!(
        how == ResumeRequest::ResumeSinglestep || how == ResumeRequest::ResumeSysemuSinglestep
    );
    let result = FastForwardStatus::new();

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

    unimplemented!()
}

/// Return true if the instruction at t->ip(), or the instruction immediately
/// before t->ip(), could be a REP-prefixed string instruction. It's OK to
/// return true if it's not really a string instruction (though for performance
/// reasons, this should be rare).
pub fn maybe_at_or_after_x86_string_instruction<T: Task>(_t: &T) -> bool {
    unimplemented!()
}

#[derive(Default)]
struct InstructionBuf {
    arch: SupportedArch,
    code_buf: [u8; 32],
    /// code_buf_len <= 32
    code_buf_len: usize,
}

fn read_instruction<T: Task>(t: &mut T, ip: RemoteCodePtr) -> Result<InstructionBuf, ()> {
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

    let mut decoded = DecodedInstruction::default();
    decoded.modifies_flags = false;
    decoded.uses_si = false;

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
        } else {
            if found_operand_prefix {
                2
            } else {
                4
            }
        };
    } else {
        decoded.operand_size = 1;
    }
    decoded.address_size = if found_address_prefix { 4 } else { 8 };
    Ok(decoded)
}
