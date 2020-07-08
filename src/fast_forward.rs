use crate::{
    kernel_abi::SupportedArch,
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    session::{
        address_space::WatchConfig,
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
pub fn at_x86_string_instruction<T: Task>(t: &mut T) -> bool {
    if !is_x86ish(t) {
        return false;
    }

    is_string_instruction_at(t, t.ip())
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
pub fn maybe_at_or_after_x86_string_instruction<T: Task>(t: &mut T) -> bool {
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
    match byte {
     0x26| // ES override
     0x2E| // CS override
     0x36| // SS override
     0x3E| // DS override
     0x64| // FS override
     0x65| // GS override
     0x66| // operand-size override
     0x67| // address-size override
     0xF0  // LOCK
     => true,
    _ => false
  }
}

fn is_rep_prefix(byte: u8) -> bool {
    byte == 0xF2 || byte == 0xF3
}

fn is_string_instruction(byte: u8) -> bool {
    match byte {
     0xA4| // MOVSB
     0xA5| // MOVSW
     0xA6| // CMPSB
     0xA7| // CMPSW
     0xAA| // STOSB
     0xAB| // STOSW
     0xAC| // LODSB
     0xAD| // LODSW
     0xAE| // SCASB
     0xAF  // SCASW
     => true,
    _=> false
  }
}

fn fallible_read_byte<T: Task>(t: &mut T, ip: RemotePtr<u8>) -> Result<u8, ()> {
    let mut byte = [0u8; 1];
    match t.read_bytes_fallible(ip, &mut byte) {
        Ok(1) => Ok(byte[0]),
        _ => Err(()),
    }
}

fn is_string_instruction_at<T: Task>(t: &mut T, ip: RemoteCodePtr) -> bool {
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
        bare_ip = bare_ip + 1usize;
    }
}

fn is_string_instruction_before<T: Task>(t: &mut T, ip: RemoteCodePtr) -> bool {
    let mut bare_ip = ip.to_data_ptr::<u8>();
    bare_ip = bare_ip - 1usize;
    match fallible_read_byte(t, bare_ip) {
        Err(()) => return false,
        Ok(byte) if !is_string_instruction(byte) => return false,
        Ok(_) => (),
    }

    loop {
        bare_ip = bare_ip - 1usize;
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
