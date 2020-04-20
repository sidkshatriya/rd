use crate::commands::RdCommand;
use crate::event::{Event, EventType};
#[cfg(target_arch = "x86_64")]
use crate::kernel_abi::x64;
#[cfg(target_arch = "x86")]
use crate::kernel_abi::x86;
use crate::registers::Registers;
use crate::remote_code_ptr::RemoteCodePtr;
use crate::trace::trace_frame::FrameTime;
use std::io;
use std::io::Write;
use structopt::clap;

impl RdCommand for ReRerunCommand {
    fn run(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}

const SENTINEL_RET_ADDRESS: u64 = 9;

const GP_REG_NAMES: [&'static str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

const GP_REG_NAMES_32: [&'static str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];

const SEG_REG_NAMES: [&'static str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];

lazy_static! {
    static ref USER_REGS_FIELDS: Vec<usize> = init_user_regs_fields();
}

#[cfg(target_arch = "x86_64")]
fn init_user_regs_fields() -> Vec<usize> {
    let fields = vec![
        offset_of!(x64::user_regs_struct, rax),
        offset_of!(x64::user_regs_struct, rcx),
        offset_of!(x64::user_regs_struct, rdx),
        offset_of!(x64::user_regs_struct, rbx),
        offset_of!(x64::user_regs_struct, rsp),
        offset_of!(x64::user_regs_struct, rbp),
        offset_of!(x64::user_regs_struct, rsi),
        offset_of!(x64::user_regs_struct, rdi),
        offset_of!(x64::user_regs_struct, r8),
        offset_of!(x64::user_regs_struct, r9),
        offset_of!(x64::user_regs_struct, r10),
        offset_of!(x64::user_regs_struct, r11),
        offset_of!(x64::user_regs_struct, r12),
        offset_of!(x64::user_regs_struct, r13),
        offset_of!(x64::user_regs_struct, r14),
        offset_of!(x64::user_regs_struct, r15),
    ];
    fields
}

#[cfg(target_arch = "x86")]
fn init_user_regs_fields() -> Vec<usize> {
    let fields = vec![
        offset_of!(x86::user_regs_struct, eax),
        offset_of!(x86::user_regs_struct, ecx),
        offset_of!(x86::user_regs_struct, edx),
        offset_of!(x86::user_regs_struct, ebx),
        offset_of!(x86::user_regs_struct, esp),
        offset_of!(x86::user_regs_struct, ebp),
        offset_of!(x86::user_regs_struct, esi),
        offset_of!(x86::user_regs_struct, edi),
    ];
    fields
}

fn seg_reg(regs: &Registers, index: u8) -> u64 {
    match index {
        0 => regs.es(),
        1 => regs.cs(),
        2 => regs.ss(),
        3 => regs.ds(),
        4 => regs.fs(),
        5 => regs.gs(),
        _ => {
            fatal!("Unknown seg reg {}", index);
            unreachable!();
        }
    }
}

fn write_hex(value: &[u8], out: &mut dyn Write) -> io::Result<()> {
    let mut any_printed = false;
    let mut i = value.len() as isize - 1;
    while i >= 0 {
        if value[i as usize] != 0 || any_printed || i == 0 {
            if any_printed {
                write!(out, "{:02x}", value[i as usize])?;
            } else {
                write!(out, "{:x}", value[i as usize])?;
            }
            any_printed = true;
            i -= 1;
        }
    }
    Ok(())
}

fn write_value(
    name: &str,
    value: &[u8],
    flags: &ReRerunCommand,
    out: &mut dyn Write,
) -> io::Result<()> {
    if flags.raw_dump {
        out.write(value)?;
    } else {
        write!(out, "{}:0x", name)?;
        write_hex(value, out)?;
    }
    Ok(())
}

fn find_gp_reg(reg: &str) -> Option<u8> {
    for i in 0u8..16 {
        if reg == GP_REG_NAMES[i as usize] || (i < 8 && reg == GP_REG_NAMES_32[i as usize]) {
            return Some(i);
        }
    }
    None
}

fn find_seg_reg(reg: &str) -> Option<u8> {
    for i in 0u8..6 {
        if reg == SEG_REG_NAMES[i as usize] {
            return Some(i);
        }
    }
    None
}

fn treat_event_completion_as_singlestep_complete(ev: Event) -> bool {
    match ev.event_type() {
        EventType::EvPatchSyscall | EventType::EvInstructionTrap | EventType::EvSyscall => true,
        _ => false,
    }
}

/// Return true if the final "event" state change doesn't really change any
/// user-visible state and is therefore not to be considered a singlestep for
/// our purposes.
fn ignore_singlestep_for_event(ev: Event) -> bool {
    match ev.event_type() {
        // These don't actually change user-visible state, so we skip them.
        EventType::EvSignal | EventType::EvSignalDelivery => true,
        _ => false,
    }
}

#[derive(Clone, Debug)]
enum TraceFieldKind {
    /// outputs 64-bit value
    TraceEventNumber,
    /// outputs 64-bit value
    TraceInstructionCount,
    /// outputs 64-bit value
    TraceIp,
    /// outputs 64-bit value
    TraceFsbase,
    /// outputs 64-bit value
    TraceGsbase,
    /// outputs 64-bit value
    TraceFlags,
    /// outputs 64-bit value
    TraceOrigAx,
    /// outputs 64-bit value
    TraceSegReg,
    /// outputs 64-bit value
    TraceXinuse,
    /// outputs 64-bit value
    TraceGpReg,
    /// outputs 128-bit value
    TraceXmmReg,
    /// outputs 256-bit value
    TraceYmmReg,
}

#[derive(Clone, Debug)]
struct TraceField {
    kind: TraceFieldKind,
    reg_num: u8,
}

#[derive(Clone, Debug)]
pub struct TraceFields(Vec<TraceField>);

pub struct ReRerunCommand {
    trace_start: FrameTime,
    trace_end: FrameTime,
    function: RemoteCodePtr,
    singlestep_trace: Vec<TraceField>,
    raw_dump: bool,
    cpu_unbound: bool,
}

impl ReRerunCommand {}

pub(super) fn parse_regs(regs_s: &str) -> Result<TraceFields, clap::Error> {
    let reg_strs: Vec<&str> = regs_s.split(',').map(|r| r.trim()).collect();
    let mut registers = Vec::<TraceField>::new();
    for reg in reg_strs {
        if reg == "event" {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceEventNumber,
                reg_num: 0,
            });
        } else if reg == "icount" {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceInstructionCount,
                reg_num: 0,
            });
        } else if reg == "ip" || reg == "rip" {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceIp,
                reg_num: 0,
            });
        } else if reg == "fsbase" {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceFsbase,
                reg_num: 0,
            });
        } else if reg == "gsbase" {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceGsbase,
                reg_num: 0,
            });
        } else if reg == "flags" || reg == "rflags" {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceFlags,
                reg_num: 0,
            });
        } else if reg == "orig_rax" || reg == "orig_eax" {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceOrigAx,
                reg_num: 0,
            });
        } else if reg == "gp_x16" {
            for i in 0u8..16 {
                registers.push(TraceField {
                    kind: TraceFieldKind::TraceGpReg,
                    reg_num: i,
                });
            }
        } else if reg == "xmm_x16" {
            for i in 0u8..16 {
                registers.push(TraceField {
                    kind: TraceFieldKind::TraceXmmReg,
                    reg_num: i,
                });
            }
        } else if reg == "ymm_x16" {
            for i in 0u8..16 {
                registers.push(TraceField {
                    kind: TraceFieldKind::TraceYmmReg,
                    reg_num: i,
                });
            }
        } else if let Some(i) = find_gp_reg(reg) {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceGpReg,
                reg_num: i,
            });
        } else if let Some(i) = find_seg_reg(reg) {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceSegReg,
                reg_num: i,
            });
        } else if reg == "xinuse" {
            registers.push(TraceField {
                kind: TraceFieldKind::TraceXinuse,
                reg_num: 0,
            });
        } else {
            return Err(clap::Error::with_description(
                &format!("Unknown register `{}`", reg),
                clap::ErrorKind::InvalidValue,
            ));
        }
    }

    Ok(TraceFields(registers))
}
