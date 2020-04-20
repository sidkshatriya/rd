use crate::commands::RdCommand;
use crate::event::{Event, EventType};
use crate::gdb_register::{DREG_64_XMM0, DREG_64_YMM0H, DREG_XMM0, DREG_YMM0H};
#[cfg(target_arch = "x86_64")]
use crate::kernel_abi::x64;
#[cfg(target_arch = "x86")]
use crate::kernel_abi::x86;
use crate::kernel_abi::SupportedArch;
use crate::registers::Registers;
use crate::remote_code_ptr::RemoteCodePtr;
use crate::task::Task;
use crate::trace::trace_frame::FrameTime;
use std::fmt::Write as fmtWrite;
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
    // Note the `as u64` to make seg_reg() output length uniform between x86 and x86_64
    match index {
        0 => regs.es() as u64,
        1 => regs.cs() as u64,
        2 => regs.ss() as u64,
        3 => regs.ds() as u64,
        4 => regs.fs() as u64,
        5 => regs.gs() as u64,
        _ => {
            fatal!("Unknown seg reg number: {}", index);
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

#[derive(Copy, Clone, Debug)]
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

#[derive(Copy, Clone, Debug)]
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

impl ReRerunCommand {
    fn write_value(&self, name: &str, value: &[u8], out: &mut dyn Write) -> io::Result<()> {
        if self.raw_dump {
            out.write(value)?;
        } else {
            write!(out, "{}:0x", name)?;
            write_hex(value, out)?;
        }
        Ok(())
    }

    pub fn write_regs(
        &self,
        t: &dyn Task,
        event: FrameTime,
        instruction_count: u64,
        out: &mut dyn Write,
    ) -> io::Result<()> {
        let mut got_gp_regs = false;
        let mut first = true;

        for field in &self.singlestep_trace {
            if first {
                first = false;
            } else if !self.raw_dump {
                write!(out, " ")?;
            }

            match field.kind {
                TraceFieldKind::TraceEventNumber => {
                    let value: u64 = event;
                    self.write_value("event", &value.to_le_bytes(), out)?;
                }
                TraceFieldKind::TraceInstructionCount => {
                    self.write_value("icount", &instruction_count.to_le_bytes(), out)?;
                }
                TraceFieldKind::TraceIp => {
                    // Note the `as u64` to make write_regs() output length uniform between x86 and x86_64
                    let value: u64 = t.regs_ref().ip().register_value() as u64;
                    match t.arch() {
                        SupportedArch::X86 => {
                            self.write_value("rip", &value.to_le_bytes(), out)?;
                        }
                        SupportedArch::X64 => {
                            self.write_value("eip", &value.to_le_bytes(), out)?;
                        }
                    }
                }
                TraceFieldKind::TraceFsbase => {
                    // @TODO will rr also give 0 for x86?
                    let value: u64 = match t.regs_ref() {
                        Registers::X64(regs) => regs.fs_base,
                        Registers::X86(_) => 0,
                    };
                    self.write_value("fsbase", &value.to_le_bytes(), out)?;
                }
                TraceFieldKind::TraceGsbase => {
                    // @TODO will rr also give 0 for x86?
                    let value: u64 = match t.regs_ref() {
                        Registers::X64(regs) => regs.gs_base,
                        Registers::X86(_) => 0,
                    };
                    self.write_value("gsbase", &value.to_le_bytes(), out)?;
                }
                TraceFieldKind::TraceFlags => {
                    // Note the `as u64` to make write_regs() output length uniform between x86 and x86_64
                    let value: u64 = t.regs_ref().flags() as u64;
                    match t.arch() {
                        SupportedArch::X86 => {
                            self.write_value("rflags", &value.to_le_bytes(), out)?;
                        }
                        SupportedArch::X64 => {
                            self.write_value("eflags", &value.to_le_bytes(), out)?;
                        }
                    }
                }
                TraceFieldKind::TraceOrigAx => {
                    // Note the `as u64` to make write_regs() output length uniform between x86 and x86_64
                    let value: u64 = t.regs_ref().original_syscallno() as u64;
                    match t.arch() {
                        SupportedArch::X86 => {
                            self.write_value("orig_rax", &value.to_le_bytes(), out)?;
                        }
                        SupportedArch::X64 => {
                            self.write_value("orig_eax", &value.to_le_bytes(), out)?;
                        }
                    }
                }
                TraceFieldKind::TraceSegReg => {
                    let value: u64 = seg_reg(t.regs_ref(), field.reg_num);
                    self.write_value(
                        SEG_REG_NAMES[field.reg_num as usize],
                        &value.to_le_bytes(),
                        out,
                    )?;
                }
                TraceFieldKind::TraceXinuse => {
                    let value: u64 = t.extra_regs().read_xinuse().unwrap_or(0);
                    self.write_value("xinuse", &value.to_le_bytes(), out)?;
                }
                TraceFieldKind::TraceGpReg => unimplemented!(),
                TraceFieldKind::TraceXmmReg => {
                    let mut value = [0u8; 16];
                    match t.arch() {
                        SupportedArch::X86 => {
                            if field.reg_num < 8 {
                                t.extra_regs().read_register(
                                    &mut value,
                                    (DREG_XMM0 + field.reg_num as u32).unwrap(),
                                );
                            }
                        }
                        SupportedArch::X64 => {
                            if field.reg_num < 16 {
                                t.extra_regs().read_register(
                                    &mut value,
                                    (DREG_64_XMM0 + field.reg_num as u32).unwrap(),
                                );
                            }
                        }
                    }
                    let mut name = String::new();
                    write!(name, "xmm{}", field.reg_num).unwrap();
                    self.write_value(&name, &value, out)?;
                }
                TraceFieldKind::TraceYmmReg => {
                    let mut value = [0u8; 32];
                    match t.arch() {
                        SupportedArch::X86 => {
                            if field.reg_num < 8 {
                                t.extra_regs().read_register(
                                    &mut value[0..16],
                                    (DREG_XMM0 + field.reg_num as u32).unwrap(),
                                );
                                t.extra_regs().read_register(
                                    &mut value[16..32],
                                    (DREG_YMM0H + field.reg_num as u32).unwrap(),
                                );
                            }
                        }
                        SupportedArch::X64 => {
                            if field.reg_num < 16 {
                                t.extra_regs().read_register(
                                    &mut value[0..16],
                                    (DREG_64_XMM0 + field.reg_num as u32).unwrap(),
                                );
                                t.extra_regs().read_register(
                                    &mut value[16..32],
                                    (DREG_64_YMM0H + field.reg_num as u32).unwrap(),
                                );
                            }
                        }
                    }
                    let mut name = String::new();
                    write!(name, "ymm{}", field.reg_num).unwrap();
                    self.write_value(&name, &value, out)?;
                }
            }
            write!(out, "\n")?;
        }
        Ok(())
    }
}
