#[cfg(target_arch = "x86_64")]
use crate::kernel_abi::x64;
#[cfg(target_arch = "x86")]
use crate::kernel_abi::x86;
use crate::{
    assert_prerequisites,
    bindings::kernel::user_regs_struct as native_user_regs_struct,
    commands::{
        rd_options::{RdOptions, RdSubCommand},
        RdCommand,
    },
    event::{Event, EventType},
    flags::Flags,
    gdb_register::{DREG_64_XMM0, DREG_64_YMM0H, DREG_XMM0, DREG_YMM0H},
    kernel_abi::SupportedArch,
    log::LogLevel::{LogDebug, LogInfo},
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::RemotePtr,
    session::{
        replay_session,
        replay_session::{ReplaySession, ReplayStatus},
        session_inner::RunCommand,
        task::{common::write_val_mem, Task},
        Session,
        SessionSharedPtr,
    },
    taskish_uid::TaskUid,
    trace::trace_frame::FrameTime,
    util::{raise_resource_limits, running_under_rd},
};
use nix::unistd::{getpid, getppid};
use std::{
    fmt::Write as fmtWrite,
    io,
    io::{stderr, stdout, Write},
    mem,
    mem::size_of,
    path::PathBuf,
};
use structopt::clap;

impl RdCommand for ReRunCommand {
    /// DIFF NOTE: In rr a result code e.g. 3 is returned. We simply return `Ok(())` in case there is
    /// no error or a `Err(_)` if there is.
    fn run(&mut self) -> io::Result<()> {
        assert_prerequisites(None);
        if running_under_rd() {
            if !Flags::get().suppress_environment_warnings {
                write!(
                    stderr(),
                    "rd: rd pid {} running under parent {}. Good luck.\n",
                    getpid(),
                    getppid()
                )?;
            }
            if self.trace_dir.is_none() {
                // DIFF NOTE: An error code of 3 is returned in rr. We return an `Err(_)`
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No trace-dir supplied. You'll try to rerun the recording of this rd \
                        and have a bad time. Bailing out.",
                ));
            }
        }

        self.rerun()
    }
}

#[repr(C)]
union RegsData {
    native: native_user_regs_struct,
    regs_values: [usize; size_of::<native_user_regs_struct>() / size_of::<usize>()],
}

// DIFF NOTE: This is a u64 in rr. We make it a usize as x86 has 4 byte pointers.
const SENTINEL_RET_ADDRESS: usize = 9;

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

fn treat_event_completion_as_singlestep_complete(ev: &Event) -> bool {
    match ev.event_type() {
        EventType::EvPatchSyscall | EventType::EvInstructionTrap | EventType::EvSyscall => true,
        _ => false,
    }
}

/// Return true if the final "event" state change doesn't really change any
/// user-visible state and is therefore not to be considered a singlestep for
/// our purposes.
fn ignore_singlestep_for_event(ev: &Event) -> bool {
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

pub struct ReRunCommand {
    trace_start: FrameTime,
    trace_end: FrameTime,
    function: Option<RemoteCodePtr>,
    singlestep_trace: Vec<TraceField>,
    raw_dump: bool,
    cpu_unbound: bool,
    trace_dir: Option<PathBuf>,
}

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

impl ReRunCommand {
    pub fn new(options: &RdOptions) -> ReRunCommand {
        match options.cmd.clone() {
            RdSubCommand::ReRun {
                trace_start,
                trace_end,
                raw,
                cpu_unbound,
                function_addr,
                singlestep_regs,
                trace_dir,
            } => ReRunCommand {
                trace_start: trace_start.unwrap_or(FrameTime::MIN),
                trace_end: trace_end.unwrap_or(FrameTime::MAX),
                function: function_addr.map(|a| a.into()),
                singlestep_trace: singlestep_regs.map_or(Vec::new(), |r| r.0),
                raw_dump: raw,
                cpu_unbound,
                trace_dir,
            },
            _ => panic!("Unexpected RdSubCommand variant. Not a ReRun variant!"),
        }
    }
    fn session_flags(&self) -> replay_session::Flags {
        replay_session::Flags {
            redirect_stdio: false,
            share_private_mappings: false,
            cpu_unbound: self.cpu_unbound,
        }
    }
    // DIFF NOTE: In rr a result code e.g. 0 is return. We simply return Ok(()) if there is no error.
    fn rerun(&self) -> io::Result<()> {
        let session: SessionSharedPtr =
            ReplaySession::create(self.trace_dir.as_ref(), self.session_flags());
        let replay_session = session.as_replay().unwrap();
        let mut instruction_count_within_event: u64 = 0;
        let mut done_first_step = false;

        // Now that we've spawned the replay, raise our resource limits if possible.
        raise_resource_limits();

        while replay_session.trace_reader().time() < self.trace_end {
            let mut cmd = RunCommand::RunContinue;

            let before_time: FrameTime = replay_session.trace_reader().time();
            let done_initial_exec = replay_session.done_initial_exec();
            let old_task_tuid: Option<TaskUid>;
            let old_ip: RemoteCodePtr;
            {
                let old_task = replay_session.current_task();
                old_task_tuid = old_task.as_ref().map(|t| t.borrow().tuid());
                old_ip = old_task.as_ref().map_or(0.into(), |t| t.borrow().ip());
                if done_initial_exec && before_time >= self.trace_start {
                    if !done_first_step {
                        if !self.function.is_some() {
                            self.run_diversion_function(
                                replay_session,
                                old_task.unwrap().borrow_mut().as_mut(),
                            )?;
                            return Ok(());
                        }

                        if !self.singlestep_trace.is_empty() {
                            done_first_step = true;
                            self.write_regs(
                                old_task.unwrap().borrow_mut().as_mut(),
                                before_time - 1,
                                instruction_count_within_event,
                                &mut stdout(),
                            )?;
                        }
                    }

                    cmd = RunCommand::RunSinglestepFastForward;
                }
            }

            let replayed_event = replay_session.current_trace_frame().event().clone();

            let result = replay_session.replay_step(cmd);
            if result.status == ReplayStatus::ReplayExited {
                break;
            }

            let after_time: FrameTime = replay_session.trace_reader().time();
            let singlestep_really_complete: bool;
            if cmd != RunCommand::RunContinue {
                {
                    let old_task =
                        old_task_tuid.map(|id| replay_session.find_task_from_task_uid(id).unwrap());
                    let after_ip: RemoteCodePtr =
                        old_task.as_ref().map_or(0.into(), |t| t.borrow().ip());
                    debug_assert!(after_time >= before_time && after_time <= before_time + 1);

                    debug_assert_eq!(result.status, ReplayStatus::ReplayContinue);
                    debug_assert!(result.break_status.watchpoints_hit.is_empty());
                    debug_assert!(!result.break_status.breakpoint_hit);
                    debug_assert!(
                        cmd == RunCommand::RunSinglestepFastForward
                            || !result.break_status.singlestep_complete
                    );

                    // Treat singlesteps that partially executed a string instruction (that
                    // was not interrupted) as not really singlestepping.
                    singlestep_really_complete = result.break_status.singlestep_complete &&
                        // ignore_singlestep_for_event only matters if we really completed the
                        // event
                        (!ignore_singlestep_for_event(&replayed_event) ||
                            before_time == after_time) &&
                        (!result.incomplete_fast_forward || old_ip != after_ip ||
                            before_time < after_time);
                    if !self.singlestep_trace.is_empty()
                        && cmd == RunCommand::RunSinglestepFastForward
                        && (singlestep_really_complete
                            || (before_time < after_time
                                && treat_event_completion_as_singlestep_complete(&replayed_event)))
                    {
                        self.write_regs(
                            old_task.unwrap().borrow_mut().as_mut(),
                            before_time,
                            instruction_count_within_event,
                            &mut stdout(),
                        )?;
                    }
                }

                if singlestep_really_complete {
                    instruction_count_within_event += 1;
                }
            }
            if before_time < after_time {
                log!(
                    LogDebug,
                    "Completed event {} instruction_count={}",
                    before_time,
                    instruction_count_within_event
                );
                instruction_count_within_event = 1;
            }
        }

        log!(LogInfo, "Rerun successfully finished");
        Ok(())
    }

    fn run_diversion_function(
        &self,
        replay: &ReplaySession,
        task: &mut dyn Task,
    ) -> io::Result<()> {
        let diversion_session = replay.clone_diversion();
        let diversion_ref = diversion_session.borrow_mut();
        let t = diversion_ref.find_task_from_task_uid(task.tuid()).unwrap();
        let mut regs = t.borrow().regs_ref().clone();
        // align stack;
        let sp = RemotePtr::<usize>::new_from_val((regs.sp().as_usize() & !0xf) - 1);
        write_val_mem(t.borrow_mut().as_mut(), sp, &SENTINEL_RET_ADDRESS, None);
        regs.set_sp(RemotePtr::cast(sp));
        // If we've called this method then we assume that there is always an address in self.function
        regs.set_ip(self.function.unwrap());
        regs.set_di(0);
        regs.set_si(0);
        t.borrow_mut().set_regs(&regs);
        let cmd = if self.singlestep_trace.is_empty() {
            RunCommand::RunContinue
        } else {
            RunCommand::RunSinglestep
        };

        loop {
            let result =
                diversion_session
                    .borrow()
                    .diversion_step(t.borrow_mut().as_mut(), Some(cmd), None);
            self.write_regs(t.borrow_mut().as_mut(), 0, 0, &mut stdout())?;
            match result.break_status.signal {
                Some(siginfo) => {
                    if siginfo.si_signo == libc::SIGSEGV
                        && unsafe { siginfo.si_addr() } as usize == SENTINEL_RET_ADDRESS
                    {
                        return Ok(());
                    }
                    ed_assert!(task, false, "Unexpected signal {:?}", siginfo);
                }
                None => (),
            }
        }
    }
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
        let mut gp_regs: RegsData = unsafe { mem::zeroed() };
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
                            self.write_value("eip", &value.to_le_bytes(), out)?;
                        }
                        SupportedArch::X64 => {
                            self.write_value("rip", &value.to_le_bytes(), out)?;
                        }
                    }
                }
                TraceFieldKind::TraceFsbase => {
                    // @TODO will rr also give 0 for x86?
                    let value: u64 = match t.regs_ref() {
                        Registers::X86(_) => 0,
                        Registers::X64(regs) => regs.fs_base,
                    };
                    self.write_value("fsbase", &value.to_le_bytes(), out)?;
                }
                TraceFieldKind::TraceGsbase => {
                    // @TODO will rr also give 0 for x86?
                    let value: u64 = match t.regs_ref() {
                        Registers::X86(_) => 0,
                        Registers::X64(regs) => regs.gs_base,
                    };
                    self.write_value("gsbase", &value.to_le_bytes(), out)?;
                }
                TraceFieldKind::TraceFlags => {
                    // Note the `as u64` to make write_regs() output length uniform between x86 and x86_64
                    let value: u64 = t.regs_ref().flags() as u64;
                    match t.arch() {
                        SupportedArch::X86 => {
                            self.write_value("eflags", &value.to_le_bytes(), out)?;
                        }
                        SupportedArch::X64 => {
                            self.write_value("rflags", &value.to_le_bytes(), out)?;
                        }
                    }
                }
                TraceFieldKind::TraceOrigAx => {
                    // Note the `as u64` to make write_regs() output length uniform between x86 and x86_64
                    let value: u64 = t.regs_ref().original_syscallno() as u64;
                    match t.arch() {
                        SupportedArch::X86 => {
                            self.write_value("orig_eax", &value.to_le_bytes(), out)?;
                        }
                        SupportedArch::X64 => {
                            self.write_value("orig_rax", &value.to_le_bytes(), out)?;
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
                // @TODO Will this work properly if rr is a x86 build?
                TraceFieldKind::TraceGpReg => {
                    if !got_gp_regs {
                        gp_regs = RegsData {
                            native: t.regs_ref().get_ptrace(),
                        };
                        got_gp_regs = true;
                    }
                    let mut value: u64 = if (field.reg_num as usize) < USER_REGS_FIELDS.len() {
                        (unsafe {
                            gp_regs.regs_values
                                [USER_REGS_FIELDS[field.reg_num as usize] / size_of::<usize>()]
                        }) as u64
                    } else {
                        0
                    };
                    if field.reg_num == 0 && t.arch() == SupportedArch::X86 {
                        // EAX->RAX is sign-extended, so undo that.
                        value = (value as u32) as u64;
                    }
                    let name = if t.arch() == SupportedArch::X86 && field.reg_num < 8 {
                        GP_REG_NAMES_32[field.reg_num as usize]
                    } else {
                        GP_REG_NAMES[field.reg_num as usize]
                    };
                    self.write_value(name, &value.to_le_bytes(), out)?;
                }
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
