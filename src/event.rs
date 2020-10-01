use crate::{
    bindings::signal::siginfo_t,
    event::EventType::{
        EvDesched,
        EvExit,
        EvGrowMap,
        EvInstructionTrap,
        EvNoop,
        EvPatchSyscall,
        EvSched,
        EvSeccompTrap,
        EvSentinel,
        EvSyscall,
        EvSyscallInterruption,
        EvSyscallbufAbortCommit,
        EvSyscallbufFlush,
        EvSyscallbufReset,
        EvTraceTermination,
    },
    kernel_abi::{is_execve_syscall, SupportedArch},
    kernel_metadata::{is_sigreturn, signal_name, syscall_name},
    log::LogLevel::LogInfo,
    preload_interface::{mprotect_record, syscallbuf_record},
    registers::Registers,
    remote_ptr::RemotePtr,
    sig::Sig,
};
use libc::{dev_t, ino_t};
use std::{
    convert::TryFrom,
    ffi::OsString,
    fmt::{Display, Formatter, Result, Write},
};

/// During recording, sometimes we need to ensure that an iteration of
/// RecordSession::record_step schedules the same task as in the previous
/// iteration. The PreventSwitch value indicates that this is required.
/// For example, the futex operation FUTEX_WAKE_OP modifies userspace
/// memory; those changes are only recorded after the system call completes;
/// and they must be replayed before we allow a context switch to a woken-up
/// task (because the kernel guarantees those effects are seen by woken-up
/// tasks).
/// Entering a potentially blocking system call must use AllowSwitch, or
/// we risk deadlock. Most non-blocking system calls could use PreventSwitch
/// or AllowSwitch; for simplicity we use AllowSwitch to indicate a call could
/// block and PreventSwitch otherwise.
/// Note that even if a system call uses PreventSwitch, as soon as we've
/// recorded the completion of the system call, we can switch to another task.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Switchable {
    PreventSwitch,
    AllowSwitch,
}

/// Events serve two purposes: tracking Task state during recording, and
/// being stored in traces to guide replay. Some events are only used during
/// recording and are never actually stored in traces (and are thus irrelevant
/// to replay).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum EventType {
    // @TODO EvUnassigned could potentially be removed
    EvUnassigned,
    EvSentinel,
    /// NOTE/TODO: this is actually a pseudo-pseudosignal: it will never
    /// appear in a trace, but is only used to communicate between
    /// different parts of the recorder code that should be
    /// refactored to not have to do that.
    EvNoop,
    EvDesched,
    EvSeccompTrap,
    EvSyscallInterruption,
    /// Not stored in trace, but synthesized when we reach the end of the trace.
    EvTraceTermination,

    /// Events present in traces:

    /// No associated data.
    EvExit,
    /// Scheduling signal interrupted the trace.
    EvSched,
    /// A disabled RDTSC or CPUID instruction.
    EvInstructionTrap,
    /// Recorded syscallbuf data for one or more buffered syscalls.
    EvSyscallbufFlush,
    EvSyscallbufAbortCommit,
    /// The syscallbuf was reset to the empty state. We record this event
    /// later than it really happens, because during replay we must proceed to
    /// the event *after* a syscallbuf flush and then reset the syscallbuf,
    /// to ensure we don't reset it while preload code is still using the data.
    EvSyscallbufReset,
    /// Syscall was entered, the syscall instruction was patched, and the
    /// syscall was aborted. Resume execution at the patch.
    EvPatchSyscall,
    /// Map memory pages due to a (future) memory access. This is associated
    /// with a mmap entry for the new pages.
    EvGrowMap,
    /// Use .signal_event.
    EvSignal,
    EvSignalDelivery,
    EvSignalHandler,
    /// Use .syscall_event.
    EvSyscall,
}

/// Desched events track the fact that a tracee's desched-event
/// notification fired during a may-block buffered syscall, which rd
/// interprets as the syscall actually blocking (for a potentially
/// unbounded amount of time).  After the syscall exits, rd advances
/// the tracee to where the desched is "disarmed" by the tracee.
#[derive(Clone)]
pub struct DeschedEventData {
    /// Record of the syscall that was interrupted by a desched
    /// notification.  It's legal to reference this memory /while
    /// the desched is being processed only/, because `t` is in the
    /// middle of a desched, which means it's successfully
    /// allocated (but not yet committed) this syscall record.
    pub rec: RemotePtr<syscallbuf_record>,
}

#[derive(Clone)]
pub struct SyscallbufFlushEventData {
    pub mprotect_records: Vec<mprotect_record>,
}

impl SyscallbufFlushEventData {
    pub fn new() -> SyscallbufFlushEventData {
        SyscallbufFlushEventData {
            mprotect_records: vec![],
        }
    }
}

impl Default for SyscallbufFlushEventData {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SignalDeterministic {
    NondeterministicSig = 0,
    DeterministicSig = 1,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SignalResolvedDisposition {
    DispositionFatal = 0,
    DispositionUserHandler = 1,
    DispositionIgnored = 2,
}

#[derive(Clone)]
pub struct SignalEventData {
    /// Signal info
    pub siginfo: siginfo_t,
    /// True if this signal will be deterministically raised as the
    /// side effect of retiring an instruction during replay, for
    /// example `load $r 0x0` deterministically raises SIGSEGV.
    pub deterministic: SignalDeterministic,
    pub disposition: SignalResolvedDisposition,
}
impl SignalEventData {
    pub fn new(
        siginfo: &siginfo_t,
        deterministic: SignalDeterministic,
        disposition: SignalResolvedDisposition,
    ) -> SignalEventData {
        SignalEventData {
            siginfo: siginfo.clone(),
            deterministic,
            disposition,
        }
    }

    pub fn maybe_sig(&self) -> Option<Sig> {
        Sig::try_from(self.siginfo.si_signo).ok()
    }
}

/// Syscall events track syscalls through entry into the kernel,
/// processing in the kernel, and exit from the kernel.
///
/// This also models interrupted syscalls.  During recording, only
/// descheduled buffered syscalls /push/ syscall interruptions; all
/// others are detected at exit time and transformed into syscall
/// interruptions from the original, normal syscalls.
///
/// Normal system calls (interrupted or not) record two events: EnteringSyscall
/// and ExitingSyscall. If the process exits before the syscall exit (because
/// this is an exit/exit_group syscall or the process gets SIGKILL), there's no
/// syscall exit event.
///
/// When PTRACE_SYSCALL is used, there will be three events:
/// EnteringSyscallPtrace to run the process until it gets into the kernel,
/// then EnteringSyscall and ExitingSyscall. We need three events to handle
/// PTRACE_SYSCALL with clone/fork/vfork and execve. The tracee must run to
/// the EnteringSyscallPtrace state, allow a context switch so the ptracer
/// can modify tracee registers, then perform EnteringSyscall (which actually
/// creates the new task or does the exec), allow a context switch so the
/// ptracer can modify the new task or post-exec state in a PTRACE_EVENT_EXEC/
/// CLONE/FORK/VFORK, then perform ExitingSyscall to get into the correct
/// post-syscall state.
///
/// When PTRACE_SYSEMU is used, there will only be one event: an
/// EnteringSyscallPtrace.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SyscallState {
    /// Not present in trace. Just a dummy value.
    NoSyscall,
    /// Run to the given register state and enter the kernel but don't
    /// perform any system call processing yet.
    EnteringSyscallPtrace,
    /// Run to the given register state and enter the kernel, if not already
    /// there due to a EnteringSyscallPtrace, and then perform the initial part
    /// of the system call (any work required before issuing a during-system-call
    /// ptrace event).
    EnteringSyscall,
    /// Not present in trace.
    ProcessingSyscall,
    /// Already in the kernel. Perform the final part of the system call and exit
    /// with the recorded system call result.
    ExitingSyscall,
}

impl Display for SyscallState {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let disp = match self {
            SyscallState::NoSyscall => "NO_SYSCALL",
            SyscallState::EnteringSyscallPtrace => "ENTERING_SYSCALL_PTRACE",
            SyscallState::EnteringSyscall => "ENTERING_SYSCALL",
            SyscallState::ProcessingSyscall => "PROCESSING_SYSCALL",
            SyscallState::ExitingSyscall => "EXITING_SYSCALL",
        };

        write!(f, "{}", disp)
    }
}

#[derive(Clone, Default)]
pub struct OpenedFd {
    pub path: OsString,
    pub fd: i32,
    pub device: dev_t,
    pub inode: ino_t,
}

#[derive(Clone)]
pub struct SyscallEventData {
    /// @TODO Is this field redundant?
    /// We can get arch from `regs` field also
    pub arch_: SupportedArch,
    /// The original (before scratch is set up) arguments to the
    /// syscall passed by the tracee.  These are used to detect
    /// restarted syscalls.
    pub regs: Registers,
    /// If this is a descheduled buffered syscall, points at the
    /// record for that syscall. RemotePtr::null() if there isn't any.
    pub desched_rec: RemotePtr<syscallbuf_record>,

    /// Extra data for specific syscalls. Only used for exit events currently.
    /// This is a int64_t with -1 to indicate no offset in rr.
    pub write_offset: Option<u64>,
    pub exec_fds_to_close: Vec<i32>,
    pub opened: Vec<OpenedFd>,

    pub state: SyscallState,
    /// Syscall number.
    pub number: i32,
    /// Records the switchable state when this syscall was prepared
    pub switchable: Switchable,
    /// True when this syscall was restarted after a signal interruption.
    pub is_restart: bool,
    /// True when this syscall failed during preparation: syscall entry events
    /// that were interrupted by a user seccomp filter forcing SIGSYS or errno,
    /// and clone system calls that failed. These system calls failed no matter
    /// what the syscall-result register says.
    pub failed_during_preparation: bool,
    /// Syscall is being emulated via PTRACE_SYSEMU.
    pub in_sysemu: bool,
}

impl SyscallEventData {
    pub fn new(syscallno: i32, arch: SupportedArch) -> SyscallEventData {
        SyscallEventData {
            arch_: arch,
            regs: Registers::new(arch),
            desched_rec: Default::default(),
            write_offset: None,
            state: SyscallState::NoSyscall,
            number: syscallno,
            switchable: Switchable::PreventSwitch,
            exec_fds_to_close: vec![],
            is_restart: false,
            failed_during_preparation: false,
            in_sysemu: false,
            opened: vec![],
        }
    }

    pub fn syscall_name(&self) -> String {
        syscall_name(self.number, self.arch())
    }

    pub fn arch(&self) -> SupportedArch {
        self.arch_
    }

    /// Change the architecture for this event.
    pub fn set_arch(&mut self, a: SupportedArch) {
        self.arch_ = a;
    }
}

#[derive(Clone)]
pub enum EventExtraData {
    NoExtraData,
    DeschedEvent(DeschedEventData),
    SignalEvent(SignalEventData),
    SyscallEvent(SyscallEventData),
    SyscallbufFlushEvent(SyscallbufFlushEventData),
}

#[derive(Clone)]
pub struct Event {
    event_type: EventType,
    event_extra_data: EventExtraData,
}

impl Default for EventExtraData {
    fn default() -> Self {
        EventExtraData::NoExtraData
    }
}

impl Default for EventType {
    fn default() -> Self {
        EventType::EvUnassigned
    }
}

impl Default for Event {
    fn default() -> Self {
        Event {
            event_type: Default::default(),
            event_extra_data: Default::default(),
        }
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.str())
    }
}

impl Display for EventType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let disp = match self {
            EventType::EvUnassigned => "UNASSIGNED",
            EventType::EvSentinel => "(none)",
            EventType::EvNoop => "NOOP",
            EventType::EvDesched => "DESCHED",
            EventType::EvSeccompTrap => "SECCOMP_TRAP",
            EventType::EvSyscallInterruption => "SYSCALL_INTERRUPTION",
            EventType::EvTraceTermination => "TRACE_TERMINATION",
            EventType::EvExit => "EXIT",
            EventType::EvSched => "SCHED",
            EventType::EvInstructionTrap => "INSTRUCTION_TRAP",
            EventType::EvSyscallbufFlush => "SYSCALLBUF_FLUSH",
            EventType::EvSyscallbufAbortCommit => "SYSCALLBUF_ABORT_COMMIT",
            EventType::EvSyscallbufReset => "SYSCALLBUF_RESET",
            EventType::EvPatchSyscall => "PATCH_SYSCALL",
            EventType::EvGrowMap => "GROW_MAP",
            EventType::EvSignal => "SIGNAL",
            EventType::EvSignalDelivery => "SIGNAL_DELIVERY",
            EventType::EvSignalHandler => "SIGNAL_HANDLER",
            EventType::EvSyscall => "SYSCALL",
        };

        write!(f, "{}", disp)
    }
}

impl Event {
    pub fn new_desched_event(ev: DeschedEventData) -> Event {
        Event {
            event_type: EvDesched,
            event_extra_data: EventExtraData::DeschedEvent(ev),
        }
    }

    pub fn new_signal_event(type_: EventType, ev: SignalEventData) -> Event {
        Event {
            event_type: type_,
            event_extra_data: EventExtraData::SignalEvent(ev),
        }
    }

    pub fn new_syscallbuf_flush_event(ev: SyscallbufFlushEventData) -> Event {
        Event {
            event_type: EvSyscallbufFlush,
            event_extra_data: EventExtraData::SyscallbufFlushEvent(ev),
        }
    }

    pub fn new_syscall_event(ev: SyscallEventData) -> Event {
        Event {
            event_type: EvSyscall,
            event_extra_data: EventExtraData::SyscallEvent(ev),
        }
    }

    pub fn new_syscall_interruption_event(ev: SyscallEventData) -> Event {
        Event {
            event_type: EvSyscallInterruption,
            event_extra_data: EventExtraData::SyscallEvent(ev),
        }
    }

    pub fn is_syscall_event(&self) -> bool {
        match self.event_type {
            EventType::EvSyscall | EventType::EvSyscallInterruption => true,
            _ => false,
        }
    }

    pub fn is_signal_event(&self) -> bool {
        match self.event_type {
            EventType::EvSignal | EventType::EvSignalHandler | EventType::EvSignalDelivery => true,
            _ => false,
        }
    }

    pub fn record_regs(&self) -> bool {
        match self.event_type {
            EventType::EvInstructionTrap
            | EventType::EvPatchSyscall
            | EventType::EvSched
            | EventType::EvSyscall
            | EventType::EvSignal
            | EventType::EvSignalDelivery
            | EventType::EvSignalHandler => true,
            _ => false,
        }
    }

    pub fn record_extra_regs(&self) -> bool {
        match self.event_type {
            EventType::EvSyscall => {
                let sys_ev = self.syscall_event();
                // sigreturn/rt_sigreturn restores register state
                sys_ev.state == SyscallState::ExitingSyscall
                    && (is_sigreturn(sys_ev.number, sys_ev.arch())
                        || is_execve_syscall(sys_ev.number, sys_ev.arch()))
            }
            EventType::EvSignalHandler => {
                // entering a signal handler seems to clear FP/SSE regs,
                // so record these effects.
                true
            }
            _ => false,
        }
    }

    pub fn has_ticks_slop(&self) -> bool {
        match self.event_type {
            EventType::EvSyscallbufAbortCommit
            | EventType::EvSyscallbufFlush
            | EventType::EvSyscallbufReset
            | EventType::EvDesched
            | EventType::EvGrowMap => true,
            _ => false,
        }
    }

    /// Dump info about this to INFO log.
    ///
    /// Note: usually you want to use `log!(LogInfo,...)`.
    pub fn log(&self) {
        log!(LogInfo, "{}", self);
    }

    pub fn str(&self) -> String {
        let mut ss = format!("{}", self.event_type());
        match self.event_type {
            EventType::EvSignal | EventType::EvSignalDelivery | EventType::EvSignalHandler => {
                let deterministic =
                    if self.signal_event().deterministic == SignalDeterministic::DeterministicSig {
                        "det"
                    } else {
                        "async"
                    };

                write!(
                    ss,
                    ": {}({})",
                    signal_name(self.signal_event().siginfo.si_signo),
                    deterministic
                )
                .unwrap_or(());
            }
            EventType::EvSyscall | EventType::EvSyscallInterruption => {
                write!(
                    ss,
                    ": {}",
                    syscall_name(
                        self.syscall_event().number,
                        self.syscall_event().regs.arch()
                    )
                )
                .unwrap_or(());
            }
            _ => {
                // No auxiliary information.
            }
        }
        ss
    }

    /// Dynamically change the type of this.  Only a small number
    /// of type changes are allowed.
    pub fn transform(&mut self, new_type: EventType) {
        match self.event_type {
            EventType::EvSignal => {
                debug_assert_eq!(EventType::EvSignalDelivery, new_type);
            }
            EventType::EvSignalDelivery => {
                debug_assert_eq!(EventType::EvSignalHandler, new_type);
            }
            EventType::EvSyscall => {
                debug_assert_eq!(EventType::EvSyscallInterruption, new_type);
            }
            EventType::EvSyscallInterruption => {
                debug_assert_eq!(EventType::EvSyscall, new_type);
            }
            _ => fatal!("Can't transform immutable {} into {:?}", self, new_type),
        }

        self.event_type = new_type;
    }

    pub fn noop() -> Event {
        Event::new_event(EvNoop)
    }

    pub fn trace_termination() -> Event {
        Event::new_event(EvTraceTermination)
    }

    pub fn instruction_trap() -> Event {
        Event::new_event(EvInstructionTrap)
    }

    pub fn patch_syscall() -> Event {
        Event::new_event(EvPatchSyscall)
    }

    pub fn sched() -> Event {
        Event::new_event(EvSched)
    }

    pub fn seccomp_trap() -> Event {
        Event::new_event(EvSeccompTrap)
    }

    pub fn syscallbuf_abort_commit() -> Event {
        Event::new_event(EvSyscallbufAbortCommit)
    }

    pub fn syscallbuf_reset() -> Event {
        Event::new_event(EvSyscallbufReset)
    }

    pub fn grow_map() -> Event {
        Event::new_event(EvGrowMap)
    }

    pub fn exit() -> Event {
        Event::new_event(EvExit)
    }

    pub fn sentinel() -> Event {
        Event::new_event(EvSentinel)
    }

    /// Note that this is NOT pub
    fn new_event(event_type: EventType) -> Event {
        Event {
            event_type,
            event_extra_data: EventExtraData::NoExtraData,
        }
    }

    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    pub fn desched_event(&self) -> &DeschedEventData {
        match &self.event_extra_data {
            EventExtraData::DeschedEvent(ev) => ev,
            _ => panic!("Not a desched event"),
        }
    }

    pub fn desched_event_mut(&mut self) -> &mut DeschedEventData {
        match &mut self.event_extra_data {
            EventExtraData::DeschedEvent(ev) => ev,
            _ => panic!("Not a desched event"),
        }
    }

    pub fn syscallbuf_flush_event(&self) -> &SyscallbufFlushEventData {
        match &self.event_extra_data {
            EventExtraData::SyscallbufFlushEvent(ev) => ev,
            _ => panic!("Not a syscallbuf flush event"),
        }
    }

    pub fn syscallbuf_flush_event_mut(&mut self) -> &mut SyscallbufFlushEventData {
        match &mut self.event_extra_data {
            EventExtraData::SyscallbufFlushEvent(ev) => ev,
            _ => panic!("Not a syscallbuf flush event"),
        }
    }

    pub fn signal_event(&self) -> &SignalEventData {
        match &self.event_extra_data {
            EventExtraData::SignalEvent(ev) => ev,
            _ => panic!("Not a signal event"),
        }
    }

    pub fn signal_event_mut(&mut self) -> &mut SignalEventData {
        match &mut self.event_extra_data {
            EventExtraData::SignalEvent(ev) => ev,
            _ => panic!("Not a signal event"),
        }
    }

    pub fn syscall_event(&self) -> &SyscallEventData {
        match &self.event_extra_data {
            EventExtraData::SyscallEvent(ev) => ev,
            _ => panic!("Not a syscall event"),
        }
    }

    pub fn syscall_event_mut(&mut self) -> &mut SyscallEventData {
        match &mut self.event_extra_data {
            EventExtraData::SyscallEvent(ev) => ev,
            _ => panic!("Not a syscall event"),
        }
    }
}
