use crate::kernel_abi::common::preload_interface::{mprotect_record, syscallbuf_record};
use crate::kernel_abi::SupportedArch;
use crate::registers::Registers;
use crate::remote_ptr::RemotePtr;
use libc::{dev_t, ino_t, siginfo_t};
use std::ffi::OsString;
use std::fmt::{Display, Formatter, Result};

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
///
/// @TODO If this is stored in trace then will need worry about values
/// and possibly ensure they are same as in rr.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum EventType {
    EvUnassigned,
    EvSentinel,
    /// TODO: this is actually a pseudo-pseudosignal: it will never
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
    /// Use .signal.
    EvSignal,
    EvSignalDelivery,
    EvSignalHandler,
    /// Use .syscall.
    EvSyscall,

    EvLast,
}

/// Desched events track the fact that a tracee's desched-event
/// notification fired during a may-block buffered syscall, which rd
/// interprets as the syscall actually blocking (for a potentially
/// unbounded amount of time).  After the syscall exits, rd advances
/// the tracee to where the desched is "disarmed" by the tracee.
#[derive(Clone)]
pub struct DeschedEvent {
    /// Record of the syscall that was interrupted by a desched
    /// notification.  It's legal to reference this memory /while
    /// the desched is being processed only/, because `t` is in the
    /// middle of a desched, which means it's successfully
    /// allocated (but not yet committed) this syscall record.
    pub rec: RemotePtr<syscallbuf_record>,
}

#[derive(Clone)]
pub struct SyscallbufFlushEvent {
    pub mprotect_records: Vec<mprotect_record>,
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
pub struct SignalEvent {
    /// Signal info
    pub siginfo: siginfo_t,
    /// True if this signal will be deterministically raised as the
    /// side effect of retiring an instruction during replay, for
    /// example `load $r 0x0` deterministically raises SIGSEGV.
    pub deterministic: SignalDeterministic,
    pub disposition: SignalResolvedDisposition,
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

#[derive(Clone)]
pub struct OpenedFd {
    pub path: OsString,
    pub fd: i32,
    pub device: dev_t,
    pub inode: ino_t,
}

#[derive(Clone)]
pub struct SyscallEvent {
    pub arch_: SupportedArch,
    /// The original (before scratch is set up) arguments to the
    /// syscall passed by the tracee.  These are used to detect
    /// restarted syscalls.
    pub regs: Registers,
    /// If this is a descheduled buffered syscall, points at the
    /// record for that syscall.
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

// @TODO
struct SyscallInterruption;

// @TODO
// interrupted

#[derive(Clone)]
pub enum EventExtraData {
    NoExtraData,
    DeschedEvent(DeschedEvent),
    SignalEvent(SignalEvent),
    SyscallEvent(SyscallEvent),
    SyscallbufFlushEvent(SyscallbufFlushEvent),
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
        unimplemented!()
    }
}

impl Event {
    pub fn is_syscall_event(&self) -> bool {
        match self.event_type {
            EventType::EvSyscall | EventType::EvSyscallInterruption => true,
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

    pub fn syscall(&self) -> &SyscallEvent {
        match &self.event_extra_data {
            EventExtraData::SyscallEvent(s) => s,
            _ => panic!("Not a SyscallEvent"),
        }
    }

    pub fn syscall_mut(&mut self) -> &mut SyscallEvent {
        match &mut self.event_extra_data {
            EventExtraData::SyscallEvent(s) => s,
            _ => panic!("Not a SyscallEvent"),
        }
    }

    pub fn event_type(&self) -> EventType {
        self.event_type
    }
}
