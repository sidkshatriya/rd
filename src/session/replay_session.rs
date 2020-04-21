use crate::address_space::address_space::AddressSpaceSharedPtr;
use crate::cpuid_bug_detector::CPUIDBugDetector;
use crate::emu_fs::{EmuFs, EmuFsSharedPtr};
use crate::fast_forward::FastForwardStatus;
use crate::kernel_abi::SupportedArch;
use crate::remote_code_ptr::RemoteCodePtr;
use crate::session::diversion_session::DiversionSessionSharedPtr;
use crate::session::replay_session::ReplayTraceStepType::TstepNone;
use crate::session::session_inner::session_inner::SessionInner;
use crate::session::session_inner::{BreakStatus, RunCommand};
use crate::session::Session;
use crate::task::Task;
use crate::ticks::Ticks;
use crate::trace::trace_frame::{FrameTime, TraceFrame};
use crate::trace::trace_reader::TraceReader;
use crate::trace::trace_stream::TraceStream;
use libc::siginfo_t;
use std::cell::{Ref, RefCell, RefMut};
use std::ffi::OsStr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

pub type ReplaySessionSharedPtr = Arc<RefCell<ReplaySession>>;

/// ReplayFlushBufferedSyscallState is saved in Session and cloned with its
/// Session, so it needs to be simple data, i.e. not holding pointers to
/// per-Session data.
pub struct ReplayFlushBufferedSyscallState {
    /// An internal breakpoint is set at this address
    pub stop_breakpoint_addr: usize,
}

/// Describes the next step to be taken in order to replay a trace frame.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
#[repr(i32)]
pub enum ReplayTraceStepType {
    TstepNone,

    /// Enter/exit a syscall.  `syscall` describe what should be done at entry/exit.
    TstepEnterSyscall,
    TstepExitSyscall,

    /// Advance to the deterministic signal `signo`.
    TstepDeterministicSignal,

    /// Advance until `target.ticks` have been retired and then `target.ip` is reached.
    TstepProgramAsyncSignalInterrupt,

    /// Deliver signal `signo`.
    TstepDeliverSignal,

    /// Replay the upcoming buffered syscalls.  `flush` tracks the replay state.
    TstepFlushSyscallbuf,

    /// Replay until we enter the next syscall, then patch it.
    TstepPatchSyscall,

    /// Exit the task
    TstepExitTask,

    /// Frame has been replayed, done.
    TstepRetire,
}

pub struct ReplayTraceStepSyscall {
    /// The architecture of the syscall
    pub arch: SupportedArch,
    /// The syscall number we expect to enter/exit.
    pub number: i32,
}

pub struct ReplayTraceStepTarget {
    pub ticks: Ticks,
    pub signo: i32,
}

/// rep_trace_step is saved in Session and cloned with its Session, so it needs
/// to be simple data, i.e. not holding pointers to per-Session data.
pub enum ReplayTraceStep {
    Syscall(ReplayTraceStepSyscall),
    Target(ReplayTraceStepTarget),
    Flush(ReplayFlushBufferedSyscallState),
}

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum ReplayStatus {
    /// Some execution was replayed. replay_step() can be called again.
    ReplayContinue,
    /// All tracees are dead. replay_step() should not be called again.
    ReplayExited,
}

/// @TODO
pub struct StepConstraints;

pub struct ReplayResult {
    pub status: ReplayStatus,
    pub break_status: BreakStatus,
    /// True if we did a fast-forward operation, in which case
    /// break_status.singlestep_complete might indicate the completion of more
    /// than one instruction.
    pub did_fast_forward: bool,
    /// True if we fast-forward-singlestepped a string instruction but it has at least
    /// one iteration to go. did_fast_forward may be false in this case if the
    /// instruction executes exactly twice.
    pub incomplete_fast_forward: bool,
}

impl ReplayResult {
    pub fn new(status: ReplayStatus) -> ReplayResult {
        ReplayResult {
            status,
            break_status: BreakStatus::new(),
            did_fast_forward: false,
            incomplete_fast_forward: false,
        }
    }
}

/// An indicator of how much progress the ReplaySession has made within a given
/// (FrameTime, Ticks) pair. These can only be used for comparisons, to
/// check whether two ReplaySessions are in the same state and to help
/// order their states temporally.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ReplayStepKey {
    action: ReplayTraceStepType,
}

impl ReplayStepKey {
    /// Construct the "none" key; this value is before or equal to every other
    /// key value.
    pub fn new() -> ReplayStepKey {
        ReplayStepKey {
            action: ReplayTraceStepType::TstepNone,
        }
    }

    pub fn new_with(action: ReplayTraceStepType) -> ReplayStepKey {
        ReplayStepKey { action }
    }

    pub fn in_execution(&self) -> bool {
        self.action != TstepNone
    }

    pub fn as_i32(&self) -> i32 {
        self.action as i32
    }
}

pub struct ReplaySession {
    session_inner: SessionInner,
    emu_fs: EmuFsSharedPtr,
    trace_in: TraceReader,
    trace_frame: TraceFrame,
    current_step: ReplayTraceStep,
    ticks_at_start_of_event: Ticks,
    cpuid_bug_detector: CPUIDBugDetector,
    last_siginfo_: siginfo_t,
    flags_: Flags,
    fast_forward_status: FastForwardStatus,
    /// The clock_gettime(CLOCK_MONOTONIC) timestamp of the first trace event, used
    /// during 'replay' to calculate the elapsed time between the first event and
    /// all other recorded events in the timeline during the 'record' phase.
    trace_start_time: f64,
    /// Note that this is NOT a weak pointer!!
    syscall_bp_vm: AddressSpaceSharedPtr,
    syscall_bp_addr: RemoteCodePtr,
}

#[derive(Clone)]
pub struct Flags {
    pub redirect_stdio: bool,
    pub share_private_mappings: bool,
    pub cpu_unbound: bool,
}

impl Drop for ReplaySession {
    fn drop(&mut self) {
        unimplemented!()
    }
}

impl ReplaySession {
    /// Return a semantic copy of all the state managed by this,
    /// that is the entire tracee tree and the state it depends on.
    /// Any mutations of the returned Session can't affect the
    /// state of this, and vice versa.
    ///
    /// This operation is also called "checkpointing" the replay
    /// session.
    ///
    /// The returned clone is only partially initialized. This uses less
    /// system resources than a fully-initialized session, so if you're going
    /// to keep a session around inactive, keep the clone and not the original
    /// session. Partially initialized sessions automatically finish
    /// initializing when necessary.
    pub fn clone(&self) -> ReplaySessionSharedPtr {
        unimplemented!()
    }

    /// Return true if we're in a state where it's OK to clone. For example,
    /// we can't clone in some syscalls.
    pub fn can_clone(&self) -> bool {
        unimplemented!()
    }

    /// Like `clone()`, but return a session in "diversion" mode,
    /// which allows free execution.
    pub fn clone_diversion(&self) -> DiversionSessionSharedPtr {
        unimplemented!()
    }

    pub fn emufs(&self) -> Ref<'_, EmuFs> {
        self.emu_fs.borrow()
    }

    pub fn emufs_mut(&self) -> RefMut<'_, EmuFs> {
        self.emu_fs.borrow_mut()
    }

    pub fn trace_reader(&self) -> &TraceReader {
        &self.trace_in
    }

    pub fn trace_reader_mut(&mut self) -> &mut TraceReader {
        &mut self.trace_in
    }

    /// The trace record that we are working on --- the next event
    /// for replay to reach.
    pub fn current_trace_frame(&self) -> &TraceFrame {
        &self.trace_frame
    }
    /// Time of the current frame
    pub fn current_frame_time(&self) -> FrameTime {
        self.trace_frame.time()
    }

    /// The Task for the current trace record.
    pub fn current_task(&mut self) -> Option<Ref<'_, Box<dyn Task>>> {
        self.finish_initializing();
        let found = self.find_task_from_rec_tid(self.trace_frame.tid());
        found
            .as_ref()
            .map(|r| debug_assert!(r.as_replay_task().is_some()));
        found
    }

    pub fn current_task_mut(&mut self) -> Option<RefMut<'_, Box<dyn Task>>> {
        self.finish_initializing();
        let mut found = self.find_task_from_rec_tid_mut(self.trace_frame.tid());
        found
            .as_mut()
            .map(|r| debug_assert!(r.as_replay_task_mut().is_some()));
        found
    }

    pub fn is_ignored_signal(_sig: i32) -> bool {
        unimplemented!()
    }

    pub fn flags(&self) -> &Flags {
        &self.flags_
    }
    /// Create a replay session that will use the trace directory specified
    /// by 'dir', or the latest trace if 'dir' is not supplied.
    pub fn create(_dir: Option<&OsStr>, _flags: &Flags) -> ReplaySessionSharedPtr {
        unimplemented!()
    }

    /// Take a single replay step.
    /// Ensure we stop at event stop_at_time. If this is not specified,
    /// optimizations may cause a replay_step to pass straight through
    /// stop_at_time.
    /// Outside of replay_step, no internal breakpoints will be set for any
    /// task in this session.
    /// Stop when the current event reaches stop_at_time (i.e. this event has
    /// is the next event to be replayed).
    /// If ticks_target is nonzero, stop before the current task's ticks
    /// reaches ticks_target (but not too far before, unless we hit a breakpoint
    /// or stop_at_time). Only useful for RUN_CONTINUE.
    /// Always stops on a switch to a new task.
    pub fn replay_step_with_constraints(&mut self, _constraints: &StepConstraints) -> ReplayResult {
        unimplemented!()
    }
    pub fn replay_step(&mut self, _command: RunCommand) -> ReplayResult {
        unimplemented!()
    }
}

impl Deref for ReplaySession {
    type Target = SessionInner;

    fn deref(&self) -> &Self::Target {
        &self.session_inner
    }
}

impl DerefMut for ReplaySession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session_inner
    }
}

impl Session for ReplaySession {
    fn as_session_inner(&self) -> &SessionInner {
        &self.session_inner
    }

    fn as_session_inner_mut(&mut self) -> &mut SessionInner {
        &mut self.session_inner
    }

    fn as_replay(&self) -> Option<&ReplaySession> {
        Some(self)
    }

    fn as_replay_mut(&mut self) -> Option<&mut ReplaySession> {
        Some(self)
    }

    fn new_task(&self, _tid: i32, _rec_tid: i32, _serial: u32, _a: SupportedArch) -> &mut dyn Task {
        unimplemented!()
    }

    fn cpu_binding(&self, trace: &TraceStream) -> Option<u32> {
        if self.flags_.cpu_unbound {
            return None;
        }
        Session::cpu_binding(self, trace)
    }
}
