use super::{
    address_space::{kernel_mapping::KernelMapping, MappingFlags},
    on_create_task_common,
    session_common::kill_all_tasks,
    session_inner::{is_singlestep, PtraceSyscallSeccompOrdering},
    task::{
        replay_task::ReplayTaskIgnore,
        task_common::{read_mem, read_val_mem},
        task_inner::{TrapReasons, WriteFlags, MAX_TICKS_REQUEST},
    },
};
use crate::{
    arch::{Architecture, X86Arch},
    auto_remote_syscalls::AutoRemoteSyscalls,
    bindings::{
        ptrace::{PTRACE_EVENT_EXIT, PTRACE_EVENT_SECCOMP},
        signal::siginfo_t,
    },
    cpuid_bug_detector::CPUIDBugDetector,
    emu_fs::{EmuFs, EmuFsSharedPtr},
    event::{Event, EventType, SignalDeterministic, SignalEventData, SyscallState},
    fast_forward::{fast_forward_through_instruction, FastForwardStatus},
    flags::Flags as ProgramFlags,
    kernel_abi::{is_execve_syscall, syscall_number_for_exit, SupportedArch},
    kernel_metadata::syscall_name,
    log::LogLevel::{LogDebug, LogError},
    perf_counters,
    perf_counters::{PerfCounters, TIME_SLICE_SIGNAL},
    preload_interface::{
        mprotect_record,
        preload_globals,
        syscallbuf_hdr,
        syscallbuf_locked_why,
        SYS_rdcall_mprotect_record,
    },
    registers::{MismatchBehavior, Registers},
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    replay_syscall::{
        rep_after_enter_syscall,
        rep_prepare_run_to_syscall,
        rep_process_syscall,
        restore_mapped_region,
    },
    scoped_fd::ScopedFd,
    session::{
        address_space::{
            address_space::{AddressSpace, AddressSpaceSharedPtr},
            BreakpointType,
            Enabled,
            Traced,
        },
        diversion_session::DiversionSessionSharedPtr,
        replay_session::ReplayTraceStepType::TstepNone,
        session_inner::{BreakStatus, RunCommand, SessionInner},
        task::{
            replay_task::ReplayTask,
            task_common::write_val_mem,
            task_inner::{ResumeRequest, SaveTraceeFdNumber, TaskInner, TicksRequest, WaitRequest},
            Task,
            TaskSharedPtr,
        },
        Session,
        SessionSharedPtr,
    },
    sig,
    sig::Sig,
    thread_group::ThreadGroupSharedPtr,
    ticks::Ticks,
    trace::{
        trace_frame::{FrameTime, TraceFrame},
        trace_reader::TraceReader,
        trace_stream::{MappedData, TraceStream},
    },
    util::{
        cpuid,
        cpuid_compatible,
        default_action,
        find_cpuid_record,
        running_under_rd,
        should_checksum,
        should_dump_memory,
        trapped_instruction_at,
        trapped_instruction_len,
        validate_process_memory,
        xcr0,
        xsave_enabled,
        CPUIDData,
        Completion,
        SignalAction,
        TrappedInstruction,
        CPUID_GETFEATURES,
        CPUID_GETXSAVE,
        OSXSAVE_FEATURE_FLAG,
        XSAVEC_FEATURE_FLAG,
    },
    wait_status::WaitStatus,
};
use libc::{pid_t, ENOSYS, SIGBUS, SIGSEGV, SIGTRAP};
use nix::sys::mman::{MapFlags, ProtFlags};
use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    cmp::min,
    convert::TryInto,
    ffi::{OsStr, OsString},
    intrinsics::copy_nonoverlapping,
    mem::size_of,
    ops::{Deref, DerefMut},
    rc::{Rc, Weak},
};

const USE_BREAKPOINT_TARGET: bool = true;

pub type ReplaySessionSharedPtr = Rc<RefCell<ReplaySession>>;

/// ReplayFlushBufferedSyscallState is saved in Session and cloned with its
/// Session, so it needs to be simple data, i.e. not holding pointers to
/// per-Session data.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct ReplayFlushBufferedSyscallState {
    /// An internal breakpoint is set at this address
    pub stop_breakpoint_addr: usize,
}

/// Describes the next step to be taken in order to replay a trace frame.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
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

impl Default for ReplayTraceStepType {
    fn default() -> Self {
        ReplayTraceStepType::TstepNone
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReplayTraceStepSyscall {
    /// The architecture of the syscall
    pub arch: SupportedArch,
    /// The syscall number we expect to enter/exit.
    pub number: i32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReplayTraceStepTarget {
    /// DIFF NOTE: In rr a `-1` value is used to indicate "not applicable" if understood correctly
    /// Use `None` instead in rd.
    /// @TODO Or should this be an enum TicksRequest ??
    pub ticks: Option<Ticks>,
    pub signo: Option<Sig>,
}

/// rep_trace_step is saved in Session and cloned with its Session, so it needs
/// to be simple data, i.e. not holding pointers to per-Session data.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReplayTraceStepData {
    None,
    Syscall(ReplayTraceStepSyscall),
    Target(ReplayTraceStepTarget),
    Flush(ReplayFlushBufferedSyscallState),
}

impl Default for ReplayTraceStepData {
    fn default() -> Self {
        ReplayTraceStepData::None
    }
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Debug)]
pub struct ReplayTraceStep {
    pub action: ReplayTraceStepType,
    pub data: ReplayTraceStepData,
}

impl ReplayTraceStep {
    pub fn syscall(&self) -> ReplayTraceStepSyscall {
        match self.data {
            ReplayTraceStepData::Syscall(s) => s,
            _ => {
                panic!("Unexpected variant. Not a ReplayTraceStepData::Syscall");
            }
        }
    }

    pub fn syscall_mut(&mut self) -> &mut ReplayTraceStepSyscall {
        match &mut self.data {
            ReplayTraceStepData::Syscall(s) => s,
            _ => {
                panic!("Unexpected variant. Not a ReplayTraceStepData::Syscall");
            }
        }
    }

    pub fn target(&self) -> ReplayTraceStepTarget {
        match self.data {
            ReplayTraceStepData::Target(t) => t,
            _ => {
                panic!("Unexpected variant. Not a ReplayTraceStepData::Target");
            }
        }
    }

    pub fn target_mut(&mut self) -> &mut ReplayTraceStepTarget {
        match &mut self.data {
            ReplayTraceStepData::Target(t) => t,
            _ => {
                panic!("Unexpected variant. Not a ReplayTraceStepData::Target");
            }
        }
    }

    pub fn flush(&self) -> ReplayFlushBufferedSyscallState {
        match self.data {
            ReplayTraceStepData::Flush(f) => f,
            _ => {
                panic!("Unexpected variant. Not a ReplayTraceStepData::Flush");
            }
        }
    }

    pub fn flush_mut(&mut self) -> &mut ReplayFlushBufferedSyscallState {
        match &mut self.data {
            ReplayTraceStepData::Flush(f) => f,
            _ => {
                panic!("Unexpected variant. Not a ReplayTraceStepData::Flush");
            }
        }
    }
}

#[derive(Eq, Debug, PartialEq, Copy, Clone)]
pub enum ReplayStatus {
    /// Some execution was replayed. replay_step() can be called again.
    ReplayContinue,
    /// All tracees are dead. replay_step() should not be called again.
    ReplayExited,
}

impl Default for ReplayStatus {
    fn default() -> Self {
        Self::ReplayContinue
    }
}

#[derive(Clone)]
pub struct StepConstraints {
    pub command: RunCommand,
    pub stop_at_time: FrameTime,
    /// @TODO If there is a no ticks target, we set this to 0
    pub ticks_target: Ticks,
    /// When the RunCommand is RunSinglestepFastForward, stop if the next
    /// singlestep would enter one of the register states in this list.
    /// RunSinglestepFastForwardWill always singlestep at least once
    /// regardless.
    /// DIFF NOTE: @TODO? In rr this is a pointer to the registers
    /// i.e. in Rust it would be Vec<&Registers>
    pub stop_before_states: Vec<Registers>,
}

impl StepConstraints {
    pub fn is_singlestep(&self) -> bool {
        self.command == RunCommand::RunSinglestep
            || self.command == RunCommand::RunSinglestepFastForward
    }
    pub fn new(command: RunCommand) -> StepConstraints {
        StepConstraints {
            command,
            stop_at_time: Default::default(),
            ticks_target: Default::default(),
            stop_before_states: Vec::new(),
        }
    }
}

#[derive(Clone, Default)]
pub struct ReplayResult {
    pub status: ReplayStatus,
    /// @TODO Might want to consider having Option<BreakStatus> here??
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
    trace_in: RefCell<TraceReader>,
    trace_frame: RefCell<TraceFrame>,
    current_step: Cell<ReplayTraceStep>,
    ticks_at_start_of_event: Cell<Ticks>,
    cpuid_bug_detector: RefCell<CPUIDBugDetector>,
    last_siginfo_: Cell<Option<siginfo_t>>,
    flags_: Flags,
    fast_forward_status: Cell<FastForwardStatus>,
    /// The clock_gettime(CLOCK_MONOTONIC) timestamp of the first trace event, used
    /// during 'replay' to calculate the elapsed time between the first event and
    /// all other recorded events in the timeline during the 'record' phase.
    trace_start_time: Cell<f64>,
    /// Note that this is NOT a weak pointer!!
    /// DIFF NOTE: Made into an Option<>
    syscall_bp_vm: RefCell<Option<AddressSpaceSharedPtr>>,
    // @TODO Set to the 0 address on init. More principled solution?!
    syscall_bp_addr: Cell<RemoteCodePtr>,
}

#[derive(Copy, Clone)]
pub struct Flags {
    pub redirect_stdio: bool,
    pub share_private_mappings: bool,
    pub cpu_unbound: bool,
}

impl Drop for ReplaySession {
    fn drop(&mut self) {
        // We won't permanently leak any OS resources by not ensuring
        // we've cleaned up here, but sessions can be created and
        // destroyed many times, and we don't want to temporarily hog
        // resources.
        self.kill_all_tasks();
        // Drop any AddressSpace
        *self.syscall_bp_vm.borrow_mut() = None;
        debug_assert!(self.task_map.borrow().is_empty());
        debug_assert!(self.vm_map.borrow().is_empty());
        debug_assert_eq!(self.emufs().size(), 0);
        log!(
            LogDebug,
            "ReplaySession {:?} destroyed",
            self as *const Self
        );
    }
}

impl ReplaySession {
    pub fn get_trace_start_time(&self) -> f64 {
        self.trace_start_time.get()
    }

    /// The current ReplayStepKey.
    pub fn current_step_key(&self) -> ReplayStepKey {
        ReplayStepKey::new_with(self.current_step.get().action)
    }

    pub fn ticks_at_start_of_current_event(&self) -> Ticks {
        self.ticks_at_start_of_event.get()
    }

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
    ///
    /// DIFF NOTE: Simply called clone() in rr
    pub fn clone_replay(&self) -> SessionSharedPtr {
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

    pub fn trace_reader(&self) -> Ref<'_, TraceReader> {
        self.trace_in.borrow()
    }

    pub fn trace_reader_mut(&self) -> RefMut<'_, TraceReader> {
        self.trace_in.borrow_mut()
    }

    /// The trace record that we are working on --- the next event
    /// for replay to reach.
    pub fn current_trace_frame(&self) -> Ref<'_, TraceFrame> {
        self.trace_frame.borrow()
    }

    /// The trace record that we are working on --- the next event
    /// for replay to reach.
    pub fn current_trace_frame_mut(&self) -> RefMut<'_, TraceFrame> {
        self.trace_frame.borrow_mut()
    }

    /// Time of the current frame
    pub fn current_frame_time(&self) -> FrameTime {
        self.trace_frame.borrow().time()
    }

    /// The Task for the current trace record.
    pub fn current_task(&self) -> Option<TaskSharedPtr> {
        self.finish_initializing();
        let found = self.find_task_from_rec_tid(self.current_trace_frame().tid());
        found
    }

    /// @TODO Check this
    pub fn is_ignored_signal(sig: Option<Sig>) -> bool {
        match sig {
            // TIME_SLICE_SIGNALs can be queued but not delivered before we stop
            // execution for some other reason. Ignore them.
            Some(TIME_SLICE_SIGNAL) => true,
            _ => false,
        }
    }

    pub fn flags(&self) -> &Flags {
        &self.flags_
    }

    fn new<T: AsRef<OsStr>>(dir: Option<&T>, flags: Flags) -> ReplaySession {
        let mut rs = ReplaySession {
            emu_fs: EmuFs::create(),
            trace_in: RefCell::new(TraceReader::new(dir)),
            trace_frame: Default::default(),
            current_step: Default::default(),
            ticks_at_start_of_event: Default::default(),
            flags_: flags,
            last_siginfo_: Default::default(),
            trace_start_time: Default::default(),
            session_inner: Default::default(),
            cpuid_bug_detector: Default::default(),
            fast_forward_status: Default::default(),
            syscall_bp_vm: Default::default(),
            syscall_bp_addr: Default::default(),
        };

        let semantics = rs.trace_in.borrow().ticks_semantics();
        rs.ticks_semantics_ = semantics;
        rs.advance_to_next_trace_frame();
        rs.trace_start_time
            .set(rs.current_trace_frame().monotonic_time());

        if rs.trace_in.borrow().uses_cpuid_faulting() && !SessionInner::has_cpuid_faulting() {
            clean_fatal!(
                "Trace was recorded with CPUID faulting enabled, but this\n\
                          system does not support CPUID faulting."
            );
        }
        if !SessionInner::has_cpuid_faulting()
            && !cpuid_compatible(rs.trace_in.borrow().cpuid_records())
        {
            clean_fatal!(
                "Trace was recorded on a machine with different CPUID values\n\
                          and CPUID faulting is not enabled; replay will not work."
            );
        }
        if !PerfCounters::supports_ticks_semantics(rs.ticks_semantics_) {
            clean_fatal!(
                "Trace was recorded on a machine that defines ticks differently\n\
                          to this machine; replay will not work."
            );
        }

        check_xsave_compatibility(&rs.trace_in.borrow());
        rs
    }

    fn advance_to_next_trace_frame(&self) {
        if self.trace_in.borrow().at_end() {
            let global_time = self.current_frame_time();
            let tick_count = self.current_trace_frame().ticks();
            let monotonic_time = self.current_trace_frame().monotonic_time();
            *self.current_trace_frame_mut() = TraceFrame::new_with(
                global_time,
                0,
                Event::trace_termination(),
                tick_count,
                monotonic_time,
            );
            return;
        }

        *self.trace_frame.borrow_mut() = self.trace_in.borrow_mut().read_frame();
    }

    /// Create a replay session that will use the trace directory specified
    /// by 'dir', or the latest trace if 'dir' is not supplied.
    pub fn create<T: AsRef<OsStr>>(dir: Option<&T>, flags: Flags) -> SessionSharedPtr {
        let mut session: ReplaySession = ReplaySession::new(dir, flags);

        // It doesn't really matter what we use for argv/env here, since
        // replay_syscall's process_execve is going to follow the recording and
        // ignore the parameters.
        let exe_path: OsString = OsString::new();
        let argv: Vec<OsString> = Vec::new();
        let env: Vec<OsString> = Vec::new();

        let error_fd: ScopedFd = session.create_spawn_task_error_pipe();
        let sock_fd_out = session.tracee_socket_fd();
        let tid = session.trace_reader_mut().peek_frame().unwrap().tid();

        let mut rc: SessionSharedPtr = Rc::new(Box::new(session));
        let weak_self = Rc::downgrade(&rc);
        // We never change the weak_self pointer so its a good idea to use
        // a bit of unsafe here.
        unsafe { Rc::get_mut_unchecked(&mut rc) }.weak_self = weak_self;
        let t = TaskInner::spawn(
            (*rc).as_ref(),
            &error_fd,
            sock_fd_out,
            SaveTraceeFdNumber::SaveToSession,
            &exe_path,
            &argv,
            &env,
            Some(tid),
        );

        rc.on_create_task(t);

        rc
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
    pub fn replay_step_with_constraints(&self, constraints: &StepConstraints) -> ReplayResult {
        self.finish_initializing();
        let mut result = ReplayResult::new(ReplayStatus::ReplayContinue);
        let mut maybe_rc_t = self.current_task();

        if self.current_trace_frame().event().event_type() == EventType::EvTraceTermination {
            result.status = ReplayStatus::ReplayExited;
            return result;
        }
        // If we restored from a checkpoint, the steps might have been
        // computed already in which case step.action will not be TstepNone.
        if self.current_step.get().action == ReplayTraceStepType::TstepNone {
            let rc_t = self.setup_replay_one_trace_frame(maybe_rc_t);
            if self.current_step.get().action == ReplayTraceStepType::TstepNone {
                // Already at the destination event.
                self.advance_to_next_trace_frame();
            }
            if self.current_step.get().action == ReplayTraceStepType::TstepExitTask {
                result.break_status.task = rc_t.borrow().weak_self.clone();
                result.break_status.task_exit = true;
            }
            return result;
        }
        {
            let rc_t = maybe_rc_t.as_ref().unwrap().clone();
            self.fast_forward_status.set(FastForwardStatus::new());
            // Now we know `t` hasn't died, so save it in break_status.
            result.break_status.task = rc_t.borrow().weak_self.clone();
            let mut dt = rc_t.borrow_mut();
            let t = dt.as_replay_task_mut().unwrap();
            // Advance towards fulfilling `current_step`.
            if self.try_one_trace_step(t, &constraints) == Completion::Incomplete {
                if EventType::EvTraceTermination == self.current_trace_frame().event().event_type()
                {
                    // An irregular trace step had to read the
                    // next trace frame, and that frame was an
                    // early-termination marker.  Otherwise we
                    // would have seen the marker above.
                    result.status = ReplayStatus::ReplayExited;
                    return result;
                }

                // We got INCOMPLETE because there was some kind of debugger trap or
                // we got close to ticks_target.
                result.break_status = self.diagnose_debugger_trap(t, constraints.command);
                ed_assert!(
                    t,
                    result.break_status.signal.is_none(),
                    "Expected either SIGTRAP at $ip {} or USER breakpoint just after it",
                    t.ip()
                );
                ed_assert!(
                    t,
                    !result.break_status.singlestep_complete || constraints.is_singlestep()
                );

                self.check_approaching_ticks_target(t, &constraints, &mut result.break_status);
                result.did_fast_forward = self.fast_forward_status.get().did_fast_forward;
                result.incomplete_fast_forward =
                    self.fast_forward_status.get().incomplete_fast_forward;
                return result;
            }

            result.did_fast_forward = self.fast_forward_status.get().did_fast_forward;
            result.incomplete_fast_forward = self.fast_forward_status.get().incomplete_fast_forward;
            match self.current_step.get().action {
                ReplayTraceStepType::TstepDeterministicSignal
                | ReplayTraceStepType::TstepProgramAsyncSignalInterrupt => {
                    match self.current_step.get().target().signo {
                        None => (),
                        Some(signo) => {
                            if self.current_trace_frame().event().event_type()
                                != EventType::EvInstructionTrap
                            {
                                ed_assert!(
                                    t,
                                    signo.as_raw() == self.last_siginfo_.get().unwrap().si_signo
                                );
                                result.break_status.signal =
                                    Some(Box::new(self.last_siginfo_.get().unwrap()));
                            }
                            if constraints.is_singlestep() {
                                result.break_status.singlestep_complete = true;
                            }
                        }
                    }
                }
                ReplayTraceStepType::TstepDeliverSignal => {
                    // When we deliver a terminating signal, do not let the singlestep
                    // complete; proceed on to report our synthetic SIGKILL or task death.
                    if constraints.is_singlestep()
                        && !(self.current_trace_frame().event().event_type()
                            == EventType::EvSignalDelivery
                            && is_fatal_default_action(
                                self.current_step.get().target().signo.unwrap(),
                            ))
                    {
                        result.break_status.singlestep_complete = true;
                    }
                }
                ReplayTraceStepType::TstepExitTask => {
                    result.break_status.task = Weak::new();
                    maybe_rc_t = None;
                    debug_assert!(!result.break_status.any_break());
                }
                ReplayTraceStepType::TstepEnterSyscall => {
                    self.cpuid_bug_detector
                        .borrow_mut()
                        .notify_reached_syscall_during_replay(t);
                }
                ReplayTraceStepType::TstepExitSyscall => {
                    if constraints.is_singlestep() {
                        result.break_status.singlestep_complete = true;
                    }
                }
                _ => (),
            }
        }
        match maybe_rc_t {
            None => (),
            Some(rc_t) => {
                let mut dt = rc_t.borrow_mut();
                let t = dt.as_replay_task_mut().unwrap();

                let frame = self.current_trace_frame();
                let ev = frame.event();
                if self.done_initial_exec()
                    && ev.is_syscall_event()
                    && ProgramFlags::get().check_cached_mmaps
                {
                    t.vm().verify(t);
                }

                if has_deterministic_ticks(ev, self.current_step.get()) {
                    self.check_ticks_consistency(t, ev);
                }

                debug_memory(t);

                self.check_for_watchpoint_changes(t, &mut result.break_status);
                self.check_approaching_ticks_target(t, &constraints, &mut result.break_status);
            }
        }

        self.advance_to_next_trace_frame();
        // Record that this step completed successfully.
        self.current_step.set(Default::default());
        let maybe_next_task = self.current_task();
        match maybe_next_task {
            None => (),
            Some(next_task_shr_ptr) => {
                let next_task_t = next_task_shr_ptr.borrow_mut();
                let next_task = next_task_t.as_replay_task().unwrap();
                if next_task.vm().first_run_event() == 0 && self.done_initial_exec() {
                    next_task
                        .vm()
                        .set_first_run_event(self.current_frame_time());
                }
                self.ticks_at_start_of_event.set(next_task.tick_count());
            }
        }

        result
    }

    /// Set up rep_trace_step state in t's Session to start replaying towards
    /// the event given by the session's current_trace_frame --- but only if
    /// it's not already set up.
    /// Return true if we should continue replaying, false if the debugger
    /// requested a restart. If this returns false, t's Session state was not
    /// modified.
    fn setup_replay_one_trace_frame(&self, maybe_t: Option<TaskSharedPtr>) -> TaskSharedPtr {
        let trace_frame = self.current_trace_frame();
        let ev = trace_frame.event();
        let trace_frame_tid = trace_frame.tid();

        let t_shr_ptr = match maybe_t {
            None => self.revive_task_for_exec(ev, trace_frame_tid),
            Some(ts) => ts,
        };
        let mut dyn_t = t_shr_ptr.borrow_mut();
        let t = dyn_t.as_replay_task_mut().unwrap();

        log!(
            LogDebug,
            "[event {}] {}: replaying {}; state {}",
            self.current_frame_time(),
            t.rec_tid,
            ev,
            if ev.is_syscall_event() {
                format!("{}", ev.syscall_event().state)
            } else {
                " (none)".to_owned()
            }
        );

        if !t.syscallbuf_child.is_null() {
            let syscallbuf_hdr: RemotePtr<u8> = RemotePtr::cast(t.syscallbuf_child);
            let syscallbuf_num_rec_bytes: RemotePtr<u32> =
                RemotePtr::cast(syscallbuf_hdr + offset_of!(syscallbuf_hdr, num_rec_bytes));
            let syscallbuf_abort_commit: RemotePtr<u8> =
                RemotePtr::cast(syscallbuf_hdr + offset_of!(syscallbuf_hdr, abort_commit));
            let syscallbuf_locked: RemotePtr<syscallbuf_locked_why> =
                RemotePtr::cast(syscallbuf_hdr + offset_of!(syscallbuf_hdr, locked));
            log!(
                LogDebug,
                "    (syscllbufsz:{}, abrtcmt:{}, locked:{:?})",
                read_val_mem(t, syscallbuf_num_rec_bytes, None),
                read_val_mem(t, syscallbuf_abort_commit, None) != 0,
                read_val_mem(t, syscallbuf_locked, None),
            );
        }

        // Ask the trace-interpretation code what to do next in order
        // to retire the current frame.
        let mut current_step: ReplayTraceStep = Default::default();
        match ev.event_type() {
            EventType::EvExit => {
                current_step.action = ReplayTraceStepType::TstepExitTask;
            }
            EventType::EvSyscallbufAbortCommit => {
                let child_addr = RemotePtr::<u8>::cast(t.syscallbuf_child)
                    + offset_of!(syscallbuf_hdr, abort_commit);
                write_val_mem(t, child_addr, &1u8, None);
                t.apply_all_data_records_from_trace();
                current_step.action = ReplayTraceStepType::TstepRetire;
            }
            EventType::EvSyscallbufFlush => {
                self.prepare_syscallbuf_records(t, &mut current_step);
            }
            EventType::EvSyscallbufReset => {
                // Reset syscallbuf_hdr->num_rec_bytes and zero out the recorded data.
                // Zeroing out the data is important because we only save and restore
                // the recorded data area when making checkpoints. We want the checkpoint
                // to have the same syscallbuf contents as its original, i.e. zero outside
                // the recorded data area. This is important because stray reads such
                // as those performed by return_addresses should be consistent.
                t.reset_syscallbuf();
                current_step.action = ReplayTraceStepType::TstepRetire;
            }
            EventType::EvPatchSyscall => {
                current_step.action = ReplayTraceStepType::TstepPatchSyscall;
            }
            EventType::EvSched => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepProgramAsyncSignalInterrupt,
                    data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                        ticks: Some(trace_frame.ticks()),
                        signo: None,
                    }),
                };
            }
            EventType::EvInstructionTrap => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepDeterministicSignal,
                    data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                        ticks: None,
                        signo: Some(sig::SIGSEGV),
                    }),
                };
            }
            EventType::EvGrowMap => {
                process_grow_map(t);
                current_step.action = ReplayTraceStepType::TstepRetire;
            }
            EventType::EvSignal => {
                self.last_siginfo_.set(Some(ev.signal_event().siginfo));
                if treat_signal_event_as_deterministic(ev.signal_event()) {
                    current_step = ReplayTraceStep {
                        action: ReplayTraceStepType::TstepDeterministicSignal,
                        data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                            ticks: None,
                            signo: Some(ev.signal_event().maybe_sig().unwrap()),
                        }),
                    };
                } else {
                    current_step = ReplayTraceStep {
                        action: ReplayTraceStepType::TstepProgramAsyncSignalInterrupt,
                        data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                            ticks: Some(trace_frame.ticks()),
                            signo: Some(ev.signal_event().maybe_sig().unwrap()),
                        }),
                    };
                }
            }
            EventType::EvSignalDelivery | EventType::EvSignalHandler => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepDeliverSignal,
                    data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                        // Note this should NOT be None.
                        ticks: Some(0),
                        signo: Some(ev.signal_event().maybe_sig().unwrap()),
                    }),
                };
            }
            EventType::EvSyscall => {
                if ev.syscall_event().state == SyscallState::EnteringSyscall
                    || ev.syscall_event().state == SyscallState::EnteringSyscallPtrace
                {
                    rep_prepare_run_to_syscall(t, &mut current_step);
                } else {
                    rep_process_syscall(t, &mut current_step);
                    if current_step.action == ReplayTraceStepType::TstepRetire {
                        t.on_syscall_exit(
                            current_step.syscall().number,
                            current_step.syscall().arch,
                            trace_frame.regs_ref(),
                        );
                    }
                }
            }
            EventType::EvUnassigned
            | EventType::EvSentinel
            | EventType::EvNoop
            | EventType::EvDesched
            | EventType::EvSeccompTrap
            | EventType::EvSyscallInterruption
            | EventType::EvTraceTermination => {
                fatal!("Unexpected event {}", ev);
            }
        }

        self.current_step.set(current_step);
        drop(dyn_t);
        t_shr_ptr
    }

    /// Restore the recorded syscallbuf data to the tracee, preparing the
    /// tracee for replaying the records.
    ///
    /// DIFF NOTE: Extra param compared to rr
    fn prepare_syscallbuf_records(&self, t: &mut ReplayTask, current_step: &mut ReplayTraceStep) {
        // Read the recorded syscall buffer back into the buffer region.
        let buf = t.trace_reader_mut().read_raw_data();
        ed_assert!(t, buf.data.len() >= size_of::<syscallbuf_hdr>());
        ed_assert!(t, buf.data.len() <= t.syscallbuf_size);
        ed_assert_eq!(t, buf.addr, RemotePtr::cast(t.syscallbuf_child));

        let mut recorded_hdr: syscallbuf_hdr = Default::default();
        unsafe {
            copy_nonoverlapping(
                buf.data.as_ptr(),
                &raw mut recorded_hdr as *mut u8,
                size_of::<syscallbuf_hdr>(),
            );
        }
        // Don't overwrite syscallbuf_hdr. That needs to keep tracking the current
        // syscallbuf state.
        t.write_bytes_helper(
            RemotePtr::cast(t.syscallbuf_child + 1usize),
            &buf.data[size_of::<syscallbuf_hdr>()..],
            None,
            WriteFlags::empty(),
        );

        let num_rec_bytes = recorded_hdr.num_rec_bytes;
        ed_assert!(
            t,
            num_rec_bytes as usize + size_of::<syscallbuf_hdr>() <= t.syscallbuf_size
        );

        current_step.action = ReplayTraceStepType::TstepFlushSyscallbuf;
        let stop_breakpoint_addr = t.stopping_breakpoint_table.to_data_ptr::<Void>().as_usize()
            + (num_rec_bytes as usize / 8) * t.stopping_breakpoint_table_entry_size;
        current_step.data = ReplayTraceStepData::Flush(ReplayFlushBufferedSyscallState {
            stop_breakpoint_addr,
        });

        log!(
            LogDebug,
            "Prepared {} bytes of syscall records",
            num_rec_bytes
        );
    }

    fn revive_task_for_exec(&self, ev: &Event, trace_frame_tid: pid_t) -> TaskSharedPtr {
        if !ev.is_syscall_event()
            || !is_execve_syscall(ev.syscall_event().number, ev.syscall_event().arch())
        {
            fatal!("Can't find task, but we're not in an execve");
        }

        let mut maybe_tg: Option<ThreadGroupSharedPtr> = None;
        for (&tgid, weak_ptr) in self.thread_group_map.borrow().iter() {
            if tgid.tid() == trace_frame_tid {
                maybe_tg = Some(weak_ptr.upgrade().unwrap());
                break;
            }
        }
        if maybe_tg.is_none() {
            fatal!("Dead task tid should be task-group leader, but we can't find it");
        }

        let tg = maybe_tg.unwrap();
        if tg.borrow().task_set().len() != 1 {
            fatal!("Should only be one task left in the taskgroup");
        }

        let t_rc = tg.borrow().task_set().iter().next().unwrap();
        let t_rec_tid = t_rc.borrow().rec_tid;
        log!(
            LogDebug,
            "Changing task tid from {} to {}",
            t_rec_tid,
            trace_frame_tid,
        );
        let t_rc_removed = self.task_map.borrow_mut().remove(&t_rec_tid).unwrap();
        debug_assert!(Rc::ptr_eq(&t_rc_removed, &t_rc));
        t_rc.borrow_mut().rec_tid = trace_frame_tid;
        self.task_map.borrow_mut().insert(trace_frame_tid, t_rc);
        // The real tid is not changing yet. It will, in process_execve.
        t_rc_removed
    }

    pub fn replay_step(&self, command: RunCommand) -> ReplayResult {
        self.replay_step_with_constraints(&StepConstraints::new(command))
    }

    fn emulate_signal_delivery(&self, t: &mut ReplayTask, sig: Sig) -> Completion {
        let maybe_t = self.current_task();
        match maybe_t {
            None => {
                // Trace terminated abnormally.  We'll pop out to code
                // that knows what to do.
                Completion::Incomplete
            }
            Some(newtask) => {
                ed_assert!(
                    t,
                    t.weak_self_ptr().ptr_eq(&Rc::downgrade(&newtask)),
                    "emulate_signal_delivery changed task"
                );

                {
                    let trace_frame = self.current_trace_frame();
                    let ev = trace_frame.event();
                    ed_assert!(
                        t,
                        ev.event_type() == EventType::EvSignalDelivery
                            || ev.event_type() == EventType::EvSignalHandler,
                        "Unexpected signal disposition"
                    );
                    // Entering a signal handler seems to clear FP/SSE registers for some
                    // reason. So we saved those cleared values, and now we restore that
                    // state so they're cleared during replay.
                    if ev.event_type() == EventType::EvSignalHandler {
                        t.set_extra_regs(trace_frame.extra_regs_ref());
                    }

                    // Restore the signal-hander frame data, if there was one.
                    let restored_sighandler_frame: bool = 0 < t.set_data_from_trace(None);
                    if restored_sighandler_frame {
                        log!(LogDebug, "-. restoring sighandler frame for {}", sig)
                    }
                    // Note that fatal signals are not actually injected into the task!
                    // This is very important; we must never actually inject fatal signals
                    // into a task. All replay task death must go through exit_task.
                    // If this signal had a user handler, and we just set up the
                    // callframe, and we need to restore the $sp for continued
                    // execution.
                    t.set_regs(trace_frame.regs_ref());
                }
                t.validate_regs(Default::default());
                Completion::Complete
            }
        }
    }

    /// Continue until reaching either the "entry" of an emulated syscall,
    /// or the entry or exit of an executed syscall.  `emu` is nonzero when
    /// we're emulating the syscall. Return Completion::Complete when the next syscall
    /// boundary is reached, or Completion::Incomplete if advancing to the boundary was
    /// interrupted by an unknown trap.
    /// When the syscall trace frame is non-null, we continue to the syscall by
    /// setting a breakpoint instead of running until we execute a system
    /// call instruction. In that case we will not actually enter the kernel.
    fn cont_syscall_boundary(
        &self,
        t: &mut ReplayTask,
        constraints: &StepConstraints,
    ) -> Completion {
        let mut ticks_request: TicksRequest = TicksRequest::ResumeUnlimitedTicks;
        if constraints.ticks_target <= self.trace_frame.borrow().ticks() {
            if !compute_ticks_request(t, constraints, &mut ticks_request) {
                return Completion::Incomplete;
            }
        }

        if constraints.command == RunCommand::RunSinglestepFastForward {
            // ignore ticks_period. We can't add more than one tick during a
            // fast_forward so it doesn't matter.
            self.fast_forward_status.set(
                self.fast_forward_status.get()
                    | fast_forward_through_instruction(
                        t,
                        ResumeRequest::ResumeSysemuSinglestep,
                        &constraints.stop_before_states,
                    ),
            );
        } else {
            let resume_how = if constraints.is_singlestep() {
                ResumeRequest::ResumeSysemuSinglestep
            } else {
                ResumeRequest::ResumeSysemu
            };
            t.resume_execution(resume_how, WaitRequest::ResumeWait, ticks_request, None);
        }

        match t.maybe_stop_sig().get_raw_repr() {
            Some(perf_counters::TIME_SLICE_SIGNAL) => {
                // This would normally be triggered by constraints.ticks_target but it's
                // also possible to get stray signals here.
                return Completion::Incomplete;
            }
            Some(sig::SIGSEGV) => {
                if self.handle_unrecorded_cpuid_fault(t, constraints) {
                    return Completion::Incomplete;
                }
            }
            Some(sig::SIGTRAP) => {
                return Completion::Incomplete;
            }
            _ => (),
        }
        if t.maybe_stop_sig().is_sig() {
            ed_assert!(
                t,
                false,
                "Replay got unrecorded signal {:?}",
                t.get_siginfo()
            );
        }
        if t.seccomp_bpf_enabled
            && self.syscall_seccomp_ordering_.get()
                == PtraceSyscallSeccompOrdering::SyscallBeforeSeccompUnknown
        {
            ed_assert!(t, !constraints.is_singlestep());
            if t.maybe_ptrace_event() == PTRACE_EVENT_SECCOMP {
                self.syscall_seccomp_ordering_
                    .set(PtraceSyscallSeccompOrdering::SeccompBeforeSyscall);
            } else {
                self.syscall_seccomp_ordering_
                    .set(PtraceSyscallSeccompOrdering::SyscallBeforeSeccomp);
            }
            // Eat the following event, either a seccomp or syscall notification
            t.resume_execution(
                ResumeRequest::ResumeSysemu,
                WaitRequest::ResumeWait,
                ticks_request,
                None,
            );
        }

        let maybe_syscall_type = AddressSpace::rd_page_syscall_from_exit_point(t.ip());
        match maybe_syscall_type {
            Some(syscall_type)
                if syscall_type.traced == Traced::Untraced
                    && syscall_type.enabled == Enabled::ReplayOnly =>
            {
                // Actually perform it. We can hit these when replaying through syscallbuf
                // code that was interrupted.
                perform_interrupted_syscall(t);
                Completion::Incomplete
            }
            _ => Completion::Complete,
        }
    }

    /// Advance to the next syscall entry (or virtual entry) according to constraints
    /// Return `Complete` if successful, or `Incomplete` if an unhandled trap occurred.
    fn enter_syscall(&self, t: &mut ReplayTask, constraints: &StepConstraints) -> Completion {
        if t.regs_ref().matches(self.current_trace_frame().regs_ref())
            && t.tick_count() == self.current_trace_frame().ticks()
        {
            // We already entered the syscall via an ENTERING_SYSCALL_PTRACE
            ed_assert!(
                t,
                self.current_trace_frame().event().syscall_event().state
                    == SyscallState::EnteringSyscall
            );
        } else {
            let mut syscall_instruction = RemoteCodePtr::null();

            if self.done_initial_exec() {
                syscall_instruction = self
                    .current_trace_frame()
                    .regs_ref()
                    .ip()
                    .decrement_by_syscall_insn_length(t.arch());
                // If the breakpoint already exists, it must have been from a previous
                // invocation of this function for the same event (once the event
                // completes, the breakpoint is cleared).
                debug_assert!(
                    self.syscall_bp_vm.borrow().is_none()
                        || Rc::ptr_eq(
                            self.syscall_bp_vm.borrow().as_ref().unwrap(),
                            t.as_.as_ref().unwrap()
                        ) && syscall_instruction == self.syscall_bp_addr.get()
                            && t.vm().get_breakpoint_type_at_addr(syscall_instruction)
                                != BreakpointType::BkptNone
                );

                // Skip this optimization if we can't set the breakpoint, or if it's
                // in writeable or shared memory, since in those cases it could be
                // overwritten by the tracee. It could even be dynamically generated and
                // not generated yet.
                if self.syscall_bp_vm.borrow().is_none()
                    && t.vm_shr_ptr()
                        .is_breakpoint_in_private_read_only_memory(syscall_instruction, t)
                    && t.vm_shr_ptr().add_breakpoint(
                        t,
                        syscall_instruction,
                        BreakpointType::BkptInternal,
                    )
                {
                    *self.syscall_bp_vm.borrow_mut() = Some(t.as_.as_ref().unwrap().clone());
                    self.syscall_bp_addr.set(syscall_instruction);
                }
            }
            if self.cont_syscall_boundary(t, constraints) == Completion::Incomplete {
                let reached_target: bool = self.syscall_bp_vm.borrow().is_some()
                    && t.maybe_stop_sig() == SIGTRAP
                    && t.ip().decrement_by_bkpt_insn_length(t.arch()) == syscall_instruction
                    && t.vm().get_breakpoint_type_at_addr(syscall_instruction)
                        == BreakpointType::BkptInternal;
                if reached_target {
                    // Emulate syscall state change
                    let mut r: Registers = t.regs_ref().clone();
                    r.set_ip(syscall_instruction.increment_by_syscall_insn_length(t.arch()));
                    r.set_original_syscallno(r.syscallno());
                    r.set_syscall_result_signed(-ENOSYS as isize);
                    t.set_regs(&r);
                    t.canonicalize_regs(self.current_trace_frame().event().syscall_event().arch());
                    t.validate_regs(Default::default());
                    self.clear_syscall_bp(t);
                } else {
                    return Completion::Incomplete;
                }
            } else {
                // If we use the breakpoint optimization, we must get a SIGTRAP before
                // reaching a syscall, so cont_syscall_boundary must return Completion::Incomplete.
                ed_assert!(t, self.syscall_bp_vm.borrow().is_none());
                t.canonicalize_regs(self.current_trace_frame().event().syscall_event().arch());
                t.validate_regs(Default::default());
                t.finish_emulated_syscall();
            }
        }

        if self.current_trace_frame().event().syscall_event().state == SyscallState::EnteringSyscall
        {
            rep_after_enter_syscall(t);
        }

        Completion::Complete
    }

    fn exit_syscall(&self, t: &mut ReplayTask) -> Completion {
        let arch = self.current_step.get().syscall().arch;
        let sys = self.current_step.get().syscall().number;
        t.on_syscall_exit(sys, arch, self.current_trace_frame().regs_ref());

        t.apply_all_data_records_from_trace();
        t.set_return_value_from_trace();

        let mut flags = ReplayTaskIgnore::IgnoreNone;
        if t.arch() == SupportedArch::X86
            && (<X86Arch as Architecture>::PWRITE64 == sys
                || <X86Arch as Architecture>::PREAD64 == sys)
        {
            flags = ReplayTaskIgnore::IgnoreEsi;
        }
        t.validate_regs(flags);

        Completion::Complete
    }

    fn exit_task(&self, t: &mut ReplayTask) -> Completion {
        ed_assert!(t, !t.seen_ptrace_exit_event);
        // Apply robust-futex updates captured during recording.
        t.apply_all_data_records_from_trace();
        end_task(t);
        // `t` is dead now.
        Completion::Complete
    }

    fn handle_unrecorded_cpuid_fault(
        &self,
        t: &mut ReplayTask,
        constraints: &StepConstraints,
    ) -> bool {
        if t.maybe_stop_sig() != SIGSEGV
            || !SessionInner::has_cpuid_faulting()
            || self.trace_in.borrow().uses_cpuid_faulting()
            || trapped_instruction_at(t, t.ip()) != TrappedInstruction::CpuId
        {
            return false;
        }
        // OK, this is a case where we did not record using CPUID faulting but we are
        // replaying with CPUID faulting and the tracee just executed a CPUID.
        // We try to find the results in the "all CPUID leaves" we saved.
        let trace_in_b = self.trace_in.borrow();
        let records = trace_in_b.cpuid_records();
        let mut r = t.regs_ref().clone();
        let maybe_rec = find_cpuid_record(records, r.ax() as u32, r.cx() as u32);
        ed_assert!(
            t,
            maybe_rec.is_some(),
            "Can't find CPUID record for request AX={:#x} CX={:#x}",
            r.ax(),
            r.cx()
        );
        let rec = maybe_rec.unwrap();
        r.set_cpuid_output(rec.out.eax, rec.out.ebx, rec.out.ecx, rec.out.edx);
        // Don't need the trace_in borrow anymore
        drop(trace_in_b);

        r.set_ip(r.ip() + trapped_instruction_len(TrappedInstruction::CpuId));
        t.set_regs(&r);
        // Clear SIGSEGV status since we're handling it
        t.set_status(if constraints.is_singlestep() {
            WaitStatus::for_stop_sig(sig::SIGTRAP)
        } else {
            WaitStatus::default()
        });
        true
    }

    fn check_ticks_consistency(&self, t: &ReplayTask, ev: &Event) {
        if !self.done_initial_exec() {
            return;
        }

        let ticks_now = t.tick_count();
        let trace_ticks = self.current_trace_frame().ticks();

        ed_assert!(
            t,
            ticks_now == trace_ticks,
            "ticks mismatch for '{}'; expected {}, got {}",
            ev,
            trace_ticks,
            ticks_now
        );
    }

    fn check_pending_sig(&self, t: &mut ReplayTask) {
        if t.maybe_stop_sig().is_not_sig() {
            let syscall_arch = t.detect_syscall_arch();
            ed_assert!(
                t,
                false,
                "Replaying `{}': expecting tracee signal or trap, but instead at `{}' (ticks:{})",
                self.current_trace_frame().event(),
                syscall_name(t.regs_ref().original_syscallno() as i32, syscall_arch),
                t.tick_count()
            )
        }
    }

    /// Advance `t` to the next signal or trap according to `constraints.command`.
    ///
    /// Default `resume_how` is ResumeSysemu for error checking:
    /// since the next event is supposed to be a signal, entering a syscall here
    /// means divergence.  There shouldn't be any straight-line execution overhead
    /// for SYSEMU vs. CONT, so the difference in cost should be negligible.
    ///
    /// Some callers pass ResumeCont because they want to execute any syscalls
    /// encountered.
    ///
    /// If we return Incomplete, callers need to recalculate the constraints and
    /// tick_request and try again. We may return Incomplete because we successfully
    /// processed a CPUID trap.
    fn continue_or_step(
        &self,
        t: &mut ReplayTask,
        constraints: &StepConstraints,
        tick_request: TicksRequest,
        maybe_resume_how: Option<ResumeRequest>,
    ) -> Completion {
        let resume_how = maybe_resume_how.unwrap_or(ResumeRequest::ResumeSysemu);

        if constraints.command == RunCommand::RunSinglestep {
            t.resume_execution(
                ResumeRequest::ResumeSinglestep,
                WaitRequest::ResumeWait,
                tick_request,
                None,
            );
            self.handle_unrecorded_cpuid_fault(t, constraints);
        } else if constraints.command == RunCommand::RunSinglestepFastForward {
            self.fast_forward_status.set(
                self.fast_forward_status.get()
                    | fast_forward_through_instruction(
                        t,
                        ResumeRequest::ResumeSinglestep,
                        &constraints.stop_before_states,
                    ),
            );
            self.handle_unrecorded_cpuid_fault(t, constraints);
        } else {
            t.resume_execution(resume_how, WaitRequest::ResumeWait, tick_request, None);
            if t.maybe_stop_sig().is_not_sig() {
                let maybe_type = AddressSpace::rd_page_syscall_from_exit_point(t.ip());
                match maybe_type {
                    Some(type_) if type_.traced == Traced::Untraced => {
                        // If we recorded an rd replay of an application doing a
                        // syscall-buffered 'mprotect', the replay's `flush_syscallbuf`
                        // PTRACE_CONT'ed to execute the mprotect syscall and nothing was
                        // recorded for that until we hit the replay's breakpoint, when we
                        // record a SIGTRAP. However, when we replay that SIGTRAP via
                        // `emulate_deterministic_signal`, we call `continue_or_step`
                        // with `ResumeRequest::ResumeSysemu` (to detect bugs when we reach a stray
                        // syscall instead of the SIGTRAP). So, we'll stop for the
                        // `mprotect` syscall here. We need to execute it and continue
                        // as if it wasn't hit.
                        // (Alternatively we could just replay with ResumeRequest::ResumeCont, but that
                        // would make it harder to track down bugs. There is a performance hit
                        // to stopping for each mprotect, but replaying recordings of replays
                        // is not fast anyway.)
                        perform_interrupted_syscall(t);
                        return Completion::Incomplete;
                    }
                    _ => (),
                }
            } else if self.handle_unrecorded_cpuid_fault(t, constraints) {
                return Completion::Incomplete;
            }
        }
        self.check_pending_sig(t);
        Completion::Complete
    }

    fn advance_to_ticks_target(
        &self,
        _t: &ReplayTask,
        _constraints: &StepConstraints,
    ) -> Completion {
        unimplemented!();
    }

    fn emulate_deterministic_signal(
        &self,
        t: &mut ReplayTask,
        sig: Sig,
        constraints: &StepConstraints,
    ) -> Completion {
        loop {
            if t.regs_ref().matches(self.current_trace_frame().regs_ref())
                && t.tick_count() == self.current_trace_frame().ticks()
            {
                // We're already at the target. This can happen when multiple signals
                // are delivered with no intervening execution.
                return Completion::Complete;
            }

            let complete = self.continue_or_step(
                t,
                constraints,
                TicksRequest::ResumeUnlimitedTicks,
                Some(ResumeRequest::ResumeSysemu),
            );

            if complete == Completion::Complete
                && !ReplaySession::is_ignored_signal(t.maybe_stop_sig().get_raw_repr())
            {
                break;
            }
        }
        if t.maybe_stop_sig() == SIGTRAP {
            let trap_reasons: TrapReasons = t.compute_trap_reasons();
            if trap_reasons.singlestep || trap_reasons.watchpoint {
                // Singlestep or watchpoint must have been debugger-requested
                return Completion::Incomplete;
            }
            if trap_reasons.breakpoint {
                // An explicit breakpoint instruction in the tracee would produce a
                // |breakpoint| reason as we emulate the deterministic SIGTRAP.
                let type_: BreakpointType = t.vm().get_breakpoint_type_for_retired_insn(t.ip());
                if BreakpointType::BkptNone != type_ {
                    ed_assert_eq!(t, BreakpointType::BkptUser, type_);
                    return Completion::Incomplete;
                }
            }
        }
        ed_assert!(
            t,
            t.maybe_stop_sig() == sig,
            "Replay got unrecorded signal {} (expecting {})",
            t.maybe_stop_sig(),
            sig
        );

        {
            let ctf_b = self.current_trace_frame();
            let ev = ctf_b.event();
            self.check_ticks_consistency(t, ev);

            if EventType::EvInstructionTrap == ev.event_type() {
                t.set_regs(self.current_trace_frame().regs_ref());
            }
        }

        Completion::Complete
    }

    fn emulate_async_signal(
        &self,
        t: &mut ReplayTask,
        constraints: &StepConstraints,
        ticks: Ticks,
    ) -> Completion {
        let regs = self.trace_frame.borrow().regs_ref().clone();
        let ip: RemoteCodePtr = regs.ip();
        let mut did_set_internal_breakpoint: bool = false;

        // Step 1: advance to the target ticks (minus a slack region) as
        // quickly as possible by programming the hpc.
        let mut ticks_left: i64 = ticks as i64 - t.tick_count() as i64;

        log!(
            LogDebug,
            "advancing {} ticks to reach {}/{}",
            ticks_left,
            ticks,
            ip
        );

        // XXX should we only do this if ticks > 10000?
        while ticks_left > 2 * PerfCounters::skid_size() as i64 {
            log!(
                LogDebug,
                "  programming interrupt for {} ticks",
                ticks_left - PerfCounters::skid_size() as i64
            );

            // Avoid overflow. If ticks_left > MAX_TICKS_REQUEST, execution will stop
            // early but we'll treat that just like a stray TIME_SLICE_SIGNAL and
            // continue as needed.
            self.continue_or_step(
                t,
                constraints,
                TicksRequest::ResumeWithTicksRequest(
                    min(MAX_TICKS_REQUEST, ticks_left as u64) - PerfCounters::skid_size(),
                ),
                None,
            );
            guard_unexpected_signal(t);

            // Update ticks_left
            ticks_left = ticks as i64 - t.tick_count() as i64;

            if t.maybe_stop_sig() == SIGTRAP {
                // We proved we're not at the execution
                // target, and we haven't set any internal
                // breakpoints, and we're not temporarily
                // internally single-stepping, so we must have
                // hit a debugger breakpoint or the debugger
                // was single-stepping the tracee.  (The
                // debugging code will verify that.)
                return Completion::Incomplete;
            }
        }
        guard_overshoot(t, &regs, ticks, ticks_left, None);

        // True when our advancing has triggered a tracee SIGTRAP that needs to
        // be dealt with.
        #[allow(non_snake_case)]
        let mut pending_SIGTRAP: bool = false;
        #[allow(non_snake_case)]
        let mut SIGTRAP_run_command: RunCommand = RunCommand::RunContinue;

        // Step 2: more slowly, find our way to the target ticks and
        // execution point.  We set an internal breakpoint on the
        // target $ip and then resume execution.  When that *internal*
        // breakpoint is hit (i.e., not one incidentally also set on
        // that $ip by the debugger), we check again if we're at the
        // target ticks and execution point.  If not, we temporarily
        // remove the breakpoint, single-step over the insn, and
        // repeat.
        //
        // What we really want to do is set a (precise)
        // retired-instruction interrupt and do away with all this
        // cruft.
        let mut mismatched_regs: Option<Registers> = None;
        loop {
            // Invariants here are
            //  o ticks_left is up-to-date
            //  o ticks_left >= 0
            //
            // Possible state of the execution of `t`
            //  0. at a debugger trap (breakpoint, watchpoint, stepi)
            //  1. at an internal breakpoint
            //  2. at the execution target
            //  3. not at the execution target, but incidentally
            //     at the target $ip
            //  4. otherwise not at the execution target
            //
            // Determining whether we're at a debugger trap is
            // surprisingly complicated.
            let at_target: bool =
                is_same_execution_point(t, &regs, ticks_left, &mut mismatched_regs);
            if pending_SIGTRAP {
                let trap_reasons: TrapReasons = t.compute_trap_reasons();
                let breakpoint_type: BreakpointType =
                    t.vm().get_breakpoint_type_for_retired_insn(t.ip());

                if constraints.is_singlestep() {
                    ed_assert!(t, trap_reasons.singlestep);
                }
                if constraints.is_singlestep()
                    || (trap_reasons.watchpoint && t.vm().has_any_watchpoint_changes())
                    || (trap_reasons.breakpoint && BreakpointType::BkptUser == breakpoint_type)
                {
                    // Case (0) above: interrupt for the debugger.
                    log!(LogDebug, "    trap was debugger singlestep/breakpoint");
                    if did_set_internal_breakpoint {
                        t.vm_shr_ptr()
                            .remove_breakpoint(ip, BreakpointType::BkptInternal, t);
                    }
                    return Completion::Incomplete;
                }

                if trap_reasons.breakpoint {
                    // We didn't hit a user breakpoint, and executing an explicit
                    // breakpoint instruction in the tracee would have triggered a
                    // deterministic signal instead of an async one.
                    // So we must have hit our internal breakpoint.
                    ed_assert!(t, did_set_internal_breakpoint);
                    ed_assert!(
                        t,
                        regs.ip().increment_by_bkpt_insn_length(t.arch()) == t.ip()
                    );
                    // We didn't do an internal singlestep, and if we'd done a
                    // user-requested singlestep we would have hit the above case.
                    ed_assert!(t, !trap_reasons.singlestep);
                    // Case (1) above: cover the tracks of
                    // our internal breakpoint, and go
                    // check again if we're at the
                    // target.
                    log!(LogDebug, "    trap was for target $ip");
                    // (The breakpoint would have trapped
                    // at the $ip one byte beyond the
                    // target.)
                    debug_assert!(!at_target);

                    pending_SIGTRAP = false;
                    t.move_ip_before_breakpoint();
                    // We just backed up the $ip, but
                    // rewound it over an `int $3`
                    // instruction, which couldn't have
                    // retired a branch.  So we don't need
                    // to adjust `tick_count()`.
                    continue;
                }

                // Otherwise, either we did an internal singlestep or a hardware
                // watchpoint fired but values didn't change. */
                if trap_reasons.singlestep {
                    ed_assert!(t, is_singlestep(SIGTRAP_run_command));
                    log!(LogDebug, "    (SIGTRAP; stepi'd target $ip)");
                } else {
                    ed_assert!(t, trap_reasons.watchpoint);
                    log!(
                        LogDebug,
                        "    (SIGTRAP; HW watchpoint fired without changes)"
                    );
                }
            }

            // We had to keep the internal breakpoint set (if it
            // was when we entered the loop) for the checks above.
            // But now we're either done (at the target) or about
            // to resume execution in one of a variety of ways,
            // and it's simpler to start out knowing that the
            // breakpoint isn't set.
            if did_set_internal_breakpoint {
                t.vm_shr_ptr()
                    .remove_breakpoint(ip, BreakpointType::BkptInternal, t);
                did_set_internal_breakpoint = false;
            }

            if at_target {
                // Case (2) above: done.
                return Completion::Complete;
            }

            // At this point, we've proven that we're not at the
            // target execution point, and we've ensured the
            // internal breakpoint is unset.
            if USE_BREAKPOINT_TARGET && regs.ip() != t.regs_ref().ip() {
                // Case (4) above: set a breakpoint on the
                // target $ip and PTRACE_CONT in an attempt to
                // execute as many non-trapped insns as we
                // can.  (Unless the debugger is stepping, of
                // course.)  Trapping and checking
                // are-we-at-target is slow.  It bears
                // repeating that the ideal implementation
                // would be programming a precise counter
                // interrupt (insns-retired best of all), but
                // we're forced to be conservative by observed
                // imprecise counters.  This should still be
                // no slower than single-stepping our way to
                // the target execution point.
                log!(LogDebug, "    breaking on target $ip");
                t.vm_shr_ptr()
                    .add_breakpoint(t, ip, BreakpointType::BkptInternal);
                did_set_internal_breakpoint = true;
                self.continue_or_step(t, constraints, TicksRequest::ResumeUnlimitedTicks, None);
                SIGTRAP_run_command = constraints.command;
            } else {
                // Case (3) above: we can't put a breakpoint
                // on the $ip, because resuming execution
                // would just trap and we'd be back where we
                // started.  Single-step or fast-forward past it.
                log!(LogDebug, "    (fast-forwarding over target $ip)");
                // Just do whatever the user asked for if the user requested
                // singlestepping
                // or there is user breakpoint at the run address. The latter is safe
                // because the breakpoint will be triggered immediately. This gives us the
                // invariant that an internal singlestep never triggers a user breakpoint.
                if constraints.command == RunCommand::RunSinglestep
                    || t.vm().get_breakpoint_type_at_addr(t.regs_ref().ip())
                        == BreakpointType::BkptUser
                {
                    self.continue_or_step(t, constraints, TicksRequest::ResumeUnlimitedTicks, None);
                    SIGTRAP_run_command = constraints.command;
                } else {
                    // @TODO Avoid the performance hit by explicitly copying all the registers??
                    let mut states = constraints.stop_before_states.clone();
                    // This state may not be relevant if we don't have the correct tick
                    // count yet. But it doesn't hurt to push it on anyway.
                    states.push(regs.clone());
                    self.fast_forward_status.set(
                        self.fast_forward_status.get()
                            | fast_forward_through_instruction(
                                t,
                                ResumeRequest::ResumeSinglestep,
                                &states,
                            ),
                    );
                    SIGTRAP_run_command = RunCommand::RunSinglestepFastForward;
                    self.check_pending_sig(t);
                }
            }
            pending_SIGTRAP = t.maybe_stop_sig() == SIGTRAP;

            // Maintain the "'ticks_left'-is-up-to-date"
            // invariant.
            ticks_left = ticks as i64 - t.tick_count() as i64;

            // Sometimes (e.g. in the ptrace_signal_32 test), we're in almost
            // the correct state when we enter |advance_to|, except that exotic
            // registers (i.e. segment registers) need to be normalized by the kernel
            // by continuing and hitting a deterministic signal without actually
            // advancing execution. So we allow |advance_to| to proceed and actually
            // reach the desired state.
            if !is_same_execution_point(t, &regs, ticks_left, &mut mismatched_regs) {
                guard_unexpected_signal(t);
            }

            guard_overshoot(t, &regs, ticks, ticks_left, mismatched_regs.as_ref());
        }
    }

    fn flush_syscallbuf(&self, t: &mut ReplayTask, constraints: &StepConstraints) -> Completion {
        let mut user_breakpoint_at_addr: bool;

        loop {
            let mut next_rec = t.next_syscallbuf_record();
            let child_addr: RemotePtr<u8> = RemotePtr::cast(t.syscallbuf_child)
                + offset_of!(syscallbuf_hdr, mprotect_record_count_completed);
            let skip_mprotect_records = read_val_mem::<u32>(t, RemotePtr::cast(child_addr), None);

            let mut ticks_request = TicksRequest::default();
            if !compute_ticks_request(t, constraints, &mut ticks_request) {
                return Completion::Incomplete;
            }

            let added: bool = t.vm_shr_ptr().add_breakpoint(
                t,
                RemoteCodePtr::from(self.current_step.get().flush().stop_breakpoint_addr),
                BreakpointType::BkptInternal,
            );
            ed_assert!(t, added);
            let complete = self.continue_or_step(
                t,
                constraints,
                ticks_request,
                Some(ResumeRequest::ResumeCont),
            );
            user_breakpoint_at_addr = t.vm().get_breakpoint_type_at_addr(RemoteCodePtr::from(
                self.current_step.get().flush().stop_breakpoint_addr,
            )) != BreakpointType::BkptInternal;

            t.vm_shr_ptr().remove_breakpoint(
                RemoteCodePtr::from(self.current_step.get().flush().stop_breakpoint_addr),
                BreakpointType::BkptInternal,
                t,
            );

            // Account for buffered syscalls just completed
            let end_rec = t.next_syscallbuf_record();
            while next_rec != end_rec {
                self.accumulate_syscall_performed();
                next_rec = RemotePtr::cast(
                    RemotePtr::<u8>::cast(next_rec) + t.stored_record_size(next_rec),
                );
            }

            // Apply the mprotect records we just completed.
            apply_mprotect_records(t, skip_mprotect_records);

            if t.maybe_stop_sig() == perf_counters::TIME_SLICE_SIGNAL {
                // This would normally be triggered by constraints.ticks_target but it's
                // also possible to get stray signals here.
                return Completion::Incomplete;
            }

            if complete == Completion::Complete
                && !Self::is_ignored_signal(t.maybe_stop_sig().get_raw_repr())
            {
                break;
            }
        }

        ed_assert!(
            t,
            t.maybe_stop_sig() == SIGTRAP,
            "Replay got unexpected signal (or none) {}",
            t.maybe_stop_sig()
        );

        if t.ip().decrement_by_bkpt_insn_length(t.arch())
            == RemoteCodePtr::from(self.current_step.get().flush().stop_breakpoint_addr)
            && !user_breakpoint_at_addr
        {
            let mut r: Registers = t.regs_ref().clone();
            r.set_ip(RemoteCodePtr::from(
                self.current_step.get().flush().stop_breakpoint_addr,
            ));
            t.set_regs(&r);

            Completion::Complete
        } else {
            Completion::Incomplete
        }
    }

    fn patch_next_syscall(&self, t: &mut ReplayTask, constraints: &StepConstraints) -> Completion {
        if self.cont_syscall_boundary(t, constraints) == Completion::Incomplete {
            return Completion::Incomplete;
        }

        let arch = t.arch();
        t.canonicalize_regs(arch);
        t.exit_syscall_and_prepare_restart();

        // All patching effects have been recorded to the trace.
        // First, replay any memory mapping done by Monkeypatcher. There should be
        // at most one but we might as well be general.
        loop {
            let mut data = MappedData::default();
            let maybe_km =
                t.trace_reader_mut()
                    .read_mapped_region(Some(&mut data), None, None, None, None);

            match maybe_km {
                None => {
                    break;
                }
                Some(km) => {
                    let mut remote = AutoRemoteSyscalls::new(t);
                    ed_assert!(remote.task(), km.flags().contains(MapFlags::MAP_ANONYMOUS));
                    remote.infallible_mmap_syscall(
                        Some(km.start()),
                        km.size(),
                        km.prot(),
                        km.flags() | MapFlags::MAP_FIXED,
                        -1,
                        0,
                    );
                    remote.task().vm_shr_ptr().map(
                        remote.task_mut(),
                        km.start(),
                        km.size(),
                        km.prot(),
                        km.flags(),
                        0,
                        OsStr::new(""),
                        KernelMapping::NO_DEVICE,
                        KernelMapping::NO_INODE,
                        None,
                        Some(&km),
                        None,
                        None,
                        None,
                    );
                    *remote.task().vm().mapping_flags_of_mut(km.start()) |=
                        MappingFlags::IS_PATCH_STUBS;
                }
            }
        }

        // Now replay all data records.
        t.apply_all_data_records_from_trace();
        Completion::Complete
    }

    /// Try to execute step, adjusting for `constraints` if needed.  Return `Complete` if
    /// step was made, or `Incomplete` if there was a trap or step needs
    /// more work.
    fn try_one_trace_step(&self, t: &mut ReplayTask, constraints: &StepConstraints) -> Completion {
        if constraints.ticks_target > 0
            && !self.trace_frame.borrow().event().has_ticks_slop()
            && t.current_trace_frame().ticks() > constraints.ticks_target
        {
            // Instead of doing this step, just advance to the ticks_target, since
            // that happens before this event completes.
            // Unfortunately we can't do this for TSTEP_FLUSH_SYSCALLBUF
            // because its tick count can't be trusted.
            // cont_syscall_boundary handles the ticks constraint for those cases.
            return self.advance_to_ticks_target(t, &constraints);
        }

        match self.current_step.get().action {
            ReplayTraceStepType::TstepRetire => Completion::Complete,
            ReplayTraceStepType::TstepEnterSyscall => self.enter_syscall(t, &constraints),
            ReplayTraceStepType::TstepExitSyscall => self.exit_syscall(t),
            ReplayTraceStepType::TstepDeterministicSignal => self.emulate_deterministic_signal(
                t,
                self.current_step.get().target().signo.unwrap(),
                &constraints,
            ),
            ReplayTraceStepType::TstepProgramAsyncSignalInterrupt => {
                // @TODO Ok to have an unwrap here?
                self.emulate_async_signal(
                    t,
                    &constraints,
                    self.current_step.get().target().ticks.unwrap(),
                )
            }
            ReplayTraceStepType::TstepDeliverSignal => {
                self.emulate_signal_delivery(t, self.current_step.get().target().signo.unwrap())
            }
            ReplayTraceStepType::TstepFlushSyscallbuf => self.flush_syscallbuf(t, &constraints),
            ReplayTraceStepType::TstepPatchSyscall => self.patch_next_syscall(t, &constraints),
            ReplayTraceStepType::TstepExitTask => self.exit_task(t),
            _ => {
                fatal!("Unhandled step type: {:?}", self.current_step.get().action);
            }
        }
    }

    fn check_approaching_ticks_target(
        &self,
        t: &ReplayTask,
        constraints: &StepConstraints,
        break_status: &mut BreakStatus,
    ) {
        if constraints.ticks_target > 0 {
            let ticks_left = constraints.ticks_target - t.tick_count();
            if ticks_left <= PerfCounters::skid_size() {
                break_status.approaching_ticks_target = true;
            }
        }
    }

    // DIFF NOTE: Additional Param `active_task`
    fn clear_syscall_bp(&self, active_task: &mut dyn Task) {
        let mut maybe_bp_vm = self.syscall_bp_vm.borrow_mut();
        maybe_bp_vm.as_ref().map(|bp_vm| {
            bp_vm.remove_breakpoint(
                self.syscall_bp_addr.get(),
                BreakpointType::BkptInternal,
                active_task,
            )
        });
        *maybe_bp_vm = None;
        self.syscall_bp_addr.set(RemoteCodePtr::null());
    }
}

/// Returns mprotect record count
fn apply_mprotect_records(t: &mut ReplayTask, skip_mprotect_records: u32) -> u32 {
    let final_mprotect_record_count_addr = RemotePtr::<u32>::cast(
        RemotePtr::<u8>::cast(t.syscallbuf_child)
            + offset_of!(syscallbuf_hdr, mprotect_record_count),
    );

    let final_mprotect_record_count =
        read_val_mem::<u32>(t, final_mprotect_record_count_addr, None);

    if skip_mprotect_records < final_mprotect_record_count {
        let records_addr = RemotePtr::<mprotect_record>::cast(
            RemotePtr::<u8>::cast(t.preload_globals.unwrap())
                + offset_of!(preload_globals, mprotect_records),
        ) + skip_mprotect_records;

        let records: Vec<mprotect_record> = read_mem(
            t,
            records_addr,
            final_mprotect_record_count as usize - skip_mprotect_records as usize,
            None,
        );

        for (i, r) in records.iter().enumerate() {
            let completed_count_addr = RemotePtr::<u32>::cast(
                RemotePtr::<u8>::cast(t.syscallbuf_child)
                    + offset_of!(syscallbuf_hdr, mprotect_record_count_completed),
            );
            let completed_count: u32 = read_val_mem(t, completed_count_addr, None);
            if i >= completed_count as usize {
                let km = AddressSpace::read_kernel_mapping(t, RemotePtr::from(r.start));
                if km.prot() != ProtFlags::from_bits(r.prot).unwrap() {
                    // mprotect didn't happen yet.
                    continue;
                }
            }
            t.vm_shr_ptr().protect(
                t,
                RemotePtr::from(r.start),
                r.size as usize,
                ProtFlags::from_bits(r.prot).unwrap(),
            );
            if running_under_rd() {
                unsafe {
                    libc::syscall(
                        SYS_rdcall_mprotect_record as _,
                        t.tid,
                        r.start as usize,
                        r.size as usize,
                        r.prot,
                    );
                }
            }
        }
    }
    final_mprotect_record_count
}

/// Task death during replay always goes through here (except for
/// Session::kill_all_tasks when we forcibly kill all tasks in the session at
/// once). `exit` and `exit_group` syscalls are both emulated so the real
/// task doesn't die until we reach the EXIT/UNSTABLE_EXIT events in the trace.
/// This ensures the real tasks are alive and available as long as our Task
/// object exists, which simplifies code like Session cloning.
///
/// Killing tasks with fatal signals doesn't work because a fatal signal will
/// try to kill all the tasks in the thread group. Instead we inject an `exit`
/// syscall, which is apparently the only way to kill one specific thread.
fn end_task(t: &mut ReplayTask) {
    ed_assert_ne!(t, t.maybe_ptrace_event(), PTRACE_EVENT_EXIT);

    t.destroy_buffers();

    let mut r: Registers = t.regs_ref().clone();
    r.set_ip(t.vm().privileged_traced_syscall_ip().unwrap());
    r.set_syscallno(syscall_number_for_exit(t.arch()) as isize);
    t.set_regs(&r);
    // Enter the syscall.
    t.resume_execution(
        ResumeRequest::ResumeCont,
        WaitRequest::ResumeWait,
        TicksRequest::ResumeNoTicks,
        None,
    );
    ed_assert_eq!(t, t.maybe_ptrace_event(), PTRACE_EVENT_EXIT);

    t.stable_exit = true;
    t.destroy(None);
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
    /// Forwarded Method
    fn on_create_task(&self, t: TaskSharedPtr) {
        on_create_task_common(self, t);
    }

    /// Forwarded method
    fn kill_all_tasks(&self) {
        kill_all_tasks(self)
    }

    fn as_session_inner(&self) -> &SessionInner {
        &self.session_inner
    }

    fn as_session_inner_mut(&mut self) -> &mut SessionInner {
        &mut self.session_inner
    }

    fn as_replay(&self) -> Option<&ReplaySession> {
        Some(self)
    }

    fn new_task(
        &self,
        tid: pid_t,
        rec_tid: Option<pid_t>,
        serial: u32,
        a: SupportedArch,
    ) -> Box<dyn Task> {
        let t = ReplayTask::new(self, tid, rec_tid, serial, a);
        Box::new(t)
    }

    fn trace_stream(&self) -> Option<Ref<'_, TraceStream>> {
        let r = self.trace_in.borrow();
        Some(Ref::map(r, |t| t.deref()))
    }

    fn trace_stream_mut(&self) -> Option<RefMut<'_, TraceStream>> {
        let r = self.trace_in.borrow_mut();
        Some(RefMut::map(r, |t| t.deref_mut()))
    }

    fn cpu_binding(&self, trace: &TraceStream) -> Option<u32> {
        if self.flags_.cpu_unbound {
            return None;
        }
        trace.bound_to_cpu()
    }
}

fn tracee_xsave_enabled(trace_in: &TraceReader) -> bool {
    let maybe_record = find_cpuid_record(trace_in.cpuid_records(), CPUID_GETFEATURES, 0);
    maybe_record.unwrap().out.ecx & OSXSAVE_FEATURE_FLAG != 0
}

fn check_xsave_compatibility(trace_in: &TraceReader) {
    if !tracee_xsave_enabled(trace_in) {
        // Tracee couldn't use XSAVE so everything should be fine.
        // If it didn't detect absence of XSAVE and actually executed an XSAVE
        // and got a fault then replay will probably diverge :-(
        return;
    }
    if !xsave_enabled() {
        // Replaying on a super old CPU that doesn't even support XSAVE!
        if !ProgramFlags::get().suppress_environment_warnings {
            eprintln!(
                "rr: Tracees had XSAVE but XSAVE is not available\n\
                now; Replay will probably fail because glibc dynamic loader\n\
                            uses XSAVE\n\n"
            );
        }
        return;
    }

    let tracee_xcr0: u64 = trace_in.xcr0();
    let our_xcr0: u64 = xcr0();
    let maybe_record = find_cpuid_record(trace_in.cpuid_records(), CPUID_GETXSAVE, 1);
    let tracee_xsavec: bool = match maybe_record {
        Some(record) => record.out.eax & XSAVEC_FEATURE_FLAG != 0,
        None => false,
    };
    let data: CPUIDData = cpuid(CPUID_GETXSAVE, 1);
    let our_xsavec: bool = (data.eax & XSAVEC_FEATURE_FLAG) != 0;
    if tracee_xsavec && !our_xsavec && !ProgramFlags::get().suppress_environment_warnings {
        eprintln!(
            "rd: Tracees had XSAVEC but XSAVEC is not available\n\
            now; Replay will probably fail because glibc dynamic loader\n\
                         uses XSAVEC\n\n"
        );
    }

    if tracee_xcr0 != our_xcr0 {
        if !ProgramFlags::get().suppress_environment_warnings {
            // If the tracee used XSAVE instructions which write different components
            // to XSAVE instructions executed on our CPU, or examines XCR0 directly,
            // This will cause divergence. The dynamic linker examines XCR0 so this
            // is nearly guaranteed.
            eprintln!(
                "Trace XCR0 value {:#x} != our XCR0 value {:#x};\n\
                 Replay will probably fail because glibc dynamic loader examines XCR0\n\n",
                tracee_xcr0, our_xcr0
            );
        }
    }

    let check_alignment: bool = tracee_xsavec && our_xsavec;
    // Check that sizes and offsets of supported XSAVE areas area all identical.
    // An Intel employee promised this on a mailing list...
    // https://lists.xen.org/archives/html/xen-devel/2013-09/msg00484.html
    for feature in 2u32..=63 {
        if (tracee_xcr0 & our_xcr0 & (1u64 << feature as u64)) == 0 {
            continue;
        }
        let maybe_record = find_cpuid_record(trace_in.cpuid_records(), CPUID_GETXSAVE, feature);
        let data = cpuid(CPUID_GETXSAVE, feature);
        if maybe_record.is_none()
            || maybe_record.unwrap().out.eax != data.eax
            || maybe_record.unwrap().out.ebx != data.ebx
            || (check_alignment && (maybe_record.unwrap().out.ecx & 2u32) != (data.ecx & 2u32))
        {
            clean_fatal!(
                "XSAVE offset/size/alignment differs for feature {};\n\
                    H. Peter Anvin said this would never happen!",
                feature
            );
        }
    }
}

fn process_grow_map(t: &mut ReplayTask) {
    let mut data = MappedData::default();
    let km = t
        .trace_reader_mut()
        .read_mapped_region(Some(&mut data), None, None, None, None)
        .unwrap();
    ed_assert!(t, km.size() > 0);
    let mut remote = AutoRemoteSyscalls::new(t);
    restore_mapped_region(&mut remote, &km, &data);
}

fn treat_signal_event_as_deterministic(ev: &SignalEventData) -> bool {
    ev.deterministic == SignalDeterministic::DeterministicSig && ev.siginfo.si_signo != SIGBUS
}

fn perform_interrupted_syscall(t: &mut ReplayTask) {
    t.finish_emulated_syscall();
    let mut remote = AutoRemoteSyscalls::new(t);
    let r: Registers = remote.task().regs_ref().clone();
    let ret = remote.syscall(
        r.original_syscallno() as i32,
        &[r.arg1(), r.arg2(), r.arg3(), r.arg4(), r.arg5(), r.arg6()],
    );
    remote.initial_regs_mut().set_syscall_result_signed(ret);
}

/// Why a skid region?  Interrupts generated by perf counters don't
/// fire at exactly the programmed point (as of 2013 kernel/HW);
/// there's a variable slack region, which is technically unbounded.
/// This means that an interrupt programmed for retired branch k might
/// fire at `k + 50`, for example.  To counteract the slack, we program
/// interrupts just short of our target, by the `SKID_SIZE` region
/// below, and then more slowly advance to the real target.
///
/// How was this magic number determined?  Trial and error: we want it
/// to be as small as possible for efficiency, but not so small that
/// overshoots are observed.  If all other possible causes of overshoot
/// have been ruled out, like memory divergence, then you'll know that
/// this magic number needs to be increased if the following symptom is
/// observed during replay.  Running with DEBUGLOG enabled (see above),
/// a sequence of log messages like the following will appear
///
/// 1. programming interrupt for `target - SKID_SIZE` ticks
/// 2. Error: Replay diverged.  Dumping register comparison.
/// 3. Error: \[list of divergent registers; arbitrary\]
/// 4. Error: overshot target ticks=`target` by `i`
///
/// The key is that no other replayer log messages occur between (1)
/// and (2).  This spew means that the replayer programmed an interrupt
/// for ticks=`target-SKID_SIZE`, but the tracee was actually interrupted
/// at ticks=`target+i`.  And that in turn means that the kernel/HW
/// skidded too far past the programmed target for rd to handle it.
///
/// If that occurs, the SKID_SIZE needs to be increased by at least
/// `i`.
///
/// NB: there are probably deeper reasons for the target slack that
/// could perhaps let it be deduced instead of arrived at empirically;
/// perhaps pipeline depth and things of that nature are involved.  But
/// those reasons if they exit are currently not understood.
fn compute_ticks_request(
    t: &mut ReplayTask,
    constraints: &StepConstraints,
    ticks_request: &mut TicksRequest,
) -> bool {
    *ticks_request = TicksRequest::ResumeUnlimitedTicks;
    if constraints.ticks_target > 0 {
        let ticks_period = constraints.ticks_target as i64
            - PerfCounters::skid_size() as i64
            - t.tick_count() as i64;
        if ticks_period <= 0 {
            // Behave as if we actually executed something. Callers assume we did.
            t.clear_wait_status();
            return false;
        }
        if ticks_period > MAX_TICKS_REQUEST as i64 {
            // Avoid overflow. The execution will stop early but we'll treat that
            // just like a stray TIME_SLICE_SIGNAL and continue as needed.
            *ticks_request = TicksRequest::ResumeWithTicksRequest(MAX_TICKS_REQUEST);
        } else {
            *ticks_request = TicksRequest::ResumeWithTicksRequest(ticks_period as u64);
        }
    }
    true
}

fn is_fatal_default_action(sig: Sig) -> bool {
    let action: SignalAction = default_action(sig);
    action == SignalAction::DumpCore || action == SignalAction::Terminate
}

/// Return true if replaying `ev` by running `step` should result in
/// the target task having the same ticks value as it did during
/// recording.
fn has_deterministic_ticks(ev: &Event, step: ReplayTraceStep) -> bool {
    if ev.has_ticks_slop() {
        return false;
    }
    // We won't necessarily reach the same ticks when replaying an
    // async signal, due to debugger interrupts and other
    // implementation details.  This is checked in |advance_to()|
    // anyway.
    ReplayTraceStepType::TstepProgramAsyncSignalInterrupt != step.action
}

fn debug_memory(t: &mut ReplayTask) {
    let current_time = t.current_frame_time();
    if should_dump_memory(t.current_trace_frame().event(), current_time) {
        unimplemented!()
    }

    if t.session().done_initial_exec()
        && should_checksum(t.current_trace_frame().event(), current_time)
    {
        // Validate the checksum we computed during the
        // recording phase
        validate_process_memory(t, current_time);
    }
}

fn guard_unexpected_signal(t: &mut ReplayTask) {
    if ReplaySession::is_ignored_signal(t.maybe_stop_sig().get_raw_repr())
        || t.maybe_stop_sig() == SIGTRAP
    {
        return;
    }

    if t.maybe_stop_sig().is_sig() {
        ed_assert!(
            t,
            false,
            "Replay got unrecorded signal {} while awaiting signal",
            t.maybe_stop_sig()
        );
    } else if t.status().is_syscall() {
        ed_assert!(
            t,
            false,
            "Replay got unrecorded syscall {} while awaiting signal",
            syscall_name(
                t.regs_ref().original_syscallno().try_into().unwrap(),
                t.arch()
            )
        );
    }
}

fn is_same_execution_point(
    t: &mut ReplayTask,
    rec_regs: &Registers,
    ticks_left: i64,
    mismatched_regs: &mut Option<Registers>,
) -> bool {
    let behavior: MismatchBehavior = if is_logging!(LogDebug) {
        MismatchBehavior::LogMismatches
    } else {
        MismatchBehavior::ExpectMismatches
    };

    if ticks_left != 0 {
        log!(
            LogDebug,
            "  not same execution point: {} ticks left (@{})",
            ticks_left,
            rec_regs.ip()
        );

        if is_logging!(LogDebug) {
            Registers::compare_register_files(
                Some(t),
                "(rep)",
                t.regs_ref(),
                "(rec)",
                rec_regs,
                MismatchBehavior::LogMismatches,
            );
        }
        return false;
    }
    if !Registers::compare_register_files(Some(t), "rep", t.regs_ref(), "rec", rec_regs, behavior) {
        log!(
            LogDebug,
            "  not same execution point: regs differ (@{})",
            rec_regs.ip()
        );

        *mismatched_regs = Some(t.regs_ref().clone());
        return false;
    }
    log!(LogDebug, "  same execution point");
    true
}

fn guard_overshoot(
    t: &mut ReplayTask,
    target_regs: &Registers,
    target_ticks: Ticks,
    remaining_ticks: i64,
    closest_matching_regs: Option<&Registers>,
) {
    if remaining_ticks < 0 {
        let target_ip: RemoteCodePtr = target_regs.ip();

        // Cover up the internal breakpoint that we may have
        // set, and restore the tracee's $ip to what it would
        // have been had it not hit the breakpoint (if it did
        // hit the breakpoint).
        t.vm_shr_ptr()
            .remove_breakpoint(target_ip, BreakpointType::BkptInternal, t);
        if t.regs_ref().ip() == target_ip.increment_by_bkpt_insn_length(t.arch()) {
            t.move_ip_before_breakpoint();
        }
        match closest_matching_regs {
            Some(cmr) => {
                log!(
                    LogError,
                    "Replay diverged; target registers at ticks target mismatched: "
                );
                Registers::compare_register_files(
                    Some(t),
                    "rep overshoot",
                    t.regs_ref(),
                    "rec",
                    cmr,
                    MismatchBehavior::LogMismatches,
                );
            }
            None => {
                log!(LogError, "Replay diverged; target registers mismatched: ");
                Registers::compare_register_files(
                    Some(t),
                    "rep overshoot",
                    t.regs_ref(),
                    "rec",
                    target_regs,
                    MismatchBehavior::LogMismatches,
                );
            }
        }
        ed_assert!(
            t,
            false,
            "overshot target ticks={} by {}",
            target_ticks,
            -remaining_ticks
        );
    }
}
