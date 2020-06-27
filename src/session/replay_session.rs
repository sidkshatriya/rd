use super::task::task_inner::MAX_TICKS_REQUEST;
use crate::{
    bindings::{ptrace::PTRACE_EVENT_SECCOMP, signal::siginfo_t},
    cpuid_bug_detector::CPUIDBugDetector,
    emu_fs::{EmuFs, EmuFsSharedPtr},
    event::{Event, EventType, SignalDeterministic, SignalEventData, SyscallState},
    fast_forward::{fast_forward_through_instruction, FastForwardStatus},
    flags::Flags as ProgramFlags,
    kernel_abi::{common::preload_interface::syscallbuf_hdr, SupportedArch},
    log::LogLevel::LogDebug,
    perf_counters,
    perf_counters::{PerfCounters, TIME_SLICE_SIGNAL},
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::RemotePtr,
    replay_syscall::{rep_prepare_run_to_syscall, rep_process_syscall},
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
        session_inner::{
            session_inner::{
                PtraceSyscallBeforeSeccomp::{
                    PtraceSyscallBeforeSeccomp,
                    PtraceSyscallBeforeSeccompUnknown,
                    SeccompBeforePtraceSyscall,
                },
                SessionInner,
            },
            BreakStatus,
            RunCommand,
        },
        task::{
            common::write_val_mem,
            replay_task::ReplayTask,
            task_inner::{
                task_inner::{SaveTraceeFdNumber, TaskInner},
                ResumeRequest,
                TicksRequest,
                WaitRequest,
            },
            Task,
            TaskSharedPtr,
        },
        Session,
        SessionSharedPtr,
    },
    ticks::Ticks,
    trace::{
        trace_frame::{FrameTime, TraceFrame},
        trace_reader::TraceReader,
        trace_stream::TraceStream,
    },
    util::{
        cpuid,
        cpuid_compatible,
        find_cpuid_record,
        xcr0,
        xsave_enabled,
        CPUIDData,
        Completion,
        CPUID_GETFEATURES,
        CPUID_GETXSAVE,
        OSXSAVE_FEATURE_FLAG,
        XSAVEC_FEATURE_FLAG,
    },
};
use libc::{ENOSYS, SIGBUS, SIGSEGV, SIGTRAP};
use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    ffi::{OsStr, OsString},
    io,
    io::Write,
    ops::{Deref, DerefMut},
    rc::Rc,
};

pub type ReplaySessionSharedPtr = Rc<RefCell<ReplaySession>>;

/// ReplayFlushBufferedSyscallState is saved in Session and cloned with its
/// Session, so it needs to be simple data, i.e. not holding pointers to
/// per-Session data.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
    pub signo: i32,
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
    pub fn target(&self) -> ReplayTraceStepTarget {
        match self.data {
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
}

#[derive(Eq, Debug, PartialEq, Copy, Clone)]
pub enum ReplayStatus {
    /// Some execution was replayed. replay_step() can be called again.
    ReplayContinue,
    /// All tracees are dead. replay_step() should not be called again.
    ReplayExited,
}

#[derive(Clone)]
pub struct StepConstraints {
    pub command: RunCommand,
    pub stop_at_time: FrameTime,
    pub ticks_target: Ticks,
    // When the RunCommand is RUN_SINGLESTEP_FAST_FORWARD, stop if the next
    // singlestep would enter one of the register states in this list.
    // RUN_SINGLESTEP_FAST_FORWARD will always singlestep at least once
    // regardless.
    // DIFF NOTE: @TODO? In rr this is a pointer to the registers i.e. in Rust it would be
    // Vec<&Registers>
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
    trace_in: RefCell<TraceReader>,
    trace_frame: RefCell<TraceFrame>,
    current_step: Cell<ReplayTraceStep>,
    ticks_at_start_of_event: Ticks,
    cpuid_bug_detector: CPUIDBugDetector,
    last_siginfo_: Cell<siginfo_t>,
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
    pub fn clone_replay(&self) -> ReplaySessionSharedPtr {
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
    /// Time of the current frame
    pub fn current_frame_time(&self) -> FrameTime {
        self.trace_frame.borrow().time()
    }

    /// The Task for the current trace record.
    pub fn current_task(&self) -> Option<TaskSharedPtr> {
        self.finish_initializing();
        let found = self.find_task_from_rec_tid(self.current_trace_frame().tid());
        found
            .as_ref()
            .map(|r| debug_assert!(r.borrow().as_replay_task().is_some()));
        found
    }

    pub fn is_ignored_signal(sig: i32) -> bool {
        match sig {
            // TIME_SLICE_SIGNALs can be queued but not delivered before we stop
            // execution for some other reason. Ignore them.
            TIME_SLICE_SIGNAL => true,
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
            ticks_at_start_of_event: 0,
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
            *self.trace_frame.borrow_mut() = TraceFrame::new_with(
                self.current_frame_time(),
                0,
                Event::trace_termination(),
                self.current_trace_frame().ticks(),
                self.current_trace_frame().monotonic_time(),
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
            tid,
        );

        rc.on_create(t);

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
    pub fn replay_step_with_constraints(&self, constraints: StepConstraints) -> ReplayResult {
        self.finish_initializing();
        let mut result = ReplayResult::new(ReplayStatus::ReplayContinue);
        let maybe_rc_t = self.current_task();

        if self.current_trace_frame().event().event_type() == EventType::EvTraceTermination {
            result.status = ReplayStatus::ReplayExited;
            return result;
        }
        // If we restored from a checkpoint, the steps might have been
        // computed already in which case step.action will not be TSTEP_NONE.
        if self.current_step.get().action == ReplayTraceStepType::TstepNone {
            let rc_t = self.setup_replay_one_trace_frame(maybe_rc_t);
            if self.current_step.get().action == ReplayTraceStepType::TstepNone {
                // Already at the destination event.
                self.advance_to_next_trace_frame();
            }
            if self.current_step.get().action == ReplayTraceStepType::TstepNone {
                result.break_status.task = rc_t.borrow().weak_self.clone();
                result.break_status.task_exit = true;
            }
            return result;
        }
        let rc_t = maybe_rc_t.unwrap();
        self.fast_forward_status.set(FastForwardStatus::new());
        // Now we know |t| hasn't died, so save it in break_status.
        result.break_status.task = rc_t.borrow().weak_self.clone();
        let mut dt = rc_t.borrow_mut();
        let t = dt.as_replay_task_mut().unwrap();
        // Advance towards fulfilling |current_step|.
        if self.try_one_trace_step(t, &constraints) == Completion::Incomplete {
            if EventType::EvTraceTermination == self.current_trace_frame().event().event_type() {
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
            result.incomplete_fast_forward = self.fast_forward_status.get().incomplete_fast_forward;
            return result;
        }
        unimplemented!();
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

        let t_shr_ptr = match maybe_t {
            None => self.revive_task_for_exec(),
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
            unimplemented!()
        }

        // Ask the trace-interpretation code what to do next in order
        // to retire the current frame.
        let mut current_step = Default::default();
        match ev.event_type() {
            EventType::EvExit => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepExitTask,
                    data: Default::default(),
                }
            }
            EventType::EvSyscallbufAbortCommit => {
                let child_addr = RemotePtr::<u8>::cast(t.syscallbuf_child)
                    + offset_of!(syscallbuf_hdr, abort_commit);
                write_val_mem(t, child_addr, &1u8, None);
                t.apply_all_data_records_from_trace();
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepRetire,
                    data: Default::default(),
                }
            }
            EventType::EvSyscallbufFlush => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepFlushSyscallbuf,
                    data: Default::default(),
                };

                self.prepare_syscallbuf_records(t);
            }
            EventType::EvSyscallbufReset => {
                // Reset syscallbuf_hdr->num_rec_bytes and zero out the recorded data.
                // Zeroing out the data is important because we only save and restore
                // the recorded data area when making checkpoints. We want the checkpoint
                // to have the same syscallbuf contents as its original, i.e. zero outside
                // the recorded data area. This is important because stray reads such
                // as those performed by return_addresses should be consistent.
                t.reset_syscallbuf();
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepRetire,
                    data: Default::default(),
                };
            }
            EventType::EvPatchSyscall => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepPatchSyscall,
                    data: Default::default(),
                };
            }
            EventType::EvSched => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepProgramAsyncSignalInterrupt,
                    data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                        ticks: Some(trace_frame.ticks()),
                        signo: 0,
                    }),
                };
            }
            EventType::EvInstructionTrap => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepDeterministicSignal,
                    data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                        ticks: None,
                        signo: SIGSEGV,
                    }),
                };
            }
            EventType::EvGrowMap => {
                process_grow_map(t);
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepRetire,
                    data: Default::default(),
                }
            }
            EventType::EvSignal => {
                self.last_siginfo_.set(ev.signal_event().siginfo.clone());
                if treat_signal_event_as_deterministic(ev.signal_event()) {
                    current_step = ReplayTraceStep {
                        action: ReplayTraceStepType::TstepDeterministicSignal,
                        data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                            ticks: None,
                            signo: ev.signal_event().siginfo.si_signo,
                        }),
                    };
                } else {
                    current_step = ReplayTraceStep {
                        action: ReplayTraceStepType::TstepProgramAsyncSignalInterrupt,
                        data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                            ticks: Some(trace_frame.ticks()),
                            signo: ev.signal_event().siginfo.si_signo,
                        }),
                    };
                }
            }
            EventType::EvSignalDelivery | EventType::EvSignalHandler => {
                current_step = ReplayTraceStep {
                    action: ReplayTraceStepType::TstepDeliverSignal,
                    data: ReplayTraceStepData::Target(ReplayTraceStepTarget {
                        ticks: Some(0),
                        signo: ev.signal_event().siginfo.si_signo,
                    }),
                };
            }
            EventType::EvSyscall => {
                if ev.syscall_event().state == SyscallState::EnteringSyscall
                    || ev.syscall_event().state == SyscallState::EnteringSyscallPtrace
                {
                    current_step = rep_prepare_run_to_syscall(t);
                } else {
                    rep_process_syscall(t, &current_step);
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
                unreachable!()
            }
        }

        self.current_step.set(current_step);
        drop(dyn_t);
        t_shr_ptr
    }

    fn prepare_syscallbuf_records(&self, _t: &ReplayTask) {
        unimplemented!()
    }

    fn revive_task_for_exec(&self) -> TaskSharedPtr {
        unimplemented!()
    }

    pub fn replay_step(&self, command: RunCommand) -> ReplayResult {
        self.replay_step_with_constraints(StepConstraints::new(command))
    }

    fn emulate_signal_delivery(&self, _oldtask: &ReplayTask, _sig: i32) -> Completion {
        unimplemented!();
    }
    // Continue until reaching either the "entry" of an emulated syscall,
    // or the entry or exit of an executed syscall.  |emu| is nonzero when
    // we're emulating the syscall.  Return COMPLETE when the next syscall
    // boundary is reached, or INCOMPLETE if advancing to the boundary was
    // interrupted by an unknown trap.
    // When |syscall_trace_frame| is non-null, we continue to the syscall by
    // setting a breakpoint instead of running until we execute a system
    // call instruction. In that case we will not actually enter the kernel.
    fn cont_syscall_boundary(
        &self,
        t: &mut ReplayTask,
        constraints: &StepConstraints,
    ) -> Completion {
        let mut ticks_request: TicksRequest = Default::default();
        if !compute_ticks_request(t, constraints, &mut ticks_request) {
            return Completion::Incomplete;
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
            perf_counters::TIME_SLICE_SIGNAL => {
                // This would normally be triggered by constraints.ticks_target but it's
                // also possible to get stray signals here.
                return Completion::Incomplete;
            }
            SIGSEGV => {
                if self.handle_unrecorded_cpuid_fault(t, constraints) {
                    return Completion::Incomplete;
                }
            }
            SIGTRAP => {
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
            && self.syscall_seccomp_ordering_.get() == PtraceSyscallBeforeSeccompUnknown
        {
            ed_assert!(t, !constraints.is_singlestep());
            if t.maybe_ptrace_event() == PTRACE_EVENT_SECCOMP {
                self.syscall_seccomp_ordering_
                    .set(SeccompBeforePtraceSyscall);
            } else {
                self.syscall_seccomp_ordering_
                    .set(PtraceSyscallBeforeSeccomp);
            }
            // Eat the following event, either a seccomp or syscall notification
            t.resume_execution(
                ResumeRequest::ResumeSysemu,
                WaitRequest::ResumeWait,
                ticks_request,
                None,
            );
        }

        let type_ = AddressSpace::rd_page_syscall_from_exit_point(t.ip());
        if type_.is_some()
            && type_.unwrap().traced == Traced::Untraced
            && type_.unwrap().enabled == Enabled::ReplayOnly
        {
            // Actually perform it. We can hit these when replaying through syscallbuf
            // code that was interrupted.
            perform_interrupted_syscall(t);
            return Completion::Incomplete;
        }

        Completion::Complete
    }

    /// Advance to the next syscall entry (or virtual entry) according to
    /// |step|.  Return COMPLETE if successful, or INCOMPLETE if an unhandled trap
    /// occurred.
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
            // By default we get the null address
            let mut syscall_instruction = RemoteCodePtr::new();

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
                    && t.vm()
                        .is_breakpoint_in_private_read_only_memory(syscall_instruction)
                    && t.vm_mut()
                        .add_breakpoint(syscall_instruction, BreakpointType::BkptInternal)
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
                    self.clear_syscall_bp();
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

    fn exit_syscall(&self, _t: &ReplayTask) -> Completion {
        unimplemented!();
    }
    fn exit_task(&self, _t: &ReplayTask) -> Completion {
        unimplemented!();
    }
    fn handle_unrecorded_cpuid_fault(
        &self,
        _t: &ReplayTask,
        _constraints: &StepConstraints,
    ) -> bool {
        unimplemented!();
    }
    fn check_ticks_consistency(&self, _t: &ReplayTask, _ev: &Event) {
        unimplemented!();
    }
    fn check_pending_sig(&self, _t: &ReplayTask) {
        unimplemented!();
    }
    fn continue_or_step(
        &self,
        _t: &ReplayTask,
        _constraints: &StepConstraints,
        _tick_request: TicksRequest,
        _resume_request: Option<ResumeRequest>,
    ) -> Completion {
        unimplemented!();
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
        _t: &ReplayTask,
        _sig: i32,
        _constraints: &StepConstraints,
    ) -> Completion {
        unimplemented!();
    }
    fn emulate_async_signal(
        &self,
        _t: &ReplayTask,
        _constraints: &StepConstraints,
        _ticks: Ticks,
    ) -> Completion {
        unimplemented!();
    }
    fn flush_syscallbuf(&self, _t: &ReplayTask, _constraints: &StepConstraints) -> Completion {
        unimplemented!();
    }
    fn patch_next_syscall(&self, _t: &ReplayTask, _constraints: &StepConstraints) -> Completion {
        unimplemented!();
    }

    /// Try to execute |step|, adjusting for |req| if needed.  Return Complete if
    /// |step| was made, or Incomplete if there was a trap or |step| needs
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
                self.current_step.get().target().signo,
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
                self.emulate_signal_delivery(t, self.current_step.get().target().signo)
            }
            ReplayTraceStepType::TstepFlushSyscallbuf => self.flush_syscallbuf(t, &constraints),
            ReplayTraceStepType::TstepPatchSyscall => self.patch_next_syscall(t, &constraints),
            ReplayTraceStepType::TstepExitTask => self.exit_task(t),
            _ => {
                fatal!("Unhandled step type: {:?}", self.current_step.get().action);
                unreachable!();
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

    fn clear_syscall_bp(&self) {
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

    fn new_task(&self, tid: i32, rec_tid: i32, serial: u32, a: SupportedArch) -> Box<dyn Task> {
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
            write!(
                io::stderr(),
                "rr: Tracees had XSAVE but XSAVE is not available\n\
                now; Replay will probably fail because glibc dynamic loader\n\
                            uses XSAVE\n\n"
            )
            .unwrap();
        }
        return;
    }

    let tracee_xcr0: u64 = trace_in.xcr0();
    let our_xcr0: u64 = xcr0();
    let maybe_record = find_cpuid_record(trace_in.cpuid_records(), CPUID_GETXSAVE, 1);
    let tracee_xsavec: bool =
        maybe_record.is_some() && (maybe_record.unwrap().out.eax & XSAVEC_FEATURE_FLAG != 0);
    let data: CPUIDData = cpuid(CPUID_GETXSAVE, 1);
    let our_xsavec: bool = (data.eax & XSAVEC_FEATURE_FLAG) != 0;
    if tracee_xsavec && !our_xsavec && !ProgramFlags::get().suppress_environment_warnings {
        write!(
            io::stderr(),
            "rr: Tracees had XSAVEC but XSAVEC is not available\n\
            now; Replay will probably fail because glibc dynamic loader\n\
                         uses XSAVEC\n\n"
        )
        .unwrap();
    }

    if tracee_xcr0 != our_xcr0 {
        if !ProgramFlags::get().suppress_environment_warnings {
            // If the tracee used XSAVE instructions which write different components
            // to XSAVE instructions executed on our CPU, or examines XCR0 directly,
            // This will cause divergence. The dynamic linker examines XCR0 so this
            // is nearly guaranteed.
            write!(io::stderr(), "Trace XCR0 value {:x} != our XCR0 value {:x};\n\
                            Replay will probably fail because glibc dynamic loader examines XCR0\n\n",
                            tracee_xcr0, our_xcr0).unwrap();
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

fn process_grow_map(_t: &ReplayTask) {
    unimplemented!()
}

fn treat_signal_event_as_deterministic(ev: &SignalEventData) -> bool {
    ev.deterministic == SignalDeterministic::DeterministicSig && ev.siginfo.si_signo != SIGBUS
}

fn perform_interrupted_syscall(_t: &mut ReplayTask) {
    unimplemented!()
}

/// Why a skid region?  Interrupts generated by perf counters don't
/// fire at exactly the programmed point (as of 2013 kernel/HW);
/// there's a variable slack region, which is technically unbounded.
/// This means that an interrupt programmed for retired branch k might
/// fire at |k + 50|, for example.  To counteract the slack, we program
/// interrupts just short of our target, by the |SKID_SIZE| region
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
/// 1. programming interrupt for [target - SKID_SIZE] ticks
/// 2. Error: Replay diverged.  Dumping register comparison.
/// 3. Error: [list of divergent registers; arbitrary]
/// 4. Error: overshot target ticks=[target] by [i]
///
/// The key is that no other replayer log messages occur between (1)
/// and (2).  This spew means that the replayer programmed an interrupt
/// for ticks=[target-SKID_SIZE], but the tracee was actually interrupted
/// at ticks=[target+i].  And that in turn means that the kernel/HW
/// skidded too far past the programmed target for rr to handle it.
///
/// If that occurs, the SKID_SIZE needs to be increased by at least
/// [i].
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

/// Call this when |t| has just entered a syscall.
pub fn rep_after_enter_syscall(_t: &ReplayTask) {
    unimplemented!()
}
