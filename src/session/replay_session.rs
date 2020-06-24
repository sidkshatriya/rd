use crate::{
    bindings::signal::siginfo_t,
    cpuid_bug_detector::CPUIDBugDetector,
    emu_fs::{EmuFs, EmuFsSharedPtr},
    event::{Event, EventType},
    fast_forward::FastForwardStatus,
    flags::Flags as ProgramFlags,
    kernel_abi::SupportedArch,
    perf_counters::{PerfCounters, TIME_SLICE_SIGNAL},
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    scoped_fd::ScopedFd,
    session::{
        address_space::address_space::AddressSpaceSharedPtr,
        diversion_session::DiversionSessionSharedPtr,
        replay_session::ReplayTraceStepType::TstepNone,
        session_inner::{session_inner::SessionInner, BreakStatus, RunCommand},
        task::{replay_task::ReplayTask, task_inner::task_inner::TaskInner, Task, TaskSharedPtr},
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
use std::{
    cell::{Ref, RefCell, RefMut},
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

impl Default for ReplayTraceStepType {
    fn default() -> Self {
        ReplayTraceStepType::TstepNone
    }
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
pub enum ReplayTraceStepUnion {
    None,
    Syscall(ReplayTraceStepSyscall),
    Target(ReplayTraceStepTarget),
    Flush(ReplayFlushBufferedSyscallState),
}

impl Default for ReplayTraceStepUnion {
    fn default() -> Self {
        ReplayTraceStepUnion::None
    }
}

#[derive(Default)]
pub struct ReplayTraceStep {
    pub action: ReplayTraceStepType,
    pub data: ReplayTraceStepUnion,
}

#[derive(Eq, Debug, PartialEq, Copy, Clone)]
pub enum ReplayStatus {
    /// Some execution was replayed. replay_step() can be called again.
    ReplayContinue,
    /// All tracees are dead. replay_step() should not be called again.
    ReplayExited,
}

pub struct StepConstraints {
    pub command: RunCommand,
    pub stop_at_time: FrameTime,
    pub ticks_target: Ticks,
    // When the RunCommand is RUN_SINGLESTEP_FAST_FORWARD, stop if the next
    // singlestep would enter one of the register states in this list.
    // RUN_SINGLESTEP_FAST_FORWARD will always singlestep at least once
    // regardless.
    // @TODO In rr this is a pointer to the registers
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
    /// DIFF NOTE: Made into an Option<>
    syscall_bp_vm: Option<AddressSpaceSharedPtr>,
    // @TODO Set to the 0 address on init. More principled solution?!
    syscall_bp_addr: RemoteCodePtr,
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
    pub fn current_trace_frame(&self) -> &TraceFrame {
        &self.trace_frame
    }
    /// Time of the current frame
    pub fn current_frame_time(&self) -> FrameTime {
        self.trace_frame.time()
    }

    /// The Task for the current trace record.
    pub fn current_task(&self) -> Option<TaskSharedPtr> {
        self.finish_initializing();
        let found = self.find_task_from_rec_tid(self.trace_frame.tid());
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
            trace_start_time: 0.0,
            session_inner: Default::default(),
            cpuid_bug_detector: Default::default(),
            fast_forward_status: Default::default(),
            syscall_bp_vm: Default::default(),
            syscall_bp_addr: Default::default(),
        };

        // @TODO Important!! Need to set the weak self pointer for Session.

        let semantics = rs.trace_in.borrow().ticks_semantics();
        rs.ticks_semantics_ = semantics;
        rs.advance_to_next_trace_frame();
        rs.trace_start_time = rs.trace_frame.monotonic_time();

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

    fn advance_to_next_trace_frame(&mut self) {
        if self.trace_in.borrow().at_end() {
            self.trace_frame = TraceFrame::new_with(
                self.trace_frame.time(),
                0,
                Event::trace_termination(),
                self.trace_frame.ticks(),
                self.trace_frame.monotonic_time(),
            );
            return;
        }

        self.trace_frame = self.trace_in.borrow_mut().read_frame();
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
        let mut tracee_socket_fd_number: i32 = -1;
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
            &mut tracee_socket_fd_number,
            &exe_path,
            &argv,
            &env,
            tid,
        );
        // We never change the tracee_socket_fd_number so its a good idea
        // to use a bit of unsafe here.
        unsafe { Rc::get_mut_unchecked(&mut rc) }.tracee_socket_fd_number = tracee_socket_fd_number;
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
    pub fn replay_step_with_constraints(&mut self, constraints: &StepConstraints) -> ReplayResult {
        self.finish_initializing();
        let mut result = ReplayResult::new(ReplayStatus::ReplayContinue);
        let maybe_rc_t = self.current_task();

        if self.trace_frame.event().event_type() == EventType::EvTraceTermination {
            result.status = ReplayStatus::ReplayExited;
            return result;
        }
        // If we restored from a checkpoint, the steps might have been
        // computed already in which case step.action will not be TSTEP_NONE.
        if self.current_step.action == ReplayTraceStepType::TstepNone {
            let rc_t = self.setup_replay_one_trace_frame(maybe_rc_t);
            if self.current_step.action == ReplayTraceStepType::TstepNone {
                // Already at the destination event.
                self.advance_to_next_trace_frame();
            }
            if self.current_step.action == ReplayTraceStepType::TstepNone {
                result.break_status.task = rc_t.borrow().weak_self.clone();
                result.break_status.task_exit = true;
            }
            return result;
        }
        let rc_t = maybe_rc_t.unwrap();
        self.fast_forward_status = FastForwardStatus::new();
        // Now we know |t| hasn't died, so save it in break_status.
        result.break_status.task = rc_t.borrow().weak_self.clone();
        let mut dt = rc_t.borrow_mut();
        let t = dt.as_replay_task_mut().unwrap();
        // Advance towards fulfilling |current_step|.
        if self.try_one_trace_step(t, constraints) == Completion::Incomplete {
            if EventType::EvTraceTermination == self.trace_frame.event().event_type() {
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

            self.check_approaching_ticks_target(t, constraints, &mut result.break_status);
            result.did_fast_forward = self.fast_forward_status.did_fast_forward;
            result.incomplete_fast_forward = self.fast_forward_status.incomplete_fast_forward;
            return result;
        }
        unimplemented!();
    }
    fn setup_replay_one_trace_frame(&self, _maybe_t: Option<TaskSharedPtr>) -> TaskSharedPtr {
        unimplemented!()
    }

    pub fn replay_step(&self, _command: RunCommand) -> ReplayResult {
        unimplemented!()
    }

    fn try_one_trace_step(
        &self,
        _t: &mut ReplayTask,
        _step_constraints: &StepConstraints,
    ) -> Completion {
        unimplemented!()
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
