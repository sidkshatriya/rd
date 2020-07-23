use crate::{
    bindings::signal::siginfo_t,
    session::{address_space::WatchConfig, task::TaskSharedWeakPtr},
};

#[derive(Clone)]
pub struct BreakStatus {
    /// The triggering Task. This may be different from session->current_task()
    /// when replay switches to a new task when ReplaySession::replay_step() ends.
    /// @TODO Must this be an Option<>??
    pub task: Option<TaskSharedWeakPtr>,
    /// List of watchpoints hit; any watchpoint hit causes a stop after the
    /// instruction that triggered the watchpoint has completed.
    pub watchpoints_hit: Vec<WatchConfig>,
    /// When non-`None`, we stopped because a signal was delivered to `task`.
    pub signal: Option<Box<siginfo_t>>,
    /// True when we stopped because we hit a software breakpoint at `task`'s
    /// current ip().
    pub breakpoint_hit: bool,
    /// True when we stopped because a singlestep completed in `task`.
    pub singlestep_complete: bool,
    /// True when we stopped because we got too close to the specified ticks
    /// target.
    pub approaching_ticks_target: bool,
    /// True when we stopped because `task` is about to exit.
    pub task_exit: bool,
}

/// In general, multiple break reasons can apply simultaneously.
impl BreakStatus {
    pub fn new() -> BreakStatus {
        BreakStatus {
            task: Default::default(),
            breakpoint_hit: false,
            singlestep_complete: false,
            approaching_ticks_target: false,
            task_exit: false,
            watchpoints_hit: vec![],
            signal: None,
        }
    }

    /// True when we stopped because we hit a software or hardware breakpoint at
    /// `task`'s current ip().
    pub fn hardware_or_software_breakpoint_hit(&self) -> bool {
        unimplemented!()
    }

    /// Returns just the data watchpoints hit.
    pub fn data_watchpoints_hit(&self) -> Vec<WatchConfig> {
        unimplemented!()
    }

    pub fn any_break(&self) -> bool {
        !self.watchpoints_hit.is_empty()
            || self.signal.is_some()
            || self.breakpoint_hit
            || self.singlestep_complete
            || self.approaching_ticks_target
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum RunCommand {
    /// Continue until we hit a breakpoint or a new replay event
    RunContinue,
    /// Execute a single instruction (unless at a breakpoint or a replay event)
    RunSinglestep,
    /// Like RunSinglestep, but a single-instruction loop is allowed (but not
    /// required) to execute multiple times if we don't reach a different
    /// instruction. Usable with ReplaySession::replay_step only.
    RunSinglestepFastForward,
}

#[inline]
pub fn is_singlestep(command: RunCommand) -> bool {
    command == RunCommand::RunSinglestep || command == RunCommand::RunSinglestepFastForward
}

pub mod session_inner {
    use super::{is_singlestep, BreakStatus, RunCommand};
    use crate::{
        flags::Flags,
        log::LogLevel::LogDebug,
        perf_counters::{self, PerfCounters, TicksSemantics},
        remote_ptr::{RemotePtr, Void},
        scoped_fd::ScopedFd,
        session::{
            address_space::{
                address_space::{AddressSpace, AddressSpaceSharedPtr, AddressSpaceSharedWeakPtr},
                BreakpointType,
            },
            task::{
                task_inner::{task_inner::CapturedState, TrapReasons},
                Task,
                TaskSharedPtr,
                TaskSharedWeakPtr,
            },
            SessionSharedWeakPtr,
        },
        taskish_uid::{AddressSpaceUid, ThreadGroupUid},
        thread_group::{ThreadGroup, ThreadGroupSharedPtr, ThreadGroupSharedWeakPtr},
        ticks::Ticks,
        util::cpuid_faulting_works,
    };
    use libc::{pid_t, SIGTRAP};
    use nix::{
        fcntl::OFlag,
        unistd::{pipe2, read},
    };
    use std::{
        cell::{Cell, RefCell},
        collections::{BTreeMap, HashMap},
        ffi::{OsStr, OsString},
        os::unix::ffi::OsStringExt,
        rc::Rc,
    };

    /// AddressSpaces and ThreadGroups are indexed by their first task's TaskUid
    /// (effectively), so that if the first task dies and its tid is recycled,
    /// we don't get confused. TaskMap is indexed by tid since there can never be
    /// two Tasks with the same tid at the same time.
    pub type AddressSpaceMap = HashMap<AddressSpaceUid, AddressSpaceSharedWeakPtr>;
    pub type TaskMap = BTreeMap<pid_t, TaskSharedPtr>;
    pub type ThreadGroupMap = HashMap<ThreadGroupUid, ThreadGroupSharedWeakPtr>;

    #[derive(Copy, Clone, Eq, PartialEq)]
    pub enum PtraceSyscallSeccompOrdering {
        SyscallBeforeSeccomp,
        SeccompBeforeSyscall,
        SyscallBeforeSeccompUnknown,
    }

    impl Default for PtraceSyscallSeccompOrdering {
        fn default() -> Self {
            PtraceSyscallSeccompOrdering::SyscallBeforeSeccompUnknown
        }
    }

    /// struct is NOT pub
    #[derive(Clone)]
    pub(in super::super) struct AddressSpaceClone {
        /// @TODO need to think about this
        pub clone_leader: TaskSharedWeakPtr,
        pub clone_leader_state: CapturedState,
        pub member_states: Vec<CapturedState>,
        pub captured_memory: Vec<(RemotePtr<Void>, Vec<u8>)>,
    }

    /// struct is NOT pub
    #[derive(Clone)]
    pub(in super::super) struct CloneCompletion {
        pub address_spaces: Vec<AddressSpaceClone>,
    }

    /// Sessions track the global state of a set of tracees corresponding
    /// to an rd recorder or replayer.  During recording, the tracked
    /// tracees will all write to the same TraceWriter, and during
    /// replay, the tracees that will be tracked will all be created based
    /// on the same TraceReader.
    ///
    /// Multiple sessions can coexist in the same process.  This
    /// is required when using replay checkpoints, for example.
    impl SessionInner {
        /// Returns true after the tracee has done the initial exec in Task::spawn.
        /// Before then, tracee state can be inconsistent; from the exec exit-event
        /// onwards, the tracee state much be consistent.
        pub fn done_initial_exec(&self) -> bool {
            self.done_initial_exec_.get()
        }

        /// Create and return a new address space that's constructed
        /// from `t`'s actual OS address space. When spawning, `exe` is the empty
        /// string; it will be replaced during the first execve(), when we first
        /// start running real tracee code.
        /// If `exe` is not specified it is assumed to be an empty string.
        /// If `exec_count` is not specified it is assumed to be 0.
        pub fn create_vm(
            &self,
            t: &mut dyn Task,
            maybe_exe: Option<&OsStr>,
            maybe_exec_count: Option<u32>,
        ) -> AddressSpaceSharedPtr {
            let exe = maybe_exe.unwrap_or(OsStr::new(""));
            let exec_count = maybe_exec_count.unwrap_or(0);
            self.assert_fully_initialized();
            let as_ = AddressSpace::new_after_execve(t, exe, exec_count);
            as_.task_set_mut().insert(t.weak_self_ptr());
            let as_uid = as_.uid();
            let shr_ptr = Rc::new(as_);
            self.vm_map
                .borrow_mut()
                .insert(as_uid, Rc::downgrade(&shr_ptr));
            shr_ptr
        }

        /// Return a copy of `vm` with the same mappings.  If any
        /// mapping is changed, only the `clone()`d copy is updated,
        /// not its origin (i.e. copy-on-write semantics).
        /// NOTE: Called simply Session::clone() in rr
        pub fn clone_vm(&self, t: &dyn Task, vm: AddressSpaceSharedPtr) -> AddressSpaceSharedPtr {
            self.assert_fully_initialized();
            // If vm already belongs to our session this is a fork, otherwise it's
            // a session-clone
            let addr_space: AddressSpace;
            if self.weak_self.ptr_eq(vm.session_weak()) {
                addr_space = AddressSpace::new_after_fork_or_session_clone(
                    self.weak_self.clone(),
                    &vm,
                    t.rec_tid,
                    t.tuid().serial(),
                    0,
                );
            } else {
                let vm_uid_tid: i32;
                let vm_uid_serial: u32;
                let vm_uid_exec_count: u32;
                {
                    let vmb = vm.uid();
                    vm_uid_tid = vmb.tid();
                    vm_uid_serial = vmb.serial();
                    vm_uid_exec_count = vmb.exec_count();
                }
                addr_space = AddressSpace::new_after_fork_or_session_clone(
                    self.weak_self.clone(),
                    &vm,
                    vm_uid_tid,
                    vm_uid_serial,
                    vm_uid_exec_count,
                );
            }
            let as_uid = addr_space.uid();
            let shr_ptr = Rc::new(addr_space);
            self.vm_map
                .borrow_mut()
                .insert(as_uid, Rc::downgrade(&shr_ptr));
            shr_ptr
        }

        /// Create the initial thread group.
        pub fn create_initial_tg(&self, t: TaskSharedPtr) -> ThreadGroupSharedPtr {
            let rec_tid: i32;
            let tid: i32;
            let tuid_serial: u32;
            {
                let tb = t.borrow();
                rec_tid = tb.rec_tid;
                tid = tb.tid;
                tuid_serial = tb.tuid().serial();
            }

            let tg = ThreadGroup::new(self.weak_self.clone(), None, rec_tid, tid, tid, tuid_serial);
            tg.borrow_mut().task_set_mut().insert(Rc::downgrade(&t));
            tg
        }

        pub fn next_task_serial(&self) -> u32 {
            let val = self.next_task_serial_.get();
            self.next_task_serial_.set(val + 1);
            val
        }

        /// Call these functions from the objects' drop impl in order
        /// to notify this session that the objects are dying.
        /// DIFF NOTE: Method is simply called on_Session::on_destroy() in rr.
        /// Also in rd this takes a vm uid instead of a AddressSpace space reference.
        pub fn on_destroy_vm(&self, vm_uid: AddressSpaceUid) {
            debug_assert!(self.vm_map.borrow().get(&vm_uid).is_some());
            self.vm_map.borrow_mut().remove(&vm_uid);
        }

        /// NOTE: Method is simply called Session::on_create() in rr.
        pub fn on_create_tg(&self, tg: &ThreadGroupSharedPtr) {
            self.thread_group_map
                .borrow_mut()
                .insert(tg.borrow().tguid(), Rc::downgrade(tg));
        }
        /// NOTE: Method is simply called on_Session::on_destroy() in rr.
        pub fn on_destroy_tg(&self, tguid: ThreadGroupUid) {
            self.thread_group_map.borrow_mut().remove(&tguid);
        }

        /// Return the set of AddressSpaces being tracked in this session.
        pub fn vms(&self) -> Vec<Rc<AddressSpace>> {
            let res: Vec<Rc<AddressSpace>> = self
                .vm_map
                .borrow()
                .iter()
                .map(|weak| weak.1.upgrade().unwrap())
                .collect();
            res
        }

        pub fn visible_execution(&self) -> bool {
            self.visible_execution_
        }

        pub fn set_visible_execution(&mut self, visible: bool) {
            self.visible_execution_ = visible
        }

        pub fn accumulate_bytes_written(&self, bytes_written: u64) {
            self.statistics_.borrow_mut().bytes_written += bytes_written
        }

        pub fn accumulate_syscall_performed(&self) {
            self.statistics_.borrow_mut().syscalls_performed += 1
        }

        pub fn accumulate_ticks_processed(&self, ticks: Ticks) {
            self.statistics_.borrow_mut().ticks_processed += ticks;
        }

        pub fn statistics(&self) -> Statistics {
            *self.statistics_.borrow()
        }

        pub fn read_spawned_task_error(&self) -> OsString {
            let mut buf: Vec<u8> = vec![0; 1000];
            let res = read(self.spawned_task_error_fd_.borrow().as_raw(), &mut buf);
            match res {
                Ok(nread) => {
                    buf.truncate(nread);
                    OsString::from_vec(buf)
                }
                Err(_) => OsString::new(),
            }
        }

        pub fn syscall_seccomp_ordering(&self) -> PtraceSyscallSeccompOrdering {
            self.syscall_seccomp_ordering_.get()
        }

        pub fn has_cpuid_faulting() -> bool {
            !Flags::get().disable_cpuid_faulting && cpuid_faulting_works()
        }
        pub fn rd_mapping_prefix() -> &'static str {
            "/rd-shared-"
        }

        /// @TODO is the return type what we really want?
        pub fn tracee_socket_fd(&self) -> Rc<RefCell<ScopedFd>> {
            self.tracee_socket.clone()
        }
        pub fn tracee_fd_number(&self) -> i32 {
            self.tracee_socket_fd_number.get()
        }

        pub fn ticks_semantics(&self) -> TicksSemantics {
            self.ticks_semantics_
        }

        pub(in super::super) fn new() -> SessionInner {
            let s = SessionInner {
                weak_self: Default::default(),
                vm_map: Default::default(),
                task_map: Default::default(),
                thread_group_map: Default::default(),
                clone_completion: Default::default(),
                statistics_: Default::default(),
                tracee_socket: Default::default(),
                tracee_socket_fd_number: Cell::new(-1),
                next_task_serial_: Cell::new(1),
                spawned_task_error_fd_: Default::default(),
                syscall_seccomp_ordering_: Default::default(),
                ticks_semantics_: PerfCounters::default_ticks_semantics(),
                done_initial_exec_: Default::default(),
                visible_execution_: true,
            };
            log!(LogDebug, "Session @TODO unique identifier created");
            s
        }

        pub(in super::super) fn create_spawn_task_error_pipe(&mut self) -> ScopedFd {
            let res = pipe2(OFlag::O_CLOEXEC);
            match res {
                Ok((fd0, fd1)) => {
                    *self.spawned_task_error_fd_.borrow_mut() = ScopedFd::from_raw(fd0);
                    ScopedFd::from_raw(fd1)
                }
                Err(e) => {
                    fatal!("Unsuccessful call to pipe2: {}", e);
                    unreachable!()
                }
            }
        }

        pub(in super::super) fn diagnose_debugger_trap(
            &self,
            t: &mut dyn Task,
            run_command: RunCommand,
        ) -> BreakStatus {
            self.assert_fully_initialized();
            let mut break_status = BreakStatus::new();
            break_status.task = Some(t.weak_self_ptr());

            let maybe_stop_sig = t.maybe_stop_sig();
            if maybe_stop_sig.is_not_sig() {
                // This can happen if we were INCOMPLETE because we're close to
                // the ticks_target.
                return break_status;
            }

            if maybe_stop_sig != SIGTRAP {
                let pending_bp: BreakpointType = t.vm().get_breakpoint_type_at_addr(t.ip());
                if BreakpointType::BkptUser == pending_bp {
                    // A signal was raised /just/ before a trap
                    // instruction for a SW breakpoint.  This is
                    // observed when debuggers write trap
                    // instructions into no-exec memory, for
                    // example the stack.
                    //
                    // We report the breakpoint before any signal
                    // that might have been raised in order to let
                    // the debugger do something at the breakpoint
                    // insn; possibly clearing the breakpoint and
                    // changing the $ip.  Otherwise, we expect the
                    // debugger to clear the breakpoint and resume
                    // execution, which should raise the original
                    // signal again.
                    log!(
                        LogDebug,
                        "hit debugger breakpoint BEFORE ip {} for {:?}",
                        t.ip(),
                        t.get_siginfo()
                    );
                    break_status.breakpoint_hit = true;
                } else if maybe_stop_sig.is_sig()
                    && maybe_stop_sig != perf_counters::TIME_SLICE_SIGNAL
                {
                    break_status.signal = Some(Box::new(*t.get_siginfo()));
                    log!(
                        LogDebug,
                        "Got signal {:?} (expected sig {})",
                        break_status.signal.as_ref().unwrap(),
                        maybe_stop_sig
                    );
                    break_status
                        .signal
                        .as_mut()
                        .map(|si| si.si_signo = maybe_stop_sig.unwrap_sig());
                }
            } else {
                let trap_reasons: TrapReasons = t.compute_trap_reasons();

                // Conceal any internal singlestepping
                if trap_reasons.singlestep && is_singlestep(run_command) {
                    log!(LogDebug, "  finished debugger stepi");
                    break_status.singlestep_complete = true;
                }

                if trap_reasons.watchpoint {
                    self.check_for_watchpoint_changes(t, &mut break_status);
                }

                if trap_reasons.breakpoint {
                    let retired_bp: BreakpointType =
                        t.vm().get_breakpoint_type_for_retired_insn(t.ip());
                    if BreakpointType::BkptUser == retired_bp {
                        log!(LogDebug, "hit debugger breakpoint at ip {}", t.ip());
                        // SW breakpoint: $ip is just past the
                        // breakpoint instruction.  Move $ip back
                        // right before it.
                        t.move_ip_before_breakpoint();
                        break_status.breakpoint_hit = true;
                    }
                }
            }

            break_status
        }
        pub(in super::super) fn check_for_watchpoint_changes(
            &self,
            t: &dyn Task,
            break_status: &mut BreakStatus,
        ) {
            self.assert_fully_initialized();
            break_status.watchpoints_hit = t.vm().consume_watchpoint_changes();
        }

        /// XXX Move CloneCompletion/CaptureState etc to ReplayTask/ReplaySession

        pub(in super::super) fn assert_fully_initialized(&self) {
            debug_assert!(
                self.clone_completion.borrow().is_none(),
                "Session not fully initialized"
            );
        }
    }

    impl Drop for SessionInner {
        fn drop(&mut self) {
            // Do nothing
        }
    }

    #[derive(Copy, Clone)]
    pub struct Statistics {
        pub bytes_written: u64,
        pub ticks_processed: Ticks,
        pub syscalls_performed: u32,
    }

    impl Default for Statistics {
        fn default() -> Self {
            Statistics::new()
        }
    }

    impl Statistics {
        pub fn new() -> Statistics {
            Statistics {
                bytes_written: 0,
                ticks_processed: 0,
                syscalls_performed: 0,
            }
        }
    }

    /// Sessions track the global state of a set of tracees corresponding
    /// to an rd recorder or replayer.  During recording, the tracked
    /// tracees will all write to the same TraceWriter, and during
    /// replay, the tracees that will be tracked will all be created based
    /// on the same TraceReader.
    ///
    /// Multiple sessions can coexist in the same process.  This
    /// is required when using replay checkpoints, for example.
    ///
    /// This struct should NOT impl the Session trait
    pub struct SessionInner {
        /// Weak dyn Session pointer to self
        pub(in super::super) weak_self: SessionSharedWeakPtr,
        /// All these members are NOT pub
        pub(in super::super) vm_map: RefCell<AddressSpaceMap>,
        pub(in super::super) task_map: RefCell<TaskMap>,
        pub(in super::super) thread_group_map: RefCell<ThreadGroupMap>,

        /// If non-None, data required to finish initializing the tasks of this
        /// session.
        /// @TODO is a Box required here?
        pub(in super::super) clone_completion: RefCell<Option<Box<CloneCompletion>>>,

        pub(in super::super) statistics_: RefCell<Statistics>,

        pub(in super::super) tracee_socket: Rc<RefCell<ScopedFd>>,
        pub(in super::super) tracee_socket_fd_number: Cell<i32>,
        pub(in super::super) next_task_serial_: Cell<u32>,
        // @TODO Should this be an Option?
        pub(in super::super) spawned_task_error_fd_: RefCell<ScopedFd>,

        pub(in super::super) syscall_seccomp_ordering_: Cell<PtraceSyscallSeccompOrdering>,

        pub(in super::super) ticks_semantics_: TicksSemantics,

        /// True if we've done an exec so tracees are now in a state that will be
        /// consistent across record and replay.
        pub(in super::super) done_initial_exec_: Cell<bool>,

        /// True while the execution of this session is visible to users.
        pub(in super::super) visible_execution_: bool,
    }

    impl Default for SessionInner {
        fn default() -> Self {
            Self::new()
        }
    }
}
