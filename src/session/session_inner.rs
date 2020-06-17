use crate::{
    address_space::WatchConfig,
    bindings::signal::siginfo_t,
    session::task::TaskSharedWeakPtr,
};

#[derive(Clone)]
pub struct BreakStatus {
    /// The triggering Task. This may be different from session->current_task()
    /// when replay switches to a new task when ReplaySession::replay_step() ends.
    /// @TODO Do we want a weak pointer here??
    pub task: TaskSharedWeakPtr,
    /// List of watchpoints hit; any watchpoint hit causes a stop after the
    /// instruction that triggered the watchpoint has completed.
    pub watchpoints_hit: Vec<WatchConfig>,
    /// When non-`None`, we stopped because a signal was delivered to `task`.
    /// DIFF NOTE: - @TODO: In rr this is a unique_ptr. Do we need to make this a Box?
    ///            - In rr None is indicated by a null
    pub signal: Option<siginfo_t>,
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
        unimplemented!()
    }

    /// True when we stopped because we hit a software or hardware breakpoint at
    /// `task`'s current ip().
    pub fn hardware_or_software_breakpoint_hit() -> bool {
        unimplemented!()
    }

    /// Returns just the data watchpoints hit.
    pub fn data_watchpoints_hit() -> Vec<WatchConfig> {
        unimplemented!()
    }

    pub fn any_break() -> bool {
        unimplemented!()
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
    use super::{BreakStatus, RunCommand};
    use crate::{
        address_space::address_space::{
            AddressSpace,
            AddressSpaceSharedPtr,
            AddressSpaceSharedWeakPtr,
        },
        bindings::ptrace::PTRACE_DETACH,
        kernel_abi::syscall_number_for_exit,
        log::LogLevel::LogDebug,
        perf_counters::TicksSemantics,
        remote_ptr::{RemotePtr, Void},
        scoped_fd::ScopedFd,
        session::{
            task::{
                task_inner::task_inner::{CapturedState, PtraceData},
                Task,
                TaskSharedPtr,
                TaskSharedWeakPtr,
            },
            SessionSharedWeakPtr,
        },
        taskish_uid::{AddressSpaceUid, ThreadGroupUid},
        thread_group::{ThreadGroup, ThreadGroupSharedPtr, ThreadGroupSharedWeakPtr},
        ticks::Ticks,
        util::is_zombie_process,
    };
    use libc::{pid_t, ESRCH};
    use nix::errno::errno;
    use std::{
        cell::{Cell, RefCell},
        collections::{BTreeMap, HashMap},
        ffi::{OsStr, OsString},
        rc::Rc,
    };

    /// AddressSpaces and ThreadGroups are indexed by their first task's TaskUid
    /// (effectively), so that if the first task dies and its tid is recycled,
    /// we don't get confused. TaskMap is indexed by tid since there can never be
    /// two Tasks with the same tid at the same time.
    pub type AddressSpaceMap = HashMap<AddressSpaceUid, AddressSpaceSharedWeakPtr>;
    pub type TaskMap = BTreeMap<pid_t, TaskSharedPtr>;
    pub type ThreadGroupMap = HashMap<ThreadGroupUid, ThreadGroupSharedWeakPtr>;

    #[derive(Copy, Clone)]
    pub enum PtraceSyscallBeforeSeccomp {
        PtraceSyscallBeforeSeccomp,
        SeccompBeforePtraceSyscall,
        PtraceSyscallBeforeSeccompUnknown,
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
    /// to an rr recorder or replayer.  During recording, the tracked
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
            self.done_initial_exec_
        }

        /// Create and return a new address space that's constructed
        /// from `t`'s actual OS address space. When spawning, `exe` is the empty
        /// string; it will be replaced during the first execve(), when we first
        /// start running real tracee code.
        /// If `exe` is not specified it is assumed to be an empty string.
        /// If `exec_count` is not specified it is assumed to be 0.
        pub fn create_vm(
            &self,
            t: TaskSharedPtr,
            maybe_exe: Option<&OsStr>,
            maybe_exec_count: Option<u32>,
        ) -> AddressSpaceSharedPtr {
            let exe = maybe_exe.unwrap_or(OsStr::new(""));
            let exec_count = maybe_exec_count.unwrap_or(0);
            self.assert_fully_initialized();
            let mut as_ = AddressSpace::new_after_execve(t.borrow_mut().as_mut(), exe, exec_count);
            as_.insert(Rc::downgrade(&t));
            let as_uid = as_.uid();
            let shr_ptr = Rc::new(RefCell::new(as_));
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
            let as_: AddressSpace;
            if self.weak_self_session.ptr_eq(vm.borrow().session_weak()) {
                as_ = AddressSpace::new_after_fork_or_session_clone(
                    self.weak_self_session.clone(),
                    &vm.borrow(),
                    t.rec_tid,
                    t.tuid().serial(),
                    0,
                );
            } else {
                let vm_uid_tid: i32;
                let vm_uid_serial: u32;
                let vm_uid_exec_count: u32;
                {
                    let vmb = vm.borrow().uid();
                    vm_uid_tid = vmb.tid();
                    vm_uid_serial = vmb.serial();
                    vm_uid_exec_count = vmb.exec_count();
                }
                as_ = AddressSpace::new_after_fork_or_session_clone(
                    self.weak_self_session.clone(),
                    &vm.borrow(),
                    vm_uid_tid,
                    vm_uid_serial,
                    vm_uid_exec_count,
                );
            }
            let as_uid = as_.uid();
            let shr_ptr = Rc::new(RefCell::new(as_));
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

            let tg = ThreadGroup::new(
                self.weak_self_session.clone(),
                None,
                rec_tid,
                tid,
                tid,
                tuid_serial,
            );
            tg.borrow_mut().insert(Rc::downgrade(&t));
            tg
        }

        pub fn next_task_serial(&self) -> u32 {
            let val = self.next_task_serial_.get();
            self.next_task_serial_.set(val + 1);
            val
        }

        /// `tasks().size()` will be zero and all the OS tasks will be
        /// gone when this returns, or this won't return.
        pub fn kill_all_tasks(&mut self) {
            for (_, t) in self.task_map.borrow().iter() {
                if !t.borrow().is_stopped {
                    // During recording we might be aborting the recording, in which case
                    // one or more tasks might not be stopped. We haven't got any really
                    // good options here so we'll just skip detaching and try killing
                    // it with SIGKILL below. rr will usually exit immediately after this
                    // so the likelihood that we'll leak a zombie task isn't too bad.
                    continue;
                }

                // Prepare to forcibly kill this task by detaching it first. To ensure
                // the task doesn't continue executing, we first set its ip() to an
                // invalid value. We need to do this for all tasks in the Session before
                // kill() is guaranteed to work properly. SIGKILL on ptrace-attached tasks
                // seems to not work very well, and after sending SIGKILL we can't seem to
                // reliably detach.
                log!(LogDebug, "safely detaching from {} ...", t.borrow().tid);
                // Detaching from the process lets it continue. We don't want a replaying
                // process to perform syscalls or do anything else observable before we
                // get around to SIGKILLing it. So we move its ip() to an address
                // which will cause it to do an exit() syscall if it runs at all.
                // We used to set this to an invalid address, but that causes a SIGSEGV
                // to be raised which can cause core dumps after we detach from ptrace.
                // Making the process undumpable with PR_SET_DUMPABLE turned out not to
                // be practical because that has a side effect of triggering various
                // security measures blocking inspection of the process (PTRACE_ATTACH,
                // access to /proc/<pid>/fd).
                // Disabling dumps via setrlimit(RLIMIT_CORE, 0) doesn't stop dumps
                // if /proc/sys/kernel/core_pattern is set to pipe the core to a process
                // (e.g. to systemd-coredump).
                // We also tried setting ip() to an address that does an infinite loop,
                // but that leaves a runaway process if something happens to kill rd
                // after detaching but before we get a chance to SIGKILL the tracee.
                let mut r = t.borrow().regs_ref().clone();
                r.set_ip(t.borrow().vm().privileged_traced_syscall_ip().unwrap());
                r.set_syscallno(syscall_number_for_exit(r.arch()) as isize);
                r.set_arg1(0);
                t.borrow_mut().set_regs(&r);
                t.borrow_mut().flush_regs();
                let mut result: isize;
                loop {
                    // We have observed this failing with an ESRCH when the thread clearly
                    // still exists and is ptraced. Retrying the PTRACE_DETACH seems to
                    // work around it.
                    result = t.borrow().fallible_ptrace(
                        PTRACE_DETACH,
                        RemotePtr::null(),
                        PtraceData::None,
                    );
                    ed_assert!(&t.borrow(), result >= 0 || errno() == ESRCH);
                    // But we it might get ESRCH because it really doesn't exist.
                    if errno() == ESRCH && is_zombie_process(t.borrow().tid) {
                        break;
                    }

                    if result >= 0 {
                        break;
                    }
                }
            }

            unimplemented!()
        }

        /// Call these functions from the objects' destructors in order
        /// to notify this session that the objects are dying.
        /// NOTE: Method is simply called on_Session::on_destroy() in rr.
        pub fn on_destroy_vm(&mut self, _vm: &AddressSpace) {
            unimplemented!()
        }
        /// NOTE: Method is simply called on_Session::on_create() in rr.
        pub fn on_create_tg(&self, _tg: ThreadGroupSharedWeakPtr) {
            unimplemented!()
        }
        /// NOTE: Method is simply called on_Session::on_destroy() in rr.
        pub fn on_destroy_tg(&mut self, _tg: &ThreadGroup) {
            unimplemented!()
        }

        /// Return the set of AddressSpaces being tracked in this session.
        pub fn vms(&self) -> Vec<&AddressSpace> {
            unimplemented!()
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
            *self.statistics_.borrow_mut()
        }

        pub fn read_spawned_task_error(&self) -> OsString {
            unimplemented!()
        }

        pub fn syscall_seccomp_ordering(&self) -> PtraceSyscallBeforeSeccomp {
            self.syscall_seccomp_ordering_
        }

        pub fn has_cpuid_faulting() -> bool {
            unimplemented!()
        }
        pub fn rd_mapping_prefix() -> &'static str {
            "/rd-shared-"
        }

        /// @TODO is the return type what we really want?
        pub fn tracee_socket_fd(&self) -> Rc<RefCell<ScopedFd>> {
            self.tracee_socket.clone()
        }
        pub fn tracee_fd_number(&self) -> i32 {
            self.tracee_socket_fd_number
        }

        pub fn ticks_semantics(&self) -> TicksSemantics {
            self.ticks_semantics_
        }

        pub(in super::super) fn new() {
            unimplemented!()
        }

        pub(in super::super) fn create_spawn_task_error_pipe(&mut self) -> ScopedFd {
            unimplemented!()
        }

        pub(in super::super) fn diagnose_debugger_trap(
            &self,
            _t: &dyn Task,
            _run_command: RunCommand,
        ) -> BreakStatus {
            unimplemented!()
        }
        pub(in super::super) fn check_for_watchpoint_changes(
            &self,
            _t: &dyn Task,
            _break_status: &BreakStatus,
        ) {
            unimplemented!()
        }

        /// XXX Move CloneCompletion/CaptureState etc to ReplayTask/ReplaySession

        pub(in super::super) fn assert_fully_initialized(&self) {
            unimplemented!()
        }
    }

    impl Drop for SessionInner {
        fn drop(&mut self) {
            unimplemented!()
        }
    }

    #[derive(Copy, Clone)]
    pub struct Statistics {
        pub bytes_written: u64,
        pub ticks_processed: Ticks,
        pub syscalls_performed: u32,
    }

    impl Statistics {
        pub fn new() -> Statistics {
            unimplemented!()
        }
    }

    /// Sessions track the global state of a set of tracees corresponding
    /// to an rr recorder or replayer.  During recording, the tracked
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
        pub(in super::super) weak_self_session: SessionSharedWeakPtr,
        /// All these members are NOT pub
        pub(in super::super) vm_map: RefCell<AddressSpaceMap>,
        pub(in super::super) task_map: RefCell<TaskMap>,
        pub(in super::super) thread_group_map: ThreadGroupMap,

        /// If non-None, data required to finish initializing the tasks of this
        /// session.
        /// @TODO is a Box required here?
        pub(in super::super) clone_completion: RefCell<Option<Box<CloneCompletion>>>,

        pub(in super::super) statistics_: RefCell<Statistics>,

        pub(in super::super) tracee_socket: Rc<RefCell<ScopedFd>>,
        pub(in super::super) tracee_socket_fd_number: i32,
        pub(in super::super) next_task_serial_: Cell<u32>,
        pub(in super::super) spawned_task_error_fd_: ScopedFd,

        pub(in super::super) syscall_seccomp_ordering_: PtraceSyscallBeforeSeccomp,

        pub(in super::super) ticks_semantics_: TicksSemantics,

        /// True if we've done an exec so tracees are now in a state that will be
        /// consistent across record and replay.
        pub(in super::super) done_initial_exec_: bool,

        /// True while the execution of this session is visible to users.
        pub(in super::super) visible_execution_: bool,
    }
}
