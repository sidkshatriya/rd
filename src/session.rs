use crate::address_space::WatchConfig;
use crate::task::task::Task;
use libc::siginfo_t;

#[derive(Clone)]
pub struct BreakStatus {
    /// The triggering Task. This may be different from session->current_task()
    /// when replay switches to a new task when ReplaySession::replay_step() ends.
    pub task: *mut Task,
    /// List of watchpoints hit; any watchpoint hit causes a stop after the
    /// instruction that triggered the watchpoint has completed.
    pub watchpoints_hit: Vec<WatchConfig>,
    /// When non-null, we stopped because a signal was delivered to |task|.
    /// @TODO does this really need to be a Box?
    pub signal: Box<siginfo_t>,
    /// True when we stopped because we hit a software breakpoint at |task|'s
    /// current ip().
    pub breakpoint_hit: bool,
    /// True when we stopped because a singlestep completed in |task|.
    pub singlestep_complete: bool,
    /// True when we stopped because we got too close to the specified ticks
    /// target.
    pub approaching_ticks_target: bool,
    /// True when we stopped because |task| is about to exit.
    pub task_exit: bool,
}

/// In general, multiple break reasons can apply simultaneously.
impl BreakStatus {
    pub fn new() {
        unimplemented!()
    }

    /// True when we stopped because we hit a software or hardware breakpoint at
    /// |task|'s current ip().
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

#[derive(Copy, Clone)]
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

pub fn is_singlestep(command: RunCommand) -> bool {
    unimplemented!()
}

pub mod session {
    use super::BreakStatus;
    use super::RunCommand;
    use crate::address_space::address_space::{AddressSpace, AddressSpaceSharedPtr, Mapping};
    use crate::address_space::kernel_mapping::KernelMapping;
    use crate::auto_remote_syscalls::AutoRemoteSyscalls;
    use crate::emu_fs::EmuFs;
    use crate::monitored_shared_memory::MonitoredSharedMemorySharedPtr;
    use crate::perf_counters::TicksSemantics;
    use crate::remote_ptr::RemotePtr;
    use crate::scoped_fd::ScopedFd;
    use crate::task::task::{CapturedState, Task};
    use crate::taskish_uid::{AddressSpaceUid, TaskUid, ThreadGroupUid};
    use crate::thread_group::{ThreadGroup, ThreadGroupSharedPtr};
    use crate::ticks::Ticks;
    use libc::pid_t;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    /// AddressSpaces and ThreadGroups are indexed by their first task's TaskUid
    /// (effectively), so that if the first task dies and its tid is recycled,
    /// we don't get confused. TaskMap is indexed by tid since there can never be
    /// two Tasks with the same tid at the same time.
    pub type AddressSpaceMap = HashMap<AddressSpaceUid, *mut AddressSpace>;
    pub type TaskMap = HashMap<pid_t, *mut Task>;
    pub type ThreadGroupMap = HashMap<ThreadGroupUid, *mut ThreadGroup>;

    #[derive(Copy, Clone)]
    pub enum PreserveContents {
        PreserveContents,
        DiscardContents,
    }

    #[derive(Copy, Clone)]
    pub enum PtraceSyscallBeforeSeccomp {
        PtraceSyscallBeforeSeccomp,
        SeccompBeforePtraceSyscall,
        PtraceSyscallBeforeSeccompUnknown,
    }

    /// struct is NOT pub
    #[derive(Clone)]
    struct AddressSpaceClone {
        pub clone_leader: *mut Task,
        pub clone_leader_state: CapturedState,
        pub member_states: Vec<CapturedState>,
        pub captured_memory: Vec<(RemotePtr<u8>, Vec<u8>)>,
    }

    /// struct is NOT pub
    #[derive(Clone)]
    struct CloneCompletion {
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
    impl Session {
        /// Call |post_exec()| immediately after a tracee has successfully
        /// |execve()|'d.  After that, |done_initial_exec()| returns true.
        /// This is called while we're still in the execve syscall so it's not safe
        /// to perform remote syscalls in this method.
        ///
        /// Tracee state can't be validated before the first exec,
        /// because the address space inside the rr process for |rr
        /// replay| will be different than it was for |rr record|.
        /// After the first exec, we're running tracee code, and
        /// everything must be the same.
        pub fn post_exec(&mut self) {
            unimplemented!()
        }

        /// Returns true after the tracee has done the initial exec in Task::spawn.
        /// Before then, tracee state can be inconsistent; from the exec exit-event
        /// onwards, the tracee state much be consistent.
        pub fn done_initial_exec(&self) -> bool {
            self.done_initial_exec_
        }

        /// Create and return a new address space that's constructed
        /// from |t|'s actual OS address space. When spawning, |exe| is the empty
        /// string; it will be replaced during the first execve(), when we first
        /// start running real tracee code.
        /// If |exe| is not specified it is assumed to be an empty string.
        /// If |exec_count| is not specified it is assumed to be 0.
        pub fn create_vm(
            &mut self,
            t: &Task,
            exe: Option<&str>,
            exec_count: Option<u32>,
        ) -> AddressSpaceSharedPtr {
            unimplemented!()
        }

        /// Return a copy of |vm| with the same mappings.  If any
        /// mapping is changed, only the |clone()|d copy is updated,
        /// not its origin (i.e. copy-on-write semantics).
        /// NOTE: Called simply Session::clone() in rr
        pub fn clone_vm(&mut self, t: &Task, vm: AddressSpaceSharedPtr) -> AddressSpaceSharedPtr {
            unimplemented!()
        }

        /// Create the initial thread group.
        pub fn create_initial_tg(&mut self, t: &Task) -> ThreadGroupSharedPtr {
            unimplemented!()
        }

        /// Return a copy of |tg| with the same mappings.
        /// NOTE: Called simply Session::clone() in rr
        pub fn clone_tg(&mut self, t: &Task, tg: ThreadGroupSharedPtr) -> ThreadGroupSharedPtr {
            unimplemented!()
        }

        /// See Task::clone().
        /// This method is simply called Session::clone in rr.
        pub fn clone_task(
            &mut self,
            p: &Task,
            flags: i32,
            stack: RemotePtr<u8>,
            tls: RemotePtr<u8>,
            cleartid_addr: RemotePtr<i32>,
            new_tid: pid_t,
            new_rec_tid: Option<pid_t>,
        ) -> &Task {
            unimplemented!()
        }

        pub fn next_task_serial(&mut self) -> u32 {
            self.next_task_serial_ += 1;
            self.next_task_serial_
        }

        /// Return the task created with |rec_tid|, or None if no such
        /// task exists.
        /// NOTE: Method is simply called Session::find task() in rr
        pub fn find_task_from_rec_tid(&self, rec_tid: pid_t) -> Option<&Task> {
            unimplemented!()
        }

        /// NOTE: Method is simply called Session::find task() in rr
        pub fn find_task_from_task_uid(&self, tuid: &TaskUid) -> Option<&Task> {
            unimplemented!()
        }

        /// Return the thread group whose unique ID is |tguid|, or None if no such
        /// thread group exists.
        /// NOTE: Method is simply called Session::find thread_group() in rr
        pub fn find_thread_group_from_tguid(&self, tguid: &ThreadGroupUid) -> Option<&ThreadGroup> {
            unimplemented!()
        }

        /// Find the thread group for a specific pid
        /// NOTE: Method is simply called Session::find thread_group() in rr
        pub fn find_thread_group_from_pid(&self, pid: pid_t) -> Option<&ThreadGroup> {
            unimplemented!()
        }

        /// Return the AddressSpace whose unique ID is |vmuid|, or None if no such
        /// address space exists.
        pub fn find_address_space(&self, vmuid: &AddressSpaceUid) -> Option<&AddressSpace> {
            unimplemented!()
        }

        /// |tasks().size()| will be zero and all the OS tasks will be
        /// gone when this returns, or this won't return.
        pub fn kill_all_tasks(&mut self) {
            unimplemented!()
        }

        /// Call these functions from the objects' destructors in order
        /// to notify this session that the objects are dying.
        /// NOTE: Method is simply called on_Session::on_destroy() in rr.
        pub fn on_destroy_vm(&mut self, vm: &AddressSpace) {
            unimplemented!()
        }
        /// NOTE: Method is simply called on_Session::on_create() in rr.
        pub fn on_create_tg(&mut self, tg: &ThreadGroup) {
            unimplemented!()
        }
        /// NOTE: Method is simply called on_Session::on_destroy() in rr.
        pub fn on_destroy_tg(&mut self, tg: &ThreadGroup) {
            unimplemented!()
        }

        /// Return the set of Tasks being traced in this session.
        /// @TODO shouldn't need for this to be mutable but it is due to finish_initializing()
        pub fn tasks(&mut self) -> &TaskMap {
            self.finish_initializing();
            &self.task_map
        }

        /// Return the set of AddressSpaces being tracked in this session.
        pub fn vms(&self) -> Vec<&AddressSpace> {
            unimplemented!()
        }

        pub fn is_recording(&self) -> bool {
            unimplemented!()
        }
        pub fn is_replaying(&self) -> bool {
            unimplemented!()
        }
        pub fn is_diversion(&self) -> bool {
            unimplemented!()
        }

        pub fn visible_execution(&self) -> bool {
            self.visible_execution_
        }
        pub fn set_visible_execution(&mut self, visible: bool) {
            self.visible_execution_ = visible
        }
        pub fn accumulate_bytes_written(&mut self, bytes_written: u64) {
            self.statistics_.bytes_written += bytes_written
        }
        pub fn accumulate_syscall_performed(&mut self) {
            self.statistics_.syscalls_performed += 1
        }
        pub fn accumulate_ticks_processed(&mut self, ticks: Ticks) {
            self.statistics_.ticks_processed += ticks;
        }
        pub fn statistics(&self) -> Statistics {
            self.statistics_
        }

        pub fn read_spawned_task_error(&self) -> String {
            unimplemented!()
        }

        /// If None is provided for |tracee_prot|, PROT_READ | PROT_WRITE is assumed.
        /// If None is provided for |tracee_flags|, 0 is assumed
        /// If None is provided for |monitored| it is assumed that there is no memory monitor.
        pub fn create_shared_mmap(
            remote: &AutoRemoteSyscalls,
            size: usize,
            map_hint: RemotePtr<u8>,
            name: &str,
            tracee_prot: Option<i32>,
            tracee_flags: Option<i32>,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) -> KernelMapping {
            unimplemented!()
        }

        /// As this stands, it looks to be a move as far as m is concerned.
        pub fn make_private_shared(remote: &AutoRemoteSyscalls, m: Mapping) -> bool {
            unimplemented!()
        }

        /// Recreate an mmap region that is shared between rr and the tracee. The
        /// caller
        /// is responsible for recreating the data in the new mmap, if `preserve` is
        /// DiscardContents.
        /// OK to call this while 'm' references one of the mappings in remote's
        /// AddressSpace
        /// If None is provided for |preserve| then DISCARD_CONTENTS is assumed
        /// If None is provided for |monitored| it is assumed that there is no memory monitor.
        /// @TODO figure out lifetime
        pub fn recreate_shared_mmap<'a>(
            remote: &AutoRemoteSyscalls,
            m: &Mapping,
            preserve: Option<PreserveContents>,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) -> &'a Mapping {
            unimplemented!()
        }

        /// Takes a mapping and replaces it by one that is shared between rr and
        /// the tracee. The caller is responsible for filling the contents of the
        /// new mapping.
        /// If None is provided for |monitored| it is assumed that there is no memory monitor.
        /// @TODO figure out lifetime
        pub fn steal_mapping<'a>(
            remote: &AutoRemoteSyscalls,
            m: &Mapping,
            monitored: Option<MonitoredSharedMemorySharedPtr>,
        ) -> &'a Mapping {
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

        fn new() {
            unimplemented!()
        }

        fn create_spawn_task_error_pipe(&mut self) -> ScopedFd {
            unimplemented!()
        }

        fn diagnose_debugger_trap(&self, t: &Task, run_command: RunCommand) -> BreakStatus {
            unimplemented!()
        }
        fn check_for_watchpoint_changes(&self, t: &Task, break_status: &BreakStatus) {
            unimplemented!()
        }

        /// NOTE: called Session::copy_state_to() in rr.
        fn copy_state_to_session(&self, dest: &Session, emu_fs: &EmuFs, dest_emu_fs: EmuFs) {
            unimplemented!()
        }

        /// XXX Move CloneCompletion/CaptureState etc to ReplayTask/ReplaySession

        /// Call this before doing anything that requires access to the full set
        /// of tasks (i.e., almost anything!).
        fn finish_initializing(&mut self) {
            unimplemented!()
        }
        fn assert_fully_initialized(&self) {
            unimplemented!()
        }
    }

    impl Drop for Session {
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
    pub struct Session {
        /// All these members are NOT pub
        vm_map: AddressSpaceMap,
        task_map: TaskMap,
        thread_group_map: ThreadGroupMap,

        /// If non-None, data required to finish initializing the tasks of this
        /// session.
        /// @TODO is a Box required here?
        clone_completion: Option<Box<CloneCompletion>>,

        statistics_: Statistics,

        tracee_socket: Rc<RefCell<ScopedFd>>,
        tracee_socket_fd_number: i32,
        next_task_serial_: u32,
        spawned_task_error_fd_: ScopedFd,

        syscall_seccomp_ordering_: PtraceSyscallBeforeSeccomp,

        ticks_semantics_: TicksSemantics,

        /// True if we've done an exec so tracees are now in a state that will be
        /// consistent across record and replay.
        done_initial_exec_: bool,

        /// True while the execution of this session is visible to users.
        visible_execution_: bool,
    }
}
