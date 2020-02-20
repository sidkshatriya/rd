use crate::bindings::ptrace::{
    PTRACE_CONT, PTRACE_SINGLESTEP, PTRACE_SYSCALL, PTRACE_SYSEMU, PTRACE_SYSEMU_SINGLESTEP,
};

/// @TODO temporarily define locally.
const PRELOAD_THREAD_LOCALS_SIZE: usize = 104;

pub enum CloneFlags {
    /// The child gets a semantic copy of all parent resources (and
    /// becomes a new thread group).  This is the semantics of the
    /// fork() syscall.
    CloneShareNothing = 0,
    /// Child will share the table of signal dispositions with its
    /// parent.
    CloneShareSighandlers = 1 << 0,
    /// Child will join its parent's thread group.
    CloneShareThreadGroup = 1 << 1,
    /// Child will share its parent's address space.
    CloneShareVm = 1 << 2,
    /// Child will share its parent's file descriptor table.
    CloneShareFiles = 1 << 3,
    /// Kernel will clear and notify tid futex on task exit.
    CloneCleartid = 1 << 4,
    /// Set the thread area to what's specified by the |tls| arg.
    CloneSetTls = 1 << 5,
}

/// Enumeration of ways to resume execution.  See the ptrace manual for
/// details of the semantics of these.
///
/// We define a new datatype because the PTRACE_SYSEMU* requests aren't
/// part of the official ptrace API, and we want to use a strong type
/// for these resume requests to ensure callers don't confuse their
/// arguments.
pub enum ResumeRequest {
    ResumeCont = PTRACE_CONT as isize,
    ResumeSinglestep = PTRACE_SINGLESTEP as isize,
    ResumeSyscall = PTRACE_SYSCALL as isize,
    ResumeSysemu = PTRACE_SYSEMU as isize,
    ResumeSysemuSinglestep = PTRACE_SYSEMU_SINGLESTEP as isize,
}

pub enum WaitRequest {
    /// After resuming, blocking-waitpid() until tracee status
    /// changes.
    ResumeWait,
    /// Don't wait after resuming.
    ResumeNonblocking,
}

pub enum TicksRequest {
    /// We don't expect to see any ticks (though we seem to on the odd buggy
    /// system...). Using this is a small performance optimization because we don't
    /// have to stop and restart the performance counters. This may also avoid
    /// bugs on some systems that report performance counter advances while
    /// in the kernel...
    ResumeNoTicks = -2,
    ResumeUnlimitedTicks = -1,
    /// Positive values are a request for an interrupt
    /// after that number of ticks
    /// Don't request more than this!
    MaxTicksRequest = 2000000000,
}

pub mod task {
    use super::*;
    use crate::address_space::address_space::AddressSpaceSharedPtr;
    use crate::address_space::WatchConfig;
    use crate::auto_remote_syscalls::AutoRemoteSyscalls;
    use crate::bindings::kernel::user_desc;
    use crate::extra_registers::ExtraRegisters;
    use crate::fd_table::FdTableSharedPtr;
    use crate::kernel_abi::SupportedArch;
    use crate::property_table::PropertyTable;
    use crate::registers::Registers;
    use crate::remote_code_ptr::RemoteCodePtr;
    use crate::remote_ptr::RemotePtr;
    use crate::scoped_fd::ScopedFd;
    use crate::session::Session;
    use crate::syscallbuf_record::{syscallbuf_hdr, syscallbuf_record};
    use crate::task_trait::TaskTrait;
    use crate::taskish_uid::TaskUid;
    use crate::thread_group::ThreadGroup;
    use crate::ticks::Ticks;
    use crate::wait_status::WaitStatus;
    use libc::{pid_t, siginfo_t, uid_t};
    use std::cell::RefCell;
    use std::io::Write;
    use std::rc::Rc;

    pub struct TrapReason;

    pub struct Task;

    pub type DebugRegs = Vec<WatchConfig>;

    pub type ThreadLocals = [u8; PRELOAD_THREAD_LOCALS_SIZE];

    enum WriteFlags {
        IsBreakpointRelated = 0x1,
    }

    enum CloneReason {
        /// Cloning a task in the same session due to tracee fork()/vfork()/clone()
        TraceeClone,
        /// Cloning a task into a new session as the leader for a checkpoint
        SessionCloneLeader,
        /// Cloning a task into the same session to recreate threads while
        /// restoring a checkpoint
        SessionCloneNonleader,
    }

    impl Task {
        /// We hide the destructor and require clients to call this instead. This
        /// lets us make virtual calls from within the destruction code. This
        /// does the actual PTRACE_DETACH and then calls the real destructor.
        fn destroy(&self) {
            unimplemented!()
        }

        /// This must be in an emulated syscall, entered through
        /// |cont_sysemu()| or |cont_sysemu_singlestep()|, but that's
        /// not checked.  If so, step over the system call instruction
        /// to "exit" the emulated syscall.
        pub fn finish_emulated_syscall(&self) {
            unimplemented!()
        }

        pub fn syscallbuf_data_size(&self) -> usize {
            unimplemented!()
        }

        /// Dump attributes of this process, including pending events,
        /// to |out|, which defaults to LOG_FILE.
        pub fn dump(&self, out: Option<&dyn Write>) {
            unimplemented!()
        }

        /// Called after the first exec in a session, when the session first
        /// enters a consistent state. Prior to that, the task state
        /// can vary based on how rr set up the child process. We have to flush
        /// out any state that might have been affected by that.
        pub fn flush_inconsistent_state(&self) {
            unimplemented!()
        }

        /// Return total number of ticks ever executed by this task.
        /// Updates tick count from the current performance counter values if
        /// necessary.
        pub fn tick_count(&self) -> Ticks {
            unimplemented!()
        }

        /// Stat |fd| in the context of this task's fd table.
        pub fn stat_fd(&self, fd: i32) -> libc::stat {
            unimplemented!()
        }

        /// Lstat |fd| in the context of this task's fd table.
        pub fn lstat_fd(fd: i32) -> libc::stat {
            unimplemented!()
        }

        /// Open |fd| in the context of this task's fd table.
        pub fn open_fd(&self, fd: i32, flags: i32) -> ScopedFd {
            unimplemented!()
        }

        /// Get the name of the file referenced by |fd| in the context of this
        /// task's fd table.
        pub fn file_name_of_fd(&self, fd: i32) -> String {
            unimplemented!()
        }

        /// Force the wait status of this to |status|, as if
        /// |wait()/try_wait()| had returned it. Call this whenever a waitpid
        /// returned activity for this past.
        pub fn did_waitpid(&self, status: WaitStatus) {
            unimplemented!()
        }

        /// Syscalls have side effects on registers (e.g. setting the flags register).
        /// Perform those side effects on |registers| to make it look like a syscall
        /// happened.
        pub fn canonicalize_regs(&self, syscall_arch: SupportedArch) {
            unimplemented!()
        }

        /// Return the ptrace message pid associated with the current ptrace
        /// event, f.e. the new child's pid at PTRACE_EVENT_CLONE.
        pub fn get_ptrace_eventmsg<T>(&self) -> T {
            unimplemented!()
        }

        /// Return the siginfo at the signal-stop of this.
        /// Not meaningful unless this is actually at a signal stop.
        pub fn get_siginfo(&self) -> siginfo_t {
            unimplemented!()
        }

        /// Destroy in the tracee task the scratch buffer and syscallbuf (if
        /// syscallbuf_child is non-null).
        /// This task must already be at a state in which remote syscalls can be
        /// executed; if it's not, results are undefined.
        pub fn destroy_buffers(&self) {
            unimplemented!()
        }

        pub fn unmap_buffers_for(
            &self,
            remote: &AutoRemoteSyscalls,
            t: &Task,
            saved_syscallbuf_child: RemotePtr<syscallbuf_hdr>,
        ) {
            unimplemented!()
        }

        pub fn close_buffers_for(&self, remote: &AutoRemoteSyscalls, t: &Task) {
            unimplemented!()
        }

        pub fn next_syscallbuf_record(&self) -> RemotePtr<syscallbuf_record> {
            unimplemented!()
        }
        pub fn stored_record_size(&self, record: RemotePtr<syscallbuf_record>) -> usize {
            unimplemented!()
        }

        /// Return the current $ip of this.
        pub fn ip(&self) -> RemoteCodePtr {
            unimplemented!()
        }

        /// Emulate a jump to a new IP, updating the ticks counter as appropriate.
        pub fn emulate_jump(&self, ptr: RemoteCodePtr) {
            unimplemented!()
        }

        /// Return true if this is at an arm-desched-event or
        /// disarm-desched-event syscall.
        pub fn is_desched_event_syscall(&self) -> bool {
            unimplemented!()
        }

        /// Return true when this task is in a traced syscall made by the
        /// syscallbuf code. Callers may assume |is_in_syscallbuf()|
        /// is implied by this. Note that once we've entered the traced syscall,
        /// ip() is immediately after the syscall instruction.
        pub fn is_in_traced_syscall(&self) -> bool {
            unimplemented!()
        }

        pub fn is_at_traced_syscall_entry(&self) -> bool {
            unimplemented!()
        }

        /// Return true when this task is in an untraced syscall, i.e. one
        /// initiated by a function in the syscallbuf. Callers may
        /// assume |is_in_syscallbuf()| is implied by this. Note that once we've
        /// entered the traced syscall, ip() is immediately after the syscall
        /// instruction.
        pub fn is_in_untraced_syscall(&self) -> bool {
            unimplemented!()
        }

        pub fn is_in_rr_page(&self) -> bool {
            unimplemented!()
        }

        /// Return true if |ptrace_event()| is the trace event
        /// generated by the syscallbuf seccomp-bpf when a traced
        /// syscall is entered.
        pub fn is_ptrace_seccomp_event(&self) -> bool {
            unimplemented!()
        }

        /// Assuming ip() is just past a breakpoint instruction, adjust
        /// ip() backwards to point at that breakpoint insn.
        pub fn move_ip_before_breakpoint(&self) {
            unimplemented!()
        }

        /// Assuming we've just entered a syscall, exit that syscall and reset
        /// state to reenter the syscall just as it was called the first time.
        /// Returns false if we see the process exit instead.
        pub fn exit_syscall_and_prepare_restart(&self) -> bool {
            unimplemented!()
        }

        /// We're currently in user-space with registers set up to perform a system
        /// call. Continue into the kernel and stop where we can modify the syscall
        /// state.
        pub fn enter_syscall(&self) {
            unimplemented!()
        }

        /// We have observed entry to a syscall (either by PTRACE_EVENT_SECCOMP or
        /// a syscall, depending on the value of Session::syscall_seccomp_ordering()).
        /// Continue into the kernel to perform the syscall and stop at the
        /// PTRACE_SYSCALL syscall-exit trap. Returns false if we see the process exit
        /// before that.
        pub fn exit_syscall(&self) -> bool {
            unimplemented!()
        }

        /// Return the "task name"; i.e. what |prctl(PR_GET_NAME)| or
        /// /proc/tid/comm would say that the task's name is.
        pub fn name(&self) -> String {
            unreachable!()
        }

        /// Call this method when this task has just performed an |execve()|
        /// (so we're in the new address space), but before the system call has
        /// returned.
        pub fn post_exec(&self, exe_file: &str) {
            unimplemented!()
        }

        /// Call this method when this task has exited a successful execve() syscall.
        /// At this point it is safe to make remote syscalls.
        pub fn post_exec_syscall(&self) {
            unimplemented!()
        }

        /// Return true if this task has execed.
        pub fn execed(&self) -> bool {
            unimplemented!()
        }

        /// Read |N| bytes from |child_addr| into |buf|, or don't
        /// return.
        pub fn read_bytes(&self, child_addr: RemotePtr<u8>, buf: &mut [u8]) {
            unimplemented!()
        }

        /// Return the current regs of this.
        pub fn regs(&self) -> &Registers {
            unimplemented!()
        }

        /// Return the extra registers of this.
        pub fn extra_regs(&self) -> &ExtraRegisters {
            unimplemented!()
        }

        /// Return the current arch of this. This can change due to exec(). */
        pub fn arch(&self) -> SupportedArch {
            unimplemented!()
        }

        /// Return the debug status (DR6 on x86). The debug status is always cleared
        /// in resume_execution() before we resume, so it always only reflects the
        /// events since the last resume.
        pub fn debug_status(&self) -> usize {
            unimplemented!()
        }

        /// Set the debug status (DR6 on x86).
        pub fn set_debug_status(&self, status: usize) {
            unimplemented!()
        }

        /// Determine why a SIGTRAP occurred. Uses debug_status() but doesn't
        /// consume it.
        pub fn compute_trap_reasons(&self) -> TrapReason {
            unimplemented!()
        }

        /// Read |val| from |child_addr|.
        /// If the data can't all be read, then if |ok| is non-null
        /// sets *ok to false, otherwise asserts.
        pub fn read_val_mem<T>(&self, child_addr: RemotePtr<T>, ok: Option<&mut bool>) {
            unimplemented!()
        }

        /// Read |count| values from |child_addr|.
        pub fn read_mem<T>(
            &self,
            child_addr: RemotePtr<T>,
            count: usize,
            ok: Option<&mut bool>,
        ) -> Vec<T> {
            unimplemented!()
        }

        /// Read and return the C string located at |child_addr| in
        /// this address space.
        pub fn read_c_str(&self, child_addr: RemotePtr<u8>) -> String {
            unimplemented!()
        }

        /// Resume execution |how|, deliverying |sig| if nonzero.
        /// After resuming, |wait_how|. In replay, reset hpcs and
        /// request a tick period of tick_period. The default value
        /// of tick_period is 0, which means effectively infinite.
        /// If interrupt_after_elapsed is nonzero, we interrupt the task
        /// after that many seconds have elapsed.
        ///
        /// All tracee execution goes through here.
        pub fn resume_execution(
            &self,
            how: ResumeRequest,
            wait_how: WaitRequest,
            tick_period: TicksRequest,
            sig: Option<i32>,
        ) {
            unimplemented!()
        }

        /// Return the session this is part of.
        pub fn session(&self) -> &Session {
            unimplemented!()
        }

        /// Set the tracee's registers to |regs|. Lazy.
        pub fn set_regs(&self, regs: &Registers) {
            unimplemented!()
        }

        /// Ensure registers are flushed back to the underlying task.
        pub fn flush_regs(&self) {
            unimplemented!()
        }

        /** Set the tracee's extra registers to |regs|. */
        pub fn set_extra_regs(&self, regs: &ExtraRegisters) {
            unimplemented!()
        }

        /// Program the debug registers to the vector of watchpoint
        /// configurations in |reg| (also updating the debug control
        /// register appropriately).  Return true if all registers were
        /// successfully programmed, false otherwise.  Any time false
        /// is returned, the caller is guaranteed that no watchpoint
        /// has been enabled; either all of |regs| is enabled and true
        /// is returned, or none are and false is returned.
        pub fn set_debug_regs(&self, regs: &DebugRegs) -> bool {
            unimplemented!()
        }

        /// @TODO should this be a GdbRegister type?
        pub fn get_debug_reg(&self, regno: usize) -> usize {
            unimplemented!()
        }

        pub fn set_debug_reg(&self, regno: usize, value: usize) {
            unimplemented!()
        }

        /// Update the thread area to |addr|.
        pub fn set_thread_area(&self, tls: RemotePtr<user_desc>) {
            unimplemented!()
        }

        /// Set the thread area at index `idx` to desc and reflect this
        /// into the OS task. Returns 0 on success, errno otherwise.
        pub fn emulate_set_thread_area(&self, idx: i32, desc: user_desc) {
            unimplemented!()
        }

        /// Get the thread area from the remote process.
        /// Returns 0 on success, errno otherwise.
        pub fn emulate_get_thread_area(&self, idx: i32, desc: &mut user_desc) -> i32 {
            unimplemented!()
        }

        pub fn thread_areas(&self) -> Vec<user_desc> {
            unimplemented!()
        }

        pub fn set_status(&self, status: WaitStatus) {
            unimplemented!()
        }

        /// Return true when the task is running, false if it's stopped.
        pub fn is_running(&self) -> bool {
            unimplemented!()
        }

        /// Return the status of this as of the last successful wait()/try_wait() call.
        pub fn status(&self) -> WaitStatus {
            unimplemented!()
        }

        /// Return the ptrace event as of the last call to |wait()/try_wait()|.
        pub fn ptrace_event(&self) -> i32 {
            unimplemented!()
        }

        /// Return the signal that's pending for this as of the last
        /// call to |wait()/try_wait()|.  Return of `None` means "no signal".
        pub fn stop_sig(&self) -> Option<i32> {
            unimplemented!()
        }

        pub fn clear_wait_status(&self) {
            unimplemented!()
        }

        /// Return the thread group this belongs to.
        pub fn thread_group(&self) -> Rc<RefCell<ThreadGroup>> {
            unimplemented!()
        }

        /// Return the id of this task's recorded thread group. */
        pub fn tgid(&self) -> pid_t {
            unimplemented!()
        }
        /// Return id of real OS thread group. */
        pub fn real_tgid(&self) -> pid_t {
            unimplemented!()
        }

        pub fn tuid(&self) -> TaskUid {
            unimplemented!()
        }

        /// Return the dir of the trace we're using.
        pub fn trace_dir(&self) -> String {
            unimplemented!()
        }

        /// Get the current "time" measured as ticks on recording trace
        /// events.  |task_time()| returns that "time" wrt this task
        /// only.
        /// @TODO should we be returning some other type?
        pub fn trace_time(&self) -> u32 {
            unimplemented!()
        }

        /// Call this after the tracee successfully makes a
        /// |prctl(PR_SET_NAME)| call to change the task name to the
        /// string pointed at in the tracee's address space by
        /// |child_addr|.
        pub fn update_prname(&self, child_addr: RemotePtr<u8>) {
            unimplemented!()
        }

        /// Call this to reset syscallbuf_hdr->num_rec_bytes and zero out the data
        /// recorded in the syscall buffer. This makes for more deterministic behavior
        /// especially during replay, where during checkpointing we only save and
        /// restore the recorded data area.
        pub fn reset_syscallbuf(&self) {
            unimplemented!()
        }

        /// Return the virtual memory mapping (address space) of this
        /// task.
        pub fn vm(&self) -> AddressSpaceSharedPtr {
            unimplemented!()
        }

        pub fn fd_table(&self) -> FdTableSharedPtr {
            unimplemented!()
        }

        /// Block until the status of this changes. wait() expects the wait to end
        /// with the process in a stopped() state. If interrupt_after_elapsed > 0,
        /// interrupt the task after that many seconds have elapsed.
        pub fn wait(&self, interrupt_after_elapsed: Option<f64>) {
            unimplemented!()
        }

        /// Return true if the status of this has changed, but don't
        /// block.
        pub fn try_wait(&self) -> bool {
            unimplemented!()
        }

        /// Return true if an unexpected exit was already detected for this task and
        /// it is ready to be reported.
        pub fn wait_unexpected_exit(&self) -> bool {
            unimplemented!()
        }

        /// Currently we don't allow recording across uid changes, so we can
        /// just return rd's uid.
        pub fn getuid(&self) -> uid_t {
            unimplemented!()
        }

        /// Write |N| bytes from |buf| to |child_addr|, or don't return.
        pub fn write_bytes(&self, child_addr: RemotePtr<u8>, buf: &[u8]) {
            unimplemented!()
        }

        /// Write |val| to |child_addr|.
        pub fn write_val_mem<T>(
            &self,
            child_addr: RemotePtr<T>,
            val: &T,
            ok: Option<&mut bool>,
            flags: u32,
        ) {
            unimplemented!()
        }

        pub fn write_mem<T>(
            &self,
            child_addr: RemotePtr<T>,
            val: &[T],
            count: usize,
            ok: Option<&mut bool>,
        ) {
            unimplemented!()
        }

        /// Don't use these helpers directly; use the safer and more
        /// convenient variants above.
        ///
        /// Read/write the number of bytes that the template wrapper
        /// inferred.
        /// @TODO why is this returning a signed value?
        pub fn read_bytes_fallible(&self, addr: RemotePtr<u8>, buf: &[u8]) -> isize {
            unimplemented!()
        }

        /// If the data can't all be read, then if |ok| is non-null, sets *ok to
        /// false, otherwise asserts.
        pub fn read_bytes_helper(&self, addr: RemotePtr<u8>, buf: &[u8], ok: Option<&mut bool>) {
            unimplemented!()
        }

        /// |flags| is bits from WriteFlags.
        pub fn write_bytes_helper(
            &self,
            addr: RemotePtr<u8>,
            buf: &[u8],
            ok: Option<&mut bool>,
            flags: Option<u32>,
        ) {
            unimplemented!()
        }

        pub fn detect_syscall_arch(&self) -> SupportedArch {
            unimplemented!()
        }

        /// Call this when performing a clone syscall in this task. Returns
        /// true if the call completed, false if it was interrupted and
        /// needs to be resumed. When the call returns true, the task is
        /// stopped at a PTRACE_EVENT_CLONE or PTRACE_EVENT_FORK.
        pub fn clone_syscall_is_complete(
            &self,
            pid: &mut pid_t,
            syscall_arch: SupportedArch,
        ) -> bool {
            unimplemented!()
        }

        /// Open /proc/[tid]/mem fd for our AddressSpace, closing the old one
        /// first. If necessary we force the tracee to open the file
        /// itself and smuggle the fd back to us.
        /// Returns false if the process no longer exists.
        pub fn open_mem_fd(&self) -> bool {
            unimplemented!()
        }

        /// Calls open_mem_fd if this task's AddressSpace doesn't already have one.
        pub fn open_mem_fd_if_needed(&self) {
            unimplemented!()
        }

        /// Lock or unlock the syscallbuf to prevent the preload library from using it.
        /// Only has an effect if the syscallbuf has been initialized.
        pub fn set_syscallbuf_locked(&self, locked: bool) {
            unimplemented!()
        }

        /// Like |fallible_ptrace()| but infallible for most purposes.
        /// Errors other than ESRCH are treated as fatal. Returns false if
        /// we got ESRCH. This can happen any time during recording when the
        /// task gets a SIGKILL from outside.
        /// @TODO param data
        pub fn ptrace_if_alive(&self, request: i32, addr: RemotePtr<u8>, data: &[u8]) -> bool {
            unimplemented!()
        }

        pub fn is_dying(&self) -> bool {
            unimplemented!()
        }

        pub fn last_execution_resume(&self) -> RemoteCodePtr {
            unimplemented!()
        }

        pub fn properties(&self) -> &PropertyTable {
            unimplemented!()
        }
        pub fn usable_scratch_size(&self) {
            unimplemented!()
        }
        pub fn syscallbuf_alt_stack(&self) -> RemotePtr<u8> {
            unimplemented!()
        }
        pub fn setup_preload_thread_locals(&self) {
            unimplemented!()
        }
        pub fn setup_preload_thread_locals_from_clone(&self, origin: &Task) {
            unimplemented!()
        }
        pub fn fetch_preload_thread_locals(&self) -> &ThreadLocals {
            unimplemented!()
        }
        pub fn activate_preload_thread_locals(&self) {
            unimplemented!()
        }
    }
}
