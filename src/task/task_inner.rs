use crate::bindings::ptrace::{
    PTRACE_CONT, PTRACE_SINGLESTEP, PTRACE_SYSCALL, PTRACE_SYSEMU, PTRACE_SYSEMU_SINGLESTEP,
};

use crate::kernel_abi::common::preload_interface::PRELOAD_THREAD_LOCALS_SIZE;

#[derive(Copy, Clone, Debug)]
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
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum ResumeRequest {
    ResumeCont = PTRACE_CONT,
    ResumeSinglestep = PTRACE_SINGLESTEP,
    ResumeSyscall = PTRACE_SYSCALL,
    ResumeSysemu = PTRACE_SYSEMU,
    ResumeSysemuSinglestep = PTRACE_SYSEMU_SINGLESTEP,
}

#[derive(Copy, Clone, Debug)]
pub enum WaitRequest {
    /// After resuming, blocking-waitpid() until tracee status
    /// changes.
    ResumeWait,
    /// Don't wait after resuming.
    ResumeNonblocking,
}

#[derive(Copy, Clone, Debug)]
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

pub mod task_inner {
    use super::*;
    use crate::address_space::address_space::AddressSpaceSharedPtr;
    use crate::address_space::kernel_mapping::KernelMapping;
    use crate::address_space::WatchConfig;
    use crate::auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem};
    use crate::bindings::kernel::user_desc;
    use crate::extra_registers::ExtraRegisters;
    use crate::fd_table::FdTableSharedPtr;
    use crate::kernel_abi::common::preload_interface::preload_globals;
    use crate::kernel_abi::common::preload_interface::{syscallbuf_hdr, syscallbuf_record};
    use crate::kernel_abi::SupportedArch;
    use crate::kernel_abi::{syscall_number_for_close, syscall_number_for_openat};
    use crate::log::LogLevel::{LogInfo, LogWarn};
    use crate::perf_counters::PerfCounters;
    use crate::property_table::PropertyTable;
    use crate::rd::RD_RESERVED_ROOT_DIR_FD;
    use crate::registers::Registers;
    use crate::remote_code_ptr::RemoteCodePtr;
    use crate::remote_ptr::{RemotePtr, Void};
    use crate::scoped_fd::ScopedFd;
    use crate::session::{Session, SessionSharedPtr, SessionSharedWeakPtr};
    use crate::task::{Task, TaskSharedWeakPtr};
    use crate::taskish_uid::TaskUid;
    use crate::thread_group::{ThreadGroup, ThreadGroupSharedPtr};
    use crate::ticks::Ticks;
    use crate::trace_stream::TraceStream;
    use crate::util::TrappedInstruction;
    use crate::wait_status::WaitStatus;
    use libc::ESRCH;
    use libc::{pid_t, siginfo_t, uid_t};
    use nix::fcntl::OFlag;
    use nix::unistd::getuid;
    use std::cell::RefCell;
    use std::convert::TryInto;
    use std::ffi::CString;
    use std::mem::size_of;
    use std::os::raw::c_long;
    use std::path::Path;
    use std::rc::Rc;

    pub struct TrapReason;
    type ThreadLocals = [u8; PRELOAD_THREAD_LOCALS_SIZE];

    /// This struct should NOT impl the Task trait
    pub struct TaskInner {
        /// Imagine that task A passes buffer |b| to the read()
        /// syscall.  Imagine that, after A is switched out for task B,
        /// task B then writes to |b|.  Then B is switched out for A.
        /// Since rr doesn't schedule the kernel code, the result is
        /// nondeterministic.  To avoid that class of replay
        /// divergence, we "redirect" (in)outparams passed to may-block
        /// syscalls, to "scratch memory".  The kernel writes to
        /// scratch deterministically, and when A (in the example
        /// above) exits its read() syscall, rr copies the scratch data
        /// back to the original buffers, serializing A and B in the
        /// example above.
        ///
        /// Syscalls can "nest" due to signal handlers.  If a syscall A
        /// is interrupted by a signal, and the sighandler calls B,
        /// then we can have scratch buffers set up for args of both A
        /// and B.  In linux, B won't actually re-enter A; A is exited
        /// with a "will-restart" error code and its args are saved for
        /// when (or if) it's restarted after the signal.  But that
        /// doesn't really matter wrt scratch space.  (TODO: in the
        /// future, we may be able to use that fact to simplify
        /// things.)
        ///
        /// Because of nesting, at first blush it seems we should push
        /// scratch allocations onto a stack and pop them as syscalls
        /// (or restarts thereof) complete.  But under a critical
        /// assumption, we can actually skip that.  The critical
        /// assumption is that the kernel writes its (in)outparams
        /// atomically wrt signal interruptions, and only writes them
        /// on successful exit.  Each syscall will complete in stack
        /// order, and it's invariant that the syscall processors must
        /// only write back to user buffers///only* the data that was
        /// written by the kernel.  So as long as the atomicity
        /// assumption holds, the completion of syscalls higher in the
        /// event stack may overwrite scratch space, but the completion
        /// of each syscall will overwrite those overwrites again, and
        /// that over-overwritten data is exactly and only what we'll
        /// write back to the tracee.
        ///
        /// |scratch_ptr| points at the mapped address in the child,
        /// and |size| is the total available space.
        pub scratch_ptr: RemotePtr<Void>,
        /// The full size of the scratch buffer.
        /// The last page of the scratch buffer is used as an alternate stack
        /// for the syscallbuf code. So the usable size is less than this.
        pub scratch_size: isize,

        /// The child's desched counter event fd number
        pub desched_fd_child: i32,
        /// The child's cloned_file_data_fd
        pub cloned_file_data_fd_child: i32,

        pub hpc: PerfCounters,

        /// This is always the "real" tid of the tracee.
        pub tid: pid_t,
        /// This is always the recorded tid of the tracee.  During
        /// recording, it's synonymous with |tid|, and during replay
        /// it's the tid that was recorded.
        pub rec_tid: pid_t,

        pub syscallbuf_size: usize,
        /// Points at the tracee's mapping of the buffer.
        pub syscallbuf_child: RemotePtr<syscallbuf_hdr>,
        /// XXX Move these fields to ReplayTask
        pub stopping_breakpoint_table: RemoteCodePtr,
        pub stopping_breakpoint_table_entry_size: i32,

        pub preload_globals: RemotePtr<preload_globals>,
        pub thread_locals: ThreadLocals,

        /// These are private
        serial: u32,
        /// The address space of this task.
        as_: AddressSpaceSharedPtr,
        /// The file descriptor table of this task.
        fds: FdTableSharedPtr,
        /// Task's OS name.
        prname: String,
        /// Count of all ticks seen by this task since tracees became
        /// consistent and the task last wait()ed.
        ticks: Ticks,
        /// When |is_stopped|, these are our child registers.
        registers: Registers,
        /// Where we last resumed execution
        address_of_last_execution_resume: RemoteCodePtr,
        how_last_execution_resumed: ResumeRequest,
        /// In certain circumstances, due to hardware bugs, we need to fudge the
        /// cx register. If so, we record the orginal value here. See comments in
        /// Task.cc
        last_resume_orig_cx: u64,
        /// The instruction type we're singlestepping through.
        singlestepping_instruction: TrappedInstruction,
        /// True if we set a breakpoint after a singlestepped CPUID instruction.
        /// We need this in addition to `singlestepping_instruction` because that
        /// might be CPUID but we failed to set the breakpoint.
        did_set_breakpoint_after_cpuid: bool,
        /// True when we know via waitpid() that the task is stopped and we haven't
        /// resumed it.
        is_stopped: bool,
        /// True when the seccomp filter has been enabled via prctl(). This happens
        /// in the first system call issued by the initial tracee (after it returns
        /// from kill(SIGSTOP) to synchronize with the tracer).
        seccomp_bpf_enabled: bool,
        /// True when we consumed a PTRACE_EVENT_EXIT that was about to race with
        /// a resume_execution, that was issued while stopped (i.e. SIGKILL).
        detected_unexpected_exit: bool,
        /// True when 'registers' has changes that haven't been flushed back to the
        /// task yet.
        registers_dirty: bool,
        /// When |extra_registers_known|, we have saved our extra registers.
        extra_registers: ExtraRegisters,
        extra_registers_known: bool,
        /// A weak pointer to the  session we're part of.
        session_: SessionSharedWeakPtr,
        /// The thread group this belongs to.
        tg: ThreadGroupSharedPtr,
        /// Entries set by |set_thread_area()| or the |tls| argument to |clone()|
        /// (when that's a user_desc). May be more than one due to different
        /// entry_numbers.
        thread_areas_: Vec<user_desc>,
        /// The |stack| argument passed to |clone()|, which for
        /// "threads" is the top of the user-allocated stack.
        top_of_stack: RemotePtr<Void>,
        /// The most recent status of this task as returned by
        /// waitpid().
        wait_status: WaitStatus,
        /// The most recent siginfo (captured when wait_status shows pending_sig())
        pending_siginfo: siginfo_t,
        /// True when a PTRACE_EXIT_EVENT has been observed in the wait_status
        /// for this task.
        seen_ptrace_exit_event: bool,
        /// Important. Weak dyn Task pointer to self.
        weak_self_task: TaskSharedWeakPtr,
    }

    pub type DebugRegs = Vec<WatchConfig>;

    #[derive(Copy, Clone, Debug)]
    enum WriteFlags {
        IsBreakpointRelated = 0x1,
    }

    #[derive(Clone)]
    pub struct CapturedState {
        pub ticks: Ticks,
        pub regs: Registers,
        pub extra_regs: ExtraRegisters,
        pub prname: String,
        pub thread_areas: Vec<user_desc>,
        pub syscallbuf_child: RemotePtr<syscallbuf_hdr>,
        pub syscallbuf_size: usize,
        pub num_syscallbuf_bytes: usize,
        pub preload_globals: RemotePtr<preload_globals>,
        pub scratch_ptr: RemotePtr<Void>,
        pub scratch_size: isize,
        pub top_of_stack: RemotePtr<Void>,
        pub cloned_file_data_offset: u64,
        pub thread_locals: ThreadLocals,
        pub rec_tid: pid_t,
        pub serial: u32,
        pub desched_fd_child: i32,
        pub cloned_file_data_fd_child: i32,
        pub wait_status: WaitStatus,
    }

    #[derive(Copy, Clone, Debug)]
    /// @TODO originally this was NOT pub. Adjust?
    pub enum CloneReason {
        /// Cloning a task in the same session due to tracee fork()/vfork()/clone()
        TraceeClone,
        /// Cloning a task into a new session as the leader for a checkpoint
        SessionCloneLeader,
        /// Cloning a task into the same session to recreate threads while
        /// restoring a checkpoint
        SessionCloneNonleader,
    }

    impl TaskInner {
        /// We hide the destructor and require clients to call this instead. This
        /// lets us make virtual calls from within the destruction code. This
        /// does the actual PTRACE_DETACH and then calls the real destructor.
        pub fn destroy(&self) {
            unimplemented!()
        }

        pub fn syscallbuf_data_size(&self) -> usize {
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
            self.ticks
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
            t: &TaskInner,
            saved_syscallbuf_child: RemotePtr<syscallbuf_hdr>,
        ) {
            unimplemented!()
        }

        pub fn close_buffers_for(&self, remote: &AutoRemoteSyscalls, t: &TaskInner) {
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
            self.registers.ip()
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

        pub fn is_in_rd_page(&self) -> bool {
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

        /// Return the "task name"; i.e. what |prctl(PR_GET_NAME)| or
        /// /proc/tid/comm would say that the task's name is.
        pub fn name(&self) -> &str {
            &self.prname
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
        pub fn read_bytes(&self, child_addr: RemotePtr<Void>, buf: &mut [u8]) {
            unimplemented!()
        }

        /// Return the current regs of this.
        pub fn regs_ref(&self) -> &Registers {
            &self.registers
        }

        /// Return the current regs of this.
        pub fn regs_mut(&mut self) -> &mut Registers {
            &mut self.registers
        }

        /// Return the extra registers of this.
        pub fn extra_regs(&self) -> &ExtraRegisters {
            &self.extra_registers
        }

        /// Return the current arch of this. This can change due to exec(). */
        pub fn arch(&self) -> SupportedArch {
            self.registers.arch()
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
        pub fn read_val_mem<T>(&self, child_addr: RemotePtr<T>, ok: Option<&mut bool>) -> T {
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
        pub fn read_c_str(&self, child_addr: RemotePtr<u8>) -> CString {
            unimplemented!()
        }

        /// Return the session this is part of.
        pub fn session(&self) -> SessionSharedPtr {
            self.session_.upgrade().unwrap()
        }

        /// Set the tracee's registers to |regs|. Lazy.
        pub fn set_regs(&mut self, regs: &Registers) {
            ed_assert!(self, self.is_stopped);
            self.registers = *regs;
            self.registers_dirty = true;
        }

        /// Ensure registers are flushed back to the underlying task.
        pub fn flush_regs(&self) {
            unimplemented!()
        }

        /// Set the tracee's extra registers to |regs|. */
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

        pub fn set_status(&mut self, status: WaitStatus) {
            self.wait_status = status;
        }

        /// Return true when the task is running, false if it's stopped.
        pub fn is_running(&self) -> bool {
            !self.is_stopped
        }

        /// Return the status of this as of the last successful wait()/try_wait() call.
        pub fn status(&self) -> WaitStatus {
            self.wait_status
        }

        /// Return the ptrace event as of the last call to |wait()/try_wait()|.
        pub fn ptrace_event(&self) -> Option<i32> {
            self.wait_status.ptrace_event()
        }

        /// Return the signal that's pending for this as of the last
        /// call to |wait()/try_wait()|.  Return of `None` means "no signal".
        pub fn stop_sig(&self) -> Option<i32> {
            self.wait_status.stop_sig()
        }

        pub fn clear_wait_status(&mut self) {
            self.wait_status = WaitStatus::default();
        }

        /// Return the thread group this belongs to.
        pub fn thread_group(&self) -> Rc<RefCell<ThreadGroup>> {
            self.tg.clone()
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
        pub fn update_prname(&self, child_addr: RemotePtr<Void>) {
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
            self.as_.clone()
        }

        pub fn fd_table(&self) -> FdTableSharedPtr {
            unimplemented!()
        }

        /// Currently we don't allow recording across uid changes, so we can
        /// just return rd's uid.
        pub fn getuid(&self) -> uid_t {
            getuid().as_raw()
        }

        /// Write |N| bytes from |buf| to |child_addr|, or don't return.
        pub fn write_bytes(&self, child_addr: RemotePtr<Void>, buf: &[u8]) {
            unimplemented!()
        }

        /// Write |val| to |child_addr|.
        pub fn write_val_mem<T>(&self, child_addr: RemotePtr<T>, val: &T, ok: Option<&mut bool>) {
            unimplemented!()
        }

        /// Write |val| to |child_addr|.
        pub fn write_val_mem_with_flags<T>(
            &self,
            child_addr: RemotePtr<T>,
            val: &T,
            ok: Option<&mut bool>,
            flags: u32,
        ) {
            unimplemented!()
        }

        pub fn write_mem<T>(&self, child_addr: RemotePtr<T>, val: &[T], ok: Option<&mut bool>) {
            unimplemented!()
        }

        /// Don't use these helpers directly; use the safer and more
        /// convenient variants above.
        ///
        /// Read/write the number of bytes that the template wrapper
        /// inferred.
        /// @TODO why is this returning a signed value?
        pub fn read_bytes_fallible(&self, addr: RemotePtr<Void>, buf: &[u8]) -> isize {
            unimplemented!()
        }

        /// If the data can't all be read, then if |ok| is non-null, sets *ok to
        /// false, otherwise asserts.
        pub fn read_bytes_helper(
            &self,
            addr: RemotePtr<Void>,
            buf: &mut [u8],
            ok: Option<&mut bool>,
        ) {
            unimplemented!()
        }

        /// If the data can't all be read, then if |ok| is non-null, sets *ok to
        /// false, otherwise asserts.
        pub fn read_bytes_helper_for<T>(
            &self,
            addr: RemotePtr<T>,
            data: &mut T,
            ok: Option<&mut bool>,
        ) {
            let buf = unsafe {
                std::slice::from_raw_parts_mut(data as *mut T as *mut u8, size_of::<T>())
            };
            self.read_bytes_helper(RemotePtr::cast(addr), buf, ok);
        }

        /// |flags| is bits from WriteFlags.
        pub fn write_bytes_helper(
            &self,
            addr: RemotePtr<Void>,
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
            pid: &mut Option<pid_t>,
            syscall_arch: SupportedArch,
        ) -> bool {
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
        pub fn ptrace_if_alive(&self, request: i32, addr: RemotePtr<Void>, data: &[u8]) -> bool {
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
        pub fn syscallbuf_alt_stack(&self) -> RemotePtr<Void> {
            unimplemented!()
        }
        pub fn setup_preload_thread_locals(&self) {
            unimplemented!()
        }
        pub fn setup_preload_thread_locals_from_clone(&self, origin: &TaskInner) {
            unimplemented!()
        }
        pub fn fetch_preload_thread_locals(&self) -> &ThreadLocals {
            unimplemented!()
        }
        pub fn activate_preload_thread_locals(&self) {
            unimplemented!()
        }

        fn new(session: &dyn Session, tid: pid_t, rec_tid: pid_t, serial: u32, a: SupportedArch) {
            unimplemented!()
        }

        fn on_syscall_exit_arch(&self, syscallno: i32, regs: &Registers) {
            unimplemented!()
        }

        /// Helper function for init_buffers. */
        fn init_buffers_arch(&self, map_hint: RemotePtr<Void>) {
            unimplemented!()
        }

        /// Grab state from this task into a structure that we can use to
        /// initialize a new task via os_clone_into/os_fork_into and copy_state.
        fn capture_state(&self) -> CapturedState {
            unimplemented!()
        }

        /// Make this task look like an identical copy of the task whose state
        /// was captured by capture_task_state(), in
        /// every way relevant to replay.  This task should have been
        /// created by calling os_clone_into() or os_fork_into(),
        /// and if it wasn't results are undefined.
        ///
        /// Some task state must be copied into this by injecting and
        /// running syscalls in this task.  Other state is metadata
        /// that can simply be copied over in local memory.
        fn copy_state(&self, stat: &CapturedState) {
            unimplemented!()
        }

        /// Make the ptrace |request| with |addr| and |data|, return
        /// the ptrace return value.
        fn fallible_ptrace(&self, request: i32, addr: RemotePtr<Void>, data: &mut [u8]) -> c_long {
            unimplemented!()
        }

        /// Like |fallible_ptrace()| but completely infallible.
        /// All errors are treated as fatal.
        fn xptrace(&self, request: i32, addr: RemotePtr<Void>, data: &mut [u8]) {
            unimplemented!()
        }

        /// Read tracee memory using PTRACE_PEEKDATA calls. Slow, only use
        /// as fallback. Returns number of bytes actually read.
        /// @TODO return an isize or usize?
        fn read_bytes_ptrace(&self, buf: &mut [u8], addr: RemotePtr<Void>) -> usize {
            unimplemented!()
        }

        /// Write tracee memory using PTRACE_POKEDATA calls. Slow, only use
        /// as fallback. Returns number of bytes actually written.
        /// @TODO return an isize or usize?
        fn write_bytes_ptrace(&self, addr: RemotePtr<Void>, buf: &[u8]) -> usize {
            unimplemented!()
        }

        /// Try writing 'buf' to 'addr' by replacing pages in the tracee
        /// address-space using a temporary file. This may work around PaX issues.
        fn try_replace_pages(&self, addr: RemotePtr<Void>, buf: &[u8]) -> bool {
            unimplemented!()
        }

        /// Map the syscallbuffer for this, shared with this process.
        /// |map_hint| is the address where the syscallbuf is expected
        /// to be mapped --- and this is asserted --- or nullptr if
        /// there are no expectations.
        /// Initializes syscallbuf_child.
        fn init_syscall_buffer(
            &self,
            remote: &AutoRemoteSyscalls,
            map_hint: RemotePtr<Void>,
        ) -> KernelMapping {
            unimplemented!()
        }

        /// Make the OS-level calls to create a new fork or clone that
        /// will eventually be a copy of this task and return that Task
        /// metadata.  These methods are used in concert with
        /// |Task::copy_state()| to create task copies during
        /// checkpointing.
        ///
        /// For |os_fork_into()|, |session| will be tracking the
        /// returned fork child.
        ///
        /// For |os_clone_into()|, |task_leader| is the "main thread"
        /// in the process into which the copy of this task will be
        /// created.  |task_leader| will perform the actual OS calls to
        /// create the new child.
        fn os_fork_into(&self, session: &dyn Session) -> &TaskInner {
            unimplemented!()
        }
        fn os_clone_into(state: &CapturedState, remote: &AutoRemoteSyscalls) -> *mut TaskInner {
            unimplemented!()
        }

        /// Return the TraceStream that we're using, if in recording or replay.
        /// Returns null if we're not in record or replay.
        fn trace_stream(&self) -> &TraceStream {
            unimplemented!()
        }

        /// Make the OS-level calls to clone |parent| into |session|
        /// and return the resulting Task metadata for that new
        /// process.  This is as opposed to |Task::clone()|, which only
        /// attaches Task metadata to an /existing/ process.
        ///
        /// The new clone will be tracked in |session|.  The other
        /// arguments are as for |Task::clone()| above.
        fn os_clone(
            reason: CloneReason,
            session: &dyn Session,
            remote: &AutoRemoteSyscalls,
            rec_child_tid: pid_t,
            new_serial: u32,
            base_flags: u32,
            stack: RemotePtr<Void>,
            ptid: RemotePtr<i32>,
            tls: RemotePtr<Void>,
            ctid: RemotePtr<i32>,
        ) {
            unimplemented!()
        }

        /// Fork and exec the initial task. If something goes wrong later
        /// (i.e. an exec does not occur before an exit), an error may be
        /// readable from the other end of the pipe whose write end is error_fd.
        fn spawn<'a>(
            session: &'a dyn Session,
            error_fd: &ScopedFd,
            sock_fd_out: &ScopedFd,
            tracee_socket_fd_number_out: &mut i32,
            trace: &TraceStream,
            exe_path: &str,
            argv: &[&str],
            envp: &[&str],
            rec_tid: pid_t,
        ) -> &'a TaskInner {
            unimplemented!()
        }

        fn work_around_knl_string_singlestep_bug() -> bool {
            unimplemented!()
        }

        fn preload_thread_locals(&self) -> &mut u8 {
            unimplemented!()
        }
    }

    /// Open /proc/[tid]/mem fd for our AddressSpace, closing the old one
    /// first. If necessary we force the tracee to open the file
    /// itself and smuggle the fd back to us.
    /// Returns false if the process no longer exists.
    pub fn open_mem_fd<T: Task>(task: &mut T) -> bool {
        // Use ptrace to read/write during open_mem_fd
        task.as_.borrow_mut().set_mem_fd(ScopedFd::new());

        if !task.is_stopped {
            log!(
                LogWarn,
                "Can't retrieve mem fd for {}; process not stopped, racing with exec?",
                task.tid
            );
            return false;
        }

        // We could try opening /proc/<pid>/mem directly first and
        // only do this dance if that fails. But it's simpler to
        // always take this path, and gives better test coverage. On Ubuntu
        // the child has to open its own mem file (unless rr is root).
        let path = "/proc/self/mem";

        let arch = task.arch();
        let mut remote = AutoRemoteSyscalls::new(task);
        let remote_fd: i32;
        {
            let mut remote_path: AutoRestoreMem = AutoRestoreMem::push_cstr(&mut remote, path);
            if remote_path.get().is_some() {
                let remote_arch = remote_path.arch();
                let remote_addr = remote_path.get().unwrap();
                // AutoRestoreMem DerefMut-s to AutoRemoteSyscalls
                // skip leading '/' since we want the path to be relative to the root fd
                remote_fd = remote_path
                    .syscall(
                        syscall_number_for_openat(remote_arch),
                        &[
                            RD_RESERVED_ROOT_DIR_FD as usize,
                            // Skip the leading '/' in the path as this is a relative path.
                            (remote_addr + 1usize).into(),
                            libc::O_RDWR as usize,
                        ],
                    )
                    .try_into()
                    .unwrap();
            } else {
                remote_fd = -ESRCH;
            }
        }
        let mut fd: ScopedFd = ScopedFd::new();
        if remote_fd != -ESRCH {
            if remote_fd < 0 {
                // This can happen when a process fork()s after setuid; it can no longer
                // open its own /proc/self/mem. Hopefully we can read the child's
                // mem file in this case (because rr is probably running as root).
                let buf: String = format!("/proc/{}/mem", remote.tid);
                fd = ScopedFd::open_path(Path::new(&buf), OFlag::O_RDWR);
            } else {
                fd = rd_arch_function!(remote, retrieve_fd, arch, remote_fd);
                // Leak fd if the syscall fails due to the task being SIGKILLed unexpectedly
                remote.syscall(
                    syscall_number_for_close(remote.arch()),
                    &[remote_fd as usize],
                );
            }
        }
        if !fd.is_open() {
            log!(
                LogInfo,
                "Can't retrieve mem fd for {}; process no longer exists?",
                remote.tid
            );
            return false;
        }
        remote.as_.borrow_mut().set_mem_fd(fd.try_into().unwrap());
        true
    }
}
