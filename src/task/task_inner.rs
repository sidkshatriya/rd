use crate::bindings::ptrace::{
    PTRACE_CONT,
    PTRACE_SINGLESTEP,
    PTRACE_SYSCALL,
    PTRACE_SYSEMU,
    PTRACE_SYSEMU_SINGLESTEP,
};

use crate::kernel_abi::common::preload_interface::PRELOAD_THREAD_LOCALS_SIZE;

bitflags! {
    /// CloneFlags::empty(): The child gets a semantic copy of all parent resources (and
    /// becomes a new thread group).  This is the semantics of the
    /// fork() syscall.
    pub struct CloneFlags : u32 {
        /// Child will share the table of signal dispositions with its
        /// parent.
        const CLONE_SHARE_SIGHANDLERS = 1 << 0;
        /// Child will join its parent's thread group.
        const CLONE_SHARE_THREAD_GROUP = 1 << 1;
        /// Child will share its parent's address space.
        const CLONE_SHARE_VM = 1 << 2;
        /// Child will share its parent's file descriptor table.
        const CLONE_SHARE_FILES = 1 << 3;
        /// Kernel will clear and notify tid futex on task exit.
        const CLONE_CLEARTID = 1 << 4;
        /// Set the thread area to what's specified by the `tls` arg.
        const CLONE_SET_TLS = 1 << 5;
    }
}

/// Enumeration of ways to resume execution.  See the ptrace manual for
/// details of the semantics of these.
///
/// We define a new datatype because the PTRACE_SYSEMU* requests aren't
/// part of the official ptrace API, and we want to use a strong type
/// for these resume requests to ensure callers don't confuse their
/// arguments.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResumeRequest {
    ResumeCont = PTRACE_CONT,
    ResumeSinglestep = PTRACE_SINGLESTEP,
    ResumeSyscall = PTRACE_SYSCALL,
    ResumeSysemu = PTRACE_SYSEMU,
    ResumeSysemuSinglestep = PTRACE_SYSEMU_SINGLESTEP,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum WaitRequest {
    /// After resuming, blocking-waitpid() until tracee status
    /// changes.
    ResumeWait,
    /// Don't wait after resuming.
    ResumeNonblocking,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TicksRequest {
    /// We don't expect to see any ticks (though we seem to on the odd buggy
    /// system...). Using this is a small performance optimization because we don't
    /// have to stop and restart the performance counters. This may also avoid
    /// bugs on some systems that report performance counter advances while
    /// in the kernel...
    ResumeNoTicks,
    ResumeUnlimitedTicks,
    /// Dont request more than MAX_TICKS_REQUEST and less than 1!
    ResumeWithTicksRequest(u64),
}

/// Positive values are a request for an interrupt
/// after that number of ticks
/// Don't request more than this!
pub const MAX_TICKS_REQUEST: u64 = 2000000000;

pub mod task_inner {
    use super::*;
    use crate::{
        address_space::{
            address_space::{
                AddressSpace,
                AddressSpaceRef,
                AddressSpaceRefMut,
                AddressSpaceSharedPtr,
            },
            kernel_mapping::KernelMapping,
            WatchConfig,
        },
        auto_remote_syscalls::AutoRemoteSyscalls,
        bindings::{
            kernel::user_desc,
            ptrace::{
                ptrace,
                PTRACE_EVENT_CLONE,
                PTRACE_EVENT_FORK,
                PTRACE_EVENT_VFORK,
                PTRACE_GETEVENTMSG,
                PTRACE_PEEKDATA,
                PTRACE_POKEDATA,
            },
            signal::siginfo_t,
        },
        extra_registers::ExtraRegisters,
        fd_table::FdTableSharedPtr,
        kernel_abi::{
            common::preload_interface::{preload_globals, syscallbuf_hdr},
            SupportedArch,
        },
        kernel_metadata::{errno_name, ptrace_event_name, ptrace_req_name, syscall_name},
        log::LogLevel::LogDebug,
        perf_counters::PerfCounters,
        registers::Registers,
        remote_code_ptr::RemoteCodePtr,
        remote_ptr::{RemotePtr, Void},
        scoped_fd::ScopedFd,
        session::{Session, SessionSharedPtr, SessionSharedWeakPtr},
        task::TaskSharedWeakPtr,
        taskish_uid::TaskUid,
        thread_group::{ThreadGroup, ThreadGroupSharedPtr},
        ticks::Ticks,
        trace::trace_stream::TraceStream,
        util::{u8_raw_slice, u8_raw_slice_mut, TrappedInstruction},
        wait_status::WaitStatus,
    };
    use libc::{__errno_location, pid_t, uid_t, EAGAIN, ENOMEM, ENOSYS};
    use nix::{
        errno::errno,
        fcntl::{readlink, OFlag},
        sys::stat::{lstat, stat, FileStat},
        unistd::getuid,
    };
    use std::{
        cell::RefCell,
        cmp::min,
        ffi::{OsStr, OsString},
        mem::size_of,
        ptr,
        ptr::copy_nonoverlapping,
        rc::Rc,
    };

    pub struct TrapReason;

    #[derive(Copy, Clone, Debug)]
    pub enum PtraceData {
        WriteInto(*mut [u8]),
        ReadFrom(*const [u8]),
        None,
    }

    impl PtraceData {
        fn get_addr(self) -> *const u8 {
            match self {
                // @TODO Check this works as intended.
                PtraceData::WriteInto(s) => s.cast(),
                PtraceData::ReadFrom(s) => s.cast(),
                PtraceData::None => ptr::null(),
            }
        }
        pub fn get_data_slice(&self) -> &[u8] {
            match self {
                PtraceData::WriteInto(s) => unsafe { s.as_ref() }.unwrap(),
                PtraceData::ReadFrom(s) => unsafe { s.as_ref() }.unwrap(),
                PtraceData::None => &[],
            }
        }
    }

    type ThreadLocals = [u8; PRELOAD_THREAD_LOCALS_SIZE];

    /// NOTE: This struct should NOT impl the Task trait
    pub struct TaskInner {
        /// True when any assumptions made about the status of this
        /// process have been invalidated, and must be re-established
        /// with a waitpid() call. Only applies to tasks which are dying, usually
        /// due to a signal sent to the entire thread group.
        pub unstable: bool,
        /// exit(), or exit_group() with one task, has been called, so
        /// the exit can be treated as stable. */
        pub stable_exit: bool,

        /// Imagine that task A passes buffer `b` to the read()
        /// syscall.  Imagine that, after A is switched out for task B,
        /// task B then writes to `b`.  Then B is switched out for A.
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
        /// `scratch_ptr` points at the mapped address in the child,
        /// and `size` is the total available space.
        pub scratch_ptr: RemotePtr<Void>,
        /// The full size of the scratch buffer.
        /// The last page of the scratch buffer is used as an alternate stack
        /// for the syscallbuf code. So the usable size is less than this.
        ///
        /// DIFF NOTE: In rr this is a signed value i.e. isize
        pub scratch_size: usize,

        /// The child's desched counter event fd number
        pub desched_fd_child: i32,
        /// The child's cloned_file_data_fd
        pub cloned_file_data_fd_child: i32,

        pub hpc: PerfCounters,

        /// This is always the "real" tid of the tracee.
        pub tid: pid_t,
        /// This is always the recorded tid of the tracee.  During
        /// recording, it's synonymous with `tid`, and during replay
        /// it's the tid that was recorded.
        pub rec_tid: pid_t,

        pub syscallbuf_size: usize,
        /// Points at the tracee's mapping of the buffer.
        pub syscallbuf_child: RemotePtr<syscallbuf_hdr>,
        /// XXX Move these fields to ReplayTask
        pub stopping_breakpoint_table: RemoteCodePtr,
        pub stopping_breakpoint_table_entry_size: i32,

        /// In rr null is used to denote no preload globals
        pub preload_globals: Option<RemotePtr<preload_globals>>,
        pub thread_locals: ThreadLocals,

        /// These are private
        serial: u32,
        /// The address space of this task.
        pub(in super::super) as_: AddressSpaceSharedPtr,
        /// The file descriptor table of this task.
        pub(in super::super) fds: FdTableSharedPtr,
        /// Task's OS name.
        pub(in super::super) prname: OsString,
        /// Count of all ticks seen by this task since tracees became
        /// consistent and the task last wait()ed.
        pub(in super::super) ticks: Ticks,
        /// When `is_stopped`, these are our child registers.
        pub(in super::super) registers: Registers,
        /// Where we last resumed execution
        pub(in super::super) address_of_last_execution_resume: RemoteCodePtr,
        pub(in super::super) how_last_execution_resumed: ResumeRequest,
        /// In certain circumstances, due to hardware bugs, we need to fudge the
        /// cx register. If so, we record the orginal value here. See comments in
        /// Task.cc
        /// DIFF NOTE: In rr this is a u64. We use usize. @TODO Will this cause any issues?
        pub(in super::super) last_resume_orig_cx: usize,
        /// The instruction type we're singlestepping through.
        pub(in super::super) singlestepping_instruction: TrappedInstruction,
        /// True if we set a breakpoint after a singlestepped CPUID instruction.
        /// We need this in addition to `singlestepping_instruction` because that
        /// might be CPUID but we failed to set the breakpoint.
        pub(in super::super) did_set_breakpoint_after_cpuid: bool,
        /// True when we know via waitpid() that the task is stopped and we haven't
        /// resumed it.
        pub(in super::super) is_stopped: bool,
        /// True when the seccomp filter has been enabled via prctl(). This happens
        /// in the first system call issued by the initial tracee (after it returns
        /// from kill(SIGSTOP) to synchronize with the tracer).
        pub(in super::super) seccomp_bpf_enabled: bool,
        /// True when we consumed a PTRACE_EVENT_EXIT that was about to race with
        /// a resume_execution, that was issued while stopped (i.e. SIGKILL).
        pub(in super::super) detected_unexpected_exit: bool,
        /// True when 'registers' has changes that haven't been flushed back to the
        /// task yet.
        pub(in super::super) registers_dirty: bool,
        /// When `extra_registers_known`, we have saved our extra registers.
        pub(in super::super) extra_registers: ExtraRegisters,
        pub(in super::super) extra_registers_known: bool,
        /// A weak pointer to the  session we're part of.
        pub(in super::super) session_: SessionSharedWeakPtr,
        /// The thread group this belongs to.
        pub(in super::super) tg: ThreadGroupSharedPtr,
        /// Entries set by `set_thread_area()` or the `tls` argument to `clone()`
        /// (when that's a user_desc). May be more than one due to different
        /// entry_numbers.
        pub(in super::super) thread_areas_: Vec<user_desc>,
        /// The `stack` argument passed to `clone()`, which for
        /// "threads" is the top of the user-allocated stack.
        pub(in super::super) top_of_stack: RemotePtr<Void>,
        /// The most recent status of this task as returned by
        /// waitpid().
        pub(in super::super) wait_status: WaitStatus,
        /// The most recent siginfo (captured when wait_status shows pending_sig())
        pub(in super::super) pending_siginfo: siginfo_t,
        /// True when a PTRACE_EXIT_EVENT has been observed in the wait_status
        /// for this task.
        pub(in super::super) seen_ptrace_exit_event: bool,
        /// A counter for the number of stops for which the stop may have been caused
        /// by PTRACE_INTERRUPT. See description in do_waitpid
        pub(in super::super) expecting_ptrace_interrupt_stop: u32,

        /// Important. Weak dyn Task pointer to self.
        pub(in super::super) weak_self_task: TaskSharedWeakPtr,
    }

    pub type DebugRegs = Vec<WatchConfig>;

    bitflags! {
        pub struct WriteFlags: u32 {
            const IS_BREAKPOINT_RELATED = 0x1;
        }
    }

    #[derive(Clone)]
    pub struct CapturedState {
        pub ticks: Ticks,
        pub regs: Registers,
        pub extra_regs: ExtraRegisters,
        pub prname: OsString,
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
        pub fn weak_self_ptr(&self) -> TaskSharedWeakPtr {
            self.weak_self_task.clone()
        }

        /// We hide the destructor and require clients to call this instead. This
        /// lets us make virtual calls from within the destruction code. This
        /// does the actual PTRACE_DETACH and then calls the real destructor.
        pub fn destroy(&self) {
            unimplemented!()
        }

        /// Called after the first exec in a session, when the session first
        /// enters a consistent state. Prior to that, the task state
        /// can vary based on how rd set up the child process. We have to flush
        /// out any state that might have been affected by that.
        pub fn flush_inconsistent_state(&mut self) {
            self.ticks = 0;
        }

        /// Return total number of ticks ever executed by this task.
        /// Updates tick count from the current performance counter values if
        /// necessary.
        pub fn tick_count(&self) -> Ticks {
            self.ticks
        }

        /// Stat `fd` in the context of this task's fd table.
        pub fn stat_fd(&self, fd: i32) -> FileStat {
            let path = format!("/proc/{}/fd/{}", self.tid, fd);
            let res = stat(path.as_str());
            ed_assert!(self, res.is_ok());
            res.unwrap()
        }

        /// Lstat `fd` in the context of this task's fd table.
        pub fn lstat_fd(&self, fd: i32) -> FileStat {
            let path = format!("/proc/{}/fd/{}", self.tid, fd);
            let res = lstat(path.as_str());
            ed_assert!(self, res.is_ok());
            res.unwrap()
        }

        /// Open `fd` in the context of this task's fd table.
        pub fn open_fd(&self, fd: i32, flags: OFlag) -> ScopedFd {
            let path = format!("/proc/{}/fd/{}", self.tid, fd);
            ScopedFd::open_path(path.as_str(), flags)
        }

        /// Get the name of the file referenced by `fd` in the context of this
        /// task's fd table.
        pub fn file_name_of_fd(&self, fd: i32) -> OsString {
            let path = format!("/proc/{}/fd/{}", self.tid, fd);
            let res = readlink(path.as_str());
            // DIFF NOTE: rr returns an empty string if the file name could not be obtained.
            res.unwrap()
        }

        /// Syscalls have side effects on registers (e.g. setting the flags register).
        /// Perform those side effects on `registers` to make it look like a syscall
        /// happened.
        pub fn canonicalize_regs(&mut self, syscall_arch: SupportedArch) {
            ed_assert!(self, self.is_stopped);

            match self.registers.arch() {
                SupportedArch::X64 => {
                    match syscall_arch {
                        SupportedArch::X86 => {
                            // The int $0x80 compatibility handling clears r8-r11
                            // (see arch/x86/entry/entry_64_compat.S). The sysenter compatibility
                            // handling also clears r12-r15. However, to actually make such a syscall,
                            // the user process would have to switch itself into compatibility mode,
                            // which, though possible, does not appear to actually be done by any
                            // real application (contrary to int $0x80, which is accessible from 64bit
                            // mode as well).
                            self.registers.set_r8(0x0);
                            self.registers.set_r9(0x0);
                            self.registers.set_r10(0x0);
                            self.registers.set_r11(0x0);
                        }
                        SupportedArch::X64 => {
                            // x86-64 'syscall' instruction copies RFLAGS to R11 on syscall entry.
                            // If we single-stepped into the syscall instruction, the TF flag will be
                            // set in R11. We don't want the value in R11 to depend on whether we
                            // were single-stepping during record or replay, possibly causing
                            // divergence.
                            // This doesn't matter when exiting a sigreturn syscall, since it
                            // restores the original flags.
                            // For untraced syscalls, the untraced-syscall entry point code (see
                            // write_rd_page) does this itself.
                            // We tried just clearing %r11, but that caused hangs in
                            // Ubuntu/Debian kernels.
                            // Making this match the flags makes this operation idempotent, which is
                            // helpful.
                            self.registers.set_r11(0x246);
                            // x86-64 'syscall' instruction copies return address to RCX on syscall
                            // entry. rd-related kernel activity normally sets RCX to -1 at some point
                            // during syscall execution, but apparently in some (unknown) situations
                            // probably involving untraced syscalls, that doesn't happen. To avoid
                            // potential issues, forcibly replace RCX with -1 always.
                            // This doesn't matter (and we should not do this) when exiting a
                            // sigreturn syscall, since it will restore the original RCX and we don't
                            // want to clobber that.
                            // For untraced syscalls, the untraced-syscall entry point code (see
                            // write_rd_page) does this itself.
                            self.registers.set_cx(-1isize as usize);
                        }
                    };
                    // On kernel 3.13.0-68-generic #111-Ubuntu SMP we have observed a failed
                    // execve() clearing all flags during recording. During replay we emulate
                    // the exec so this wouldn't happen. Just reset all flags so everything's
                    // consistent.
                    // 0x246 is ZF+PF+IF+reserved, the result clearing a register using
                    // "xor reg, reg".
                    self.registers.set_flags(0x246);
                }
                SupportedArch::X86 => {
                    // The x86 SYSENTER handling in Linux modifies EBP and EFLAGS on entry.
                    // EBP is the potential sixth syscall parameter, stored on the user stack.
                    // The EFLAGS changes are described here:
                    // http://linux-kernel.2935.n7.nabble.com/ia32-sysenter-target-does-not-preserve-EFLAGS-td1074164.html
                    // In a VMWare guest, the modifications to EFLAGS appear to be
                    // nondeterministic. Cover that up by setting EFLAGS to reasonable values
                    // now.
                    self.registers.set_flags(0x246);
                }
            }

            self.registers_dirty = true;
        }

        /// Return the ptrace message pid associated with the current ptrace
        /// event, f.e. the new child's pid at PTRACE_EVENT_CLONE.
        ///
        /// This method is more generic in rr and is called get_ptrace_event_msg()
        /// However, since it is only used to extract pid_t we monomorphize it in rd.
        pub fn get_ptrace_eventmsg_pid(&self) -> pid_t {
            let mut pid: pid_t = 0;
            self.xptrace(
                PTRACE_GETEVENTMSG,
                RemotePtr::from(0usize),
                PtraceData::WriteInto(u8_raw_slice_mut(&mut pid)),
            );
            pid
        }

        /// Return the siginfo at the signal-stop of `self`.
        /// Not meaningful unless this is actually at a signal stop.
        pub fn get_siginfo(&self) -> &siginfo_t {
            &self.pending_siginfo
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
            _remote: &AutoRemoteSyscalls,
            _t: &TaskInner,
            _saved_syscallbuf_child: RemotePtr<syscallbuf_hdr>,
        ) {
            unimplemented!()
        }

        pub fn close_buffers_for(&self, _remote: &AutoRemoteSyscalls, _t: &TaskInner) {
            unimplemented!()
        }

        /// Return the current $ip of this.
        pub fn ip(&self) -> RemoteCodePtr {
            self.registers.ip()
        }

        /// Emulate a jump to a new IP, updating the ticks counter as appropriate.
        pub fn emulate_jump(&self, _ptr: RemoteCodePtr) {
            unimplemented!()
        }

        /// Return true if this is at an arm-desched-event or
        /// disarm-desched-event syscall.
        pub fn is_desched_event_syscall(&self) -> bool {
            unimplemented!()
        }

        /// Return true when this task is in a traced syscall made by the
        /// syscallbuf code. Callers may assume `is_in_syscallbuf()`
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
        /// assume `is_in_syscallbuf()` is implied by this. Note that once we've
        /// entered the traced syscall, ip() is immediately after the syscall
        /// instruction.
        pub fn is_in_untraced_syscall(&self) -> bool {
            unimplemented!()
        }

        pub fn is_in_rd_page(&self) -> bool {
            let p = self.ip().to_data_ptr::<Void>();
            AddressSpace::rd_page_start() <= p && p < AddressSpace::rd_page_end()
        }

        /// Return true if `ptrace_event()` is the trace event
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

        /// Return the "task name"; i.e. what `prctl(PR_GET_NAME)` or
        /// /proc/tid/comm would say that the task's name is.
        pub fn name(&self) -> &OsStr {
            &self.prname
        }

        /// Call this method when this task has just performed an `execve()`
        /// (so we're in the new address space), but before the system call has
        /// returned.
        pub fn post_exec(&self, _exe_file: &str) {
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

        /// Read `N` bytes from `child_addr` into `buf`, or don't
        /// return.
        pub fn read_bytes(&self, _child_addr: RemotePtr<Void>, _buf: &mut [u8]) {
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
        pub fn set_debug_status(&self, _status: usize) {
            unimplemented!()
        }

        /// Determine why a SIGTRAP occurred. Uses debug_status() but doesn't
        /// consume it.
        pub fn compute_trap_reasons(&self) -> TrapReason {
            unimplemented!()
        }

        /// Return the session this is part of.
        pub fn session(&self) -> SessionSharedPtr {
            self.session_.upgrade().unwrap()
        }

        /// Set the tracee's registers to `regs`. Lazy.
        pub fn set_regs(&mut self, regs: &Registers) {
            ed_assert!(self, self.is_stopped);
            self.registers = *regs;
            self.registers_dirty = true;
        }

        /// Ensure registers are flushed back to the underlying task.
        pub fn flush_regs(&self) {
            unimplemented!()
        }

        /// Set the tracee's extra registers to `regs`. */
        pub fn set_extra_regs(&self, _regs: &ExtraRegisters) {
            unimplemented!()
        }

        /// Program the debug registers to the vector of watchpoint
        /// configurations in `reg` (also updating the debug control
        /// register appropriately).  Return true if all registers were
        /// successfully programmed, false otherwise.  Any time false
        /// is returned, the caller is guaranteed that no watchpoint
        /// has been enabled; either all of `regs` is enabled and true
        /// is returned, or none are and false is returned.
        pub fn set_debug_regs(&self, _regs: &DebugRegs) -> bool {
            unimplemented!()
        }

        /// @TODO should this be a GdbRegister type?
        pub fn get_debug_reg(&self, _regno: usize) -> usize {
            unimplemented!()
        }

        /// @TODO should this be a GdbRegister type?
        pub fn set_debug_reg(&self, _regno: usize, _value: usize) {
            unimplemented!()
        }

        /// Update the thread area to `addr`.
        pub fn set_thread_area(&self, _tls: RemotePtr<user_desc>) {
            unimplemented!()
        }

        /// Set the thread area at index `idx` to desc and reflect this
        /// into the OS task. Returns 0 on success, errno otherwise.
        pub fn emulate_set_thread_area(&self, _idx: i32, _desc: user_desc) {
            unimplemented!()
        }

        /// Get the thread area from the remote process.
        /// Returns 0 on success, errno otherwise.
        pub fn emulate_get_thread_area(&self, _idx: i32, _desc: &mut user_desc) -> i32 {
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

        /// Return the ptrace event as of the last call to `wait()/try_wait()`.
        pub fn ptrace_event(&self) -> Option<u32> {
            self.wait_status.ptrace_event()
        }

        /// Return the signal that's pending for this as of the last
        /// call to `wait()/try_wait()`.  Return of `None` means "no signal".
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

        /// Return the id of this task's recorded thread group.
        pub fn tgid(&self) -> pid_t {
            unimplemented!()
        }
        /// Return id of real OS thread group.
        pub fn real_tgid(&self) -> pid_t {
            unimplemented!()
        }

        pub fn tuid(&self) -> TaskUid {
            TaskUid::new_with(self.rec_tid, self.serial)
        }

        /// Return the dir of the trace we're using.
        pub fn trace_dir(&self) -> OsString {
            unimplemented!()
        }

        /// Get the current "time" measured as ticks on recording trace
        /// events.  `task_time()` returns that "time" wrt this task
        /// only.
        /// @TODO should we be returning some other type?
        pub fn trace_time(&self) -> u32 {
            unimplemented!()
        }

        /// Call this after the tracee successfully makes a
        /// `prctl(PR_SET_NAME)` call to change the task name to the
        /// string pointed at in the tracee's address space by
        /// `child_addr`.
        pub fn update_prname(&self, _child_addr: RemotePtr<Void>) {
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
        pub fn vm(&self) -> AddressSpaceRef {
            self.as_.borrow()
        }

        /// This is rarely needed. Please use vm() or vm_mut()
        pub fn vm_as_ptr(&self) -> *const AddressSpace {
            self.as_.as_ptr()
        }

        /// Return the virtual memory mapping (address space) of this
        /// task.
        /// Note that we DONT need &mut self here
        pub fn vm_mut(&self) -> AddressSpaceRefMut {
            self.as_.borrow_mut()
        }

        pub fn fd_table(&self) -> FdTableSharedPtr {
            unimplemented!()
        }

        /// Currently we don't allow recording across uid changes, so we can
        /// just return rd's uid.
        pub fn getuid(&self) -> uid_t {
            getuid().as_raw()
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
            let event = self.ptrace_event();
            match event {
                Some(pte)
                    if pte == PTRACE_EVENT_CLONE
                        || pte == PTRACE_EVENT_FORK
                        || pte == PTRACE_EVENT_VFORK =>
                {
                    *pid = Some(self.get_ptrace_eventmsg_pid());
                    return true;
                }
                Some(pte) => {
                    ed_assert!(
                        self,
                        false,
                        "Unexpected ptrace event {}",
                        ptrace_event_name(pte)
                    );
                }
                None => (),
            }

            // EAGAIN can happen here due to fork failing under load. The caller must
            // handle this.
            // XXX ENOSYS shouldn't happen here.
            let result = self.regs_ref().syscall_result_signed();
            ed_assert!(
                self,
                self.regs_ref().syscall_may_restart()
                    || -ENOSYS as isize == result
                    || -EAGAIN as isize == result
                    || -ENOMEM as isize == result,
                "Unexpected task status {} ({} syscall errno: {})",
                self.status(),
                syscall_name(self.regs_ref().original_syscallno() as i32, syscall_arch),
                errno_name(-result as i32)
            );
            false
        }

        /// Calls open_mem_fd if this task's AddressSpace doesn't already have one.
        pub fn open_mem_fd_if_needed(&self) {
            unimplemented!()
        }

        /// Lock or unlock the syscallbuf to prevent the preload library from using it.
        /// Only has an effect if the syscallbuf has been initialized.
        pub fn set_syscallbuf_locked(&self, _locked: bool) {
            unimplemented!()
        }

        /// Like `fallible_ptrace()` but infallible for most purposes.
        /// Errors other than ESRCH are treated as fatal. Returns false if
        /// we got ESRCH. This can happen any time during recording when the
        /// task gets a SIGKILL from outside.
        pub fn ptrace_if_alive(
            &self,
            request: u32,
            addr: RemotePtr<Void>,
            data: PtraceData,
        ) -> bool {
            unsafe { *__errno_location() = 0 };
            self.fallible_ptrace(request, addr, data);
            if errno() == libc::ESRCH {
                log!(LogDebug, "ptrace_if_alive tid {} was not alive", self.tid);
                return false;
            }
            ed_assert!(
                self,
                errno() == 0,
                "ptrace({}, {}, addr={}, data={:?}) failed with errno: {}",
                ptrace_req_name(request),
                self.tid,
                addr,
                data.get_data_slice(),
                errno()
            );
            return true;
        }

        pub fn is_dying(&self) -> bool {
            unimplemented!()
        }

        pub fn last_execution_resume(&self) -> RemoteCodePtr {
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
        pub fn setup_preload_thread_locals_from_clone(&self, _origin: &TaskInner) {
            unimplemented!()
        }
        pub fn fetch_preload_thread_locals(&self) -> &ThreadLocals {
            unimplemented!()
        }
        pub fn activate_preload_thread_locals(&self) {
            unimplemented!()
        }

        pub(in super::super) fn new(
            _session: &dyn Session,
            _tid: pid_t,
            _rec_tid: pid_t,
            _serial: u32,
            _a: SupportedArch,
        ) {
            unimplemented!()
        }

        pub(in super::super) fn on_syscall_exit_arch(&self, _syscallno: i32, _regs: &Registers) {
            unimplemented!()
        }

        /// Helper function for init_buffers. */
        pub(in super::super) fn init_buffers_arch(&self, _map_hint: RemotePtr<Void>) {
            unimplemented!()
        }

        /// Grab state from this task into a structure that we can use to
        /// initialize a new task via os_clone_into/os_fork_into and copy_state.
        pub(in super::super) fn capture_state(&self) -> CapturedState {
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
        pub(in super::super) fn copy_state(&self, _stat: &CapturedState) {
            unimplemented!()
        }

        /// Make the ptrace `request` with `addr` and `data`, return
        /// the ptrace return value.
        pub(in super::super) fn fallible_ptrace(
            &self,
            request: u32,
            addr: RemotePtr<Void>,
            data: PtraceData,
        ) -> isize {
            let res = unsafe { ptrace(request, self.tid, addr, data.get_addr()) };
            res as isize
        }

        /// Like `fallible_ptrace()` but completely infallible.
        /// All errors are treated as fatal.
        pub(in super::super) fn xptrace(
            &self,
            request: u32,
            addr: RemotePtr<Void>,
            data: PtraceData,
        ) {
            unsafe { *(__errno_location()) = 0 };
            self.fallible_ptrace(request, addr, data);
            let errno = errno();
            ed_assert!(
                self,
                errno == 0,
                "ptrace({}, {}, addr={}, data={:?}) failed with errno: {}",
                ptrace_req_name(request),
                self.tid,
                addr,
                data.get_data_slice(),
                errno
            );
        }

        /// Read tracee memory using PTRACE_PEEKDATA calls. Slow, only use
        /// as fallback. Returns number of bytes actually read.
        pub(in super::super) fn read_bytes_ptrace(
            &self,
            addr: RemotePtr<Void>,
            buf: &mut [u8],
        ) -> usize {
            let mut nwritten: usize = 0;
            // ptrace operates on the word size of the host, so we really do want
            // to use sizes of host types here.
            let word_size = size_of::<isize>();
            unsafe { *(__errno_location()) = 0 };
            // Only write aligned words. This ensures we can always read the last
            // byte before an unmapped region.
            let buf_size = buf.len();
            while nwritten < buf_size {
                let start: usize = addr.as_usize() + nwritten;
                let start_word: usize = start & !(word_size - 1);
                let end_word: usize = start_word + word_size;
                let length = min(end_word - start, buf_size - nwritten);

                let v = self.fallible_ptrace(
                    PTRACE_PEEKDATA,
                    RemotePtr::from(start_word),
                    PtraceData::None,
                );
                if errno() != 0 {
                    break;
                }
                unsafe {
                    copy_nonoverlapping(
                        (&raw const v as *const u8).add(start - start_word),
                        buf.as_mut_ptr().add(nwritten),
                        length,
                    );
                }

                nwritten += length;
            }

            nwritten
        }

        /// Write tracee memory using PTRACE_POKEDATA calls. Slow, only use
        /// as fallback. Returns number of bytes actually written.
        pub(in super::super) fn write_bytes_ptrace(
            &self,
            addr: RemotePtr<Void>,
            buf: &[u8],
        ) -> usize {
            let mut nwritten: usize = 0;
            // ptrace operates on the word size of the host, so we really do want
            // to use sizes of host types here.
            let word_size = size_of::<isize>();
            unsafe { *(__errno_location()) = 0 };
            // Only write aligned words. This ensures we can always write the last
            // byte before an unmapped region.
            let buf_size = buf.len();
            while nwritten < buf_size {
                let start: usize = addr.as_usize() + nwritten;
                let start_word: usize = start & !(word_size - 1);
                let end_word: usize = start_word + word_size;
                let length = min(end_word - start, buf_size - nwritten);

                let mut v: isize = 0;
                if length < word_size {
                    v = self.fallible_ptrace(
                        PTRACE_PEEKDATA,
                        RemotePtr::from(start_word),
                        PtraceData::None,
                    );
                    if errno() != 0 {
                        break;
                    }
                }
                unsafe {
                    copy_nonoverlapping(
                        buf.as_ptr().add(nwritten),
                        (&raw mut v as *mut u8).add(start - start_word),
                        length,
                    );
                }

                self.fallible_ptrace(
                    PTRACE_POKEDATA,
                    RemotePtr::from(start_word),
                    PtraceData::ReadFrom(u8_raw_slice(&v)),
                );
                nwritten += length;
            }

            nwritten
        }

        /// Try writing 'buf' to 'addr' by replacing pages in the tracee
        /// address-space using a temporary file. This may work around PaX issues.
        pub(in super::super) fn try_replace_pages(
            &self,
            _addr: RemotePtr<Void>,
            _buf: &[u8],
        ) -> bool {
            unimplemented!()
        }

        /// Map the syscallbuffer for this, shared with this process.
        /// `map_hint` is the address where the syscallbuf is expected
        /// to be mapped --- and this is asserted --- or nullptr if
        /// there are no expectations.
        /// Initializes syscallbuf_child.
        pub(in super::super) fn init_syscall_buffer(
            &self,
            _remote: &AutoRemoteSyscalls,
            _map_hint: RemotePtr<Void>,
        ) -> KernelMapping {
            unimplemented!()
        }

        /// Make the OS-level calls to create a new fork or clone that
        /// will eventually be a copy of this task and return that Task
        /// metadata.  These methods are used in concert with
        /// `Task::copy_state()` to create task copies during
        /// checkpointing.
        ///
        /// For `os_fork_into()`, `session` will be tracking the
        /// returned fork child.
        ///
        /// For `os_clone_into()`, `task_leader` is the "main thread"
        /// in the process into which the copy of this task will be
        /// created.  `task_leader` will perform the actual OS calls to
        /// create the new child.
        pub(in super::super) fn os_fork_into(&self, _session: &dyn Session) -> &TaskInner {
            unimplemented!()
        }
        pub(in super::super) fn os_clone_into(
            _state: &CapturedState,
            _remote: &AutoRemoteSyscalls,
        ) -> *mut TaskInner {
            unimplemented!()
        }

        /// Return the TraceStream that we're using, if in recording or replay.
        /// Returns null if we're not in record or replay.
        pub(in super::super) fn trace_stream(&self) -> &TraceStream {
            unimplemented!()
        }

        /// Make the OS-level calls to clone `parent` into `session`
        /// and return the resulting Task metadata for that new
        /// process.  This is as opposed to `Task::clone()`, which only
        /// attaches Task metadata to an /existing/ process.
        ///
        /// The new clone will be tracked in `session`.  The other
        /// arguments are as for `Task::clone()` above.
        pub(in super::super) fn os_clone(
            _reason: CloneReason,
            _session: &dyn Session,
            _remote: &AutoRemoteSyscalls,
            _rec_child_tid: pid_t,
            _new_serial: u32,
            _base_flags: u32,
            _stack: RemotePtr<Void>,
            _ptid: RemotePtr<i32>,
            _tls: RemotePtr<Void>,
            _ctid: RemotePtr<i32>,
        ) {
            unimplemented!()
        }

        /// Fork and exec the initial task. If something goes wrong later
        /// (i.e. an exec does not occur before an exit), an error may be
        /// readable from the other end of the pipe whose write end is error_fd.
        pub(in super::super) fn spawn<'a>(
            _session: &'a dyn Session,
            _error_fd: &ScopedFd,
            _sock_fd_out: &ScopedFd,
            _tracee_socket_fd_number_out: &mut i32,
            _trace: &TraceStream,
            _exe_path: &str,
            _argv: &[&str],
            _envp: &[&str],
            _rec_tid: pid_t,
        ) -> &'a TaskInner {
            unimplemented!()
        }

        pub(in super::super) fn work_around_knl_string_singlestep_bug(&mut self) -> bool {
            unimplemented!()
        }

        pub(in super::super) fn preload_thread_locals(&self) -> &mut u8 {
            unimplemented!()
        }
    }
}
