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
    /// Corresponds to value -2 in the rr enum
    ResumeNoTicks,
    /// Corresponds to value -1 in the rr enum
    ResumeUnlimitedTicks,
    /// Dont request more than MAX_TICKS_REQUEST and less than 1!
    ResumeWithTicksRequest(u64),
}

impl Default for TicksRequest {
    fn default() -> Self {
        // @TODO do we want this as our default??
        Self::ResumeUnlimitedTicks
    }
}

/// Positive values are a request for an interrupt
/// after that number of ticks
/// Don't request more than this!
pub const MAX_TICKS_REQUEST: u64 = 2000000000;

pub mod task_inner {
    use super::*;
    use crate::{
        auto_remote_syscalls::AutoRemoteSyscalls,
        bindings::{
            kernel::{sock_fprog, user_desc},
            ptrace::{
                ptrace,
                PTRACE_EVENT_CLONE,
                PTRACE_EVENT_EXIT,
                PTRACE_EVENT_FORK,
                PTRACE_EVENT_SECCOMP,
                PTRACE_EVENT_VFORK,
                PTRACE_GETEVENTMSG,
                PTRACE_O_EXITKILL,
                PTRACE_O_TRACECLONE,
                PTRACE_O_TRACEEXEC,
                PTRACE_O_TRACEEXIT,
                PTRACE_O_TRACEFORK,
                PTRACE_O_TRACESECCOMP,
                PTRACE_O_TRACESYSGOOD,
                PTRACE_O_TRACEVFORK,
                PTRACE_PEEKDATA,
                PTRACE_POKEDATA,
                PTRACE_SEIZE,
                PTRACE_SETREGS,
            },
            signal::siginfo_t,
        },
        extra_registers::ExtraRegisters,
        fd_table::FdTableSharedPtr,
        kernel_abi::{
            common::preload_interface::{preload_globals, syscallbuf_hdr},
            SupportedArch,
        },
        kernel_metadata::{errno_name, ptrace_req_name, syscall_name},
        kernel_supplement::PTRACE_EVENT_SECCOMP_OBSOLETE,
        log::LogLevel::{LogDebug, LogWarn},
        perf_counters::PerfCounters,
        rd::RD_RESERVED_SOCKET_FD,
        registers::Registers,
        remote_code_ptr::RemoteCodePtr,
        remote_ptr::{RemotePtr, Void},
        scoped_fd::ScopedFd,
        session::{
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
            session_inner::session_inner::SessionInner,
            task::{Task, TaskSharedWeakPtr},
            Session,
            SessionSharedPtr,
            SessionSharedWeakPtr,
        },
        taskish_uid::TaskUid,
        thread_group::ThreadGroupSharedPtr,
        ticks::Ticks,
        trace::trace_stream::TraceStream,
        util::{
            choose_cpu,
            set_cpu_affinity,
            to_cstr_array,
            to_cstring_array,
            u8_raw_slice,
            u8_raw_slice_mut,
            BindCPU,
            TrappedInstruction,
        },
        wait_status::{MaybePtraceEvent, MaybeStopSignal, WaitStatus},
    };
    use libc::{
        __errno_location,
        _exit,
        fork,
        pid_t,
        uid_t,
        EAGAIN,
        EBADF,
        EINVAL,
        ENOMEM,
        ENOSYS,
        EPERM,
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER,
        SIGSTOP,
        STDERR_FILENO,
        STDOUT_FILENO,
    };
    use nix::{
        errno::errno,
        fcntl::{fcntl, readlink, FcntlArg, OFlag},
        sys::{
            socket::{socketpair, AddressFamily, SockFlag, SockType},
            stat::{lstat, stat, FileStat, Mode},
        },
        unistd::getuid,
        Error,
    };

    use crate::{
        fd_table::FdTable,
        file_monitor::{
            magic_save_data_monitor::MagicSaveDataMonitor,
            preserve_file_monitor::PreserveFileMonitor,
            stdio_monitor::StdioMonitor,
        },
        flags::Flags,
        kernel_abi::RD_NATIVE_ARCH,
        rd::{RD_MAGIC_SAVE_DATA_FD, RD_RESERVED_ROOT_DIR_FD},
        seccomp_bpf::SeccompFilter,
        session::{address_space::Traced, task::TaskSharedPtr},
    };

    use crate::{
        bindings::{
            kernel::{user, CAP_SYS_ADMIN},
            ptrace::PTRACE_POKEUSER,
        },
        cpuid_bug_detector::CPUIDBugDetector,
        fd_table::{FdTableRef, FdTableRefMut},
        thread_group::{ThreadGroupRef, ThreadGroupRefMut},
        trace::trace_frame::FrameTime,
        util::{has_effective_caps, restore_initial_resource_limits, running_under_rd, write_all},
    };
    use libc::{
        prctl,
        syscall,
        SYS_write,
        PR_SET_NO_NEW_PRIVS,
        PR_SET_PDEATHSIG,
        PR_SET_TSC,
        PR_TSC_SIGSEGV,
        SIGKILL,
    };
    use nix::{
        errno::{Errno, Errno::ESRCH},
        fcntl::open,
        sys::signal::{kill, sigaction, signal, SaFlags, SigAction, SigHandler, SigSet, Signal},
        unistd::{dup2, execve, getpid, setsid, Pid},
    };
    use rand::random;
    use std::{
        cell::{Cell, RefCell},
        cmp::min,
        ffi::{CStr, CString, OsStr, OsString},
        mem::{size_of, size_of_val},
        os::{raw::c_int, unix::ffi::OsStrExt},
        ptr,
        ptr::copy_nonoverlapping,
        rc::{Rc, Weak},
    };

    const NUM_X86_DEBUG_REGS: usize = 8;
    const NUM_X86_WATCHPOINTS: usize = 4;

    pub struct TrapReason;

    #[derive(Copy, Clone, Debug)]
    pub enum PtraceData {
        WriteInto(*mut [u8]),
        ReadFrom(*const [u8]),
        ReadWord(usize),
        None,
    }

    impl PtraceData {
        fn get_addr(self) -> *const u8 {
            match self {
                // @TODO Check this works as intended.
                PtraceData::WriteInto(s) => s.cast(),
                PtraceData::ReadFrom(s) => s.cast(),
                PtraceData::ReadWord(w) => w as *const u8,
                PtraceData::None => ptr::null(),
            }
        }
        pub fn get_data_slice(&self) -> Vec<u8> {
            match *self {
                PtraceData::WriteInto(s) => unsafe { s.as_ref() }.unwrap().to_vec(),
                PtraceData::ReadFrom(s) => unsafe { s.as_ref() }.unwrap().to_vec(),
                PtraceData::ReadWord(w) => w.to_le_bytes().into(),
                PtraceData::None => Vec::new(),
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
        pub unstable: Cell<bool>,
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
        /// @TODO Make this into an option??
        pub desched_fd_child: i32,
        /// The child's cloned_file_data_fd
        /// @TODO Make this into an option??
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
        pub(in super::super::super) as_: Option<AddressSpaceSharedPtr>,
        /// The file descriptor table of this task.
        pub(in super::super::super) fds: Option<FdTableSharedPtr>,
        /// Task's OS name.
        pub(in super::super::super) prname: OsString,
        /// Count of all ticks seen by this task since tracees became
        /// consistent and the task last wait()ed.
        pub(in super::super::super) ticks: Ticks,
        /// When `is_stopped`, these are our child registers.
        pub(in super::super::super) registers: Registers,
        /// Where we last resumed execution
        pub(in super::super::super) address_of_last_execution_resume: RemoteCodePtr,
        pub(in super::super::super) how_last_execution_resumed: ResumeRequest,
        /// In certain circumstances, due to hardware bugs, we need to fudge the
        /// cx register. If so, we record the orginal value here. See comments in
        /// Task.cc
        /// DIFF NOTE: In rr this is a u64. We use usize. @TODO Will this cause any issues?
        pub(in super::super::super) last_resume_orig_cx: usize,
        /// The instruction type we're singlestepping through.
        pub(in super::super::super) singlestepping_instruction: TrappedInstruction,
        /// True if we set a breakpoint after a singlestepped CPUID instruction.
        /// We need this in addition to `singlestepping_instruction` because that
        /// might be CPUID but we failed to set the breakpoint.
        pub(in super::super::super) did_set_breakpoint_after_cpuid: bool,
        /// True when we know via waitpid() that the task is stopped and we haven't
        /// resumed it.
        pub(in super::super::super) is_stopped: bool,
        /// True when the seccomp filter has been enabled via prctl(). This happens
        /// in the first system call issued by the initial tracee (after it returns
        /// from kill(SIGSTOP) to synchronize with the tracer).
        pub(in super::super::super) seccomp_bpf_enabled: bool,
        /// True when we consumed a PTRACE_EVENT_EXIT that was about to race with
        /// a resume_execution, that was issued while stopped (i.e. SIGKILL).
        pub(in super::super::super) detected_unexpected_exit: bool,
        /// True when 'registers' has changes that haven't been flushed back to the
        /// task yet.
        pub(in super::super::super) registers_dirty: bool,
        /// When `extra_registers_known`, we have saved our extra registers.
        pub(in super::super::super) extra_registers: ExtraRegisters,
        pub(in super::super::super) extra_registers_known: bool,
        /// A weak pointer to the  session we're part of.
        pub(in super::super::super) session_: SessionSharedWeakPtr,
        /// The thread group this belongs to.
        pub(in super::super::super) tg: Option<ThreadGroupSharedPtr>,
        /// Entries set by `set_thread_area()` or the `tls` argument to `clone()`
        /// (when that's a user_desc). May be more than one due to different
        /// entry_numbers.
        pub(in super::super::super) thread_areas_: Vec<user_desc>,
        /// The `stack` argument passed to `clone()`, which for
        /// "threads" is the top of the user-allocated stack.
        pub(in super::super::super) top_of_stack: RemotePtr<Void>,
        /// The most recent status of this task as returned by
        /// waitpid().
        pub(in super::super::super) wait_status: WaitStatus,
        /// The most recent siginfo (captured when wait_status shows pending_sig())
        /// @TODO Should this be an Option??
        pub(in super::super::super) pending_siginfo: siginfo_t,
        /// True when a PTRACE_EXIT_EVENT has been observed in the wait_status
        /// for this task.
        pub(in super::super::super) seen_ptrace_exit_event: bool,
        /// A counter for the number of stops for which the stop may have been caused
        /// by PTRACE_INTERRUPT. See description in do_waitpid
        pub(in super::super::super) expecting_ptrace_interrupt_stop: u32,

        /// Important. Weak dyn Task pointer to self.
        pub(in super::super::super) weak_self: TaskSharedWeakPtr,
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
    /// @TODO VISIBILITY originally this was NOT pub. Adjust?
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
            self.weak_self.clone()
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
        /// @TODO Should this be an Option
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
            self.maybe_ptrace_event() == PTRACE_EVENT_SECCOMP
                || self.maybe_ptrace_event() == PTRACE_EVENT_SECCOMP_OBSOLETE
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
        pub fn set_debug_status(&self, status: usize) {
            self.set_debug_reg(6, status);
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
        pub fn flush_regs(&mut self) {
            if self.registers_dirty {
                ed_assert!(self, self.is_stopped);
                let ptrace_regs = self.registers.get_ptrace();
                self.ptrace_if_alive(
                    PTRACE_SETREGS,
                    0usize.into(),
                    PtraceData::ReadFrom(u8_raw_slice(&ptrace_regs)),
                );
                self.registers_dirty = false;
            }
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
        pub fn set_debug_reg(&self, regno: usize, value: usize) -> bool {
            unsafe { Errno::clear() };
            self.fallible_ptrace(
                PTRACE_POKEUSER,
                dr_user_word_offset(regno).into(),
                PtraceData::ReadWord(value),
            );
            return errno() == 0 || Errno::last() == ESRCH;
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
        pub fn maybe_ptrace_event(&self) -> MaybePtraceEvent {
            self.wait_status.maybe_ptrace_event()
        }

        /// Return the signal that's pending for this as of the last call to `wait()/try_wait()`.
        pub fn maybe_stop_sig(&self) -> MaybeStopSignal {
            self.wait_status.maybe_stop_sig()
        }

        pub fn maybe_group_stop_sig(&self) -> MaybeStopSignal {
            self.wait_status.maybe_group_stop_sig()
        }

        pub fn clear_wait_status(&mut self) {
            self.wait_status = WaitStatus::default();
        }

        /// Return the thread group this belongs to.
        pub fn thread_group(&self) -> ThreadGroupRef {
            self.tg.as_ref().unwrap().borrow()
        }

        /// Return the thread group this belongs to.
        pub fn thread_group_mut(&self) -> ThreadGroupRefMut {
            self.tg.as_ref().unwrap().borrow_mut()
        }

        /// Return the id of this task's recorded thread group.
        pub fn tgid(&self) -> pid_t {
            self.thread_group().tgid
        }
        /// Return id of real OS thread group.|
        pub fn real_tgid(&self) -> pid_t {
            self.thread_group().real_tgid
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
        pub fn trace_time(&self) -> FrameTime {
            let trace = self.trace_stream().unwrap();
            trace.time()
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
            self.as_.as_ref().unwrap().borrow()
        }

        /// This is rarely needed. Please use vm() or vm_mut()
        pub fn vm_as_ptr(&self) -> *const AddressSpace {
            self.as_.as_ref().unwrap().as_ptr()
        }

        /// Return the virtual memory mapping (address space) of this
        /// task.
        /// Note that we DONT need &mut self here
        pub fn vm_mut(&self) -> AddressSpaceRefMut {
            self.as_.as_ref().unwrap().borrow_mut()
        }

        pub fn fd_table(&self) -> FdTableRef {
            self.fds.as_ref().unwrap().borrow()
        }

        pub fn fd_table_mut(&self) -> FdTableRefMut {
            self.fds.as_ref().unwrap().borrow_mut()
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
            let event = self.maybe_ptrace_event();
            if event.is_ptrace_event() {
                if event == PTRACE_EVENT_CLONE
                    || event == PTRACE_EVENT_FORK
                    || event == PTRACE_EVENT_VFORK
                {
                    *pid = Some(self.get_ptrace_eventmsg_pid());
                    return true;
                } else {
                    ed_assert!(self, false, "Unexpected ptrace event: {}", event);
                }
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
            unsafe { Errno::clear() };
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
            self.seen_ptrace_exit_event || self.detected_unexpected_exit
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

        pub(in super::super::super) fn new(
            session: &dyn Session,
            tid: pid_t,
            rec_tid: pid_t,
            serial: u32,
            a: SupportedArch,
        ) -> TaskInner {
            let adjusted_rec_tid = if rec_tid > 0 { rec_tid } else { tid };
            TaskInner {
                unstable: Cell::new(false),
                stable_exit: false,
                scratch_ptr: Default::default(),
                scratch_size: 0,
                // This will be initialized when the syscall buffer is
                desched_fd_child: -1,
                // This will be initialized when the syscall buffer is
                cloned_file_data_fd_child: -1,
                hpc: PerfCounters::new(tid, session.ticks_semantics()),
                tid,
                rec_tid: adjusted_rec_tid,
                syscallbuf_size: 0,
                stopping_breakpoint_table_entry_size: 0,
                serial,
                prname: "???".into(),
                ticks: 0,
                registers: Registers::new(a),
                how_last_execution_resumed: ResumeRequest::ResumeCont,
                last_resume_orig_cx: 0,
                did_set_breakpoint_after_cpuid: false,
                is_stopped: false,
                seccomp_bpf_enabled: false,
                detected_unexpected_exit: false,
                registers_dirty: false,
                extra_registers: ExtraRegisters::new(a),
                extra_registers_known: false,
                session_: session.weak_self.clone(),
                top_of_stack: Default::default(),
                seen_ptrace_exit_event: false,
                thread_locals: array_init::array_init(|_| 0),
                expecting_ptrace_interrupt_stop: 0,
                // DIFF NOTE: These are not explicitly set in rr
                syscallbuf_child: Default::default(),
                preload_globals: None,
                as_: Default::default(),
                fds: Default::default(),
                address_of_last_execution_resume: Default::default(),
                singlestepping_instruction: TrappedInstruction::None,
                tg: Default::default(),
                thread_areas_: vec![],
                wait_status: Default::default(),
                pending_siginfo: Default::default(),
                weak_self: Weak::new(),
                stopping_breakpoint_table: Default::default(),
            }
        }

        pub(in super::super::super) fn on_syscall_exit_arch(
            &self,
            _syscallno: i32,
            _regs: &Registers,
        ) {
            unimplemented!()
        }

        /// Helper function for init_buffers. */
        pub(in super::super::super) fn init_buffers_arch(&self, _map_hint: RemotePtr<Void>) {
            unimplemented!()
        }

        /// Grab state from this task into a structure that we can use to
        /// initialize a new task via os_clone_into/os_fork_into and copy_state.
        pub(in super::super::super) fn capture_state(&self) -> CapturedState {
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
        pub(in super::super::super) fn copy_state(&mut self, _stat: &CapturedState) {
            unimplemented!()
        }

        /// Make the ptrace `request` with `addr` and `data`, return
        /// the ptrace return value.
        pub(in super::super::super) fn fallible_ptrace(
            &self,
            request: u32,
            addr: RemotePtr<Void>,
            data: PtraceData,
        ) -> isize {
            let res =
                unsafe { ptrace(request, self.tid, addr.as_usize(), data.get_addr()) } as isize;
            res
        }

        /// Like `fallible_ptrace()` but completely infallible.
        /// All errors are treated as fatal.
        pub(in super::super::super) fn xptrace(
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
        pub(in super::super::super) fn read_bytes_ptrace(
            &self,
            addr: RemotePtr<Void>,
            buf: &mut [u8],
        ) -> usize {
            let mut nwritten: usize = 0;
            // ptrace operates on the word size of the host, so we really do want
            // to use sizes of host types here.
            let word_size = size_of::<isize>();
            unsafe { Errno::clear() };
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
        pub(in super::super::super) fn write_bytes_ptrace(
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
                    PtraceData::ReadWord(v as usize),
                );
                nwritten += length;
            }

            nwritten
        }

        /// Try writing 'buf' to 'addr' by replacing pages in the tracee
        /// address-space using a temporary file. This may work around PaX issues.
        pub(in super::super::super) fn try_replace_pages(
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
        pub(in super::super::super) fn init_syscall_buffer(
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
        pub(in super::super::super) fn os_fork_into(&self, _session: &dyn Session) -> &TaskInner {
            unimplemented!()
        }

        /// Return the TraceStream that we're using, if in recording or replay.
        /// Returns null if we're not in record or replay.
        pub(in super::super::super) fn trace_stream(&self) -> Option<&TraceStream> {
            unimplemented!()
        }

        /// Make the OS-level calls to clone `parent` into `session`
        /// and return the resulting Task metadata for that new
        /// process.  This is as opposed to `Task::clone()`, which only
        /// attaches Task metadata to an /existing/ process.
        ///
        /// The new clone will be tracked in `session`.  The other
        /// arguments are as for `Task::clone()` above.
        pub(in super::super::super) fn os_clone(
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
        ///
        /// DIFF NOTE: rr takes an explicit `trace` param. Since trace is available from the
        /// session we avoid it.
        pub(in super::super::super) fn spawn<'a>(
            session: &'a dyn Session,
            error_fd: &ScopedFd,
            sock_fd_out: Rc<RefCell<ScopedFd>>,
            tracee_socket_fd_number_out: &mut i32,
            exe_path: &OsStr,
            argv: &[OsString],
            envp: &[OsString],
            rec_tid: pid_t,
        ) -> TaskSharedPtr {
            debug_assert!(session.tasks().len() == 0);

            let ret = socketpair(
                AddressFamily::Unix,
                SockType::Stream,
                None,
                SockFlag::SOCK_CLOEXEC,
            );
            let sock: ScopedFd;
            match ret {
                Result::Err(_) => {
                    fatal!("socketpair() failed");
                    unreachable!()
                }
                Result::Ok((fd0, fd1)) => {
                    *sock_fd_out.borrow_mut() = ScopedFd::from_raw(fd0);
                    sock = ScopedFd::from_raw(fd1);
                }
            }

            // Find a usable FD number to dup to in the child. RR_RESERVED_SOCKET_FD
            // might already be used by an outer rr.
            let mut fd_number: i32 = RD_RESERVED_SOCKET_FD;
            // We assume no other thread is mucking with this part of the fd address space.
            loop {
                let ret = fcntl(fd_number, FcntlArg::F_GETFD);
                if ret.is_err() {
                    if errno() != EBADF {
                        fatal!("Error checking fd");
                    }
                    break;
                }
                fd_number += 1;
            }

            *tracee_socket_fd_number_out = fd_number;

            let maybe_cpu_index: Option<u32>;
            {
                let trace = session.trace_stream().unwrap();
                maybe_cpu_index = session.cpu_binding(&trace);
            }
            let is_recording = session.is_recording();
            maybe_cpu_index.map(|mut cpu_index| {
                    // Set CPU affinity now, after we've created any helper threads
                    // (so they aren't affected), but before we create any
                    // tracees (so they are all affected).
                    // Note that we're binding rr itself to the same CPU as the
                    // tracees, since this seems to help performance.
                    if !set_cpu_affinity(cpu_index) {
                        if SessionInner::has_cpuid_faulting() && !is_recording {
                            cpu_index = choose_cpu(BindCPU::RandomCPU).unwrap();
                            if !set_cpu_affinity(cpu_index) {
                                fatal!("Can't bind to requested CPU {} even after we re-selected it", cpu_index)
                            }
                            // DIFF NOTE: The logic is slightly different in rr.
                            if cpu_index != maybe_cpu_index.unwrap() {
                                log!(LogWarn,
                                     "Bound to CPU {} instead of selected {} because the latter is not available;\n\
                                Hoping tracee doesn't use LSL instruction!", cpu_index, maybe_cpu_index.unwrap());
                            }

                            let mut trace_mut = session.trace_stream_mut().unwrap();
                            trace_mut.set_bound_cpu(Some(cpu_index));
                        } else {
                            fatal!("Can't bind to requested CPU {}, and CPUID faulting not available", cpu_index)
                        }
                    }
                });

            let mut tid: pid_t;
            // After fork() in a multithreaded program, the child can safely call only
            // async-signal-safe functions, and malloc is not one of them (breaks e.g.
            // with tcmalloc).
            // Doing the allocations before the fork duplicates the allocations, but
            // prevents errors.
            let argv_array = to_cstring_array(argv);
            let envp_array = to_cstring_array(envp);
            let mut filter: SeccompFilter = create_seccomp_filter();
            let mut prog: sock_fprog = Default::default();
            prog.len = filter.filters.len() as u16;
            prog.filter = filter.filters.as_mut_ptr();
            loop {
                tid = unsafe { fork() };
                // fork() can fail with EAGAIN due to temporary load issues. In such
                // cases, retry the fork().
                if tid >= 0 || errno() != EAGAIN {
                    break;
                }
            }

            if 0 == tid {
                run_initial_child(
                    session,
                    error_fd,
                    &sock,
                    fd_number,
                    &CString::new(exe_path.as_bytes()).unwrap(),
                    &to_cstr_array(&argv_array),
                    &to_cstr_array(&envp_array),
                    &prog,
                );
                // run_initial_child never returns
            }

            if 0 > tid {
                fatal!("Failed to fork");
            }

            // Sync with the child process.
            // We minimize the code we run between fork()ing and PTRACE_SEIZE, because
            // any abnormal exit of the rr process will leave the child paused and
            // parented by the init process, i.e. effectively leaked. After PTRACE_SEIZE
            // with PTRACE_O_EXITKILL, the tracee will die if rr dies.
            let mut options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE;
            if !Flags::get().disable_ptrace_exit_events {
                options |= PTRACE_O_TRACEEXIT;
            }
            if session.is_recording() {
                options |= PTRACE_O_TRACEVFORK | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC;
            }

            let mut res = unsafe { ptrace(PTRACE_SEIZE, tid, 0, options | PTRACE_O_EXITKILL) };
            if res < 0 && errno() == EINVAL {
                // PTRACE_O_EXITKILL was added in kernel 3.8, and we only need
                // it for more robust cleanup, so tolerate not having it.
                res = unsafe { ptrace(PTRACE_SEIZE, tid, 0, options) };
            }
            if res != 0 {
                // Note that although the tracee may have died due to some fatal error,
                // we haven't reaped its exit code so there's no danger of killing
                // (or PTRACE_SEIZEing) the wrong process.
                let tmp_errno = errno();
                // @TODO: Might want to do a proper unwrap after the kill invocation?
                kill(Pid::from_raw(tid), Signal::SIGKILL).unwrap_or(());
                unsafe { *__errno_location() = tmp_errno };

                let mut hint = String::new();
                if errno() == EPERM {
                    hint = format!(
                        "; child probably died before reaching SIGSTOP\nChild's message: {:?}",
                        session.read_spawned_task_error()
                    );
                }
                fatal!("PTRACE_SEIZE failed for tid `{}`{}", tid, hint);
            }
            let next_t_serial = session.next_task_serial();
            let t = session.new_task(tid, rec_tid, next_t_serial, RD_NATIVE_ARCH);
            let wrapped_t = Rc::new(RefCell::new(t));
            // Set the weak self pointer of the task
            wrapped_t.borrow_mut().weak_self = Rc::downgrade(&wrapped_t);

            let tg = session.create_initial_tg(wrapped_t.clone());
            wrapped_t.borrow_mut().tg = Some(tg);
            let addr_space = session.create_vm(wrapped_t.clone(), None, None);
            wrapped_t.borrow_mut().as_ = Some(addr_space);
            let weak_t_ptr = wrapped_t.borrow().weak_self.clone();
            wrapped_t.borrow_mut().fds = Some(FdTable::create(weak_t_ptr));
            {
                let ref_task = wrapped_t.borrow();
                let fds: FdTableSharedPtr = ref_task.fds.as_ref().unwrap().clone();
                setup_fd_table(ref_task.as_ref(), &mut fds.borrow_mut(), fd_number);
            }

            // Install signal handler here, so that when creating the first RecordTask
            // it sees the exact same signal state in the parent as will be in the child.
            let sa = SigAction::new(
                SigHandler::Handler(handle_alarm_signal),
                SaFlags::empty(), // No SA_RESTART, so waitpid() will be interrupted
                SigSet::empty(),
            );
            unsafe { sigaction(Signal::SIGALRM, &sa) }.unwrap();

            {
                let mut t = wrapped_t.borrow_mut();
                t.wait(None);
                if t.maybe_ptrace_event() == PTRACE_EVENT_EXIT {
                    fatal!(
                        "Tracee died before reaching SIGSTOP\nChild's message: {:?}",
                        session.read_spawned_task_error()
                    );
                }
                // SIGSTOP can be reported as a signal-stop or group-stop depending on
                // whether PTRACE_SEIZE happened before or after it was delivered.
                if t.status().maybe_stop_sig() != SIGSTOP
                    && t.status().maybe_group_stop_sig() != SIGSTOP
                {
                    fatal!(
                        "Unexpected stop {}\n Child's message: {:?}",
                        t.status(),
                        session.read_spawned_task_error()
                    );
                }

                t.clear_wait_status();
                t.open_mem_fd();
            }
            wrapped_t
        }

        pub(in super::super::super) fn preload_thread_locals(&self) -> &mut u8 {
            unimplemented!()
        }
    }

    fn run_initial_child(
        session: &dyn Session,
        error_fd: &ScopedFd,
        sock_fd: &ScopedFd,
        sock_fd_number: i32,
        exe_path_cstr: &CStr,
        argv_array: &[&CStr],
        envp_array: &[&CStr],
        seccomp_prog: &sock_fprog,
    ) {
        let pid = getpid();

        set_up_process(session, error_fd, sock_fd, sock_fd_number);
        // The preceding code must run before sending SIGSTOP here,
        // since after SIGSTOP replay emulates almost all syscalls, but
        // we need the above syscalls to run "for real".

        // Signal to tracer that we're configured.
        kill(pid, Signal::SIGSTOP).unwrap_or(());

        // This code must run after rr has taken ptrace control.
        set_up_seccomp_filter(seccomp_prog, error_fd);

        // We do a small amount of dummy work here to retire
        // some branches in order to ensure that the ticks value is
        // non-zero.  The tracer can then check the ticks value
        // at the first ptrace-trap to see if it seems to be
        // working.
        let start = random::<u32>() % 5;
        let num_its = start + 5;
        let mut sum: u32 = 0;
        for i in start..num_its {
            sum = sum + i;
        }
        unsafe { syscall(SYS_write, -1, &sum, size_of_val(&sum)) };

        CPUIDBugDetector::run_detection_code();

        match execve(exe_path_cstr, argv_array, envp_array) {
            Err(Error::Sys(Errno::ENOENT)) => {
                spawned_child_fatal_error(
                    error_fd,
                    &format!(
                        "execve failed: '{:?}' (or interpreter) not found",
                        exe_path_cstr
                    ),
                );
            }
            _ => {
                spawned_child_fatal_error(
                    error_fd,
                    &format!("execve of '{:?}' failed", exe_path_cstr),
                );
            }
        }

        // Never returns!
    }

    fn create_seccomp_filter() -> SeccompFilter {
        let mut f = SeccompFilter::new();
        for e in AddressSpace::rd_page_syscalls() {
            if e.traced == Traced::Untraced {
                let ip =
                    AddressSpace::rd_page_syscall_exit_point(e.traced, e.privileged, e.enabled);
                f.allow_syscalls_from_callsite(ip);
            }
        }
        f.trace();
        f
    }

    // This function doesn't really need to do anything. The signal will cause
    // waitpid to return EINTR and that's all we need.
    extern "C" fn handle_alarm_signal(_sig: c_int) {}

    fn setup_fd_table(t: &dyn Task, fds: &mut FdTable, tracee_socket_fd_number: i32) {
        fds.add_monitor(t, STDOUT_FILENO, Box::new(StdioMonitor::new(STDOUT_FILENO)));
        fds.add_monitor(t, STDERR_FILENO, Box::new(StdioMonitor::new(STDERR_FILENO)));
        fds.add_monitor(
            t,
            RD_MAGIC_SAVE_DATA_FD,
            Box::new(MagicSaveDataMonitor::new()),
        );
        fds.add_monitor(
            t,
            RD_RESERVED_ROOT_DIR_FD,
            Box::new(PreserveFileMonitor::new()),
        );
        fds.add_monitor(
            t,
            tracee_socket_fd_number,
            Box::new(PreserveFileMonitor::new()),
        );
    }

    /// Prepare this process and its ancestors for recording/replay by
    /// preventing direct access to sources of nondeterminism, and ensuring
    /// that rr bugs don't adversely affect the underlying system.
    fn set_up_process(
        session: &dyn Session,
        err_fd: &ScopedFd,
        sock_fd: &ScopedFd,
        sock_fd_number: i32,
    ) {
        // TODO tracees can probably undo some of the setup below
        // ...
        restore_initial_resource_limits();

        // CLOEXEC so that the original fd here will be closed by the exec that's
        // about to happen.
        let maybe_fd_magic = open(
            "/dev/null",
            OFlag::O_WRONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        );
        if maybe_fd_magic.is_err() {
            spawned_child_fatal_error(err_fd, "error opening /dev/null");
        }
        let fd_magic = maybe_fd_magic.unwrap();
        let maybe_dup_magic = dup2(fd_magic, RD_MAGIC_SAVE_DATA_FD);
        if maybe_dup_magic.is_err() || RD_MAGIC_SAVE_DATA_FD != maybe_dup_magic.unwrap() {
            spawned_child_fatal_error(err_fd, "error duping to RD_MAGIC_SAVE_DATA_FD");
        }

        // If we're running under rr then don't try to set up RD_RESERVED_ROOT_DIR_FD;
        // it should already be correct (unless someone chrooted in between,
        // which would be crazy ... though we could fix it by dynamically
        // assigning RR_RESERVED_ROOT_DIR_FD.)
        if !running_under_rd() {
            // CLOEXEC so that the original fd here will be closed by the exec that's
            // about to happen.
            let maybe_fd_root = open(
                "/",
                OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                Mode::empty(),
            );
            if maybe_fd_root.is_err() {
                spawned_child_fatal_error(err_fd, "error opening root directory");
            }
            let maybe_dup_reserved = dup2(maybe_fd_root.unwrap(), RD_RESERVED_ROOT_DIR_FD);
            if maybe_dup_reserved.is_err() || RD_RESERVED_ROOT_DIR_FD != maybe_dup_reserved.unwrap()
            {
                spawned_child_fatal_error(err_fd, "error duping to RD_RESERVED_ROOT_DIR_FD");
            }
        }

        let maybe_dup_sock_fd = dup2(sock_fd.as_raw(), sock_fd_number);
        if maybe_dup_sock_fd.is_err() || sock_fd_number != maybe_dup_sock_fd.unwrap() {
            spawned_child_fatal_error(err_fd, "error duping to RD_RESERVED_SOCKET_FD");
        }

        if session.is_replaying() {
            // This task and all its descendants should silently reap any terminating
            // children.
            if unsafe { signal(Signal::SIGCHLD, SigHandler::SigIgn) }.is_err() {
                spawned_child_fatal_error(err_fd, "error doing signal()");
            }

            // If the rd process dies, prevent runaway tracee processes
            // from dragging down the underlying system.
            //
            // TODO: this isn't inherited across fork().
            if 0 > unsafe { prctl(PR_SET_PDEATHSIG, SIGKILL) } {
                spawned_child_fatal_error(err_fd, "Couldn't set parent-death signal");
            }

            // Put the replaying processes into their own session. This will stop
            // signals being sent to these processes by the terminal --- in particular
            // SIGTSTP/SIGINT/SIGWINCH.
            // NOTE: In rr too, the return result of this is not checked. Ignore failure.
            setsid().unwrap_or(Pid::from_raw(0));
        }

        // Trap to the rd process if a 'rdtsc' instruction is issued.
        // That allows rd to record the tsc and replay it
        // deterministically.
        if 0 > unsafe { prctl(PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0) } {
            spawned_child_fatal_error(err_fd, "error setting up prctl");
        }

        // If we're in setuid_sudo mode, we have CAP_SYS_ADMIN, so we don't need to
        // set NO_NEW_PRIVS here in order to install the seccomp filter later. In,
        // emulate any potentially privileged, operations, so we might as well set
        // no_new_privs
        if !session.is_recording() || !has_effective_caps(1 << CAP_SYS_ADMIN) {
            if 0 > unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } {
                spawned_child_fatal_error(
                    err_fd,
                    "prctl(NO_NEW_PRIVS) failed, SECCOMP_FILTER is not available: your\n\
           kernel is too old. Use `record -n` to disable the filter.",
                );
            }
        }
    }

    fn spawned_child_fatal_error(err_fd: &ScopedFd, msg: &str) {
        write_all(err_fd.as_raw(), msg.as_bytes());
        let errno_name = format!(" ({}) ", errno_name(errno()));
        write_all(err_fd.as_raw(), errno_name.as_bytes());
        unsafe { _exit(1) };
    }

    /// This is called (and must be called) in the tracee after rr has taken
    /// ptrace control. Otherwise, once we've installed the seccomp filter,
    /// things go wrong because we have no ptracer and the seccomp filter demands
    /// one.
    fn set_up_seccomp_filter(prog: &sock_fprog, err_fd: &ScopedFd) {
        // Note: the filter is installed only for record. This call
        // will be emulated (not passed to the kernel) in the replay. */
        if 0 > unsafe { prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog as *const _, 0, 0) } {
            spawned_child_fatal_error(
                err_fd,
                "prctl(SECCOMP) failed, SECCOMP_FILTER is not available: your\n\
kernel is too old.",
            );
        }
        // anything that happens from this point on gets filtered!
    }

    fn dr_user_word_offset(i: usize) -> usize {
        debug_assert!(i < NUM_X86_DEBUG_REGS);
        offset_of!(user, u_debugreg) + size_of::<usize>() * i
    }
}
