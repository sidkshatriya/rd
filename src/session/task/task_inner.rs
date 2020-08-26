use crate::{
    arch::Architecture,
    bindings::ptrace::{
        PTRACE_CONT,
        PTRACE_SET_THREAD_AREA,
        PTRACE_SINGLESTEP,
        PTRACE_SYSCALL,
        PTRACE_SYSEMU,
        PTRACE_SYSEMU_SINGLESTEP,
    },
    kernel_abi::{
        common::preload_interface::PRELOAD_THREAD_LOCALS_SIZE,
        x64::{self, preload_interface::preload_thread_locals as x64_preload_thread_locals},
        x86::{self, preload_interface::preload_thread_locals as x86_preload_thread_locals},
        SupportedArch,
    },
    remote_ptr::Void,
    session::address_space::{address_space::AddressSpace, MappingFlags},
};
use std::{ffi::c_void, mem::size_of, ptr::NonNull};
use task_inner::TaskInner;

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

/// Reasons why a SIGTRAP might have been delivered. Multiple reasons can
/// apply. Also, none can apply, e.g. if someone sent us a SIGTRAP via kill().
#[derive(Default, Eq, PartialEq)]
pub struct TrapReasons {
    // Singlestep completed (ResumeSinglestep, ResumeSysemuSinglestep).
    pub singlestep: bool,
    /// Hardware watchpoint fired. This includes cases where the actual values
    /// did not change (i.e. AddressSpace::has_any_watchpoint_changes() may return
    /// false even though this is set).
    pub watchpoint: bool,
    /// Breakpoint instruction was executed.
    pub breakpoint: bool,
}

pub mod task_inner {
    use super::*;
    use crate::{
        auto_remote_syscalls::AutoRemoteSyscalls,
        bindings::{
            kernel::{sock_fprog, user, user_desc, CAP_SYS_ADMIN, NT_X86_XSTATE},
            ptrace::{
                ptrace,
                PTRACE_EVENT_CLONE,
                PTRACE_EVENT_EXIT,
                PTRACE_EVENT_FORK,
                PTRACE_EVENT_SECCOMP,
                PTRACE_EVENT_VFORK,
                PTRACE_GETEVENTMSG,
                PTRACE_GETREGSET,
                PTRACE_O_EXITKILL,
                PTRACE_O_TRACECLONE,
                PTRACE_O_TRACEEXEC,
                PTRACE_O_TRACEEXIT,
                PTRACE_O_TRACEFORK,
                PTRACE_O_TRACESECCOMP,
                PTRACE_O_TRACESYSGOOD,
                PTRACE_O_TRACEVFORK,
                PTRACE_PEEKDATA,
                PTRACE_PEEKUSER,
                PTRACE_POKEDATA,
                PTRACE_POKEUSER,
                PTRACE_SEIZE,
                PTRACE_SETREGS,
                PTRACE_SETREGSET,
            },
            signal::siginfo_t,
        },
        cpuid_bug_detector::CPUIDBugDetector,
        extra_registers::{ExtraRegisters, Format},
        fd_table::{FdTable, FdTableRef, FdTableRefMut, FdTableSharedPtr},
        file_monitor::{
            magic_save_data_monitor::MagicSaveDataMonitor,
            preserve_file_monitor::PreserveFileMonitor,
            stdio_monitor::StdioMonitor,
        },
        flags::Flags,
        kernel_abi::{
            common::preload_interface::{preload_globals, syscallbuf_hdr},
            SupportedArch,
            RD_NATIVE_ARCH,
        },
        kernel_metadata::{errno_name, ptrace_req_name, syscall_name},
        kernel_supplement::PTRACE_EVENT_SECCOMP_OBSOLETE,
        log::LogLevel::{LogDebug, LogWarn},
        perf_counters::PerfCounters,
        rd::{RD_MAGIC_SAVE_DATA_FD, RD_RESERVED_ROOT_DIR_FD, RD_RESERVED_SOCKET_FD},
        registers::Registers,
        remote_code_ptr::RemoteCodePtr,
        remote_ptr::{RemotePtr, Void},
        scoped_fd::ScopedFd,
        seccomp_bpf::SeccompFilter,
        session::{
            address_space::{
                address_space::{AddressSpace, AddressSpaceSharedPtr},
                kernel_mapping::KernelMapping,
                Traced,
                WatchConfig,
                WatchType,
            },
            session_inner::session_inner::SessionInner,
            task::{task_common::set_thread_area_core, Task, TaskSharedPtr, TaskSharedWeakPtr},
            Session,
            SessionSharedPtr,
            SessionSharedWeakPtr,
        },
        taskish_uid::TaskUid,
        thread_group::{ThreadGroupRef, ThreadGroupRefMut, ThreadGroupSharedPtr},
        ticks::Ticks,
        trace::{trace_frame::FrameTime, trace_stream::TraceStream},
        util::{
            choose_cpu,
            has_effective_caps,
            restore_initial_resource_limits,
            running_under_rd,
            set_cpu_affinity,
            to_cstr_array,
            to_cstring_array,
            u8_raw_slice,
            u8_raw_slice_mut,
            write_all,
            xsave_area_size,
            BindCPU,
            TrappedInstruction,
        },
        wait_status::{MaybePtraceEvent, MaybeStopSignal, WaitStatus},
    };
    use bit_field::BitField;
    use libc::{
        __errno_location,
        _exit,
        fork,
        iovec,
        pid_t,
        prctl,
        syscall,
        uid_t,
        SYS_write,
        EAGAIN,
        EBADF,
        EINVAL,
        ENOMEM,
        ENOSYS,
        EPERM,
        ESRCH,
        PR_SET_NO_NEW_PRIVS,
        PR_SET_PDEATHSIG,
        PR_SET_SECCOMP,
        PR_SET_TSC,
        PR_TSC_SIGSEGV,
        SECCOMP_MODE_FILTER,
        SIGKILL,
        SIGSTOP,
        STDERR_FILENO,
        STDOUT_FILENO,
    };
    use nix::{
        errno::{errno, Errno},
        fcntl::{fcntl, open, readlink, FcntlArg, OFlag},
        sys::{
            signal::{kill, sigaction, signal, SaFlags, SigAction, SigHandler, SigSet, Signal},
            socket::{socketpair, AddressFamily, SockFlag, SockType},
            stat::{lstat, stat, FileStat, Mode},
        },
        unistd::{dup2, execve, getpid, getuid, setsid, Pid},
        Error,
    };
    use owning_ref::OwningHandle;
    use rand::random;
    use std::{
        cell::{Cell, Ref, RefCell},
        cmp::min,
        ffi::{CStr, CString, OsStr, OsString},
        mem::{size_of, size_of_val},
        ops::Deref,
        os::{raw::c_int, unix::ffi::OsStrExt},
        ptr,
        ptr::copy_nonoverlapping,
        rc::{Rc, Weak},
    };

    #[cfg(target_arch = "x86")]
    use crate::bindings::ptrace::{PTRACE_GETFPXREGS, PTRACE_SETFPXREGS};
    #[cfg(target_arch = "x86")]
    use crate::kernel_abi::x86;

    #[cfg(target_arch = "x86_64")]
    use crate::bindings::ptrace::{PTRACE_GETFPREGS, PTRACE_SETFPREGS};
    #[cfg(target_arch = "x86_64")]
    use crate::kernel_abi::x64;

    const NUM_X86_DEBUG_REGS: usize = 8;
    const NUM_X86_WATCHPOINTS: usize = 4;

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
        /// the exit can be treated as stable.
        pub stable_exit: bool,

        /// Imagine that task A passes buffer `b` to the read()
        /// syscall.  Imagine that, after A is switched out for task B,
        /// task B then writes to `b`.  Then B is switched out for A.
        /// Since rd doesn't schedule the kernel code, the result is
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
        pub stopping_breakpoint_table_entry_size: usize,

        /// DIFF NOTE: In rr null is used to denote no preload globals
        pub preload_globals: Option<RemotePtr<preload_globals>>,
        pub thread_locals: ThreadLocals,

        /// These are private
        pub(in super::super::super) serial: u32,
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
        /// DIFF NOTE: This is an option in rd. In rr there is `extra_registers_known`
        /// which we don't need.
        pub(in super::super::super) extra_registers: Option<ExtraRegisters>,
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

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

    pub enum SaveTraceeFdNumber<'a> {
        SaveToSession,
        SaveFdTo(&'a mut i32),
    }

    #[repr(usize)]
    enum WatchBytesX86 {
        Bytes1 = 0x00,
        Bytes2 = 0x01,
        Bytes4 = 0x03,
        Bytes8 = 0x02,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct DebugControl(usize);

    fn num_bytes_to_dr_len(num_bytes: usize) -> WatchBytesX86 {
        match num_bytes {
            1 => WatchBytesX86::Bytes1,
            2 => WatchBytesX86::Bytes2,
            4 => WatchBytesX86::Bytes4,
            8 => WatchBytesX86::Bytes8,
            _ => {
                fatal!("Unsupported breakpoint size: {}", num_bytes);
            }
        }
    }

    impl DebugControl {
        pub fn get(&self) -> usize {
            self.0
        }
        pub fn enable(&mut self, index: usize, size: WatchBytesX86, type_: WatchType) {
            match index {
                // dr0
                0 => {
                    self.0.set_bit(0, true);
                    self.0.set_bit(1, false);
                    self.0.set_bits(16..18, type_ as usize);
                    self.0.set_bits(18..20, size as usize);
                }
                // dr1
                1 => {
                    self.0.set_bit(2, true);
                    self.0.set_bit(3, false);
                    self.0.set_bits(20..22, type_ as usize);
                    self.0.set_bits(22..24, size as usize);
                }
                // dr2
                2 => {
                    self.0.set_bit(4, true);
                    self.0.set_bit(5, false);
                    self.0.set_bits(24..26, type_ as usize);
                    self.0.set_bits(26..28, size as usize);
                }
                // dr3
                3 => {
                    self.0.set_bit(6, true);
                    self.0.set_bit(7, false);
                    self.0.set_bits(28..30, type_ as usize);
                    self.0.set_bits(30..32, size as usize);
                }
                _ => fatal!("Invalid index: {}", index),
            }
        }
    }

    impl TaskInner {
        pub fn weak_self_ptr(&self) -> TaskSharedWeakPtr {
            self.weak_self.clone()
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
        /// DIFF NOTE: This method is more generic in rr and is called get_ptrace_event_msg()
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
        /// @TODO Should this be an Option??
        pub fn get_siginfo(&self) -> &siginfo_t {
            &self.pending_siginfo
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
            match AddressSpace::rd_page_syscall_from_exit_point(self.ip()) {
                Some(syscall_type) => syscall_type.traced == Traced::Untraced,
                None => false,
            }
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
        pub fn move_ip_before_breakpoint(&mut self) {
            // TODO: assert that this is at a breakpoint trap.
            let mut r: Registers = self.regs_ref().clone();
            let arch = self.arch();
            r.set_ip(r.ip().decrement_by_bkpt_insn_length(arch));
            self.set_regs(&r);
        }

        /// Return the "task name"; i.e. what `prctl(PR_GET_NAME)` or
        /// /proc/tid/comm would say that the task's name is.
        pub fn name(&self) -> &OsStr {
            &self.prname
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
            ed_assert!(self, self.is_stopped);
            &self.registers
        }

        /// Return the current regs of this.
        pub fn regs_mut(&mut self) -> &mut Registers {
            &mut self.registers
        }

        /// DIFF NOTE: simply `extra_regs()` in rr
        /// Return the extra registers of this.
        pub fn extra_regs_ref(&mut self) -> &ExtraRegisters {
            if self.extra_registers.is_none() {
                let arch_ = self.registers.arch();
                let format_ = Format::XSave;
                let mut data_ = Vec::<u8>::new();
                let er: ExtraRegisters;
                if xsave_area_size() > 512 {
                    log!(LogDebug, "  (refreshing extra-register cache using XSAVE)");

                    data_.resize(xsave_area_size(), 0u8);
                    let mut vec = iovec {
                        iov_base: data_.as_mut_ptr().cast(),
                        iov_len: data_.len(),
                    };
                    self.xptrace(
                        PTRACE_GETREGSET,
                        RemotePtr::new_from_val(NT_X86_XSTATE as usize),
                        PtraceData::WriteInto(u8_raw_slice_mut(&mut vec)),
                    );
                    data_.resize(vec.iov_len, 0u8);

                    er = ExtraRegisters {
                        data_,
                        format_,
                        arch_,
                    };
                    // The kernel may return less than the full XSTATE
                    er.validate(self);
                } else {
                    #[cfg(target_arch = "x86")]
                    {
                        log!(
                            LogDebug,
                            "  (refreshing extra-register cache using FPXREGS)"
                        );
                        data_.resize(size_of::<x86::user_fpxregs_struct>(), 0u8);
                        self.xptrace(
                            PTRACE_GETFPXREGS,
                            0.into(),
                            PtraceData::WriteInto(data_.as_mut_slice()),
                        );
                    }
                    #[cfg(target_arch = "x86_64")]
                    {
                        // x86-64 that doesn't support XSAVE; apparently Xeon E5620 (Westmere)
                        // is in this class.
                        log!(LogDebug, "  (refreshing extra-register cache using FPREGS)");
                        data_.resize(size_of::<x64::user_fpregs_struct>(), 0u8);
                        self.xptrace(
                            PTRACE_GETFPREGS,
                            0usize.into(),
                            PtraceData::WriteInto(data_.as_mut_slice()),
                        );
                    }
                    er = ExtraRegisters {
                        data_,
                        format_,
                        arch_,
                    };
                }
                self.extra_registers = Some(er);
            }

            self.extra_registers.as_ref().unwrap()
        }

        /// Return the current arch of this. This can change due to exec().
        pub fn arch(&self) -> SupportedArch {
            self.registers.arch()
        }

        /// Return the debug status (DR6 on x86). The debug status is always cleared
        /// in resume_execution() before we resume, so it always only reflects the
        /// events since the last resume.
        pub fn debug_status(&self) -> usize {
            self.fallible_ptrace(
                PTRACE_PEEKUSER,
                RemotePtr::new_from_val(dr_user_word_offset(6)),
                PtraceData::None,
            ) as usize
        }

        /// Set the debug status (DR6 on x86).
        pub fn set_debug_status(&self, status: usize) {
            self.set_debug_reg(6, status);
        }

        /// Return the session this is part of.
        pub fn session(&self) -> SessionSharedPtr {
            self.session_.upgrade().unwrap()
        }

        /// Use this method when the session weak pointer upgrade
        /// may not work e.g. when a Session Rc is being drop()-ed
        pub fn try_session(&self) -> Option<SessionSharedPtr> {
            self.session_.upgrade()
        }

        /// Set the tracee's registers to `regs`. Lazy.
        pub fn set_regs(&mut self, regs: &Registers) {
            ed_assert!(self, self.is_stopped);
            self.registers = regs.clone();
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

        /// Set the tracee's extra registers to `regs`.
        pub fn set_extra_regs(&mut self, regs: &ExtraRegisters) {
            ed_assert!(self, !regs.is_empty(), "Trying to set empty ExtraRegisters");
            ed_assert!(
                self,
                regs.arch() == self.arch(),
                "Trying to set wrong arch ExtraRegisters"
            );
            let mut er = regs.clone();
            match er.format() {
                Format::XSave => {
                    if xsave_area_size() > 512 {
                        let vec = iovec {
                            iov_base: er.data_.as_mut_ptr().cast(),
                            iov_len: er.data_.len(),
                        };

                        let d = PtraceData::ReadFrom(u8_raw_slice(&vec));
                        self.ptrace_if_alive(
                            PTRACE_SETREGSET,
                            RemotePtr::new_from_val(NT_X86_XSTATE as usize),
                            d,
                        );
                    } else {
                        #[cfg(target_arch = "x86")]
                        {
                            ed_assert!(
                                self,
                                er.data_.len() == size_of::<x86::user_fpxregs_struct>()
                            );
                            self.ptrace_if_alive(
                                PTRACE_SETFPXREGS,
                                RemotePtr::null(),
                                PtraceData::ReadFrom(er.data_.as_slice() as *const _),
                            );
                        }

                        #[cfg(target_arch = "x86_64")]
                        {
                            ed_assert!(
                                self,
                                er.data_.len() == size_of::<x64::user_fpregs_struct>()
                            );
                            self.ptrace_if_alive(
                                PTRACE_SETFPREGS,
                                RemotePtr::null(),
                                PtraceData::ReadFrom(er.data_.as_slice() as *const _),
                            );
                        }
                    }
                }
                Format::None => {
                    ed_assert!(self, false, "Unexpected ExtraRegisters format");
                    unreachable!();
                }
            }
            self.extra_registers = Some(er);
        }

        /// Program the debug registers to the vector of watchpoint
        /// configurations in `regs` (also updating the debug control
        /// register appropriately).  Return true if all registers were
        /// successfully programmed, false otherwise.  Any time false
        /// is returned, the caller is guaranteed that no watchpoint
        /// has been enabled; either all of `regs` is enabled and true
        /// is returned, or none are and false is returned.
        pub fn set_debug_regs(&self, regs: &DebugRegs) -> bool {
            // Reset the debug status since we're about to change the set
            // of programmed watchpoints.
            self.set_debug_reg(6, 0);

            if regs.len() > NUM_X86_WATCHPOINTS {
                self.set_debug_reg(7, 0);
                return false;
            }

            // Work around kernel bug https://bugzilla.kernel.org/show_bug.cgi?id=200965.
            // For every watchpoint we're going to use, enable it with size 1.
            // This will let us set the address freely without potentially triggering
            // the kernel bug which will reject an unaligned address if the watchpoint
            // is disabled but was non-size-1.
            let mut dr7 = DebugControl::default();
            for i in 0..regs.len() {
                dr7.enable(i, WatchBytesX86::Bytes1, WatchType::WatchExec);
            }
            self.set_debug_reg(7, dr7.get());

            for (index, reg) in regs.iter().enumerate() {
                if !self.set_debug_reg(index, reg.addr.as_usize()) {
                    self.set_debug_reg(7, 0);
                    return false;
                }
                dr7.enable(index, num_bytes_to_dr_len(reg.num_bytes), reg.type_);
            }
            self.set_debug_reg(7, dr7.get())
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
            errno() == 0 || errno() == ESRCH
        }

        /// Set the thread area at index `idx` to desc and reflect this
        /// into the OS task. Returns 0 on success, errno otherwise.
        pub fn emulate_set_thread_area(&mut self, idx: u32, mut desc: user_desc) -> i32 {
            unsafe { Errno::clear() };
            // @TODO Is the cast `idx as usize` what we want?
            self.fallible_ptrace(
                PTRACE_SET_THREAD_AREA,
                RemotePtr::from(idx as usize),
                PtraceData::ReadFrom(u8_raw_slice(&desc)),
            );
            if errno() != 0 {
                return errno();
            }
            desc.entry_number = idx;
            set_thread_area_core(&mut self.thread_areas_, desc);
            0
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

        /// Use thread_group() and thread_group_mut() in preference to this
        pub fn thread_group_shr_ptr(&self) -> ThreadGroupSharedPtr {
            self.tg.as_ref().unwrap().clone()
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

        /// Call this to reset syscallbuf_hdr->num_rec_bytes and zero out the data
        /// recorded in the syscall buffer. This makes for more deterministic behavior
        /// especially during replay, where during checkpointing we only save and
        /// restore the recorded data area.
        pub fn reset_syscallbuf(&self) {
            unimplemented!()
        }

        /// Return the virtual memory mapping (address space) of this
        /// task.
        pub fn vm(&self) -> &AddressSpace {
            &self.as_.as_ref().unwrap()
        }

        /// Useful for tricky situations when we need to pass a reference to task to
        /// the AddressSpace methods for instance
        pub fn vm_shr_ptr(&self) -> AddressSpaceSharedPtr {
            self.as_.as_ref().unwrap().clone()
        }

        pub fn fd_table(&self) -> FdTableRef {
            self.fds.as_ref().unwrap().borrow()
        }

        pub fn fd_table_mut(&self) -> FdTableRefMut {
            self.fds.as_ref().unwrap().borrow_mut()
        }

        /// Useful for tricky situations when we need to pass a reference to task to
        /// the FdTable methods for instance
        pub fn fd_table_shr_ptr(&self) -> FdTableSharedPtr {
            self.fds.as_ref().unwrap().clone()
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

        /// Lock or unlock the syscallbuf to prevent the preload library from using it.
        /// Only has an effect if the syscallbuf has been initialized.
        pub fn set_syscallbuf_locked(&self, _locked: bool) {
            if self.syscallbuf_child.is_null() {
                return;
            }

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
            self.address_of_last_execution_resume
        }

        pub fn usable_scratch_size(&self) {
            unimplemented!()
        }
        pub fn syscallbuf_alt_stack(&self) -> RemotePtr<Void> {
            if self.scratch_ptr.is_null() {
                RemotePtr::null()
            } else {
                self.scratch_ptr + self.scratch_size
            }
        }
        pub fn setup_preload_thread_locals(&mut self) {
            self.activate_preload_thread_locals(None);
            rd_arch_function_selfless!(setup_preload_thread_locals_arch, self.arch(), self);
        }

        pub fn setup_preload_thread_locals_from_clone(&mut self, origin: &mut TaskInner) {
            rd_arch_function_selfless!(
                setup_preload_thread_locals_from_clone_arch,
                self.arch(),
                self,
                origin
            )
        }

        pub fn fetch_preload_thread_locals(&mut self) -> &ThreadLocals {
            if self.tuid() == self.vm().thread_locals_tuid() {
                let maybe_local_addr = preload_thread_locals_local_addr(self.vm());
                match maybe_local_addr {
                    Some(local_addr) => unsafe {
                        copy_nonoverlapping(
                            local_addr.as_ptr().cast::<u8>(),
                            (&raw mut self.thread_locals).cast::<u8>(),
                            PRELOAD_THREAD_LOCALS_SIZE,
                        );
                    },
                    None => {
                        // The mapping might have been removed by crazy application code.
                        // That's OK, assuming the preload library was removed too.
                        for i in 0..PRELOAD_THREAD_LOCALS_SIZE {
                            self.thread_locals[i] = 0u8;
                        }
                    }
                }
            }
            &self.thread_locals
        }

        // DIFF NOTE: Takes an additional param maybe_active_task
        pub fn activate_preload_thread_locals(
            &mut self,
            maybe_active_task: Option<&mut TaskInner>,
        ) {
            // Switch thread-locals to the new task.
            if self.tuid() != self.vm().thread_locals_tuid() {
                let maybe_local_addr = preload_thread_locals_local_addr(&self.vm());
                match maybe_local_addr {
                    Some(local_addr) => {
                        match maybe_active_task {
                            Some(active_task)
                                if active_task.tuid() == self.vm().thread_locals_tuid() =>
                            {
                                active_task.fetch_preload_thread_locals();
                            }
                            _ => {
                                let maybe_t = self
                                    .session()
                                    .find_task_from_task_uid(self.vm().thread_locals_tuid());

                                maybe_t.map(|t| {
                                    t.borrow_mut().fetch_preload_thread_locals();
                                });
                            }
                        };

                        unsafe {
                            copy_nonoverlapping(
                                &self.thread_locals as *const u8,
                                local_addr.as_ptr().cast::<u8>(),
                                PRELOAD_THREAD_LOCALS_SIZE,
                            );
                        }
                        self.vm().set_thread_locals_tuid(self.tuid());
                    }
                    None => (),
                }
            }
        }

        pub(in super::super::super) fn new(
            session: &dyn Session,
            tid: pid_t,
            rec_tid: Option<pid_t>,
            serial: u32,
            a: SupportedArch,
        ) -> TaskInner {
            let adjusted_rec_tid = rec_tid.unwrap_or(tid);
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
                extra_registers: None,
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
            unsafe { Errno::clear() };
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
            unsafe { Errno::clear() };
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
        /// Returns `None` if we're not in record or replay.
        pub(in super::super::super) fn trace_stream(
            &self,
        ) -> Option<OwningHandle<SessionSharedPtr, Ref<TraceStream>>> {
            if self.session().is_diversion() {
                return None;
            }
            let shr_ptr = self.session();
            let owning_handle =
                OwningHandle::new_with_fn(shr_ptr, |s| match unsafe { (*s).as_record() } {
                    Some(_rec_sess) => unimplemented!(),
                    None => match unsafe { (*s).as_replay() } {
                        Some(rep_sess) => Ref::map(rep_sess.trace_reader(), |tr| tr.deref()),
                        None => unreachable!(),
                    },
                });

            Some(owning_handle)
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
        pub(in super::super::super) fn spawn<'a, 'b>(
            session: &'a dyn Session,
            error_fd: &ScopedFd,
            sock_fd_out: Rc<RefCell<ScopedFd>>,
            tracee_socket_fd_number: SaveTraceeFdNumber<'b>,
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
                Err(e) => {
                    fatal!("socketpair() failed: {:?}", e);
                }
                Ok((fd0, fd1)) => {
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

            match tracee_socket_fd_number {
                SaveTraceeFdNumber::SaveToSession => session.tracee_socket_fd_number.set(fd_number),
                SaveTraceeFdNumber::SaveFdTo(v) => *v = fd_number,
            }

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
                    // Note that we're binding rd itself to the same CPU as the
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
            // any abnormal exit of the rd process will leave the child paused and
            // parented by the init process, i.e. effectively leaked. After PTRACE_SEIZE
            // with PTRACE_O_EXITKILL, the tracee will die if rd dies.
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
            let t = session.new_task(tid, Some(rec_tid), next_t_serial, RD_NATIVE_ARCH);
            let wrapped_t = Rc::new(RefCell::new(t));
            // Set the weak self pointer of the task
            wrapped_t.borrow_mut().weak_self = Rc::downgrade(&wrapped_t);

            let tg = session.create_initial_tg(wrapped_t.clone());
            wrapped_t.borrow_mut().tg = Some(tg);
            let addr_space = session.create_vm(wrapped_t.borrow_mut().as_mut(), None, None);
            wrapped_t.borrow_mut().as_ = Some(addr_space);
            let weak_t_ptr = wrapped_t.borrow().weak_self.clone();
            wrapped_t.borrow_mut().fds = Some(FdTable::create(weak_t_ptr));
            {
                let mut ref_task = wrapped_t.borrow_mut();
                let fds: FdTableSharedPtr = ref_task.fds.as_ref().unwrap().clone();
                setup_fd_table(ref_task.as_mut(), &mut fds.borrow_mut(), fd_number);
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

        // This code must run after rd has taken ptrace control.
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

    fn setup_fd_table(t: &mut dyn Task, fds: &mut FdTable, tracee_socket_fd_number: i32) {
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
    /// that rd bugs don't adversely affect the underlying system.
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

        // If we're running under rd then don't try to set up RD_RESERVED_ROOT_DIR_FD;
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
        // @TODO How about using process::exit()?
        unsafe { _exit(1) };
    }

    /// This is called (and must be called) in the tracee after rd has taken
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

fn preload_thread_locals_local_addr(as_: &AddressSpace) -> Option<NonNull<c_void>> {
    // There might have been a mapping there, but not the one we expect (i.e.
    // the one shared with us for thread locals). In that case we behave as
    // if the mapping didn't exist at all.
    let maybe_mapping = as_.mapping_of(AddressSpace::preload_thread_locals_start());

    match maybe_mapping {
        Some(mapping) if mapping.flags.contains(MappingFlags::IS_THREAD_LOCALS) => {
            debug_assert!(mapping.local_addr.is_some());
            mapping.local_addr
        }
        _ => None,
    }
}
fn setup_preload_thread_locals_arch<Arch: Architecture>(t: &TaskInner) {
    let maybe_local_addr = preload_thread_locals_local_addr(t.vm());

    // @TODO find a way to make this more succint? Code is basically the same in both match arms
    match maybe_local_addr {
        Some(local_addr) => match Arch::arch() {
            SupportedArch::X86 => {
                let preload_ptr = local_addr.as_ptr() as *mut x86_preload_thread_locals;
                debug_assert!(size_of::<x86_preload_thread_locals>() <= PRELOAD_THREAD_LOCALS_SIZE);
                unsafe {
                    (*preload_ptr).syscallbuf_stub_alt_stack =
                        x86::ptr::<Void>::from_remote_ptr(t.syscallbuf_alt_stack())
                };
            }
            SupportedArch::X64 => {
                let preload_ptr = local_addr.as_ptr() as *mut x64_preload_thread_locals;
                debug_assert!(size_of::<x64_preload_thread_locals>() <= PRELOAD_THREAD_LOCALS_SIZE);
                unsafe {
                    (*preload_ptr).syscallbuf_stub_alt_stack =
                        x64::ptr::<Void>::from_remote_ptr(t.syscallbuf_alt_stack())
                };
            }
        },
        None => (),
    }
}

fn setup_preload_thread_locals_from_clone_arch<Arch: Architecture>(
    t: &mut TaskInner,
    origin: &mut TaskInner,
) {
    let maybe_local_addr = preload_thread_locals_local_addr(t.vm());

    // @TODO find a way to make this more succint? Code is basically the same in both match arms
    match maybe_local_addr {
        Some(local_addr) => match Arch::arch() {
            SupportedArch::X86 => {
                t.activate_preload_thread_locals(Some(origin));
                let locals = local_addr.as_ptr() as *mut x86_preload_thread_locals;
                let origin_locals =
                    origin.fetch_preload_thread_locals().as_ptr() as *mut x86_preload_thread_locals;
                unsafe {
                    (*locals).alt_stack_nesting_level = (*origin_locals).alt_stack_nesting_level
                };
                // clone() syscalls set the child stack pointer, so the child is no
                // longer in the syscallbuf code even if the parent was.
            }
            SupportedArch::X64 => {
                t.activate_preload_thread_locals(Some(origin));
                let locals = local_addr.as_ptr() as *mut x64_preload_thread_locals;
                let origin_locals =
                    origin.fetch_preload_thread_locals().as_ptr() as *mut x64_preload_thread_locals;
                unsafe {
                    (*locals).alt_stack_nesting_level = (*origin_locals).alt_stack_nesting_level
                };
                // clone() syscalls set the child stack pointer, so the child is no
                // longer in the syscallbuf code even if the parent was.
            }
        },
        None => (),
    }
}
