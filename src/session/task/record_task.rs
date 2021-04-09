use super::{
    task_common::{
        self,
        at_preload_init_common,
        clone_task_common,
        destroy_common,
        post_vm_clone_common,
        post_wait_clone_common,
        read_mem,
        read_val_mem,
        reset_syscallbuf_common,
        set_syscallbuf_locked_common,
        task_drop_common,
        write_val_mem,
    },
    task_inner::PtraceData,
    TaskSharedPtr,
    TaskSharedWeakPtr,
};
use crate::{
    arch::{Architecture, NativeArch},
    arch_structs::{kernel_sigaction, siginfo_t as siginfo_t_arch},
    auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem},
    bindings::{
        kernel::user_desc,
        perf_event::{PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE},
        ptrace::{
            PTRACE_EVENT_CLONE,
            PTRACE_EVENT_FORK,
            PTRACE_EVENT_VFORK,
            PTRACE_GETEVENTMSG,
            PTRACE_GETSIGMASK,
            PTRACE_O_TRACEEXIT,
            PTRACE_SETSIGINFO,
            PTRACE_SETSIGMASK,
        },
        signal::{siginfo_t, SI_QUEUE, __SIGRTMIN},
    },
    event::{
        Event,
        EventType,
        SignalDeterministic,
        SignalResolvedDisposition,
        SyscallEventData,
        SyscallState,
        SyscallbufFlushEventData,
    },
    file_monitor::preserve_file_monitor::PreserveFileMonitor,
    kernel_abi::{
        is_exit_group_syscall,
        is_exit_syscall,
        is_restart_syscall_syscall,
        is_wait4_syscall,
        is_waitid_syscall,
        is_waitpid_syscall,
        sigaction_sigset_size,
        syscall_number_for_close,
        syscall_number_for_dup3,
        syscall_number_for_execve,
        syscall_number_for_gettid,
        syscall_number_for_openat,
        syscall_number_for_rt_sigaction,
        SupportedArch,
    },
    kernel_metadata::syscall_name,
    kernel_supplement::{sig_set_t, NUM_SIGNALS, SA_RESETHAND, SA_SIGINFO},
    log::{LogDebug, LogInfo, LogWarn},
    perf_counters,
    preload_interface::{
        mprotect_record,
        preload_globals,
        syscallbuf_hdr,
        syscallbuf_record,
        PRELOAD_THREAD_LOCALS_SIZE,
    },
    preload_interface_arch::{
        preload_thread_locals,
        rdcall_init_buffers_params,
        rdcall_init_preload_params,
    },
    rd::RD_RESERVED_ROOT_DIR_FD,
    record_signal::{disarm_desched_event, SIGCHLD_SYNTHETIC},
    record_syscall::TaskSyscallState,
    registers::{with_converted_registers, Registers},
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    seccomp_filter_rewriter::SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO,
    session::{
        address_space::{
            address_space::AddressSpace,
            memory_range::MemoryRange,
            BreakpointType,
            Enabled,
            Privileged,
            Traced,
        },
        record_session::RecordSession,
        task::{
            task_common::{
                compute_trap_reasons_common,
                destroy_buffers_common,
                detect_syscall_arch_common,
                did_waitpid_common,
                next_syscallbuf_record_common,
                open_mem_fd_common,
                post_exec_for_exe_common,
                post_exec_syscall_common,
                read_bytes_fallible_common,
                read_bytes_helper_common,
                read_bytes_helper_for,
                read_c_str_common,
                resume_execution_common,
                set_thread_area_common,
                stored_record_size_common,
                syscallbuf_data_size_common,
                write_bytes_common,
                write_bytes_helper_common,
            },
            task_inner::{
                CloneFlags,
                CloneReason,
                ResumeRequest,
                TaskInner,
                TicksRequest,
                TrapReasons,
                WaitRequest,
                WriteFlags,
            },
            Task,
            WeakTaskPtrSet,
        },
        Session,
        SessionSharedPtr,
    },
    sig::{self, Sig},
    ticks::Ticks,
    trace::{
        trace_frame::FrameTime,
        trace_writer::{MappingOrigin, RecordInTrace, TraceWriter},
    },
    util::{
        checksum_process_memory,
        default_action,
        dump_process_memory,
        is_deterministic_signal,
        read_proc_status_fields,
        should_checksum,
        should_dump_memory,
        signal_bit,
        u8_slice,
        u8_slice_mut,
        SignalAction,
    },
    wait_status::WaitStatus,
};
use libc::{
    pid_t,
    syscall,
    SYS_rt_sigqueueinfo,
    SYS_rt_tgsigqueueinfo,
    SYS_tgkill,
    CLD_STOPPED,
    CLD_TRAPPED,
    EINVAL,
    EIO,
    ENOENT,
    O_CLOEXEC,
    O_CREAT,
    O_RDWR,
    PR_TSC_ENABLE,
    SIGCHLD,
};
use nix::{
    errno::errno,
    fcntl::readlink,
    sched::sched_yield,
    sys::{mman::ProtFlags, stat::stat},
    unistd::{access, getpgid, AccessFlags, Pid},
};
use owning_ref::OwningHandle;
use ptr::NonNull;
use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    cmp::min,
    collections::VecDeque,
    convert::{TryFrom, TryInto},
    error::Error,
    ffi::{c_void, CString, OsStr, OsString},
    mem::{self, size_of},
    ops::Deref,
    ptr::{self, copy_nonoverlapping},
    rc::{Rc, Weak},
    slice,
};

pub const SYNTHETIC_TIME_SLICE_SI_CODE: i32 = -9999;

#[derive(Clone)]
pub struct Sighandlers {
    /// Keep as opaque for now. Need to ensure correct visibility.
    handlers: [Sighandler; NUM_SIGNALS as usize],
}

impl Default for Sighandlers {
    fn default() -> Self {
        Sighandlers {
            handlers: array_init::array_init(|_| Sighandler::default()),
        }
    }
}

impl Sighandlers {
    pub fn new() -> Sighandlers {
        Self::default()
    }

    pub fn get_mut(&mut self, sig: Sig) -> &mut Sighandler {
        // DIFF NOTE: in rr there is a call to assert_valid
        // In rust we don't need this as an out of bounds index
        // will panic
        &mut self.handlers[sig.as_raw() as usize]
    }

    pub fn get(&self, sig: Sig) -> &Sighandler {
        // DIFF NOTE: in rr there is a call to assert_valid
        // In rust we don't need this as an out of bounds index
        // will panic
        &self.handlers[sig.as_raw() as usize]
    }

    pub fn init_from_current_process(&mut self) {
        for (i, h) in self.handlers.iter_mut().enumerate().skip(1) {
            let mut sa: kernel_sigaction<NativeArch> = Default::default();
            if 0 != unsafe {
                libc::syscall(
                    syscall_number_for_rt_sigaction(NativeArch::arch()) as _,
                    i,
                    0,
                    &mut sa,
                    size_of::<u64>(),
                )
            } {
                // EINVAL means we're querying an unused signal number.
                debug_assert_eq!(EINVAL, errno());
                continue;
            }
            // @TODO msan unpoison?

            h.init_arch::<NativeArch>(&sa);
        }
    }

    /// For each signal in `table` such that is_user_handler() is
    /// true, reset the disposition of that signal to SIG_DFL, and
    /// clear the resethand flag if it's set.  SIG_IGN signals are
    /// not modified.
    ///
    /// (After an exec() call copies the original sighandler table,
    /// this is the operation required by POSIX to initialize that
    /// table copy.)
    pub fn reset_user_handlers(&mut self, arch: SupportedArch) {
        for h in self.handlers.iter_mut().skip(1) {
            // If the handler was a user handler, reset to
            // default.  If it was SIG_IGN or SIG_DFL,
            // leave it alone.
            if h.disposition() == SignalDisposition::SignalHandler {
                reset_handler(h, arch);
            }
        }
    }
}

/// NOTE that the struct is NOT pub
#[derive(Clone)]
/// Stores the table of signal dispositions and metadata for an
/// arbitrary set of tasks.  Each of those tasks must own one one of
/// the `refcount`s while they still refer to this.
/// @TODO VISIBILITY forced to pub this struct even though rr does not.
pub struct Sighandler {
    k_sa_handler: RemotePtr<Void>,
    /// Saved kernel_sigaction; used to restore handler
    sa: Vec<u8>,
    resethand: bool,
    takes_siginfo: bool,
}

impl Sighandler {
    pub fn new() -> Sighandler {
        Self::default()
    }

    pub fn init_arch<Arch: Architecture>(&mut self, ksa: &kernel_sigaction<Arch>) {
        self.k_sa_handler = Arch::as_rptr(ksa.k_sa_handler);
        self.sa.resize(size_of::<kernel_sigaction<Arch>>(), 0);
        self.sa.copy_from_slice(u8_slice(ksa));
        self.resethand = Arch::ulong_as_usize(ksa.sa_flags) & SA_RESETHAND as usize != 0;
        self.takes_siginfo = Arch::ulong_as_usize(ksa.sa_flags) & SA_SIGINFO as usize != 0;
    }

    pub fn reset_arch<Arch: Architecture>(&mut self) {
        let ksa = kernel_sigaction::<Arch>::default();
        self.init_arch::<Arch>(&ksa);
    }

    pub fn disposition(&self) -> SignalDisposition {
        match self.k_sa_handler.as_usize() {
            0 => SignalDisposition::SignalDefault,
            1 => SignalDisposition::SignalIgnore,
            _ => SignalDisposition::SignalHandler,
        }
    }

    pub fn get_user_handler(&self) -> Option<RemoteCodePtr> {
        if self.disposition() == SignalDisposition::SignalHandler {
            Some(RemoteCodePtr::from_val(self.k_sa_handler.as_usize()))
        } else {
            None
        }
    }
}

fn reset_handler(handler: &mut Sighandler, arch: SupportedArch) {
    rd_arch_function!(handler, reset_arch, arch);
}

impl Default for Sighandler {
    fn default() -> Self {
        Sighandler {
            resethand: false,
            takes_siginfo: false,
            sa: Vec::new(),
            k_sa_handler: RemotePtr::null(),
        }
    }
}

/// Different kinds of waits a task can do.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum WaitType {
    /// Not waiting for anything
    WaitTypeNone,
    /// Waiting for any child process
    WaitTypeAny,
    /// Waiting for any child with the same process group ID
    WaitTypeSamePgid,
    /// Waiting for any child with a specific process group ID
    WaitTypePgid,
    /// Waiting for a specific process ID
    WaitTypePid,
}

/// Reasons why we simulate stopping of a task (see ptrace(2) man page).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EmulatedStopType {
    NotStopped,
    /// stopped by a signal. This applies to non-ptracees too.
    GroupStop,
    /// Stopped before delivering a signal. ptracees only.
    SignalDeliveryStop,
}

/// Pass UseSysgood to emulate_ptrace_stop to add 0x80 to the signal
/// if PTRACE_O_TRACESYSGOOD is in effect.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum AddSysgoodFlag {
    IgnoreSysgood,
    UseSysgood,
}

#[derive(Clone, Default)]
pub struct SyscallbufCodeLayout {
    pub syscallbuf_code_start: RemoteCodePtr,
    pub syscallbuf_code_end: RemoteCodePtr,
    pub get_pc_thunks_start: RemoteCodePtr,
    pub get_pc_thunks_end: RemoteCodePtr,
    pub syscallbuf_final_exit_instruction: RemoteCodePtr,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SignalDisposition {
    SignalDefault,
    SignalIgnore,
    SignalHandler,
}

#[derive(Copy, Clone)]
pub struct StashedSignal {
    pub siginfo: siginfo_t,
    pub deterministic: SignalDeterministic,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FlushSyscallbuf {
    FlushSyscallbuf,
    /// Pass this if it's safe to replay the event before we process the
    /// syscallbuf records.
    DontFlushSyscallbuf,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum AllowSyscallbufReset {
    AllowResetSyscallbuf,
    /// Pass this if it's safe to replay the event before we process the
    /// syscallbuf records.
    DontResetSyscallbuf,
}

pub type RecordTaskSharedWeakPtr = Weak<RefCell<RecordTask>>;
pub type RecordTaskSharedPtr = Rc<RefCell<RecordTask>>;

pub struct RecordTask {
    pub task_inner: TaskInner,
    pub ticks_at_last_recorded_syscall_exit: Cell<Ticks>,

    /// Scheduler state
    pub registers_at_start_of_last_timeslice: RefCell<Registers>,
    pub time_at_start_of_last_timeslice: Cell<FrameTime>,
    /// Task 'nice' value set by setpriority(2).
    ///
    /// We use this to drive scheduling decisions. rd's scheduler is
    /// deliberately simple and unfair; a task never runs as long as there's
    /// another runnable task with a lower nice value.
    pub priority: Cell<i32>,
    /// Tasks with in_round_robin_queue set are in the session's
    /// in_round_robin_queue instead of its task_priority_set.
    pub in_round_robin_queue: Cell<bool>,

    /// ptrace emulation state
    ///
    /// Task for which we're emulating ptrace of this task, or None
    pub emulated_ptracer: Option<TaskSharedWeakPtr>,
    pub emulated_ptrace_tracees: WeakTaskPtrSet,
    pub emulated_ptrace_event_msg: Cell<usize>,
    /// @TODO Do we want to make this a queue?
    /// Saved emulated-ptrace signals
    pub saved_ptrace_siginfos: Vec<siginfo_t>,
    /// Code to deliver to ptracer/waiter when it waits. Note that zero can be a
    /// valid code! Reset to zero when leaving the stop due to PTRACE_CONT etc.
    pub emulated_stop_code: Cell<WaitStatus>,
    /// Always zero while no ptracer is attached.
    pub emulated_ptrace_options: Cell<u32>,
    /// One of PTRACE_CONT, PTRACE_SYSCALL --- or 0 if the tracee has not been
    /// continued by its ptracer yet, or has no ptracer.
    pub emulated_ptrace_cont_command: Cell<u32>,
    /// true when a ptracer/waiter wait() can return `emulated_stop_code`.
    pub emulated_stop_pending: Cell<bool>,
    /// true if this task needs to send a SIGCHLD to its ptracer for its
    /// emulated ptrace stop
    pub emulated_ptrace_sigchld_pending: Cell<bool>,
    /// true if this task needs to send a SIGCHLD to its parent for its
    /// emulated stop
    pub emulated_sigchld_pending: Cell<bool>,
    /// tracer attached via PTRACE_SEIZE
    pub emulated_ptrace_seized: Cell<bool>,
    pub emulated_ptrace_queued_exit_stop: Cell<bool>,
    pub in_wait_type: Cell<WaitType>,
    pub in_wait_pid: Cell<pid_t>,

    /// Signal handler state
    ///
    /// Points to the signal-hander table of this task.  If this
    /// task is a non-fork clone child, then the table will be
    /// shared with all its "thread" siblings.  Any updates made to
    /// that shared table are immediately visible to all sibling
    /// threads.
    ///
    /// fork children always get their own copies of the table.
    /// And if this task exec()s, the table is copied and stripped
    /// of user sighandlers (see below).
    pub sighandlers: Rc<RefCell<Sighandlers>>,
    /// If not NotStopped, then the task is logically stopped and this is the type
    /// of stop.
    pub emulated_stop_type: Cell<EmulatedStopType>,
    /// True if the task sigmask may have changed and we need to refetch it.
    pub blocked_sigs_dirty: Cell<bool>,
    /// Most accesses to this should use set_sigmask and get_sigmask to ensure
    /// the mirroring to syscallbuf is correct.
    pub blocked_sigs: Cell<sig_set_t>,
    pub syscallbuf_blocked_sigs_generation: Cell<u32>,

    /// Syscallbuf state
    pub syscallbuf_code_layout: RefCell<SyscallbufCodeLayout>,
    pub desched_fd: RefCell<ScopedFd>,
    /// Value of hdr->num_rec_bytes when the buffer was flushed
    pub flushed_num_rec_bytes: Cell<u32>,
    /// Nonzero after the trace recorder has flushed the
    /// syscallbuf.  When this happens, the recorder must prepare a
    /// "reset" of the buffer, to zero the record count, at the
    /// next available slow (taking `desched` into
    /// consideration).
    pub flushed_syscallbuf: Cell<bool>,
    /// This bit is set when code wants to prevent the syscall
    /// record buffer from being reset when it normally would be.
    /// This bit is set by the desched code.
    pub delay_syscallbuf_reset_for_desched: Cell<bool>,
    /// This is set when code wants to prevent the syscall
    /// record buffer from being reset when it normally would be.
    /// This is set by the code for handling seccomp SIGSYS signals.
    pub delay_syscallbuf_reset_for_seccomp_trap: Cell<bool>,
    /// Value to return from PR_GET_SECCOMP
    pub prctl_seccomp_status: Cell<u8>,

    /// Mirrored kernel state
    /// This state agrees with kernel-internal values
    ///
    /// Futex list passed to `set_robust_list()`.  We could keep a
    /// strong type for this list head and read it if we wanted to,
    /// but for now we only need to remember its address / size at
    /// the time of the most recent set_robust_list() call.
    pub robust_futex_list: Cell<RemotePtr<Void>>,
    pub robust_futex_list_len: Cell<usize>,
    /// The memory cell the kernel will clear and notify on exit,
    /// if our clone parent requested it.
    pub tid_futex: Cell<RemotePtr<i32>>,
    /// This is the recorded tid of the tracee *in its own pid namespace*.
    pub own_namespace_rec_tid: Cell<pid_t>,
    pub exit_code: Cell<i32>,
    /// Signal delivered by the kernel when this task terminates
    /// DIFF NOTE: We have an Option<> here which is different from rr.
    /// In rr None is indicated by 0
    pub termination_signal: Option<Sig>,

    /// Our value for PR_GET/SET_TSC (one of PR_TSC_ENABLED, PR_TSC_SIGSEGV).
    pub tsc_mode: Cell<i32>,
    /// Our value for ARCH_GET/SET_CPUID (0 -> generate SIGSEGV, 1 -> do CPUID).
    /// Only used if session().has_cpuid_faulting().
    /// @TODO should this be made into an Option?
    pub cpuid_mode: Cell<i32>,
    /// The current stack of events being processed.  (We use a
    /// deque instead of a stack because we need to iterate the
    /// events.)
    pub pending_events: VecDeque<Event>,
    /// Stashed signal-delivery state, ready to be delivered at
    /// next opportunity.
    pub stashed_signals: VecDeque<Box<StashedSignal>>,
    pub stashed_signals_blocking_more_signals: Cell<bool>,
    pub stashed_group_stop: Cell<bool>,
    pub break_at_syscallbuf_traced_syscalls: Cell<bool>,
    pub break_at_syscallbuf_untraced_syscalls: Cell<bool>,
    pub break_at_syscallbuf_final_instruction: Cell<bool>,

    /// The pmc is programmed to interrupt at a value requested by the tracee, not
    /// by rd.
    pub next_pmc_interrupt_is_for_user: Cell<bool>,

    pub did_record_robust_futex_changes: Cell<bool>,

    /// DIFF NOTE: This field does not exist in rr
    /// Since the property system is not used intensively in rr its
    /// simpler just to add this single field instead.
    pub syscall_state: SyscallStateSharedPtr,
}

impl Deref for RecordTask {
    type Target = TaskInner;

    fn deref(&self) -> &Self::Target {
        &self.task_inner
    }
}

impl Task for RecordTask {
    fn clone_task(
        &mut self,
        reason: CloneReason,
        flags: CloneFlags,
        stack: RemotePtr<Void>,
        tls: RemotePtr<Void>,
        cleartid_addr: RemotePtr<i32>,
        new_tid: pid_t,
        new_rec_tid: Option<pid_t>,
        new_serial: u32,
        maybe_other_session: Option<SessionSharedPtr>,
    ) -> TaskSharedPtr {
        ed_assert_eq!(self, reason, CloneReason::TraceeClone);
        let t = clone_task_common(
            self,
            reason,
            flags,
            stack,
            tls,
            cleartid_addr,
            new_tid,
            new_rec_tid,
            new_serial,
            maybe_other_session,
        );
        if t.borrow().session().is_recording() {
            if flags.contains(CloneFlags::CLONE_CLEARTID) {
                log!(
                    LogDebug,
                    "cleartid futex is {:#x}",
                    cleartid_addr.as_usize()
                );
                ed_assert!(self, !cleartid_addr.is_null());
                t.borrow().as_rec_unwrap().tid_futex.set(cleartid_addr);
            } else {
                log!(LogDebug, "(clone child not enabling CLEARTID)");
            }
        }
        t
    }

    fn own_namespace_tid(&self) -> pid_t {
        self.own_namespace_rec_tid.get()
    }

    fn post_wait_clone(&mut self, clone_from: &dyn Task, flags: CloneFlags) {
        post_wait_clone_common(self, clone_from, flags);

        let rt = clone_from.as_rec_unwrap();
        self.priority.set(rt.priority.get());
        self.syscallbuf_code_layout = rt.syscallbuf_code_layout.clone();
        self.prctl_seccomp_status.set(rt.prctl_seccomp_status.get());
        self.robust_futex_list.set(rt.robust_futex_list.get());
        self.robust_futex_list_len
            .set(rt.robust_futex_list_len.get());
        self.tsc_mode.set(rt.tsc_mode.get());
        self.cpuid_mode.set(rt.cpuid_mode.get());
        if flags.contains(CloneFlags::CLONE_SHARE_SIGHANDLERS) {
            self.sighandlers = rt.sighandlers.clone();
        } else {
            self.sighandlers = Rc::new(RefCell::new(rt.sighandlers.borrow().clone()));
        }

        self.update_own_namespace_tid();
    }

    fn will_resume_execution(
        &mut self,
        _resume_req: ResumeRequest,
        _wait_req: WaitRequest,
        ticks_request: TicksRequest,
        maybe_sig: Option<Sig>,
    ) {
        // We may execute user code, which could lead to an RDTSC or grow-map
        // operation which unblocks SIGSEGV, and we'll need to know whether to
        // re-block it. So we need our cached sigmask to be up to date.
        // We don't need to this if we're not going to execute user code
        // (i.e. ticks_request == TicksRequest::ResumeNoTicks) except that did_wait can't
        // easily check for that and may restore blocked_sigs so it had better be
        // accurate.
        self.get_sigmask();

        if self.stashed_signals_blocking_more_signals.get() {
            // A stashed signal we have already accepted for this task may
            // have a sigaction::sa_mask that would block the next signal to be
            // delivered and cause it to be delivered to a different task. If we allow
            // such a signal to be delivered to this task then we run the risk of never
            // being able to process the signal (if it stays blocked indefinitely).
            // To prevent this, block any further signal delivery as long as there are
            // stashed signals.
            // We assume the kernel can't report a new signal of the same number
            // in response to us injecting a signal. XXX is this true??? We don't
            // have much choice, signal injection won't work if we block the signal.
            // We leave rr signals unblocked. TIME_SLICE_SIGNAL has to be unblocked
            // because blocking it seems to cause problems for some hardware/kernel
            // configurations (see https://github.com/rr-debugger/rr/issues/1979),
            // causing them to stop counting events.
            let mut sigset = !self.session().as_record().unwrap().rd_signal_mask();
            match maybe_sig {
                // We're injecting a signal, so make sure that signal is unblocked.
                Some(sig) => sigset = sigset & !signal_bit(sig),
                None => (),
            }
            let ret = self.fallible_ptrace(
                PTRACE_SETSIGMASK,
                RemotePtr::<Void>::from(8usize),
                &mut PtraceData::ReadFrom(u8_slice(&sigset)),
            );
            if ret < 0 {
                if errno() == EIO {
                    fatal!("PTRACE_SETSIGMASK not supported; rd requires Linux kernel >= 3.11");
                }
                ed_assert_eq!(self, errno(), EINVAL);
            } else {
                log!(LogDebug,  "Set signal mask to block all signals (bar SYSCALLBUF_DESCHED_SIGNAL/TIME_SLICE_SIGNAL) while we \
                       have a stashed signal");
            }
        }

        // TicksRequest::ResumeNoTicks means that tracee code is not going to run so there's no
        // need to set breakpoints and in fact they might interfere with rr
        // processing.
        if ticks_request != TicksRequest::ResumeNoTicks {
            if !self.at_may_restart_syscall() {
                // If the tracee has SIGTRAP blocked or ignored and we hit one of these
                // breakpoints, the kernel will automatically unblock the signal and set
                // its disposition to DFL, effects which we ought to undo to keep these
                // SIGTRAPs invisible to tracees. Fixing the sigmask happens
                // automatically in did_wait(). Restoring the signal-ignored status is
                // handled in `handle_syscallbuf_breakpoint`.

                // Set breakpoints at untraced syscalls to catch us entering an untraced
                // syscall. We don't need to do this (and shouldn't do this) if the
                // execution requestor wants to stop inside untraced syscalls.
                // If we have an interrupted syscall that we may restart, don't
                // set the breakpoints because we should restart the syscall instead
                // of breaking and delivering signals. The syscallbuf code doesn't
                // (and must not) perform more than one blocking syscall for any given
                // buffered syscall.
                for p in self.syscallbuf_syscall_entry_breakpoints() {
                    self.vm()
                        .add_breakpoint(self, p, BreakpointType::BkptInternal);
                }
            }
            let addr = self
                .syscallbuf_code_layout
                .borrow()
                .syscallbuf_final_exit_instruction;

            if self.break_at_syscallbuf_final_instruction.get() {
                self.vm()
                    .add_breakpoint(self, addr, BreakpointType::BkptInternal);
            }
        }
    }

    /// Forwarded method
    fn destroy(&mut self, maybe_detach: Option<bool>) {
        destroy_common(self, maybe_detach)
    }

    fn log_pending_events(&self) {
        let depth = self.pending_events.len();

        debug_assert!(depth > 0);
        if 1 == depth {
            log!(LogInfo, "(no pending events)");
            return;
        }

        // The event at depth 0 is the placeholder event, which isn't
        // useful to log.  Skip it.
        let mut iter = self.pending_events.iter().skip(1);
        while let Some(it) = iter.next_back() {
            it.log();
        }
    }

    /// Forwarded method
    fn detect_syscall_arch(&mut self) -> SupportedArch {
        detect_syscall_arch_common(self)
    }

    /// Forwarded method
    fn destroy_buffers(&mut self) {
        destroy_buffers_common(self)
    }

    /// Forwarded method
    fn post_exec_for_exe(&mut self, exe_file: &OsStr) {
        post_exec_for_exe_common(self, exe_file)
    }

    /// Forwarded method
    fn resume_execution(
        &mut self,
        how: ResumeRequest,
        wait_how: WaitRequest,
        tick_period: TicksRequest,
        maybe_sig: Option<Sig>,
    ) {
        resume_execution_common(self, how, wait_how, tick_period, maybe_sig)
    }

    /// Forwarded method
    fn stored_record_size(&mut self, record: RemotePtr<syscallbuf_record>) -> usize {
        stored_record_size_common(self, record)
    }

    /// Forwarded method
    fn did_waitpid(&mut self, status: WaitStatus) {
        did_waitpid_common(self, status)
    }

    /// Forwarded method
    fn next_syscallbuf_record(&mut self) -> RemotePtr<syscallbuf_record> {
        next_syscallbuf_record_common(self)
    }

    fn as_task_inner(&self) -> &TaskInner {
        &self.task_inner
    }

    fn as_record_task(&self) -> Option<&RecordTask> {
        Some(self)
    }

    fn as_record_task_mut(&mut self) -> Option<&mut RecordTask> {
        Some(self)
    }

    fn as_rec_unwrap(&self) -> &RecordTask {
        self
    }

    fn as_rec_mut_unwrap(&mut self) -> &mut RecordTask {
        self
    }

    fn on_syscall_exit(&mut self, syscallno: i32, arch: SupportedArch, regs: &Registers) {
        with_converted_registers(regs, arch, |regs| {
            task_common::on_syscall_exit_common(self, syscallno, arch, regs);
            rd_arch_function!(self, on_syscall_exit_arch, arch, syscallno, regs);
        })
    }

    fn did_wait(&mut self) {
        for p in self.syscallbuf_syscall_entry_breakpoints() {
            self.vm()
                .remove_breakpoint(p, BreakpointType::BkptInternal, self);
        }
        if self.break_at_syscallbuf_final_instruction.get() {
            let final_exit_instruction = self
                .syscallbuf_code_layout
                .borrow()
                .syscallbuf_final_exit_instruction;
            self.vm()
                .remove_breakpoint(final_exit_instruction, BreakpointType::BkptInternal, self);
        }

        if self.stashed_signals_blocking_more_signals.get() {
            // Saved 'blocked_sigs' must still be correct regardless of syscallbuf
            // state, because we do not allow stashed_signals_blocking_more_signals
            // to hold across syscalls (traced or untraced) that change the signal mask.
            ed_assert!(self, !self.blocked_sigs_dirty.get());
            self.xptrace(
                PTRACE_SETSIGMASK,
                RemotePtr::<Void>::from(size_of::<sig_set_t>()),
                &mut PtraceData::ReadFrom(u8_slice(&self.blocked_sigs)),
            );
        } else if !self.syscallbuf_child.get().is_null() {
            // The syscallbuf struct is only 32 bytes currently so read the whole thing
            // at once to aVoid multiple calls to read_mem. Even though this shouldn't
            // need a syscall because we use a local-mapping, apparently that lookup
            // is still noticeably expensive.
            let child_addr = self.syscallbuf_child.get();
            let syscallbuf = read_val_mem(self, child_addr, None);
            if syscallbuf.in_sigprocmask_critical_section != 0 {
                // `blocked_sigs` may have been updated but the syscall not yet issued.
                // Use the kernel's value.
                self.invalidate_sigmask();
            } else {
                let syscallbuf_generation = syscallbuf.blocked_sigs_generation;
                if syscallbuf_generation > self.syscallbuf_blocked_sigs_generation.get() {
                    self.syscallbuf_blocked_sigs_generation
                        .set(syscallbuf_generation);
                    self.blocked_sigs.set(syscallbuf.blocked_sigs);
                }
            }
        }
    }

    fn at_preload_init(&mut self) {
        at_preload_init_common(self);
        do_preload_init(self);
    }

    /// Forwarded method
    fn open_mem_fd(&mut self) -> bool {
        open_mem_fd_common(self)
    }

    /// Forwarded method
    fn read_bytes_fallible(&mut self, addr: RemotePtr<Void>, buf: &mut [u8]) -> Result<usize, ()> {
        read_bytes_fallible_common(self, addr, buf)
    }

    /// Forwarded method
    fn read_bytes_helper(&mut self, addr: RemotePtr<Void>, buf: &mut [u8], ok: Option<&mut bool>) {
        read_bytes_helper_common(self, addr, buf, ok)
    }

    fn read_bytes(&mut self, addr: RemotePtr<Void>, buf: &mut [u8]) {
        read_bytes_helper_common(self, addr, buf, None)
    }

    /// Forwarded method
    fn read_c_str(&mut self, child_addr: RemotePtr<u8>) -> CString {
        read_c_str_common(self, child_addr)
    }

    /// Forwarded method
    fn write_bytes_helper(
        &mut self,
        addr: RemotePtr<u8>,
        buf: &[u8],
        ok: Option<&mut bool>,
        flags: WriteFlags,
    ) {
        write_bytes_helper_common(self, addr, buf, ok, flags)
    }

    /// Forwarded method
    fn syscallbuf_data_size(&mut self) -> usize {
        syscallbuf_data_size_common(self)
    }

    /// Forwarded method
    fn write_bytes(&mut self, child_addr: RemotePtr<u8>, buf: &[u8]) {
        write_bytes_common(self, child_addr, buf);
    }
    // Forwarded method
    fn post_exec_syscall(&mut self) {
        post_exec_syscall_common(self)
    }

    // Forwarded method
    fn compute_trap_reasons(&mut self) -> TrapReasons {
        compute_trap_reasons_common(self)
    }

    fn post_vm_clone(
        &mut self,
        reason: CloneReason,
        flags: CloneFlags,
        origin: &mut dyn Task,
    ) -> bool {
        if post_vm_clone_common(self, reason, flags, origin) {
            // @TODO Could just do a &self here and avoid a clone.
            let preload_thread_locals_mapping = self
                .vm()
                .mapping_of(AddressSpace::preload_thread_locals_start())
                .unwrap()
                .map
                .clone();

            let mode = self.trace_writer_mut().write_mapped_region(
                self,
                &preload_thread_locals_mapping,
                &preload_thread_locals_mapping.fake_stat(),
                &[],
                Some(MappingOrigin::RdBufferMapping),
                None,
            );
            ed_assert_eq!(self, mode, RecordInTrace::DontRecordInTrace);

            true
        } else {
            false
        }
    }

    /// Forwarded method
    fn set_thread_area(&mut self, tls: RemotePtr<user_desc>) {
        set_thread_area_common(self, tls)
    }

    /// Forwarded method
    fn reset_syscallbuf(&mut self) {
        reset_syscallbuf_common(self);
    }

    /// Forwarded method
    fn set_syscallbuf_locked(&mut self, locked: bool) {
        set_syscallbuf_locked_common(self, locked);
    }
}

pub type SyscallStateSharedPtr = Rc<RefCell<Option<TaskSyscallState>>>;

impl RecordTask {
    pub fn syscall_state_shr_ptr(&self) -> SyscallStateSharedPtr {
        self.syscall_state.clone()
    }

    /// Every Task owned by a RecordSession is a RecordTask. Functionality that
    /// only applies during recording belongs here.
    pub fn new(
        session: &RecordSession,
        tid: pid_t,
        serial: u32,
        a: SupportedArch,
        weak_self: TaskSharedWeakPtr,
    ) -> Box<dyn Task> {
        let mut rt = RecordTask {
            task_inner: TaskInner::new(session, tid, None, serial, a, weak_self),
            ticks_at_last_recorded_syscall_exit: Default::default(),
            time_at_start_of_last_timeslice: Default::default(),
            priority: Default::default(),
            in_round_robin_queue: Default::default(),
            emulated_ptracer: None,
            emulated_ptrace_event_msg: Default::default(),
            emulated_ptrace_options: Default::default(),
            emulated_ptrace_cont_command: Default::default(),
            emulated_stop_pending: Default::default(),
            emulated_ptrace_sigchld_pending: Default::default(),
            emulated_sigchld_pending: Default::default(),
            emulated_ptrace_seized: Default::default(),
            emulated_ptrace_queued_exit_stop: Default::default(),
            in_wait_type: Cell::new(WaitType::WaitTypeNone),
            in_wait_pid: Default::default(),
            emulated_stop_type: Cell::new(EmulatedStopType::NotStopped),
            blocked_sigs_dirty: Cell::new(true),
            syscallbuf_blocked_sigs_generation: Default::default(),
            flushed_num_rec_bytes: Default::default(),
            flushed_syscallbuf: Default::default(),
            delay_syscallbuf_reset_for_desched: Default::default(),
            delay_syscallbuf_reset_for_seccomp_trap: Default::default(),
            prctl_seccomp_status: Default::default(),
            robust_futex_list_len: Default::default(),
            own_namespace_rec_tid: Cell::new(tid),
            exit_code: Cell::new(0),
            termination_signal: None,
            tsc_mode: Cell::new(PR_TSC_ENABLE),
            cpuid_mode: Cell::new(1),
            stashed_signals: Default::default(),
            stashed_signals_blocking_more_signals: Default::default(),
            stashed_group_stop: Default::default(),
            break_at_syscallbuf_traced_syscalls: Default::default(),
            break_at_syscallbuf_untraced_syscalls: Default::default(),
            break_at_syscallbuf_final_instruction: Default::default(),
            next_pmc_interrupt_is_for_user: Default::default(),
            did_record_robust_futex_changes: Default::default(),
            // Implicit
            registers_at_start_of_last_timeslice: RefCell::new(Registers::new(a)),
            emulated_ptrace_tracees: Default::default(),
            saved_ptrace_siginfos: vec![],
            emulated_stop_code: Default::default(),
            sighandlers: Rc::new(RefCell::new(Default::default())),
            blocked_sigs: Cell::new(0),
            syscallbuf_code_layout: Default::default(),
            desched_fd: Default::default(),
            robust_futex_list: Default::default(),
            tid_futex: Default::default(),
            pending_events: Default::default(),
            syscall_state: Default::default(),
        };

        rt.push_event(Event::sentinel());
        if session.tasks().is_empty() {
            // Initial tracee. It inherited its state from this process, so set it up.
            // The very first task we fork inherits the signal
            // dispositions of the current OS process (which should all be
            // default at this point, but ...).  From there on, new tasks
            // will transitively inherit from this first task.
            rt.sighandlers.borrow_mut().init_from_current_process();
        }
        let box_rt = Box::new(rt);
        box_rt
    }

    // @TODO clone_task() ??
    pub fn syscallbuf_syscall_entry_breakpoints(&self) -> Vec<RemoteCodePtr> {
        let mut result = Vec::<RemoteCodePtr>::new();
        if self.break_at_syscallbuf_untraced_syscalls.get() {
            result.push(AddressSpace::rd_page_syscall_entry_point(
                Traced::Untraced,
                Privileged::Unprivileged,
                Enabled::RecordingOnly,
                self.arch(),
            ));
            result.push(AddressSpace::rd_page_syscall_entry_point(
                Traced::Untraced,
                Privileged::Unprivileged,
                Enabled::RecordingAndReplay,
                self.arch(),
            ));
        }
        if self.break_at_syscallbuf_traced_syscalls.get() {
            result.push(AddressSpace::rd_page_syscall_entry_point(
                Traced::Traced,
                Privileged::Unprivileged,
                Enabled::RecordingAndReplay,
                self.arch(),
            ));
        }
        result
    }

    pub fn is_at_syscallbuf_syscall_entry_breakpoint(&self) -> bool {
        let arch = self.arch();
        let i = self.ip().decrement_by_bkpt_insn_length(arch);
        for p in self.syscallbuf_syscall_entry_breakpoints() {
            if i == p {
                return true;
            }
        }
        false
    }

    pub fn is_at_syscallbuf_final_instruction_breakpoint(&self) -> bool {
        if !self.break_at_syscallbuf_final_instruction.get() {
            return false;
        }
        let arch = self.arch();
        let i = self.ip().decrement_by_bkpt_insn_length(arch);
        i == self
            .syscallbuf_code_layout
            .borrow()
            .syscallbuf_final_exit_instruction
    }

    /// Initialize tracee buffers in `self`, i.e., implement
    /// RDCALL_init_syscall_buffer.  This task must be at the point
    /// of *exit from* the rdcall.  Registers will be updated with
    /// the return value from the rdcall, which is also returned
    /// from this call.
    pub fn init_buffers(&mut self) {
        let arch = self.arch();
        rd_arch_function!(self, init_buffers_arch, arch)
    }

    fn init_buffers_arch<Arch: Architecture>(&mut self) {
        // NB: the tracee can't be interrupted with a signal while
        // we're processing the rdcall, because it's masked off all
        // signals.
        let mut remote = AutoRemoteSyscalls::new(self);

        // Arguments to the rdcall.
        let child_args: RemotePtr<rdcall_init_buffers_params<Arch>> =
            RemotePtr::from(remote.task().regs_ref().arg1());
        let mut args = read_val_mem(remote.task_mut(), child_args, None);

        args.cloned_file_data_fd = -1;
        if remote.vm().syscallbuf_enabled() {
            let siz = remote
                .task()
                .session()
                .as_record()
                .unwrap()
                .syscall_buffer_size();
            remote.task_mut().syscallbuf_size.set(siz);
            args.syscallbuf_size = remote.task_mut().syscallbuf_size.get().try_into().unwrap();
            let syscallbuf_km = remote.init_syscall_buffer(RemotePtr::null());
            args.syscallbuf_ptr =
                Arch::from_remote_ptr(RemotePtr::<u8>::cast(remote.task().syscallbuf_child.get()));
            remote
                .task_mut()
                .desched_fd_child
                .set(args.desched_counter_fd);
            // Prevent the child from closing this fd
            remote.task().fd_table().add_monitor(
                remote.task_mut(),
                args.desched_counter_fd,
                Box::new(PreserveFileMonitor::new()),
            );
            *remote
                .task()
                .as_record_task()
                .unwrap()
                .desched_fd
                .borrow_mut() = remote.retrieve_fd(args.desched_counter_fd);

            let record_in_trace = remote
                .task()
                .as_record_task()
                .unwrap()
                .trace_writer_mut()
                .write_mapped_region(
                    remote.task().as_record_task().unwrap(),
                    &syscallbuf_km,
                    &syscallbuf_km.fake_stat(),
                    &[],
                    Some(MappingOrigin::RdBufferMapping),
                    None,
                );
            ed_assert_eq!(
                remote.task(),
                record_in_trace,
                RecordInTrace::DontRecordInTrace
            );

            if remote
                .task()
                .as_record_task()
                .unwrap()
                .trace_writer()
                .supports_file_data_cloning()
                && remote
                    .task()
                    .session()
                    .as_record()
                    .unwrap()
                    .use_read_cloning()
            {
                let tuid = remote.task().tuid();
                let arch = remote.task().arch();
                let clone_file_name = remote
                    .task()
                    .as_record_task()
                    .unwrap()
                    .trace_writer()
                    .file_data_clone_file_name(tuid);
                let mut name = AutoRestoreMem::push_cstr(&mut remote, clone_file_name.as_os_str());
                let filename_addr = name.get().unwrap();
                let cloned_file_data = rd_syscall!(
                    name,
                    syscall_number_for_openat(arch),
                    RD_RESERVED_ROOT_DIR_FD,
                    // skip leading '/' since we want the path to be relative to the root fd
                    filename_addr.as_usize() + 1,
                    O_RDWR | O_CREAT | O_CLOEXEC,
                    0o0600
                ) as i32;

                if cloned_file_data >= 0 {
                    let tid = name.task().tid();
                    let free_fd: i32 = find_free_file_descriptor(tid);
                    let cloned_file_data_fd_child = rd_syscall!(
                        name,
                        syscall_number_for_dup3(arch),
                        cloned_file_data,
                        free_fd,
                        O_CLOEXEC
                    ) as i32;
                    name.task_mut()
                        .cloned_file_data_fd_child
                        .set(cloned_file_data_fd_child);

                    if cloned_file_data_fd_child != free_fd {
                        ed_assert!(name.task(), cloned_file_data_fd_child < 0);
                        log!(LogWarn, "Couldn't dup clone-data file to free fd");
                        name.task_mut()
                            .cloned_file_data_fd_child
                            .set(cloned_file_data);
                    } else {
                        // Prevent the child from closing this fd. We're going to close it
                        // ourselves and we don't want the child closing it and then reopening
                        // its own file with this fd.
                        name.task().fd_table().add_monitor(
                            name.task_mut(),
                            cloned_file_data_fd_child,
                            Box::new(PreserveFileMonitor::new()),
                        );
                        rd_infallible_syscall!(
                            name,
                            syscall_number_for_close(arch),
                            cloned_file_data
                        );
                    }
                    args.cloned_file_data_fd = name.task().cloned_file_data_fd_child.get();
                }
            }
        } else {
            args.syscallbuf_ptr = Arch::from_remote_ptr(RemotePtr::null());
            args.syscallbuf_size = 0;
        }
        args.scratch_buf = Arch::from_remote_ptr(remote.task().scratch_ptr.get());
        args.usable_scratch_size = remote.task().usable_scratch_size().try_into().unwrap();

        // Return the mapped buffers to the child.
        write_val_mem(remote.task_mut(), child_args, &args, None);

        // The tracee doesn't need this addr returned, because it's
        // already written to the inout `args` param, but we stash it
        // away in the return value slot so that we can easily check
        // that we map the segment at the same addr during replay.
        let syscallbuf_child = remote.task().syscallbuf_child.get();
        remote
            .initial_regs_mut()
            .set_syscall_result(syscallbuf_child.as_usize());
    }

    pub fn post_exec(&mut self) {
        // Change syscall number to execve *for the new arch*. If we don't do this,
        // and the arch changes, then the syscall number for execve in the old arch/
        // is treated as the syscall we're executing in the new arch, with hilarious
        // results.
        let arch = self.arch();
        let syscallno: i32 = syscall_number_for_execve(arch);
        self.registers
            .borrow_mut()
            .set_original_syscallno(syscallno as isize);
        // Fix event architecture and syscall number
        self.ev_mut().syscall_event_mut().number = syscallno;
        self.ev_mut().syscall_event_mut().set_arch(arch);

        // The signal mask is inherited across execve so we don't need to invalidate.
        let exe_file = exe_path(self);
        self.post_exec_for_exe(&exe_file);
        match &self.emulated_ptracer {
            Some(emulated_ptracer) => ed_assert!(
                self,
                !(emulated_ptracer.upgrade().unwrap().borrow().arch() == SupportedArch::X86
                    && self.arch() == SupportedArch::X64),
                "We don't support a 32-bit process tracing a 64-bit process"
            ),
            None => (),
        }

        // Clear robust_list state to match kernel state. If this task is cloned
        // soon after exec, we must not do a bogus set_robust_list syscall for
        // the clone.
        self.set_robust_list(RemotePtr::null(), 0);

        // @TODO Check this again
        let cloned = self.sighandlers.borrow().clone();
        self.sighandlers = Rc::new(RefCell::new(cloned));
        self.sighandlers.borrow_mut().reset_user_handlers(arch);

        // Newly execed tasks always have non-faulting mode (from their point of
        // view, even if rr is secretly causing faults).
        self.cpuid_mode.set(1);
    }

    pub fn trace_writer(&self) -> OwningHandle<SessionSharedPtr, Ref<'_, TraceWriter>> {
        let sess = self.session();
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_record() }.unwrap().trace_writer()
        });
        owning_handle
    }

    pub fn trace_writer_mut(&self) -> OwningHandle<SessionSharedPtr, RefMut<'_, TraceWriter>> {
        let sess = self.session();
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_record() }.unwrap().trace_writer_mut()
        });
        owning_handle
    }

    /// Emulate 'tracer' ptracing this task.
    /// DIFF NOTE: Slightly odd old_maybe_tracer param to solve borrow issues
    /// @TODO Put in an enum instead of new_maybe_tracer/old_maybe_tracer
    pub fn set_emulated_ptracer(
        &mut self,
        new_maybe_tracer: Option<&mut RecordTask>,
        old_maybe_tracer: Option<&mut RecordTask>,
    ) {
        match new_maybe_tracer {
            Some(tracer) => {
                ed_assert!(self, self.emulated_ptracer.is_none());
                tracer.emulated_ptrace_tracees.insert(self.weak_self_ptr());
                self.emulated_ptracer = Some(tracer.weak_self_ptr());
            }
            None => {
                ed_assert!(self, self.emulated_ptracer.is_some());
                ed_assert!(
                    self,
                    self.emulated_stop_type.get() == EmulatedStopType::NotStopped
                        || self.emulated_stop_type.get() == EmulatedStopType::GroupStop
                );
                let removed_tracer = self.emulated_ptracer.take().unwrap();
                let tracer = old_maybe_tracer.unwrap();
                ed_assert!(self, removed_tracer.ptr_eq(&tracer.weak_self));
                tracer.emulated_ptrace_tracees.erase(self.weak_self_ptr());
            }
        }
    }

    /// Call this when an event occurs that should stop a ptraced task.
    /// If we're emulating ptrace of the task, stop the task and wake the ptracer
    /// if it's waiting, and queue "status" to be reported to the
    /// ptracer. If siginfo is non-null, we'll report that siginfo, otherwise we'll
    /// make one up based on the status (unless the status is an exit code).
    /// Returns true if the task is stopped-for-emulated-ptrace, false otherwise.
    /// DIFF NOTE: Additional param `tracer`.
    /// DIFF NOTE: We ONLY call this function if there is an emulated tracer. There is no boolean
    /// return value unlike rr.
    /// DIFF NOTE: Additional param `maybe_active_sibling` to solve already borrowed possibility
    pub fn emulate_ptrace_stop(
        &mut self,
        status: WaitStatus,
        tracer: &RecordTask,
        maybe_siginfo: Option<&siginfo_t>,
        maybe_si_code: Option<i32>,
        maybe_active_sibling: Option<&RecordTask>,
    ) {
        let si_code = maybe_si_code.unwrap_or(0);
        ed_assert_eq!(
            self,
            self.emulated_stop_type.get(),
            EmulatedStopType::NotStopped
        );
        // @TODO Check this logic again
        match maybe_siginfo {
            Some(siginfo) => {
                ed_assert_eq!(
                    self,
                    status.ptrace_signal().unwrap().as_raw(),
                    siginfo.si_signo
                );
                self.save_ptrace_signal_siginfo(siginfo);
            }
            None => {
                let mut si: siginfo_t = siginfo_t::default();
                if status.maybe_ptrace_event().is_ptrace_event() || status.is_syscall() {
                    si.si_signo = status.ptrace_signal().unwrap().as_raw();
                    si.si_code = status.get() >> 8;
                } else {
                    si.si_code = si_code;
                }
                self.save_ptrace_signal_siginfo(&si);
            }
        }

        self.force_emulate_ptrace_stop(status, tracer, maybe_active_sibling);
    }

    /// Force the ptrace-stop state no matter what state the task is currently in.
    /// DIFF NOTE: Extra param `tracer` to solve already borrowed possibility
    /// DIFF NOTE: Extra param `maybe_active_sibling` to solve already borrowed possibility
    pub fn force_emulate_ptrace_stop(
        &mut self,
        status: WaitStatus,
        tracer: &RecordTask,
        maybe_active_sibling: Option<&RecordTask>,
    ) {
        self.emulated_stop_type
            .set(if status.maybe_group_stop_sig().is_sig() {
                EmulatedStopType::GroupStop
            } else {
                EmulatedStopType::SignalDeliveryStop
            });
        self.emulated_stop_code.set(status);
        self.emulated_stop_pending.set(true);
        self.emulated_ptrace_sigchld_pending.set(true);

        ed_assert!(
            self,
            self.emulated_ptracer
                .as_ref()
                .unwrap()
                .ptr_eq(&tracer.weak_self)
        );
        tracer.send_synthetic_sigchld_if_necessary(Some(self), maybe_active_sibling);
        // The SIGCHLD will eventually be reported to rd via a ptrace stop,
        // interrupting wake_task's syscall (probably a waitpid) if necessary. At
        // that point, we'll fix up the siginfo data with values that match what
        // the kernel would have delivered for a real ptracer's SIGCHLD. When the
        // signal handler (if any) returns, if wake_task was in a blocking wait that
        // wait will be resumed, at which point rec_prepare_syscall_arch will
        // discover the pending ptrace result and emulate the wait syscall to
        // return that result immediately.
    }

    /// Called when we're about to deliver a signal to this task. If it's a
    /// synthetic SIGCHLD and there's a ptraced task that needs to SIGCHLD,
    /// update the siginfo to reflect the status and note that that
    /// ptraced task has had its SIGCHLD sent.
    /// Note that we can't set the correct siginfo when we send the signal, because
    /// it requires us to set information only the kernel has permission to set.
    /// Returns false if this signal should be deferred.
    pub fn set_siginfo_for_synthetic_sigchld(&self, si: &mut siginfo_t) -> bool {
        if !is_synthetic_sigchld(si) {
            return true;
        }

        if self.is_syscall_restart() && EventType::EvSyscallInterruption == self.ev().event_type() {
            let syscallno = self.regs_ref().original_syscallno() as i32;
            let syscall_arch = self.ev().syscall_event().arch();
            if is_waitpid_syscall(syscallno, syscall_arch)
                || is_waitid_syscall(syscallno, syscall_arch)
                || is_wait4_syscall(syscallno, syscall_arch)
            {
                // Wait-like syscalls always check for notifications from waited-for processes
                // before they check for pending signals. So, if the tracee has a pending
                // notification that also generated a signal, the wait syscall will return
                // normally rather than returning with ERESTARTSYS etc. (The signal will
                // be dequeued and any handler run on the return to userspace, however.)
                // We need to emulate this by deferring our synthetic ptrace signal
                // until after the wait syscall has returned.
                log!(LogDebug, "Deferring signal because we're in a wait");
                // Return false to tell the caller to defer the signal and resume
                // the syscall.
                return false;
            }
        }

        for tracee_rc in &self.emulated_ptrace_tracees {
            let mut traceeb = tracee_rc.borrow_mut();
            let tracee = traceeb.as_rec_mut_unwrap();
            if tracee.emulated_ptrace_sigchld_pending.get() {
                tracee.emulated_ptrace_sigchld_pending.set(false);
                let sia: &mut siginfo_t_arch<NativeArch> = unsafe { mem::transmute(si) };
                tracee.set_siginfo_for_waited_task::<NativeArch>(sia);
                sia._sifields._rt.si_sigval_.sival_int = 0;
                return true;
            }
        }

        for child_tg in self.thread_group().borrow().children() {
            for child in child_tg.borrow().task_set() {
                let mut rchildb = child.borrow_mut();
                let rchild = rchildb.as_rec_mut_unwrap();
                if rchild.emulated_sigchld_pending.get() {
                    rchild.emulated_sigchld_pending.set(false);
                    let sia: &mut siginfo_t_arch<NativeArch> = unsafe { mem::transmute(si) };
                    rchild.set_siginfo_for_waited_task::<NativeArch>(sia);
                    sia._sifields._rt.si_sigval_.sival_int = 0;
                    return true;
                }
            }
        }

        true
    }

    pub fn set_siginfo_for_waited_task<Arch: Architecture>(&self, si: &mut siginfo_t_arch<Arch>) {
        // XXX handle CLD_EXITED here
        if self.emulated_stop_type.get() == EmulatedStopType::GroupStop {
            si.si_code = CLD_STOPPED;
            // @TODO Do we want just a maybe_stop_sig().unwrap_sig().as_raw() approach here?
            let maybe_stop_sig = self.emulated_stop_code.get().maybe_stop_sig();
            if maybe_stop_sig.is_sig() {
                si._sifields._sigchld.si_status_ = maybe_stop_sig.unwrap_sig().as_raw();
            } else {
                si._sifields._sigchld.si_status_ = 0;
            }
        } else {
            si.si_code = CLD_TRAPPED;
            // @TODO Is this approach what we want? Or do we want ptrace_signal().unwrap().as_raw() ?
            si._sifields._sigchld.si_status_ = self
                .emulated_stop_code
                .get()
                .ptrace_signal()
                .map_or(0, |sig| sig.as_raw());
        }
        si._sifields._sigchld.si_pid_ = self.tgid();
        si._sifields._sigchld.si_uid_ = self.getuid();
    }

    /// Return a reference to the saved siginfo record for the stop-signal
    /// that we're currently in a ptrace-stop for.
    pub fn get_saved_ptrace_siginfo(&self) -> &siginfo_t {
        let sig = self.emulated_stop_code.get().ptrace_signal().unwrap();
        for it in &self.saved_ptrace_siginfos {
            if it.si_signo == sig.as_raw() {
                return it;
            }
        }
        ed_assert!(self, false, "No saved siginfo found for stop-signal ???");

        unreachable!()
    }

    /// When emulating a ptrace-continue with a signal number, extract the siginfo
    /// that was saved by `save_ptrace_signal_siginfo`. If no such siginfo was
    /// saved, make one up.
    pub fn take_ptrace_signal_siginfo(&mut self, sig: Sig) -> siginfo_t {
        for (i, it) in self.saved_ptrace_siginfos.iter().enumerate() {
            if it.si_signo == sig.as_raw() {
                let si = *it;
                self.saved_ptrace_siginfos.remove(i);
                return si;
            }
        }

        let mut si = siginfo_t::default();
        si.si_signo = sig.as_raw();

        si
    }

    /// Returns true if this task is in a waitpid or similar that would return
    /// when t's status changes due to a ptrace event.
    pub fn is_waiting_for_ptrace(&self, t: &RecordTask) -> bool {
        match t.emulated_ptracer.as_ref() {
            Some(ptracer)
                // DIFF NOTE: First check the more specific condition and then check if they are part of same thread group
                // This is there in rd to prevent already borrowed possibility
                if ptracer.ptr_eq(&self.weak_self)
                    || Rc::ptr_eq(
                        &ptracer.upgrade().unwrap().borrow().thread_group(),
                        &self.thread_group(),
                    ) =>
            {
                ()
            }
            _ => return false,
        }
        // XXX need to check |options| to make sure this task is eligible!!
        match self.in_wait_type.get() {
            WaitType::WaitTypeNone => false,
            WaitType::WaitTypeAny => true,
            WaitType::WaitTypeSamePgid => {
                getpgid(Some(Pid::from_raw(t.tgid()))).unwrap()
                    == getpgid(Some(Pid::from_raw(self.tgid()))).unwrap()
            }
            WaitType::WaitTypePgid => {
                getpgid(Some(Pid::from_raw(t.tgid()))).unwrap().as_raw() == self.in_wait_pid.get()
            }
            WaitType::WaitTypePid =>
            // When waiting for a ptracee, a specific pid is interpreted as the
            // exact tid.
            {
                t.tid() == self.in_wait_pid.get()
            }
        }
    }

    /// Returns true if `self` task is in a waitpid or similar that would return
    /// when t's status changes due to a regular event (exit).
    pub fn is_waiting_for(&self, t: &RecordTask) -> bool {
        // t must be a child of this task.
        if !t
            .thread_group()
            .borrow()
            .parent()
            .map_or(false, |parent| Rc::ptr_eq(&parent, &self.thread_group()))
        {
            return false;
        }

        match self.in_wait_type.get() {
            WaitType::WaitTypeNone => false,
            WaitType::WaitTypeAny => true,
            WaitType::WaitTypeSamePgid => {
                getpgid(Some(Pid::from_raw(t.tgid()))).unwrap()
                    == getpgid(Some(Pid::from_raw(self.tgid()))).unwrap()
            }
            WaitType::WaitTypePgid => {
                getpgid(Some(Pid::from_raw(t.tgid()))).unwrap().as_raw() == self.in_wait_pid.get()
            }
            WaitType::WaitTypePid => t.tgid() == self.in_wait_pid.get(),
        }
    }

    /// Call this to force a group stop for this task with signal 'sig',
    /// notifying ptracer if necessary.
    /// DIFF NOTE: Additional param `maybe_active_sibling` to deal with already borrowed possibility.
    pub fn apply_group_stop(&mut self, sig: Sig, maybe_active_sibling: Option<&RecordTask>) {
        if self.emulated_stop_type.get() == EmulatedStopType::NotStopped {
            log!(
                LogDebug,
                "setting {} to GROUP_STOP due to signal {}",
                self.tid(),
                sig
            );
            let status: WaitStatus = WaitStatus::for_group_sig(sig, self);
            ed_assert_eq!(
                self,
                self.emulated_stop_type.get(),
                EmulatedStopType::NotStopped
            );
            let maybe_emulated_ptrace =
                self.emulated_ptracer.as_ref().map(|w| w.upgrade().unwrap());
            match maybe_emulated_ptrace {
                None => {
                    self.emulated_stop_type.set(EmulatedStopType::GroupStop);
                    self.emulated_stop_code.set(status);
                    self.emulated_stop_pending.set(true);
                    self.emulated_sigchld_pending.set(true);
                    match self
                        .session()
                        .find_task_from_rec_tid(get_ppid(self.tid()).unwrap())
                    {
                        Some(t) => t
                            .borrow_mut()
                            .as_rec_mut_unwrap()
                            .send_synthetic_sigchld_if_necessary(Some(self), maybe_active_sibling),
                        None => (),
                    }
                }
                Some(tracer) => {
                    self.emulate_ptrace_stop(
                        status,
                        tracer.borrow().as_rec_unwrap(),
                        None,
                        None,
                        maybe_active_sibling,
                    );
                }
            }
        }
    }

    /// Call this after `sig` is delivered to this task.  Emulate
    /// sighandler updates induced by the signal delivery.
    pub fn signal_delivered(&mut self, sig: Sig) {
        let h_disposition: SignalDisposition;
        let arch = self.arch();

        {
            let mut hb = self.sighandlers.borrow_mut();
            let handler = hb.get_mut(sig);
            h_disposition = handler.disposition();
            if handler.resethand {
                reset_handler(handler, arch);
            }
        }

        if !self.is_sig_ignored(sig) {
            if (sig == sig::SIGTSTP || sig == sig::SIGTTIN || sig == sig::SIGTTOU)
                && h_disposition == SignalDisposition::SignalHandler
            {
                // do nothing
            } else if sig == sig::SIGTSTP
                || sig == sig::SIGTTIN
                || sig == sig::SIGTTOU
                || sig == sig::SIGSTOP
            {
                // All threads in the process are stopped.
                self.apply_group_stop(sig, None);
                for t in self
                    .thread_group()
                    .borrow()
                    .task_set()
                    .iter_except(self.weak_self_ptr())
                {
                    t.borrow_mut()
                        .as_record_task_mut()
                        .unwrap()
                        .apply_group_stop(sig, Some(self));
                }
            } else if sig == sig::SIGCONT {
                self.emulate_sigcont();
            }
        }

        self.send_synthetic_sigchld_if_necessary(None, None);
    }

    /// Return true if `sig` is pending but hasn't been reported to ptrace yet
    /// DIFF NOTE: A little more stricter than rr due to the unwraps and assert
    pub fn is_signal_pending(&self, sig: Sig) -> bool {
        let mut pending_strs =
            read_proc_status_fields(self.tid(), &[b"SigPnd", b"ShdPnd"]).unwrap();
        ed_assert_eq!(self, pending_strs.len(), 2);

        let mask2 =
            u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16).unwrap();
        let mask1 =
            u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16).unwrap();
        ((mask1 | mask2) & signal_bit(sig)) != 0
    }

    /// Return true if there are any signals pending that are not blocked
    /// DIFF NOTE: A little more stricter than rr due to the unwraps and assert
    pub fn has_any_actionable_signal(&self) -> bool {
        let mut pending_strs =
            read_proc_status_fields(self.tid(), &[b"SigPnd", b"ShdPnd", b"SigBlk"]).unwrap();
        ed_assert_eq!(self, pending_strs.len(), 3);

        let mask_blk =
            u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16).unwrap();
        let mask2 =
            u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16).unwrap();
        let mask1 =
            u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16).unwrap();
        ((mask1 | mask2) & !mask_blk) != 0
    }

    /// Get all threads out of an emulated GROUP_STOP
    pub fn emulate_sigcont(&mut self) {
        // All threads in the process are resumed.
        log!(
            LogDebug,
            "setting {} to NOT_STOPPED due to SIGCONT",
            self.tid()
        );
        self.emulated_stop_pending.set(false);
        self.emulated_stop_type.set(EmulatedStopType::NotStopped);
        for t in self
            .thread_group()
            .borrow()
            .task_set()
            .iter_except(self.weak_self_ptr())
        {
            let mut tb = t.borrow_mut();
            let rt = tb.as_rec_mut_unwrap();
            log!(
                LogDebug,
                "setting {} to NOT_STOPPED due to SIGCONT",
                rt.tid()
            );
            rt.emulated_stop_pending.set(false);
            rt.emulated_stop_type.set(EmulatedStopType::NotStopped);
        }
    }

    /// Return true if the disposition of `sig` in `table` isn't
    /// SIG_IGN or SIG_DFL, that is, if a user sighandler will be
    /// invoked when `sig` is received.
    pub fn signal_has_user_handler(&self, sig: Sig) -> bool {
        self.sighandlers.borrow().get(sig).disposition() == SignalDisposition::SignalHandler
    }

    /// If signal_has_user_handler(sig) is true, return the address of the
    /// user handler as a Some, otherwise return None.
    pub fn get_signal_user_handler(&self, sig: Sig) -> Option<RemoteCodePtr> {
        self.sighandlers.borrow().get(sig).get_user_handler()
    }

    /// Return true if the signal handler for `sig` takes a &siginfo_t
    /// parameter.
    pub fn signal_handler_takes_siginfo(&self, sig: Sig) -> bool {
        self.sighandlers.borrow().get(sig).takes_siginfo
    }

    /// Return `sig`'s current sigaction. Returned as raw bytes since the
    /// data is architecture-dependent.
    /// DIFF NOTE: Returning the vector instead of the reference
    pub fn signal_action(&self, sig: Sig) -> Vec<u8> {
        self.sighandlers.borrow().get(sig).sa.to_owned()
    }

    /// Return true iff `sig` is blocked for this.
    pub fn is_sig_blocked(&self, sig: Sig) -> bool {
        if is_unstoppable_signal(sig) {
            // These can never be blocked
            return false;
        }
        let sig_bit = sig.as_raw() - 1;
        (self.get_sigmask() >> sig_bit) & 1 != 0
    }

    /// Return true iff `sig` is SIG_IGN, or it's SIG_DFL and the
    /// default disposition is "ignore".
    pub fn is_sig_ignored(&self, sig: Sig) -> bool {
        if is_unstoppable_signal(sig) {
            // These can never be ignored
            return false;
        }
        match self.sighandlers.borrow().get(sig).disposition() {
            SignalDisposition::SignalIgnore => true,
            SignalDisposition::SignalDefault => SignalAction::Ignore == default_action(sig),
            SignalDisposition::SignalHandler => false,
        }
    }

    /// Return the applications current disposition of `sig`.
    pub fn sig_disposition(&self, sig: Sig) -> SignalDisposition {
        self.sighandlers.borrow().get(sig).disposition()
    }

    /// Return the resolved disposition --- what this signal will actually do,
    /// taking into account the default behavior.
    pub fn sig_resolved_disposition(
        &self,
        sig: Sig,
        deterministic: SignalDeterministic,
    ) -> SignalResolvedDisposition {
        if self.is_fatal_signal(sig, deterministic) {
            return SignalResolvedDisposition::DispositionFatal;
        }
        if self.signal_has_user_handler(sig) && !self.is_sig_blocked(sig) {
            return SignalResolvedDisposition::DispositionUserHandler;
        }
        SignalResolvedDisposition::DispositionIgnored
    }

    /// Set the siginfo for the signal-stop of self.
    pub fn set_siginfo(&mut self, si: &siginfo_t) {
        self.pending_siginfo.set(si.clone());
        self.ptrace_if_alive(
            PTRACE_SETSIGINFO,
            RemotePtr::null(),
            &mut PtraceData::ReadFrom(u8_slice(si)),
        );
    }

    /// Note that the task sigmask needs to be refetched.
    pub fn invalidate_sigmask(&self) {
        self.blocked_sigs_dirty.set(true);
    }

    /// Reset the signal handler for this signal to the default.
    pub fn did_set_sig_handler_default(&self, sig: Sig) {
        let mut shb = self.sighandlers.borrow_mut();
        let h: &mut Sighandler = shb.get_mut(sig);
        reset_handler(h, self.arch());
    }

    /// Check that our status for `sig` matches what's in /proc/<pid>/status.
    #[cfg(debug_assertions)]
    pub fn verify_signal_states(&self) {
        if self.ev().is_syscall_event() {
            // If the syscall event is on the event stack with PROCESSING or EXITING
            // states, we won't have applied the signal-state updates yet while the
            // kernel may have.
            return;
        }
        let mut results =
            read_proc_status_fields(self.tid(), &[b"SigBlk", b"SigIgn", b"SigCgt"]).unwrap();
        ed_assert!(self, results.len() == 3);
        let caught =
            u64::from_str_radix(&results.pop().unwrap().into_string().unwrap(), 16).unwrap();
        let ignored =
            u64::from_str_radix(&results.pop().unwrap().into_string().unwrap(), 16).unwrap();
        let blocked =
            u64::from_str_radix(&results.pop().unwrap().into_string().unwrap(), 16).unwrap();

        for sigi in 1..NUM_SIGNALS as i32 {
            let sig = Sig::try_from(sigi).unwrap();
            let mask = signal_bit(sig);
            if is_unstoppable_signal(sig) {
                ed_assert!(
                    self,
                    blocked & mask == 0,
                    "Expected {} to not be blocked, but it is",
                    sig
                );
                ed_assert!(
                    self,
                    ignored & mask == 0,
                    "Expected {} to not be ignored, but it is",
                    sig
                );
                ed_assert!(
                    self,
                    caught & mask == 0,
                    "Expected {} to not be caught, but it is",
                    sig
                );
            } else {
                let is_sig_blocked = self.is_sig_blocked(sig);
                ed_assert_eq!(
                    self,
                    blocked & mask != 0,
                    is_sig_blocked,
                    "{} {}",
                    sig,
                    if blocked & mask != 0 {
                        " is blocked"
                    } else {
                        " is not blocked"
                    }
                );
                let disposition = self.sighandlers.borrow().get(sig).disposition();
                ed_assert_eq!(
                    self,
                    ignored & mask != 0,
                    disposition == SignalDisposition::SignalIgnore,
                    "{} {}",
                    sig,
                    if ignored & mask != 0 {
                        " is ignored"
                    } else {
                        " is not ignored"
                    }
                );
                ed_assert_eq!(
                    self,
                    caught & mask != 0,
                    disposition == SignalDisposition::SignalHandler,
                    "{} {}",
                    sig,
                    if caught & mask != 0 {
                        " is caught"
                    } else {
                        " is not caught"
                    }
                );
            }
        }
    }

    #[cfg(not(debug_assertions))]
    pub fn verify_signal_states(&self) {
        // Do nothing
    }

    /// Stashed-signal API: if a signal becomes pending at an
    /// awkward time, but could be handled "soon", call
    /// `stash_sig()` to stash the current pending-signal state.
    ///
    /// `has_stashed_sig()` obviously returns true if `stash_sig()`
    /// has been called successfully.
    ///
    /// `pop_stash_sig()` restores the (relevant) state of this
    /// Task to what was saved in `stash_sig()`, and returns the
    /// saved siginfo.  After this call, `has_stashed_sig()` is
    /// false.
    ///
    /// NB: `get_siginfo()` will always return the "real" siginfo,
    /// regardless of stash popped-ness state.  Callers must ensure
    /// they do the right thing with the popped siginfo.
    ///
    /// If the process unexpectedly died (due to SIGKILL), we don't
    /// stash anything.
    pub fn stash_sig(&mut self) {
        let sig = self.maybe_stop_sig().unwrap_sig();

        // Callers should avoid passing SYSCALLBUF_DESCHED_SIGNAL in here.
        ed_assert_ne!(
            self,
            sig,
            self.session().as_record().unwrap().syscallbuf_desched_sig()
        );
        // multiple non-RT signals coalesce
        if sig.as_raw() < __SIGRTMIN as i32 {
            for it in &self.stashed_signals {
                if it.siginfo.si_signo == sig.as_raw() {
                    log!(
                        LogDebug,
                        "discarding stashed signal {} since we already have one pending",
                        sig
                    );
                    return;
                }
            }
        }
        let deterministic = is_deterministic_signal(self);
        let siginfo = self.get_siginfo();
        self.stashed_signals.push_back(Box::new(StashedSignal {
            siginfo,
            deterministic,
        }));
        // Once we've stashed a signal, stop at the next traced/untraced syscall to
        // check whether we need to process the signal before it runs.
        self.stashed_signals_blocking_more_signals.set(true);
        self.break_at_syscallbuf_final_instruction.set(true);
        self.break_at_syscallbuf_traced_syscalls.set(true);
        self.break_at_syscallbuf_untraced_syscalls.set(true);
    }

    pub fn stash_synthetic_sig(&mut self, si: &siginfo_t, deterministic: SignalDeterministic) {
        let sig = si.si_signo;
        // DIFF NOTE: In rr the debug is assert just verifies sig is non-zero
        debug_assert!(sig > 0);
        // Callers should avoid passing SYSCALLBUF_DESCHED_SIGNAL in here.
        debug_assert_ne!(
            sig,
            self.session()
                .as_record()
                .unwrap()
                .syscallbuf_desched_sig()
                .as_raw()
        );
        // multiple non-RT signals coalesce
        if sig < __SIGRTMIN as i32 {
            for (pos, it) in self.stashed_signals.iter().enumerate() {
                if it.siginfo.si_signo == sig {
                    if deterministic == SignalDeterministic::DeterministicSig
                        && it.deterministic == SignalDeterministic::NondeterministicSig
                    {
                        self.stashed_signals.remove(pos);
                        break;
                    } else {
                        log!(
                            LogDebug,
                            "discarding stashed signal {} since we already have one pending",
                            sig
                        );
                        return;
                    }
                }
            }
        }

        self.stashed_signals.insert(
            0,
            Box::new(StashedSignal {
                siginfo: si.clone(),
                deterministic,
            }),
        );
        self.stashed_signals_blocking_more_signals.set(true);
        self.break_at_syscallbuf_final_instruction.set(true);
        self.break_at_syscallbuf_traced_syscalls.set(true);
        self.break_at_syscallbuf_untraced_syscalls.set(true);
    }

    /// DIFF NOTE: Simply called has_stashed_sig() in rr
    pub fn has_any_stashed_sig(&self) -> bool {
        !self.stashed_signals.is_empty()
    }

    pub fn stashed_sig_not_synthetic_sigchld(&self) -> Option<&siginfo_t> {
        for it in &self.stashed_signals {
            if !is_synthetic_sigchld(&it.siginfo) {
                return Some(&it.siginfo);
            }
        }
        None
    }

    pub fn has_stashed_sig(&self, sig: Sig) -> bool {
        for it in &self.stashed_signals {
            if it.siginfo.si_signo == sig.as_raw() {
                return true;
            }
        }
        false
    }

    /// Deliberately returning a *const StashedSignal as we need an addr in pop_stash_sig()
    pub fn peek_stashed_sig_to_deliver(&self) -> Option<*const StashedSignal> {
        if self.stashed_signals.is_empty() {
            return None;
        }
        // Choose the first non-synthetic-SIGCHLD signal so that if a syscall should
        // be interrupted, we'll interrupt it.
        for sig in &self.stashed_signals {
            if !is_synthetic_sigchld(&sig.siginfo) {
                return Some(&**sig as *const StashedSignal);
            }
        }
        self.stashed_signals
            .get(0)
            .map(|sig| &**sig as *const StashedSignal)
    }

    /// @TODO Instead of searching by pointer address which can have its issues why not
    /// store a unique id in a StashedSignal structure or some other approach?
    pub fn pop_stash_sig(&mut self, stashed: *const StashedSignal) {
        for (pos, it) in self.stashed_signals.iter().enumerate() {
            if ptr::eq(&**it as *const StashedSignal, stashed) {
                self.stashed_signals.remove(pos);
                return;
            }
        }

        ed_assert!(self, false, "signal not found");
    }

    pub fn stashed_signal_processed(&mut self) {
        let has_any_stashed_sig = self.has_any_stashed_sig();
        self.break_at_syscallbuf_final_instruction
            .set(has_any_stashed_sig);
        self.break_at_syscallbuf_traced_syscalls
            .set(has_any_stashed_sig);
        self.break_at_syscallbuf_untraced_syscalls
            .set(has_any_stashed_sig);
        self.stashed_signals_blocking_more_signals
            .set(has_any_stashed_sig);
    }

    /// If a group-stop occurs at an inconvenient time, stash it and
    /// process it later.
    pub fn stash_group_stop(&mut self) {
        self.stashed_group_stop.set(true);
    }

    pub fn clear_stashed_group_stop(&mut self) {
        self.stashed_group_stop.set(false);
    }

    pub fn has_stashed_group_stop(&self) -> bool {
        self.stashed_group_stop.get()
    }

    /// Return true if the current state of this looks like the
    /// interrupted syscall at the top of our event stack, if there
    /// is one.
    pub fn is_syscall_restart(&self) -> bool {
        if EventType::EvSyscallInterruption != self.ev().event_type() {
            return false;
        }

        let mut syscallno = self.regs_ref().original_syscallno() as i32;
        let syscall_arch = self.ev().syscall_event().arch();
        let call_name = syscall_name(syscallno, syscall_arch);
        let mut is_restart = false;
        log!(
            LogDebug,
            "  is syscall interruption of recorded {} ? (now {})",
            self.ev(),
            call_name
        );

        // It's possible for the tracee to resume after a sighandler
        // with a fresh syscall that happens to be the same as the one
        // that was interrupted.  So we check here if the args are the
        // same.
        //
        // Of course, it's possible (but less likely) for the tracee
        // to incidentally resume with a fresh syscall that just
        // happens to have the same *arguments* too.  But in that
        // case, we would usually set up scratch buffers etc the same
        // was as for the original interrupted syscall, so we just
        // save a step here.
        //
        // TODO: it's possible for arg structures to be mutated
        // between the original call and restarted call in such a way
        // that it might change the scratch allocation decisions. */
        if is_restart_syscall_syscall(syscallno, syscall_arch) {
            is_restart = true;
            syscallno = self.ev().syscall_event().number;
            log!(LogDebug, "  (SYS_restart_syscall)");
        }

        let mut skip = false;
        if self.ev().syscall_event().number != syscallno {
            log!(LogDebug, "  interrupted {} != {}", self.ev(), call_name);
            skip = true;
        } else {
            let old_regs = &self.ev().syscall_event().regs;
            if !(old_regs.arg1() == self.regs_ref().arg1()
                && old_regs.arg2() == self.regs_ref().arg2()
                && old_regs.arg3() == self.regs_ref().arg3()
                && old_regs.arg4() == self.regs_ref().arg4()
                && old_regs.arg5() == self.regs_ref().arg5()
                && old_regs.arg6() == self.regs_ref().arg6())
            {
                log!(
                    LogDebug,
                    "  regs different at interrupted {}: {} vs {}",
                    call_name,
                    old_regs,
                    self.regs_ref()
                );
                skip = true;
            }
        }

        if !skip {
            is_restart = true;
        }

        if is_restart {
            log!(LogDebug, "  restart of {}", call_name);
        }

        is_restart
    }

    /// Return true iff this is at an execution state where
    /// resuming execution may lead to the restart of an
    /// interrupted syscall.
    ///
    /// For example, if a signal without a user handler is about to
    /// be delivered to this just after a syscall interruption,
    /// then delivering the signal may restart the first syscall
    /// and this method will return true.
    pub fn at_may_restart_syscall(&self) -> bool {
        let depth = self.pending_events.len();
        let prev_ev: Option<&Event> = if depth > 2 {
            Some(&self.pending_events[depth - 2])
        } else {
            None
        };
        EventType::EvSyscallInterruption == self.ev().event_type()
            || (EventType::EvSignalDelivery == self.ev().event_type()
                && prev_ev.is_some()
                && EventType::EvSyscallInterruption == prev_ev.unwrap().event_type())
    }

    /// Return true if this is at an arm-desched-event syscall.
    pub fn is_arm_desched_event_syscall(&self) -> bool {
        self.is_desched_event_syscall() && PERF_EVENT_IOC_ENABLE as usize == self.regs_ref().arg2()
    }

    /// Return true if this is at a disarm-desched-event syscall.
    pub fn is_disarm_desched_event_syscall(&self) -> bool {
        self.is_desched_event_syscall() && PERF_EVENT_IOC_DISABLE as usize == self.regs_ref().arg2()
    }

    /// Return true if `self` may not be immediately runnable,
    /// i.e., resuming execution and then `waitpid()`'ing may block
    /// for an unbounded amount of time.  When the task is in this
    /// state, the tracer must await a `waitpid()` notification
    /// that the task is no longer possibly-blocked before resuming
    /// its execution.
    pub fn may_be_blocked(&self) -> bool {
        (EventType::EvSyscall == self.ev().event_type()
            && SyscallState::ProcessingSyscall == self.ev().syscall_event().state)
            || self.emulated_stop_type.get() != EmulatedStopType::NotStopped
    }

    /// Returns true if it looks like this task has been spinning on an atomic
    /// access/lock.
    pub fn maybe_in_spinlock(&self) -> bool {
        self.time_at_start_of_last_timeslice.get() == self.trace_writer().time()
            && self
                .regs_ref()
                .matches(&self.registers_at_start_of_last_timeslice.borrow())
    }

    /// Return true if `self` is within the syscallbuf library.  This
    /// *does not* imply that $ip is at a buffered syscall.
    pub fn is_in_syscallbuf(&mut self) -> bool {
        if !self.vm().syscallbuf_enabled() {
            // Even if we're in the rd page, if syscallbuf isn't enabled then the
            // rd page is not being used by syscallbuf.
            return false;
        }

        let mut p = self.ip();
        if self.is_in_rd_page()
            || (self.syscallbuf_code_layout.borrow().get_pc_thunks_start <= p
                && p < self.syscallbuf_code_layout.borrow().get_pc_thunks_end)
        {
            // Look at the caller to see if we're in the syscallbuf or not.
            let mut ok = true;
            let child_addr = self.regs_ref().sp();
            let addr = read_ptr(self, child_addr, &mut ok);
            if ok {
                p = addr.into();
            }
        }
        self.vm()
            .monkeypatcher()
            .unwrap()
            .borrow()
            .is_jump_stub_instruction(p)
            || (self.syscallbuf_code_layout.borrow().syscallbuf_code_start <= p
                && p < self.syscallbuf_code_layout.borrow().syscallbuf_code_end)
    }

    /// Shortcut to the most recent `pending_event->desched.rec` when
    /// there's a desched event on the stack, and RemotePtr::null() otherwise.
    /// Exists just so that clients don't need to dig around in the
    /// event stack to find this record
    pub fn desched_rec(&self) -> RemotePtr<syscallbuf_record> {
        if self.ev().is_syscall_event() {
            self.ev().syscall_event().desched_rec
        } else {
            if EventType::EvDesched == self.ev().event_type() {
                self.ev().desched_event().rec
            } else {
                RemotePtr::null()
            }
        }
    }

    /// Returns true when the task is in a signal handler in an interrupted
    /// system call being handled by syscall buffering.
    pub fn running_inside_desched(&self) -> bool {
        for e in &self.pending_events {
            if e.event_type() == EventType::EvDesched {
                return e.desched_event().rec != self.desched_rec();
            }
        }

        false
    }

    pub fn get_ptrace_eventmsg_seccomp_data(&self) -> u16 {
        let mut data: usize = 0;
        // in theory we could hit an assertion failure if the tracee suffers
        // a SIGKILL before we get here. But the SIGKILL would have to be
        // precisely timed between the generation of a PTRACE_EVENT_FORK/CLONE/
        // SYS_clone event, and us fetching the event message here.
        self.xptrace(
            PTRACE_GETEVENTMSG,
            RemotePtr::null(),
            &mut PtraceData::WriteInto(u8_slice_mut(&mut data)),
        );

        data as u16
    }

    /// Save tracee data to the trace.  `addr` is the address in
    /// the address space of this task.  The `record_local*()`
    /// variants record data that's already been read from `self`,
    /// and the `record_remote*()` variants read the data and then
    /// record it.
    ///
    /// If 'addr' is null then no record is written.
    pub fn record_local(&mut self, addr: RemotePtr<Void>, data: &[u8]) {
        self.maybe_flush_syscallbuf();

        if addr.is_null() {
            return;
        }

        self.trace_writer_mut()
            .write_raw(self.rec_tid(), data, addr);
    }

    pub fn record_local_for<T>(&mut self, addr: RemotePtr<T>, data: &T) {
        self.record_local(RemotePtr::<Void>::cast(addr), u8_slice(data))
    }

    pub fn record_local_for_slice<T>(&mut self, addr: RemotePtr<T>, data: &[T]) {
        let num = data.len();
        let data =
            unsafe { slice::from_raw_parts(data.as_ptr() as *const u8, num * size_of::<T>()) };
        self.record_local(RemotePtr::<Void>::cast(addr), data);
    }

    pub fn record_remote(&mut self, addr: RemotePtr<Void>, num_bytes: usize) {
        self.maybe_flush_syscallbuf();

        if addr.is_null() {
            return;
        }

        if self.record_remote_by_local_map(addr, num_bytes) {
            return;
        }

        let buf = read_mem(self, addr, num_bytes, None);
        self.trace_writer_mut()
            .write_raw(self.rec_tid(), &buf, addr);
    }

    pub fn record_remote_for<T>(&mut self, addr: RemotePtr<T>) {
        self.record_remote(RemotePtr::<Void>::cast(addr), size_of::<T>())
    }

    pub fn record_remote_range(&mut self, range: MemoryRange) {
        self.record_remote(range.start(), range.size())
    }

    pub fn record_remote_range_fallible(&mut self, range: MemoryRange) -> Result<usize, ()> {
        self.record_remote_fallible(range.start(), range.size())
    }

    /// Record as much as we can of the bytes in this range. Will record only
    /// contiguous mapped data starting at `addr`.
    pub fn record_remote_fallible(
        &mut self,
        addr: RemotePtr<Void>,
        num_bytes: usize,
    ) -> Result<usize, ()> {
        if self.record_remote_by_local_map(addr, num_bytes) {
            return Ok(num_bytes);
        }

        let mut buf = Vec::new();
        let mut ret = Ok(0);
        if !addr.is_null() {
            buf.resize(num_bytes, 0u8);
            ret = match self.read_bytes_fallible(addr, &mut buf) {
                Ok(nread) => {
                    buf.truncate(nread);
                    Ok(nread)
                }
                Err(()) => {
                    buf.truncate(0);
                    Err(())
                }
            }
        }

        self.trace_writer_mut()
            .write_raw(self.rec_tid(), &buf, addr);

        ret
    }

    /// Record as much as we can of the bytes in this range. Will record only
    /// contiguous mapped-writable data starting at `addr`.
    pub fn record_remote_writable(&mut self, addr: RemotePtr<Void>, mut num_bytes: usize) {
        let mut p = addr;
        while p < addr + num_bytes {
            match self.vm().mapping_of(p) {
                Some(m) => {
                    if !m.map.prot().contains(ProtFlags::PROT_WRITE) {
                        break;
                    }
                    p = m.map.end();
                }
                None => break,
            }
        }
        num_bytes = min(num_bytes, p - addr);

        self.record_remote(addr, num_bytes);
    }

    /// Simple helper that attempts to use the local mapping to record if one
    /// exists
    pub fn record_remote_by_local_map(&mut self, addr: RemotePtr<Void>, num_bytes: usize) -> bool {
        match self.vm().local_mapping(addr, num_bytes) {
            Some(local_data) => {
                self.record_local(addr, local_data);
                true
            }
            None => false,
        }
    }

    /// Save tracee data to the trace.  `addr` is the address in
    /// the address space of this task.
    /// If 'addr' is null then a zero-length record is written.
    pub fn record_remote_even_if_null(&mut self, addr: RemotePtr<Void>, num_bytes: usize) {
        self.maybe_flush_syscallbuf();

        if addr.is_null() {
            self.trace_writer_mut().write_raw(self.rec_tid(), &[], addr);
            return;
        }

        if self.record_remote_by_local_map(addr, num_bytes) {
            return;
        }

        let buf = read_mem(self, addr, num_bytes, None);
        self.trace_writer_mut()
            .write_raw(self.rec_tid(), &buf, addr);
    }

    pub fn record_remote_even_if_null_for<T>(&mut self, addr: RemotePtr<T>) {
        self.record_remote_even_if_null(RemotePtr::<Void>::cast(addr), size_of::<T>())
    }

    /// Manage pending events.  `push_event()` pushes the given
    /// event onto the top of the event stack.  The `pop_*()`
    /// helpers pop the event at top of the stack, which must be of
    /// the specified type.
    pub fn push_event(&mut self, ev: Event) {
        self.pending_events.push_back(ev);
    }

    pub fn push_syscall_event(&mut self, no: i32) {
        let arch = self.detect_syscall_arch();
        self.push_event(Event::new_syscall_event(SyscallEventData::new(no, arch)));
    }

    pub fn pop_event(&mut self, expected_type: EventType) {
        let e = self.pending_events.pop_back().unwrap();
        ed_assert_eq!(self, e.event_type(), expected_type);
    }

    pub fn pop_noop(&mut self) {
        self.pop_event(EventType::EvNoop);
    }

    pub fn pop_desched(&mut self) {
        self.pop_event(EventType::EvDesched);
    }

    pub fn pop_seccomp_trap(&mut self) {
        self.pop_event(EventType::EvSeccompTrap);
    }

    pub fn pop_signal_delivery(&mut self) {
        self.pop_event(EventType::EvSignalDelivery);
    }

    pub fn pop_signal_handler(&mut self) {
        self.pop_event(EventType::EvSignalHandler);
    }

    pub fn pop_syscall(&mut self) {
        self.pop_event(EventType::EvSyscall);
    }

    pub fn pop_syscall_interruption(&mut self) {
        self.pop_event(EventType::EvSyscallInterruption);
    }

    /// Return the event at the top of this's stack.
    pub fn ev(&self) -> &Event {
        self.pending_events.back().unwrap()
    }

    pub fn ev_mut(&mut self) -> &mut Event {
        self.pending_events.back_mut().unwrap()
    }

    /// Call this before recording events or data.  Records
    /// syscallbuf data and flushes the buffer, if there's buffered
    /// data.
    ///
    /// The timing of calls to this is tricky. We must flush the syscallbuf
    /// before recording any data associated with events that happened after the
    /// buffered syscalls. But we don't support flushing a syscallbuf twice with
    /// no intervening reset, i.e. after flushing we have to be sure we'll get
    /// a chance to reset the syscallbuf (i.e. record some other kind of event)
    /// before the tracee runs again in a way that might append another buffered
    /// syscall --- so we can't flush too early
    pub fn maybe_flush_syscallbuf(&mut self) {
        if EventType::EvSyscallbufFlush == self.ev().event_type() {
            // Already flushing.
            return;
        }

        if self.syscallbuf_child.get().is_null() {
            return;
        }

        // This can be called while the task is not stopped, when we prematurely
        // terminate the trace. In that case, the tracee could be concurrently
        // modifying the header. We'll take a snapshot of the header now.
        // The syscallbuf code ensures that writes to syscallbuf records
        // complete before num_rec_bytes is incremented.
        let syscallbuf_child = self.syscallbuf_child.get();
        let hdr = read_val_mem(self, syscallbuf_child, None);

        ed_assert!(
            self,
            !self.flushed_syscallbuf.get() || self.flushed_num_rec_bytes.get() == hdr.num_rec_bytes
        );

        if hdr.num_rec_bytes == 0 || self.flushed_syscallbuf.get() {
            // no records, or we've already flushed.
            return;
        }

        self.push_event(Event::new_syscallbuf_flush_event(
            SyscallbufFlushEventData::default(),
        ));

        // Apply buffered mprotect operations and flush the buffer in the tracee.
        if hdr.mprotect_record_count > 0 {
            assert!(!self.preload_globals.get().is_null());
            let preload_globals = self.preload_globals.get();
            let read_records = read_mem(
                self,
                RemotePtr::<mprotect_record>::cast(
                    RemotePtr::<u8>::cast(preload_globals)
                        + offset_of!(preload_globals, mprotect_records),
                ),
                hdr.mprotect_record_count as usize,
                None,
            );
            for r in &read_records {
                self.vm().protect(
                    self,
                    RemotePtr::from(r.start),
                    r.size.try_into().unwrap(),
                    ProtFlags::from_bits(r.prot).unwrap(),
                );
            }
            self.ev_mut().syscallbuf_flush_event_mut().mprotect_records = read_records;
        }

        // Write the entire buffer in one shot without parsing it,
        // because replay will take care of that.
        if self.is_running() {
            let mut buf = Vec::<u8>::new();
            buf.resize(
                size_of::<syscallbuf_hdr>() + hdr.num_rec_bytes as usize,
                0u8,
            );
            unsafe {
                copy_nonoverlapping(
                    &raw const hdr as *const u8,
                    buf.as_mut_ptr(),
                    size_of::<syscallbuf_hdr>(),
                );
            };
            self.read_bytes_helper(
                RemotePtr::<u8>::cast(syscallbuf_child + 1usize),
                &mut buf[size_of::<syscallbuf_hdr>()..],
                None,
            );
            self.record_local(RemotePtr::<u8>::cast(syscallbuf_child), &buf);
        } else {
            let syscallbuf_data_size = self.syscallbuf_data_size();
            self.record_remote(
                RemotePtr::<u8>::cast(syscallbuf_child),
                syscallbuf_data_size,
            );
        }

        self.record_current_event();
        self.pop_event(EventType::EvSyscallbufFlush);

        self.flushed_syscallbuf.set(true);
        self.flushed_num_rec_bytes.set(hdr.num_rec_bytes);

        let num_rec_bytes = hdr.num_rec_bytes;
        log!(
            LogDebug,
            "Syscallbuf flushed with num_rec_bytes={}",
            num_rec_bytes
        );
    }

    /// Call this after recording an event when it might be safe to reset the
    /// syscallbuf. It must be after recording an event to ensure during replay
    /// we run past any syscallbuf after-syscall code that uses the buffer data.
    pub fn maybe_reset_syscallbuf(&mut self) {
        if self.flushed_syscallbuf.get()
            && !self.delay_syscallbuf_reset_for_desched.get()
            && !self.delay_syscallbuf_reset_for_seccomp_trap.get()
        {
            self.flushed_syscallbuf.set(false);
            log!(LogDebug, "Syscallbuf reset");
            self.reset_syscallbuf();
            self.syscallbuf_blocked_sigs_generation.set(0);
            self.record_event(Some(Event::syscallbuf_reset()), None, None, None);
        }
    }

    /// Record an event on behalf of this.  Record the registers of
    /// this (and other relevant execution state) so that it can be
    /// used or verified during replay, if that state is available
    /// and meaningful at this's current execution point.
    /// `record_current_event()` record `this->ev()`, and
    /// `record_event()` records the specified event.
    pub fn record_current_event(&mut self) {
        self.record_event(None, None, None, None)
    }

    pub fn record_event(
        &mut self,
        maybe_ev: Option<Event>,
        maybe_flush: Option<FlushSyscallbuf>,
        maybe_reset: Option<AllowSyscallbufReset>,
        maybe_registers: Option<&Registers>,
    ) {
        // @TODO see if we can avoid clone() for performance at some point
        let ev = maybe_ev.unwrap_or(self.ev().clone());
        let flush = maybe_flush.unwrap_or(FlushSyscallbuf::FlushSyscallbuf);
        let reset = maybe_reset.unwrap_or(AllowSyscallbufReset::AllowResetSyscallbuf);
        if flush == FlushSyscallbuf::FlushSyscallbuf {
            self.maybe_flush_syscallbuf();
        }

        let current_time = self.trace_writer().time();
        if should_dump_memory(&ev, current_time) {
            dump_process_memory(self, current_time, "rec");
        }

        if should_checksum(&ev, current_time) {
            checksum_process_memory(self, current_time);
        }

        if ev.is_syscall_event() && ev.syscall_event().state == SyscallState::ExitingSyscall {
            self.ticks_at_last_recorded_syscall_exit
                .set(self.tick_count());
        }

        let mut maybe_extra_registers = None;
        let mut maybe_record_registers = None;
        if ev.record_regs() {
            maybe_record_registers = match maybe_registers {
                Some(registers) => Some(registers.clone()),
                None => Some(self.regs_ref().clone()),
            };

            if ev.record_extra_regs() {
                maybe_extra_registers = Some(self.extra_regs_ref().clone());
            }
        }

        self.trace_writer_mut().write_frame(
            self,
            &ev,
            maybe_record_registers.as_ref(),
            maybe_extra_registers.as_ref(),
        );
        log!(LogDebug, "Wrote event {} for time {}", ev, current_time);

        if !ev.has_ticks_slop() && reset == AllowSyscallbufReset::AllowResetSyscallbuf {
            ed_assert_eq!(self, flush, FlushSyscallbuf::FlushSyscallbuf);
            // After we've output an event, it's safe to reset the syscallbuf (if not
            // explicitly delayed) since we will have exited the syscallbuf code that
            // consumed the syscallbuf data.
            // This only works if the event has a reliable tick count so when we
            // reach it, we're done.
            self.maybe_reset_syscallbuf();
        }
    }

    pub fn is_fatal_signal(&self, sig: Sig, deterministic: SignalDeterministic) -> bool {
        if self.thread_group().borrow().received_sigframe_sigsegv {
            // Can't be blocked, caught or ignored
            return true;
        }

        let action = default_action(sig);
        if action != SignalAction::DumpCore && action != SignalAction::Terminate {
            // If the default action doesn't kill the process, it won't die.
            return false;
        }

        if self.is_sig_ignored(sig) {
            // Deterministic fatal signals can't be ignored.
            return deterministic == SignalDeterministic::DeterministicSig;
        }

        // If there's a signal handler, the signal won't be fatal.
        !self.signal_has_user_handler(sig)
    }

    /// Return the pid of the newborn thread created by this task.
    /// Called when this task has a PTRACE_CLONE_EVENT with CLONE_THREAD.
    pub fn find_newborn_thread(&self) -> pid_t {
        ed_assert!(self, self.session().is_recording());
        ed_assert_eq!(self, self.maybe_ptrace_event(), PTRACE_EVENT_CLONE);

        let hint: pid_t = self.get_ptrace_eventmsg_pid();
        let filename = format!("/proc/{}/task/{}", self.tid(), hint);
        // This should always succeed, but may fail in old kernels due to
        // a kernel bug. See RecordSession::handle_ptrace_event.
        if self.session().find_task_from_rec_tid(hint).is_none() && stat(filename.as_str()).is_ok()
        {
            return hint;
        }

        // Code for older kernels
        unimplemented!()
    }

    /// Return the pid of the newborn process (whose parent has pid `parent_pid`,
    /// which need not be the same as the current task's pid, due to CLONE_PARENT)
    /// created by this task. Called when this task has a PTRACE_CLONE_EVENT
    /// without CLONE_THREAD, or PTRACE_FORK_EVENT.
    pub fn find_newborn_process(&self, child_parent: pid_t) -> pid_t {
        ed_assert!(self, self.session().is_recording());
        ed_assert!(
            self,
            self.maybe_ptrace_event() == PTRACE_EVENT_CLONE
                || self.maybe_ptrace_event() == PTRACE_EVENT_VFORK
                || self.maybe_ptrace_event() == PTRACE_EVENT_FORK
        );

        let hint = self.get_ptrace_eventmsg_pid();
        // This should always succeed, but may fail in old kernels due to
        // a kernel bug. See RecordSession::handle_ptrace_event.
        if self.session().find_task_from_rec_tid(hint).is_none()
            && get_ppid(hint).unwrap() == child_parent
        {
            return hint;
        }

        // Code for older kernels
        unimplemented!()
    }

    /// Do a tgkill to send a specific signal to this task.
    pub fn tgkill(&self, sig: Sig) {
        log!(LogDebug, "Sending {} to tid {}", sig, self.tid());
        ed_assert_eq!(self, 0, unsafe {
            syscall(SYS_tgkill, self.real_tgid(), self.tid(), sig.as_raw())
        });
    }

    /// If the process looks alive, kill it. It is recommended to call try_wait(),
    /// on this task before, to make sure liveness is correctly reflected when
    /// making this decision
    pub fn kill_if_alive(&self) {
        if !self.is_dying() {
            self.tgkill(sig::SIGKILL);
        }
    }

    pub fn robust_list(&self) -> RemotePtr<Void> {
        self.robust_futex_list.get()
    }

    pub fn robust_list_len(&self) -> usize {
        self.robust_futex_list_len.get()
    }

    /// Uses /proc so not trivially cheap.
    /// Returns -1 if there was a problem in getting the pid
    pub fn get_parent_pid(&self) -> pid_t {
        get_ppid(self.tid()).unwrap_or(-1)
    }

    /// Return true if this is a "clone child" per the wait(2) man page.
    pub fn is_clone_child(&self) -> bool {
        // @TODO Is this what we want? Should we unwrap?
        self.termination_signal != Some(sig::SIGCHLD)
    }

    pub fn set_termination_signal(&mut self, maybe_sig: Option<Sig>) {
        self.termination_signal = maybe_sig;
    }

    /// When a signal triggers an emulated a ptrace-stop for this task,
    /// save the siginfo so a later emulated ptrace-continue with this signal
    /// number can use it.
    pub fn save_ptrace_signal_siginfo(&mut self, si: &siginfo_t) {
        for (i, it) in self.saved_ptrace_siginfos.iter().enumerate() {
            if it.si_signo == si.si_signo {
                self.saved_ptrace_siginfos.remove(i);
                break;
            }
        }

        self.saved_ptrace_siginfos.push(*si);
    }

    /// Tasks normally can't change their tid. There is one very special situation
    /// where they can: when a non-main-thread does an execve, its tid changes
    /// to the tid of the thread-group leader.
    pub fn set_tid_and_update_serial(&mut self, tid: pid_t, own_namespace_tid: pid_t) {
        self.hpc.borrow_mut().set_tid(tid);
        self.rec_tid.set(tid);
        self.tid.set(tid);
        self.serial.set(self.session().next_task_serial());
        self.own_namespace_rec_tid.set(own_namespace_tid);
    }

    /// Return our cached copy of the signal mask, updating it if necessary.
    pub fn get_sigmask(&self) -> sig_set_t {
        if self.blocked_sigs_dirty.get() {
            self.blocked_sigs.set(self.read_sigmask_from_process());
            log!(
                LogDebug,
                "Refreshed sigmask, now {:#x}",
                self.blocked_sigs.get()
            );
            self.blocked_sigs_dirty.set(false);
        }
        self.blocked_sigs.get()
    }

    /// Just get the signal mask of the process.
    pub fn read_sigmask_from_process(&self) -> sig_set_t {
        // During syscall interruptions, PTRACE_GETSIGMASK may return the sigmask that is going
        // to be restored, not the kernel's current (internal) sigmask, which is what
        // /proc/.../status reports. Always go with what /proc/.../status reports. See
        // https://github.com/torvalds/linux/commit/fcfc2aa0185f4a731d05a21e9f359968fdfd02e7
        if !self.at_may_restart_syscall() {
            let mut mask: sig_set_t = Default::default();
            let ret = self.fallible_ptrace(
                PTRACE_GETSIGMASK,
                RemotePtr::<Void>::from(size_of::<sig_set_t>()),
                &mut PtraceData::WriteInto(u8_slice_mut(&mut mask)),
            );
            if ret >= 0 {
                return mask;
            }
        }

        let mut results = read_proc_status_fields(self.tid(), &[b"SigBlk"]).unwrap();
        ed_assert!(self, results.len() == 1);

        let res = u64::from_str_radix(&results.pop().unwrap().into_string().unwrap(), 16).unwrap();
        res
    }

    /// Unblock the signal for the process.
    pub fn unblock_signal(&mut self, sig: Sig) {
        let mut mask: sig_set_t = self.get_sigmask();
        mask &= !signal_bit(sig);
        let ret = self.fallible_ptrace(
            PTRACE_SETSIGMASK,
            RemotePtr::<Void>::from(size_of::<sig_set_t>()),
            &mut PtraceData::ReadFrom(u8_slice(&mask)),
        );
        if ret < 0 {
            if errno() == EIO {
                fatal!("PTRACE_SETSIGMASK not supported; rd requires Linux kernel >= 3.11");
            }
            ed_assert!(self, errno() == EINVAL);
        } else {
            log!(
                LogDebug,
                "Set signal mask to block all signals (bar \
                 SYSCALLBUF_DESCHED_SIGNAL/TIME_SLICE_SIGNAL) while we \
                 have a stashed signal"
            );
        }
        self.invalidate_sigmask();
    }

    /// Set the signal handler to default for the process.
    pub fn set_sig_handler_default(&mut self, sig: Sig) {
        self.did_set_sig_handler_default(sig);
        // This could happen during a syscallbuf untraced syscall. In that case
        // our remote syscall here could trigger a desched signal if that event
        // is armed, making progress impossible. Disarm the event now.
        disarm_desched_event(self);
        let sa = self.sighandlers.borrow().get(sig).sa.clone();
        let arch = self.arch();
        let mut remote = AutoRemoteSyscalls::new(self);
        let mut mem = AutoRestoreMem::new(&mut remote, Some(&sa), sa.len());
        let ptr_val = mem.get().unwrap().as_usize();
        rd_infallible_syscall!(
            mem,
            syscall_number_for_rt_sigaction(arch),
            sig.as_raw(),
            ptr_val,
            0,
            sigaction_sigset_size(arch)
        );
    }

    pub fn maybe_restore_original_syscall_registers(&mut self) {
        let arch = self.arch();
        let ptl = self.preload_thread_locals();
        rd_arch_function_selfless!(
            maybe_restore_original_syscall_registers_arch,
            arch,
            self,
            ptl
        );
    }

    /// Retrieve the tid of this task from the tracee and store it
    fn update_own_namespace_tid(&mut self) {
        let arch = self.arch();
        let ret: i32;
        {
            let mut remote = AutoRemoteSyscalls::new(self);
            ret = remote.infallible_syscall(syscall_number_for_gettid(arch), &[]) as i32;
        }
        self.own_namespace_rec_tid.set(ret);
    }

    /// Wait for `sync_addr` in `self` address space to have the value
    /// `sync_val`.
    ///
    /// WARNING: this implementation semi-busy-waits for the value
    /// change.  This must only be used in contexts where the futex
    /// will change "soon".
    fn futex_wait(&mut self, sync_addr: RemotePtr<i32>, sync_val: i32) -> Result<(), ()> {
        // Wait for *sync_addr == sync_val.  This implementation isn't
        // pretty, but it's pretty much the best we can do with
        // available kernel tools.
        //
        // TODO: find clever way to avoid busy-waiting.
        loop {
            let mut ok = true;
            let mem = read_val_mem(self, sync_addr, Some(&mut ok));
            if !ok {
                // Invalid addresses are just ignored by the kernel
                return Err(());
            }

            if sync_val == mem {
                break;
            }

            // Try to give our scheduling slot to the kernel
            // thread that's going to write sync_addr.
            sched_yield().unwrap();
        }

        Ok(())
    }

    fn send_synthetic_sigchld_wake_task(&self, rchild: &RecordTask) -> Option<(i32, i32, bool)> {
        // check to see if any thread in the ptracer process is in a waitpid
        // that
        // could read the status of 'tracee'. If it is, we should wake up that
        // thread. Otherwise we send SIGCHLD to the ptracer thread.
        if self.is_waiting_for(rchild) {
            return Some((self.tgid(), self.tid(), self.is_sig_blocked(sig::SIGCHLD)));
        }

        for t in self
            .thread_group()
            .borrow()
            .task_set()
            .iter_except(self.weak_self_ptr())
        {
            let mut rtb = t.borrow_mut();
            let rt = rtb.as_rec_mut_unwrap();
            if rt.is_waiting_for(rchild) {
                return Some((rt.tgid(), rt.tid(), rt.is_sig_blocked(sig::SIGCHLD)));
            }
        }

        None
    }

    /// Called when this task is able to receive a SIGCHLD (e.g. because
    /// we completed delivery of a signal). Sends a new synthetic
    /// SIGCHLD to the task if there are still tasks that need a SIGCHLD
    /// sent for them.
    /// May queue signals for specific tasks.
    /// DIFF NOTE: `maybe_active_child` extra param to deal with already borrowed possibility
    /// DIFF NOTE: `maybe_active_sibling` extra param to deal with already borrowed possibility
    fn send_synthetic_sigchld_if_necessary(
        &self,
        maybe_active_child: Option<&RecordTask>,
        maybe_active_sibling: Option<&RecordTask>,
    ) {
        let mut need_signal = false;
        let mut wake_task = None;
        for tracee_rc in &self.emulated_ptrace_tracees {
            let tracee_rc_weak = Rc::downgrade(&tracee_rc);
            let traceeb;
            let tracee = match maybe_active_child {
                Some(task) if task.weak_self.ptr_eq(&tracee_rc_weak) => task,
                _ => match maybe_active_sibling {
                    Some(task) if task.weak_self.ptr_eq(&tracee_rc_weak) => task,
                    _ => {
                        traceeb = tracee_rc.borrow();
                        traceeb.as_rec_unwrap()
                    }
                },
            };
            if tracee.emulated_ptrace_sigchld_pending.get() {
                need_signal = true;
                // check to see if any thread in the ptracer process is in a waitpid that
                // could read the status of 'tracee'. If it is, we should wake up that
                // thread. Otherwise we send SIGCHLD to the ptracer thread.
                if self.is_waiting_for_ptrace(tracee) {
                    wake_task = Some((self.tgid(), self.tid(), self.is_sig_blocked(sig::SIGCHLD)));
                    break;
                }
                for t in self
                    .thread_group()
                    .borrow()
                    .task_set()
                    .iter_except(self.weak_self_ptr())
                {
                    let rtb = t.borrow();
                    let rt = rtb.as_rec_unwrap();
                    if rt.is_waiting_for_ptrace(tracee) {
                        wake_task = Some((rt.tgid(), rt.tid(), rt.is_sig_blocked(sig::SIGCHLD)));
                        break;
                    }
                }
                if wake_task.is_some() {
                    break;
                }
            }
        }
        if !need_signal {
            for child_tg in self.thread_group().borrow().children() {
                for child_rc in child_tg.borrow().task_set().iter() {
                    let child_rc_weak = Rc::downgrade(&child_rc);
                    let rchildb;
                    let rchild = match maybe_active_child {
                        Some(task) if task.weak_self.ptr_eq(&child_rc_weak) => task,
                        _ => match maybe_active_sibling {
                            Some(task) if task.weak_self.ptr_eq(&child_rc_weak) => task,
                            _ => {
                                rchildb = child_rc.borrow();
                                rchildb.as_rec_unwrap()
                            }
                        },
                    };
                    if rchild.emulated_sigchld_pending.get() {
                        need_signal = true;
                        let wake_task = self.send_synthetic_sigchld_wake_task(rchild);
                        if wake_task.is_some() {
                            break;
                        }
                    }
                }
            }

            if !need_signal {
                return;
            }
        }

        // ptrace events trigger SIGCHLD in the ptracer's wake_task.
        // We can't set all the siginfo values to their correct values here, so
        // we'll patch this up when the signal is received.
        // If there's already a pending SIGCHLD, this signal will be ignored,
        // but at some point the pending SIGCHLD will be delivered and then
        // send_synthetic_SIGCHLD_if_necessary will be called again to deliver a new
        // SIGCHLD if necessary.
        let mut si = siginfo_t::default();
        si.si_code = SI_QUEUE;
        si._sifields._rt.si_sigval.sival_int = SIGCHLD_SYNTHETIC;
        match wake_task {
            Some((tgid, tid, sigchld_blocked)) => {
                log!(LogDebug, "Sending synthetic SIGCHLD to tid {}", tid);
                // We must use the raw SYS_rt_tgsigqueueinfo syscall here to ensure the
                // signal is sent to the correct thread by tid.
                let ret = unsafe { syscall(SYS_rt_tgsigqueueinfo, tgid, tid, SIGCHLD, &si) };
                ed_assert_eq!(self, ret, 0);
                if sigchld_blocked {
                    log!(
                        LogDebug,
                        "SIGCHLD is blocked, kicking it out of the syscall"
                    );
                    // Just sending SIGCHLD won't wake it up. Send it a TIME_SLICE_SIGNAL
                    // as well to make sure it exits a blocking syscall. We ensure those
                    // can never be blocked.
                    // We have to send a negative code here because only the kernel can set
                    // positive codes. We set a magic number so we can recognize it
                    // when received.
                    si.si_code = SYNTHETIC_TIME_SLICE_SI_CODE;
                    let ret = unsafe {
                        syscall(
                            SYS_rt_tgsigqueueinfo,
                            tgid,
                            tid,
                            perf_counters::TIME_SLICE_SIGNAL.as_raw(),
                            &si,
                        )
                    };
                    ed_assert_eq!(self, ret, 0);
                }
            }
            None => {
                // Send the signal to the process as a whole and let the kernel
                // decide which thread gets it.
                let ret = unsafe { syscall(SYS_rt_sigqueueinfo, self.tgid(), SIGCHLD, &si) };
                ed_assert_eq!(self, ret, 0);
                log!(LogDebug, "Sending synthetic SIGCHLD to pid {}", self.tgid());
            }
        }
    }

    /// Call this when SYS_sigaction is finishing with `regs`.
    fn update_sigaction(&mut self, regs: &Registers) {
        rd_arch_function!(self, update_sigaction_arch, regs.arch(), regs);
    }

    /// Update the futex robust list head pointer to `list` (which
    /// is of size `len`).
    fn set_robust_list(&mut self, list: RemotePtr<Void>, len: usize) {
        self.robust_futex_list.set(list);
        self.robust_futex_list_len.set(len);
    }

    fn on_syscall_exit_arch<Arch: Architecture>(&mut self, sys: i32, regs: &Registers) {
        if regs.original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO
            || regs.syscall_failed()
        {
            return;
        }

        if sys == Arch::SET_ROBUST_LIST {
            self.set_robust_list(RemotePtr::from(regs.arg1()), regs.arg2());
            return;
        }

        if sys == Arch::SIGACTION || sys == Arch::RT_SIGACTION {
            // TODO: SYS_signal
            self.update_sigaction(regs);
            return;
        }

        if sys == Arch::SET_TID_ADDRESS {
            self.set_tid_addr(RemotePtr::from(regs.arg1()));
            return;
        }

        if sys == Arch::SIGSUSPEND
            || sys == Arch::RT_SIGSUSPEND
            || sys == Arch::SIGPROCMASK
            || sys == Arch::RT_SIGPROCMASK
            || sys == Arch::PSELECT6
            || sys == Arch::PSELECT6_TIME64
            || sys == Arch::PPOLL
            || sys == Arch::PPOLL_TIME64
        {
            self.invalidate_sigmask();
            return;
        }
    }

    /// Helper function for update_sigaction.
    fn update_sigaction_arch<Arch: Architecture>(&mut self, regs: &Registers) {
        let sig = Sig::try_from(regs.arg1_signed() as i32).unwrap();
        let new_sigaction_addr = RemotePtr::<kernel_sigaction<Arch>>::new(regs.arg2());
        if 0 == regs.syscall_result() && !new_sigaction_addr.is_null() {
            // A new sighandler was installed.  Update our
            // sighandler table.
            // TODO: discard attempts to handle or ignore signals
            // that can't be by POSIX
            let mut sa: kernel_sigaction<Arch> = kernel_sigaction::<Arch>::default();
            read_bytes_helper_for::<Self, kernel_sigaction<Arch>>(
                self,
                new_sigaction_addr,
                &mut sa,
                None,
            );
            self.sighandlers
                .borrow_mut()
                .get_mut(sig)
                .init_arch::<Arch>(&sa);
        }
    }

    /// Update the clear-tid futex to `tid_addr`.
    fn set_tid_addr(&mut self, tid_addr: RemotePtr<i32>) {
        log!(LogDebug, "updating cleartid futex to {}", tid_addr);
        self.tid_futex.set(tid_addr);
    }
}

/// Avoid using low-numbered file descriptors since that can confuse
/// developers.
fn find_free_file_descriptor(for_tid: pid_t) -> i32 {
    assert!(for_tid >= 1);
    let mut fd = 300 + (for_tid % 500);
    loop {
        let filename = format!("/proc/{}/fd/{}", for_tid, fd);
        if access(filename.as_str(), AccessFlags::F_OK).is_err() && errno() == ENOENT {
            return fd;
        }
        fd += 1;
    }
}

fn exe_path(t: &RecordTask) -> OsString {
    let proc_link = format!("/proc/{}/exe", t.tid());
    readlink(proc_link.as_str()).unwrap()
}

fn is_unstoppable_signal(sig: Sig) -> bool {
    sig == sig::SIGSTOP || sig == sig::SIGKILL
}

impl Drop for RecordTask {
    fn drop(&mut self) {
        // DIFF NOTE: This is a bit different from rr
        // The main issue is that record task related cleanup often requires session()
        // When the parent session is being drop-ped upgrading the weak session
        // shared pointer to a normal shared pointer does not succeed
        //
        // In normal situations this `if` statement wont trigger as a session will be
        // available while a task is being drop-ed.
        if self.try_session().is_none() {
            log!(
                LogWarn,
                "parent session is being drop-ped. Doing basic task cleanup but skipping various RecordTask specific cleanups."
            );

            task_drop_common(self);
            return;
        }

        match &self.emulated_ptracer {
            Some(weak_emulated_ptracer) => {
                weak_emulated_ptracer
                    .upgrade()
                    .unwrap()
                    .borrow_mut()
                    .as_record_task_mut()
                    .unwrap()
                    .emulated_ptrace_tracees
                    .erase(self.weak_self_ptr());
                if self.emulated_ptrace_options.get() & PTRACE_O_TRACEEXIT != 0 {
                    ed_assert!(
                        self,
                        self.stable_exit.get(),
                        "PTRACE_O_TRACEEXIT only supported for stable exits for now"
                    );
                }
            }
            None => (),
        }

        for tt in self.emulated_ptrace_tracees.iter() {
            let mut bt = tt.borrow_mut();
            let t = bt.as_record_task_mut().unwrap();
            // XXX emulate PTRACE_O_EXITKILL
            ed_assert!(
                self,
                t.emulated_ptracer.as_ref().unwrap().ptr_eq(&self.weak_self)
            );
            t.emulated_ptracer = None;
            t.emulated_ptrace_options.set(0);
            t.emulated_stop_pending.set(false);
            t.emulated_stop_type.set(EmulatedStopType::NotStopped);
        }

        // Task::destroy has already done PTRACE_DETACH so the task can complete
        // exiting.
        // The kernel explicitly only clears the futex if the address space is shared.
        // If the address space has no other users then the futex will not be cleared
        // even if it lives in shared memory which other tasks can read.
        // Unstable exits may result in the kernel *not* clearing the
        // futex, for example for fatal signals.  So we would
        // deadlock waiting on the futex.
        if !self.unstable.get() && !self.tid_futex.get().is_null() && self.vm().task_set().len() > 1
        {
            // clone()'d tasks can have a pid_t* |ctid| argument
            // that's written with the new task's pid.  That
            // pointer can also be used as a futex: when the task
            // dies, the original ctid value is cleared and a
            // FUTEX_WAKE is done on the address. So
            // pthread_join() is basically a standard futex wait
            // loop.
            log!(
                LogDebug,
                " waiting for tid futex {} to be cleared ...",
                self.tid_futex.get()
            );

            if self.futex_wait(self.tid_futex.get(), 0).is_ok() {
                let val = 0;
                self.record_local_for(self.tid_futex.get(), &val);
            }
        }

        // Write the exit event here so that the value recorded above is captured.
        // Don't flush syscallbuf. Whatever triggered the exit (syscall, signal)
        // should already have flushed it, if it was running. If it was blocked,
        // then the syscallbuf would already have been flushed too. The exception
        // is kill_all_tasks() in which case it's OK to just drop the last chunk of
        // execution. Trying to flush syscallbuf for an exiting task could be bad,
        // e.g. it could be in the middle of syscallbuf code that's supposed to be
        // atomic. For the same reasons don't allow syscallbuf to be reset here.
        self.record_event(
            Some(Event::exit()),
            Some(FlushSyscallbuf::DontFlushSyscallbuf),
            Some(AllowSyscallbufReset::DontResetSyscallbuf),
            None,
        );

        // We expect tasks to usually exit by a call to exit() or
        // exit_group(), so it's not helpful to warn about that.
        if EventType::EvSentinel != self.ev().event_type()
            && (self.pending_events.len() > 2
                || !(self.ev().event_type() == EventType::EvSyscall
                    && (is_exit_syscall(
                        self.ev().syscall_event().number,
                        self.ev().syscall_event().regs.arch(),
                    ) || is_exit_group_syscall(
                        self.ev().syscall_event().number,
                        self.ev().syscall_event().regs.arch(),
                    ))))
        {
            log!(
                LogWarn,
                "{} still has pending events.  From top down:",
                self.tid()
            );
            self.log_pending_events();
        }

        // Important !!
        task_drop_common(self);
    }
}

fn get_ppid(pid: pid_t) -> Result<pid_t, Box<dyn Error>> {
    let mut ppid_str = read_proc_status_fields(pid, &[b"PPid"])?;
    let actual_ppid = pid_t::from_str_radix(&ppid_str.pop().unwrap().into_string().unwrap(), 10)?;
    Ok(actual_ppid)
}

#[allow(non_snake_case)]
fn is_synthetic_sigchld(si: &siginfo_t) -> bool {
    si.si_signo == SIGCHLD && unsafe { si._sifields._rt.si_sigval.sival_int } == SIGCHLD_SYNTHETIC
}

fn maybe_restore_original_syscall_registers_arch<Arch: Architecture>(
    t: &mut RecordTask,
    maybe_local_addr: Option<NonNull<c_void>>,
) {
    if maybe_local_addr.is_none() {
        return;
    }

    let local_addr = maybe_local_addr.unwrap();
    let locals = local_addr.as_ptr() as *const preload_thread_locals<Arch>;
    assert!(size_of::<preload_thread_locals<Arch>>() <= PRELOAD_THREAD_LOCALS_SIZE,);
    let rptr = Arch::as_rptr(unsafe { (*locals).original_syscall_parameters });
    if rptr.is_null() {
        return;
    }

    let args = read_val_mem(t, rptr, None);
    let mut r = t.regs_ref().clone();
    if Arch::long_as_isize(args.no) != r.syscallno() {
        // Maybe a preparatory syscall before the real syscall (e.g. sys_read)
        return;
    }
    r.set_arg1(Arch::long_as_usize(args.args[0]));
    r.set_arg2(Arch::long_as_usize(args.args[1]));
    r.set_arg3(Arch::long_as_usize(args.args[2]));
    r.set_arg4(Arch::long_as_usize(args.args[3]));
    r.set_arg5(Arch::long_as_usize(args.args[4]));
    r.set_arg6(Arch::long_as_usize(args.args[5]));
    t.set_regs(&r);
}

fn do_preload_init(t: &mut RecordTask) {
    rd_arch_function_selfless!(do_preload_init_arch, t.arch(), t);
}

fn do_preload_init_arch<Arch: Architecture>(t: &mut RecordTask) {
    let child_addr = t.regs_ref().arg1();
    let params = read_val_mem(
        t,
        RemotePtr::<rdcall_init_preload_params<Arch>>::from(child_addr),
        None,
    );

    t.syscallbuf_code_layout
        .borrow_mut()
        .syscallbuf_final_exit_instruction =
        Arch::as_rptr(params.syscallbuf_final_exit_instruction).to_code_ptr();
    t.syscallbuf_code_layout.borrow_mut().syscallbuf_code_start =
        Arch::as_rptr(params.syscallbuf_code_start).to_code_ptr();
    t.syscallbuf_code_layout.borrow_mut().syscallbuf_code_end =
        Arch::as_rptr(params.syscallbuf_code_end).to_code_ptr();
    t.syscallbuf_code_layout.borrow_mut().get_pc_thunks_start =
        Arch::as_rptr(params.get_pc_thunks_start).to_code_ptr();
    t.syscallbuf_code_layout.borrow_mut().get_pc_thunks_end =
        Arch::as_rptr(params.get_pc_thunks_end).to_code_ptr();

    let in_chaos: u8 = t.session().as_record().unwrap().enable_chaos() as u8;
    let in_chaos_ptr = RemotePtr::<u8>::cast(Arch::as_rptr(params.globals))
        + offset_of!(preload_globals, in_chaos);
    write_val_mem(t, in_chaos_ptr, &in_chaos, None);
    t.record_local_for(in_chaos_ptr, &in_chaos);

    let cores: i32 = t
        .session()
        .as_record()
        .unwrap()
        .scheduler()
        .pretend_num_cores()
        .try_into()
        .unwrap();
    let cores_ptr = RemotePtr::<i32>::cast(
        RemotePtr::<u8>::cast(Arch::as_rptr(params.globals))
            + offset_of!(preload_globals, pretend_num_cores),
    );
    write_val_mem(t, cores_ptr, &cores, None);
    t.record_local_for(cores_ptr, &cores);

    let desched_sig: u8 = t
        .session()
        .as_record()
        .unwrap()
        .syscallbuf_desched_sig()
        .as_raw()
        .try_into()
        .unwrap();
    let desched_sig_ptr = RemotePtr::<u8>::cast(Arch::as_rptr(params.globals))
        + offset_of!(preload_globals, desched_sig);
    write_val_mem(t, desched_sig_ptr, &desched_sig, None);
    t.record_local_for(desched_sig_ptr, &desched_sig);

    let mut random_seed: u64;
    loop {
        random_seed = rand::random();
        if random_seed > 0 {
            break;
        }
    }
    let random_seed_ptr = RemotePtr::<u64>::cast(
        RemotePtr::<u8>::cast(Arch::as_rptr(params.globals))
            + offset_of!(preload_globals, random_seed),
    );
    write_val_mem(t, random_seed_ptr, &random_seed, None);
    t.record_local_for(random_seed_ptr, &random_seed);
}

fn read_ptr_arch<Arch: Architecture>(t: &mut dyn Task, p: RemotePtr<Void>, ok: &mut bool) -> usize {
    let res = read_val_mem(t, RemotePtr::<Arch::unsigned_word>::cast(p), Some(ok));
    res.try_into().unwrap()
}

fn read_ptr(t: &mut dyn Task, p: RemotePtr<Void>, ok: &mut bool) -> usize {
    let arch = t.arch();
    rd_arch_function_selfless!(read_ptr_arch, arch, t, p, ok)
}
