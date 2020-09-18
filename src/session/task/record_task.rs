use super::{
    task_common::{
        read_mem,
        read_val_mem,
        reset_syscallbuf,
        set_syscallbuf_locked,
        task_drop_common,
    },
    task_inner::PtraceData,
};
use crate::{
    arch::{Architecture, NativeArch},
    bindings::{
        kernel::user_desc,
        ptrace::{PTRACE_GETSIGMASK, PTRACE_SETSIGINFO, PTRACE_SETSIGMASK},
        signal::siginfo_t,
    },
    event::{Event, EventType, SignalDeterministic, SignalResolvedDisposition, SyscallEventData},
    kernel_abi::{
        common::preload_interface::syscallbuf_record,
        native_arch,
        syscall_number_for_rt_sigaction,
        SupportedArch,
    },
    kernel_supplement::{sig_set_t, SA_RESETHAND, SA_SIGINFO, _NSIG},
    log::LogDebug,
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
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
                compute_trap_reasons,
                destroy_buffers,
                detect_syscall_arch,
                did_waitpid,
                next_syscallbuf_record,
                open_mem_fd,
                post_exec_for_exe,
                post_exec_syscall,
                read_bytes_fallible,
                read_bytes_helper,
                read_bytes_helper_for,
                read_c_str,
                resume_execution,
                set_thread_area,
                stored_record_size,
                syscallbuf_data_size,
                write_bytes,
                write_bytes_helper,
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
        },
        Session,
        SessionSharedPtr,
    },
    sig::{self, Sig},
    ticks::Ticks,
    trace::{trace_frame::FrameTime, trace_writer::TraceWriter},
    util::{
        default_action,
        read_proc_status_fields,
        signal_bit,
        u8_raw_slice,
        u8_raw_slice_mut,
        SignalAction,
    },
    wait_status::WaitStatus,
};
use libc::{pid_t, EINVAL, PR_TSC_ENABLE};
use nix::{errno::errno, sys::mman::ProtFlags};
use owning_ref::OwningHandle;
use std::{
    cell::{Ref, RefCell, RefMut},
    cmp::min,
    collections::{HashSet, VecDeque},
    convert::TryFrom,
    ffi::{CString, OsStr},
    mem::{self, size_of},
    ops::{Deref, DerefMut},
    ptr::copy_nonoverlapping,
    rc::{Rc, Weak},
};

#[derive(Clone)]
pub struct Sighandlers {
    /// @TODO Keep as opaque for now. Need to ensure correct visibility.
    handlers: [Sighandler; _NSIG as usize],
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
        for i in 1.._NSIG as usize {
            let h = &mut self.handlers[i];

            let mut sa = native_arch::kernel_sigaction::default();
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
        for i in 1.._NSIG as usize {
            let mut h = &mut self.handlers[i];
            // If the handler was a user handler, reset to
            // default.  If it was SIG_IGN or SIG_DFL,
            // leave it alone.
            if h.disposition() == SignalDisposition::SignalHandler {
                reset_handler(&mut h, arch);
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

    pub fn init_arch<Arch: Architecture>(&mut self, ksa: &Arch::kernel_sigaction) {
        self.k_sa_handler = Arch::get_k_sa_handler(ksa);
        self.sa.resize(size_of::<Arch::kernel_sigaction>(), 0);
        unsafe {
            copy_nonoverlapping(
                // @TODO does this cast of an associated type reference work as expected?
                &raw const ksa as *const u8,
                self.sa.as_mut_ptr() as *mut u8,
                size_of::<Arch::kernel_sigaction>(),
            );
        }
        self.resethand = Arch::get_sa_flags(ksa) & SA_RESETHAND as usize != 0;
        self.takes_siginfo = Arch::get_sa_flags(ksa) & SA_SIGINFO as usize != 0;
    }

    pub fn reset_arch<Arch: Architecture>(&mut self) {
        let ksa = Arch::kernel_sigaction::default();
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
#[derive(Copy, Clone, Eq, PartialEq)]
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

pub struct StashedSignal {
    siginfo: siginfo_t,
    deterministic: SignalDeterministic,
}

#[derive(Copy, Clone, Eq, PartialEq)]
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
    pub ticks_at_last_recorded_syscall_exit: Ticks,

    /// Scheduler state
    pub registers_at_start_of_last_timeslice: Registers,
    pub time_at_start_of_last_timeslice: FrameTime,
    /// Task 'nice' value set by setpriority(2).
    ///
    /// We use this to drive scheduling decisions. rd's scheduler is
    /// deliberately simple and unfair; a task never runs as long as there's
    /// another runnable task with a lower nice value.
    pub priority: i32,
    /// Tasks with in_round_robin_queue set are in the session's
    /// in_round_robin_queue instead of its task_priority_set.
    pub in_round_robin_queue: bool,

    /// ptrace emulation state

    /// Task for which we're emulating ptrace of this task, or null
    pub emulated_ptracer: Option<RecordTaskSharedWeakPtr>,
    pub emulated_ptrace_tracees: HashSet<RecordTaskSharedWeakPtr>,
    pub emulated_ptrace_event_msg: usize,
    /// Saved emulated-ptrace signals
    pub saved_ptrace_siginfos: Vec<siginfo_t>,
    /// Code to deliver to ptracer/waiter when it waits. Note that zero can be a
    /// valid code! Reset to zero when leaving the stop due to PTRACE_CONT etc.
    pub emulated_stop_code: WaitStatus,
    /// None while no ptracer is attached.
    /// Different from rr which uses 0.
    pub emulated_ptrace_options: Option<u32>,
    /// One of PTRACE_CONT, PTRACE_SYSCALL --- or None if the tracee has not been
    /// continued by its ptracer yet, or has no ptracer.
    /// Different from rr which uses 0 and a signed int.
    pub emulated_ptrace_cont_command: Option<u32>,
    /// true when a ptracer/waiter wait() can return `emulated_stop_code`.
    pub emulated_stop_pending: bool,
    /// true if this task needs to send a SIGCHLD to its ptracer for its
    /// emulated ptrace stop
    pub emulated_ptrace_sigchld_pending: bool,
    /// true if this task needs to send a SIGCHLD to its parent for its
    /// emulated stop
    pub emulated_sigchld_pending: bool,
    /// tracer attached via PTRACE_SEIZE
    pub emulated_ptrace_seized: bool,
    pub emulated_ptrace_queued_exit_stop: bool,
    pub in_wait_type: WaitType,
    pub in_wait_pid: pid_t,

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
    pub emulated_stop_type: EmulatedStopType,
    /// True if the task sigmask may have changed and we need to refetch it.
    pub blocked_sigs_dirty: bool,
    /// Most accesses to this should use set_sigmask and get_sigmask to ensure
    /// the mirroring to syscallbuf is correct.
    pub blocked_sigs: sig_set_t,
    pub syscallbuf_blocked_sigs_generation: u32,

    /// Syscallbuf state
    pub syscallbuf_code_layout: SyscallbufCodeLayout,
    pub desched_fd: ScopedFd,
    /// Value of hdr->num_rec_bytes when the buffer was flushed
    pub flushed_num_rec_bytes: u32,
    /// Nonzero after the trace recorder has flushed the
    /// syscallbuf.  When this happens, the recorder must prepare a
    /// "reset" of the buffer, to zero the record count, at the
    /// next available slow (taking `desched` into
    /// consideration).
    pub flushed_syscallbuf: bool,
    /// This bit is set when code wants to prevent the syscall
    /// record buffer from being reset when it normally would be.
    /// This bit is set by the desched code.
    pub delay_syscallbuf_reset_for_desched: bool,
    /// This is set when code wants to prevent the syscall
    /// record buffer from being reset when it normally would be.
    /// This is set by the code for handling seccomp SIGSYS signals.
    pub delay_syscallbuf_reset_for_seccomp_trap: bool,
    /// Value to return from PR_GET_SECCOMP
    pub prctl_seccomp_status: u8,

    /// Mirrored kernel state
    /// This state agrees with kernel-internal values
    ///
    /// Futex list passed to `set_robust_list()`.  We could keep a
    /// strong type for this list head and read it if we wanted to,
    /// but for now we only need to remember its address / size at
    /// the time of the most recent set_robust_list() call.
    pub robust_futex_list: RemotePtr<Void>,
    pub robust_futex_list_len: usize,
    /// The memory cell the kernel will clear and notify on exit,
    /// if our clone parent requested it.
    pub tid_futex: RemotePtr<i32>,
    /// This is the recorded tid of the tracee *in its own pid namespace*.
    pub own_namespace_rec_tid: pid_t,
    pub exit_code: i32,
    /// Signal delivered by the kernel when this task terminates
    /// DIFF NOTE: We have an Option<> here which is different from rr.
    /// Also should this be a u32?
    pub termination_signal: Option<Sig>,

    /// Our value for PR_GET/SET_TSC (one of PR_TSC_ENABLED, PR_TSC_SIGSEGV).
    pub tsc_mode: i32,
    /// Our value for ARCH_GET/SET_CPUID (0 -> generate SIGSEGV, 1 -> do CPUID).
    /// Only used if session().has_cpuid_faulting().
    /// @TODO should this be made into an Option?
    pub cpuid_mode: i32,
    /// The current stack of events being processed.  (We use a
    /// deque instead of a stack because we need to iterate the
    /// events.)
    pub pending_events: VecDeque<Event>,
    /// Stashed signal-delivery state, ready to be delivered at
    /// next opportunity.
    pub stashed_signals: VecDeque<StashedSignal>,
    pub stashed_signals_blocking_more_signals: bool,
    pub stashed_group_stop: bool,
    pub break_at_syscallbuf_traced_syscalls: bool,
    pub break_at_syscallbuf_untraced_syscalls: bool,
    pub break_at_syscallbuf_final_instruction: bool,

    /// The pmc is programmed to interrupt at a value requested by the tracee, not
    /// by rd.
    pub next_pmc_interrupt_is_for_user: bool,

    pub did_record_robust_futex_changes: bool,
}

impl Deref for RecordTask {
    type Target = TaskInner;

    fn deref(&self) -> &Self::Target {
        &self.task_inner
    }
}

impl DerefMut for RecordTask {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.task_inner
    }
}

impl Task for RecordTask {
    /// Forwarded method
    fn detect_syscall_arch(&mut self) -> SupportedArch {
        detect_syscall_arch(self)
    }

    /// Forwarded method
    fn destroy_buffers(&mut self) {
        destroy_buffers(self)
    }

    /// Forwarded method
    fn post_exec_for_exe(&mut self, exe_file: &OsStr) {
        post_exec_for_exe(self, exe_file)
    }

    /// Forwarded method
    fn resume_execution(
        &mut self,
        how: ResumeRequest,
        wait_how: WaitRequest,
        tick_period: TicksRequest,
        maybe_sig: Option<Sig>,
    ) {
        resume_execution(self, how, wait_how, tick_period, maybe_sig)
    }

    /// Forwarded method
    fn stored_record_size(&mut self, record: RemotePtr<syscallbuf_record>) -> usize {
        stored_record_size(self, record)
    }

    /// Forwarded method
    fn did_waitpid(&mut self, status: WaitStatus) {
        did_waitpid(self, status)
    }

    /// Forwarded method
    fn next_syscallbuf_record(&mut self) -> RemotePtr<syscallbuf_record> {
        next_syscallbuf_record(self)
    }

    fn as_task_inner(&self) -> &TaskInner {
        &self.task_inner
    }

    fn as_task_inner_mut(&mut self) -> &mut TaskInner {
        &mut self.task_inner
    }

    fn as_record_task(&self) -> Option<&RecordTask> {
        Some(self)
    }

    fn as_record_task_mut(&mut self) -> Option<&mut RecordTask> {
        Some(self)
    }

    fn on_syscall_exit(&mut self, _syscallno: i32, _arch: SupportedArch, _regs: &Registers) {
        unimplemented!()
    }

    fn did_wait(&mut self) {
        for p in self.syscallbuf_syscall_entry_breakpoints() {
            self.vm_shr_ptr()
                .remove_breakpoint(p, BreakpointType::BkptInternal, self);
        }
        if self.break_at_syscallbuf_final_instruction {
            self.vm_shr_ptr().remove_breakpoint(
                self.syscallbuf_code_layout
                    .syscallbuf_final_exit_instruction,
                BreakpointType::BkptInternal,
                self,
            );
        }

        if self.stashed_signals_blocking_more_signals {
            // Saved 'blocked_sigs' must still be correct regardless of syscallbuf
            // state, because we do not allow stashed_signals_blocking_more_signals
            // to hold across syscalls (traced or untraced) that change the signal mask.
            ed_assert!(self, !self.blocked_sigs_dirty);
            self.xptrace(
                PTRACE_SETSIGMASK,
                RemotePtr::<Void>::from(size_of::<sig_set_t>()),
                PtraceData::ReadFrom(u8_raw_slice(&self.blocked_sigs)),
            );
        } else if !self.syscallbuf_child.is_null() {
            // The syscallbuf struct is only 32 bytes currently so read the whole thing
            // at once to aVoid multiple calls to read_mem. Even though this shouldn't
            // need a syscall because we use a local-mapping, apparently that lookup
            // is still noticeably expensive.
            let child_addr = self.syscallbuf_child;
            let syscallbuf = read_val_mem(self, child_addr, None);
            if syscallbuf.in_sigprocmask_critical_section != 0 {
                // |blocked_sigs| may have been updated but the syscall not yet issued.
                // Use the kernel's value.
                self.invalidate_sigmask();
            } else {
                let syscallbuf_generation = syscallbuf.blocked_sigs_generation;
                if syscallbuf_generation > self.syscallbuf_blocked_sigs_generation {
                    self.syscallbuf_blocked_sigs_generation = syscallbuf_generation;
                    self.blocked_sigs = syscallbuf.blocked_sigs;
                }
            }
        }
    }

    fn at_preload_init(&mut self) {
        unimplemented!()
    }

    /// Forwarded method
    fn open_mem_fd(&mut self) -> bool {
        open_mem_fd(self)
    }

    /// Forwarded method
    fn read_bytes_fallible(&mut self, addr: RemotePtr<Void>, buf: &mut [u8]) -> Result<usize, ()> {
        read_bytes_fallible(self, addr, buf)
    }

    /// Forwarded method
    fn read_bytes_helper(&mut self, addr: RemotePtr<Void>, buf: &mut [u8], ok: Option<&mut bool>) {
        read_bytes_helper(self, addr, buf, ok)
    }

    /// Forwarded method
    fn read_c_str(&mut self, child_addr: RemotePtr<u8>) -> CString {
        read_c_str(self, child_addr)
    }

    /// Forwarded method
    fn write_bytes_helper(
        &mut self,
        addr: RemotePtr<u8>,
        buf: &[u8],
        ok: Option<&mut bool>,
        flags: WriteFlags,
    ) {
        write_bytes_helper(self, addr, buf, ok, flags)
    }

    /// Forwarded method
    fn syscallbuf_data_size(&mut self) -> usize {
        syscallbuf_data_size(self)
    }

    /// Forwarded method
    fn write_bytes(&mut self, child_addr: RemotePtr<u8>, buf: &[u8]) {
        write_bytes(self, child_addr, buf);
    }
    // Forwarded method
    fn post_exec_syscall(&mut self) {
        post_exec_syscall(self)
    }

    // Forwarded method
    fn compute_trap_reasons(&mut self) -> TrapReasons {
        compute_trap_reasons(self)
    }

    fn post_vm_clone(
        &mut self,
        _reason: CloneReason,
        _flags: CloneFlags,
        _origin: &mut dyn Task,
    ) -> bool {
        unimplemented!()
    }

    /// Forwarded method
    fn set_thread_area(&mut self, tls: RemotePtr<user_desc>) {
        set_thread_area(self, tls)
    }

    /// Forwarded method
    fn reset_syscallbuf(&mut self) {
        reset_syscallbuf(self);
    }

    /// Forwarded method
    fn set_syscallbuf_locked(&mut self, locked: bool) {
        set_syscallbuf_locked(self, locked);
    }
}

impl RecordTask {
    /// Every Task owned by a RecordSession is a RecordTask. Functionality that
    /// only applies during recording belongs here.
    pub fn new(
        session: &RecordSession,
        tid: pid_t,
        serial: u32,
        a: SupportedArch,
    ) -> Box<dyn Task> {
        let mut rt = RecordTask {
            task_inner: TaskInner::new(session, tid, None, serial, a),
            ticks_at_last_recorded_syscall_exit: 0,
            time_at_start_of_last_timeslice: 0,
            priority: 0,
            in_round_robin_queue: false,
            emulated_ptracer: None,
            emulated_ptrace_event_msg: 0,
            emulated_ptrace_options: None,
            emulated_ptrace_cont_command: None,
            emulated_stop_pending: false,
            emulated_ptrace_sigchld_pending: false,
            emulated_sigchld_pending: false,
            emulated_ptrace_seized: false,
            emulated_ptrace_queued_exit_stop: false,
            in_wait_type: WaitType::WaitTypeNone,
            in_wait_pid: 0,
            emulated_stop_type: EmulatedStopType::NotStopped,
            blocked_sigs_dirty: true,
            syscallbuf_blocked_sigs_generation: 0,
            flushed_num_rec_bytes: 0,
            flushed_syscallbuf: false,
            delay_syscallbuf_reset_for_desched: false,
            delay_syscallbuf_reset_for_seccomp_trap: false,
            prctl_seccomp_status: 0,
            robust_futex_list_len: 0,
            own_namespace_rec_tid: tid,
            exit_code: 0,
            termination_signal: None,
            tsc_mode: PR_TSC_ENABLE,
            cpuid_mode: 1,
            stashed_signals: Default::default(),
            stashed_signals_blocking_more_signals: false,
            stashed_group_stop: false,
            break_at_syscallbuf_traced_syscalls: false,
            break_at_syscallbuf_untraced_syscalls: false,
            break_at_syscallbuf_final_instruction: false,
            next_pmc_interrupt_is_for_user: false,
            did_record_robust_futex_changes: false,
            // Implicit
            registers_at_start_of_last_timeslice: Registers::new(a),
            emulated_ptrace_tracees: Default::default(),
            saved_ptrace_siginfos: vec![],
            emulated_stop_code: Default::default(),
            sighandlers: Rc::new(RefCell::new(Default::default())),
            blocked_sigs: 0,
            syscallbuf_code_layout: Default::default(),
            desched_fd: Default::default(),
            robust_futex_list: Default::default(),
            tid_futex: Default::default(),
            pending_events: Default::default(),
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
        if self.break_at_syscallbuf_untraced_syscalls {
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
        if self.break_at_syscallbuf_traced_syscalls {
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
        if !self.break_at_syscallbuf_final_instruction {
            return false;
        }
        let arch = self.arch();
        let i = self.ip().decrement_by_bkpt_insn_length(arch);
        i == self
            .syscallbuf_code_layout
            .syscallbuf_final_exit_instruction
    }

    /// Initialize tracee buffers in `self`, i.e., implement
    /// RDCALL_init_syscall_buffer.  This task must be at the point
    /// of *exit from* the rdcall.  Registers will be updated with
    /// the return value from the rdcall, which is also returned
    /// from this call.
    pub fn init_buffers(&self) {
        let arch = self.arch();
        rd_arch_function!(self, init_buffers_arch, arch)
    }

    fn init_buffers_arch<Arch: Architecture>(&self) {
        unimplemented!()
    }

    /// @TODO ??
    pub fn post_exec(&self) {
        unimplemented!()
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
    pub fn set_emulated_ptracer(&self, _tracer: &RecordTask) {
        unimplemented!()
    }

    /// Call this when an event occurs that should stop a ptraced task.
    /// If we're emulating ptrace of the task, stop the task and wake the ptracer
    /// if it's waiting, and queue "status" to be reported to the
    /// ptracer. If siginfo is non-null, we'll report that siginfo, otherwise we'll
    /// make one up based on the status (unless the status is an exit code).
    /// Returns true if the task is stopped-for-emulated-ptrace, false otherwise.
    pub fn emulate_ptrace_stop(
        &self,
        _status: WaitStatus,
        _siginfo: Option<&siginfo_t>,
        _si_code: Option<i32>,
    ) -> bool {
        unimplemented!()
    }

    /// Force the ptrace-stop state no matter what state the task is currently in.
    pub fn force_emulate_ptrace_stopstatus(&self) -> WaitStatus {
        unimplemented!()
    }

    /// Called when we're about to deliver a signal to this task. If it's a
    /// synthetic SIGCHLD and there's a ptraced task that needs to SIGCHLD,
    /// update the siginfo to reflect the status and note that that
    /// ptraced task has had its SIGCHLD sent.
    /// Note that we can't set the correct siginfo when we send the signal, because
    /// it requires us to set information only the kernel has permission to set.
    /// Returns false if this signal should be deferred.
    pub fn set_siginfo_for_synthetic_sigchld(&self, _si: &siginfo_t) -> bool {
        unimplemented!()
    }

    pub fn set_siginfo_for_waited_task<Arch: Architecture>(&self, si: &mut Arch::siginfo_t) {
        match Arch::arch() {
            SupportedArch::X86 => {
                Arch::set_siginfo_for_waited_task(self, si);
            }
            SupportedArch::X64 => {
                Arch::set_siginfo_for_waited_task(self, si);
            }
        }
    }

    /// Return a reference to the saved siginfo record for the stop-signal
    /// that we're currently in a ptrace-stop for.
    pub fn get_saved_ptrace_siginfo(&self) -> &siginfo_t {
        unimplemented!()
    }

    /// When emulating a ptrace-continue with a signal number, extract the siginfo
    /// that was saved by `save_ptrace_signal_siginfo`. If no such siginfo was
    /// saved, make one up.
    pub fn take_ptrace_signal_siginfo(&self, _sig: Sig) -> siginfo_t {
        unimplemented!()
    }

    /// Returns true if this task is in a waitpid or similar that would return
    /// when t's status changes due to a ptrace event.
    pub fn is_waiting_for_ptrace(&self, _t: &RecordTask) -> bool {
        unimplemented!()
    }

    /// Returns true if this task is in a waitpid or similar that would return
    /// when t's status changes due to a regular event (exit).
    pub fn is_waiting_for(&self, _t: &RecordTask) -> bool {
        unimplemented!()
    }

    /// Call this to force a group stop for this task with signal 'sig',
    /// notifying ptracer if necessary.
    pub fn apply_group_stop(&self, _sig: Sig) {
        unimplemented!()
    }

    /// Call this after `sig` is delivered to this task.  Emulate
    /// sighandler updates induced by the signal delivery.
    pub fn signal_delivered(&self, _sig: Sig) {
        unimplemented!()
    }

    /// Return true if `sig` is pending but hasn't been reported to ptrace yet
    pub fn is_signal_pending(&self, sig: Sig) -> bool {
        let mut pending_strs = read_proc_status_fields(self.tid, &[b"SigPnd", b"ShdPnd"]).unwrap();
        if pending_strs.len() < 2 {
            return false;
        }

        let mask2 = u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16);
        let mask1 = u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16);
        mask1.is_ok() && mask2.is_ok() && ((mask1.unwrap() | mask2.unwrap()) & signal_bit(sig)) != 0
    }

    /// Return true if there are any signals pending that are not blocked.
    pub fn has_any_actionable_signal(&self) -> bool {
        let mut pending_strs =
            read_proc_status_fields(self.tid, &[b"SigPnd", b"ShdPnd", b"SigBlk"]).unwrap();
        if pending_strs.len() < 3 {
            return false;
        }

        let mask_blk = u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16);
        let mask2 = u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16);
        let mask1 = u64::from_str_radix(&pending_strs.pop().unwrap().into_string().unwrap(), 16);
        mask1.is_ok()
            && mask2.is_ok()
            && mask_blk.is_ok()
            && ((mask1.unwrap() | mask2.unwrap()) & !mask_blk.unwrap()) != 0
    }

    /// Get all threads out of an emulated GROUP_STOP
    pub fn emulate_sigcont(&self) {
        unimplemented!()
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
    pub fn is_sig_blocked(&mut self, sig: Sig) -> bool {
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
        &mut self,
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
        self.pending_siginfo = si.clone();
        self.ptrace_if_alive(
            PTRACE_SETSIGINFO,
            RemotePtr::null(),
            PtraceData::ReadFrom(u8_raw_slice(si)),
        );
    }

    /// Note that the task sigmask needs to be refetched.
    pub fn invalidate_sigmask(&mut self) {
        self.blocked_sigs_dirty = true;
    }

    /// Reset the signal handler for this signal to the default.
    pub fn did_set_sig_handler_default(&self, sig: Sig) {
        let mut shb = self.sighandlers.borrow_mut();
        let h: &mut Sighandler = shb.get_mut(sig);
        reset_handler(h, self.arch());
    }

    /// Check that our status for `sig` matches what's in /proc/<pid>/status.
    #[cfg(debug_assertions)]
    pub fn verify_signal_states(&mut self) {
        if self.ev().is_syscall_event() {
            // If the syscall event is on the event stack with PROCESSING or EXITING
            // states, we won't have applied the signal-state updates yet while the
            // kernel may have.
            return;
        }
        let mut results =
            read_proc_status_fields(self.tid, &[b"SigBlk", b"SigIgn", b"SigCgt"]).unwrap();
        ed_assert!(self, results.len() == 3);
        let caught =
            u64::from_str_radix(&results.pop().unwrap().into_string().unwrap(), 16).unwrap();
        let ignored =
            u64::from_str_radix(&results.pop().unwrap().into_string().unwrap(), 16).unwrap();
        let blocked =
            u64::from_str_radix(&results.pop().unwrap().into_string().unwrap(), 16).unwrap();

        for sigi in 1.._NSIG as i32 {
            let sig = Sig::try_from(sigi).unwrap();
            let mask = signal_bit(sig);
            if is_unstoppable_signal(sig) {
                ed_assert!(
                    self,
                    blocked & mask != 0,
                    "Expected {} to not be blocked, but it is",
                    sig
                );
                ed_assert!(
                    self,
                    ignored & mask != 0,
                    "Expected {} to not be ignored, but it is",
                    sig
                );
                ed_assert!(
                    self,
                    caught & mask != 0,
                    "Expected {} to not be caught, but it is",
                    sig
                );
            } else {
                let is_sig_blocked = self.is_sig_blocked(sig);
                ed_assert!(
                    self,
                    (blocked & mask != 0) == is_sig_blocked,
                    "{} {}",
                    sig,
                    if blocked & mask != 0 {
                        " is blocked"
                    } else {
                        " is not blocked"
                    }
                );
                let disposition = self.sighandlers.borrow().get(sig).disposition();
                ed_assert!(
                    self,
                    (ignored & mask != 0) == (disposition == SignalDisposition::SignalIgnore),
                    "{} {}",
                    sig,
                    if ignored & mask != 0 {
                        " is ignored"
                    } else {
                        " is not ignored"
                    }
                );
                ed_assert!(
                    self,
                    (caught & mask != 0) == (disposition == SignalDisposition::SignalHandler),
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
    pub fn verify_signal_states(&mut self) {
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
    pub fn stash_sig(&self) {
        unimplemented!()
    }

    pub fn stash_synthetic_sig(&self, _si: &siginfo_t, _deterministic: SignalDeterministic) {
        unimplemented!()
    }

    pub fn has_any_stashed_sig(&self) -> bool {
        unimplemented!()
    }

    pub fn stashed_sig_not_synthetic_sigchld(&self) -> &siginfo_t {
        unimplemented!()
    }

    pub fn has_stashed_sig(&self, _sig: Sig) -> bool {
        unimplemented!()
    }

    pub fn peek_stashed_sig_to_deliver(&self) -> &StashedSignal {
        unimplemented!()
    }

    pub fn pop_stash_sig(&self, _stashed: &StashedSignal) {
        unimplemented!()
    }

    pub fn stashed_signal_processed(&self) {
        unimplemented!()
    }

    /// If a group-stop occurs at an inconvenient time, stash it and
    /// process it later.
    pub fn stash_group_stop(&self) {
        unimplemented!()
    }

    pub fn clear_stashed_group_stop(&self) {
        unimplemented!()
    }

    pub fn has_stashed_group_stop(&self) -> bool {
        unimplemented!()
    }

    /// Return true if the current state of this looks like the
    /// interrupted syscall at the top of our event stack, if there
    /// is one.
    pub fn is_syscall_restart(&self) -> bool {
        unimplemented!()
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
        unimplemented!()
    }

    /// Return true if this is at a disarm-desched-event syscall.
    pub fn is_disarm_desched_event_syscall(&self) -> bool {
        unimplemented!()
    }

    /// Return true if `t` may not be immediately runnable,
    /// i.e., resuming execution and then `waitpid()`'ing may block
    /// for an unbounded amount of time.  When the task is in this
    /// state, the tracer must await a `waitpid()` notification
    /// that the task is no longer possibly-blocked before resuming
    /// its execution.
    pub fn may_be_blocked(&self) -> bool {
        unimplemented!()
    }

    /// Returns true if it looks like this task has been spinning on an atomic
    /// access/lock.
    pub fn maybe_in_spinlock(&self) -> bool {
        unimplemented!()
    }

    /// Return true if this is within the syscallbuf library.  This
    /// *does not* imply that $ip is at a buffered syscall.
    pub fn is_in_syscallbuf(&self) -> bool {
        unimplemented!()
    }

    /// Shortcut to the most recent `pending_event->desched.rec` when
    /// there's a desched event on the stack, and nullptr otherwise.
    /// Exists just so that clients don't need to dig around in the
    /// event stack to find this record.
    pub fn desched_rec(&self) -> RemotePtr<syscallbuf_record> {
        unimplemented!()
    }

    /// Returns true when the task is in a signal handler in an interrupted
    /// system call being handled by syscall buffering.
    pub fn running_inside_desched(&self) -> bool {
        unimplemented!()
    }
    pub fn get_ptrace_eventmsg_seccomp_data(&self) -> u16 {
        unimplemented!()
    }

    /// Save tracee data to the trace.  `addr` is the address in
    /// the address space of this task.  The `record_local*()`
    /// variants record data that's already been read from `self`,
    /// and the `record_remote*()` variants read the data and then
    /// record it.
    ///
    /// If 'addr' is null then no record is written.
    ///
    /// DIFF NOTE: @TODO In the rr implementation ssize_t is being used instead of size_t
    /// for the record_* methods in many places. Why?
    pub fn record_local(&self, addr: RemotePtr<Void>, data: &[u8]) {
        self.maybe_flush_syscallbuf();

        if addr.is_null() {
            return;
        }

        self.trace_writer_mut().write_raw(self.rec_tid, data, addr);
    }

    pub fn record_local_for<T>(_addr: RemotePtr<T>, _data: &T) {
        unimplemented!()
    }

    pub fn record_local_for_slice<T>(_addr: RemotePtr<T>, _buf: &[T]) {
        unimplemented!()
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
        self.trace_writer_mut().write_raw(self.rec_tid, &buf, addr);
    }

    pub fn record_remote_for<T>(_addr: RemotePtr<T>) {
        unimplemented!()
    }

    pub fn record_remote_range(&mut self, _range: MemoryRange) {
        unimplemented!()
    }

    pub fn record_remote_range_fallible(&mut self, _range: MemoryRange) -> Result<usize, ()> {
        unimplemented!()
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
        let mut nread = 0;
        if !addr.is_null() {
            buf.resize(num_bytes, 0u8);
            nread = self.read_bytes_fallible(addr, &mut buf)?;
            buf.truncate(nread);
        }
        self.trace_writer_mut().write_raw(self.rec_tid, &buf, addr);

        Ok(nread)
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
    pub fn record_remote_by_local_map(&self, addr: RemotePtr<Void>, num_bytes: usize) -> bool {
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
            self.trace_writer_mut().write_raw(self.rec_tid, &[], addr);
            return;
        }

        if self.record_remote_by_local_map(addr, num_bytes) {
            return;
        }

        let buf = read_mem(self, addr, num_bytes, None);
        self.trace_writer_mut().write_raw(self.rec_tid, &buf, addr);
    }

    pub fn record_remote_even_if_null_for<T>(_addr: RemotePtr<T>) {
        unimplemented!()
    }

    /// Manage pending events.  `push_event()` pushes the given
    /// event onto the top of the event stack.  The `pop_*()`
    /// helpers pop the event at top of the stack, which must be of
    /// the specified type.
    pub fn push_event(&mut self, ev: Event) {
        self.pending_events.push_back(ev);
    }

    pub fn push_syscall_eventsyscallno(&mut self, no: i32) {
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
    pub fn maybe_flush_syscallbuf(&self) {
        unimplemented!()
    }

    /// Call this after recording an event when it might be safe to reset the
    /// syscallbuf. It must be after recording an event to ensure during replay
    /// we run past any syscallbuf after-syscall code that uses the buffer data.
    pub fn maybe_reset_syscallbuf(&self) {
        unimplemented!()
    }

    /// Record an event on behalf of this.  Record the registers of
    /// this (and other relevant execution state) so that it can be
    /// used or verified during replay, if that state is available
    /// and meaningful at this's current execution point.
    /// `record_current_event()` record `this->ev()`, and
    /// `record_event()` records the specified event.
    pub fn record_current_event(&self) {
        unimplemented!()
    }

    pub fn record_event(
        &self,
        _ev: &Event,
        _flush: Option<FlushSyscallbuf>,
        _reset: Option<AllowSyscallbufReset>,
        _registers: Option<&Registers>,
    ) {
        unimplemented!()
    }

    pub fn is_fatal_signal(&self, _sig: Sig, _deterministic: SignalDeterministic) -> bool {
        unimplemented!()
    }

    /// Return the pid of the newborn thread created by this task.
    /// Called when this task has a PTRACE_CLONE_EVENT with CLONE_THREAD.
    pub fn find_newborn_thread(&self) -> pid_t {
        unimplemented!()
    }

    /// Return the pid of the newborn process (whose parent has pid `parent_pid`,
    /// which need not be the same as the current task's pid, due to CLONE_PARENT)
    /// created by this task. Called when this task has a PTRACE_CLONE_EVENT
    /// without CLONE_THREAD, or PTRACE_FORK_EVENT.
    pub fn find_newborn_process(&self, _child_parent: pid_t) -> pid_t {
        unimplemented!()
    }

    /// Do a tgkill to send a specific signal to this task.
    pub fn tgkill(&self, _sig: Sig) {
        unimplemented!()
    }

    /// If the process looks alive, kill it. It is recommended to call try_wait(),
    /// on this task before, to make sure liveness is correctly reflected when
    /// making this decision
    pub fn kill_if_alive(&self) {
        unimplemented!()
    }

    pub fn robust_list(&self) -> RemotePtr<Void> {
        unimplemented!()
    }
    pub fn robust_list_len(&self) -> usize {
        unimplemented!()
    }

    /// Uses /proc so not trivially cheap.
    pub fn get_parent_pid(&self) -> pid_t {
        unimplemented!()
    }

    /// Return true if this is a "clone child" per the wait(2) man page.
    pub fn is_clone_child(&self) -> bool {
        unimplemented!()
    }

    pub fn set_termination_signal(&self, _sig: Sig) {
        unimplemented!()
    }

    /// When a signal triggers an emulated a ptrace-stop for this task,
    /// save the siginfo so a later emulated ptrace-continue with this signal
    /// number can use it.
    pub fn save_ptrace_signal_siginfo(&self, _si: &siginfo_t) {
        unimplemented!()
    }

    /// Tasks normally can't change their tid. There is one very special situation
    /// where they can: when a non-main-thread does an execve, its tid changes
    /// to the tid of the thread-group leader.
    pub fn set_tid_and_update_serial(&self, _tid: pid_t, _own_namespace_tid: pid_t) {
        unimplemented!()
    }

    /// Return our cached copy of the signal mask, updating it if necessary.
    pub fn get_sigmask(&mut self) -> sig_set_t {
        if self.blocked_sigs_dirty {
            self.blocked_sigs = self.read_sigmask_from_process();
            log!(LogDebug, "Refreshed sigmask, now {:#x}", self.blocked_sigs);
            self.blocked_sigs_dirty = false;
        }
        self.blocked_sigs
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
                PtraceData::WriteInto(u8_raw_slice_mut(&mut mask)),
            );
            if ret >= 0 {
                return mask;
            }
        }

        let mut results = read_proc_status_fields(self.tid, &[b"SigBlk"]).unwrap();
        ed_assert!(self, results.len() == 1);

        let res = u64::from_str_radix(&results.pop().unwrap().into_string().unwrap(), 16).unwrap();
        unsafe { mem::transmute(res) }
    }

    /// Unblock the signal for the process.
    pub fn unblock_signal(&self, _sig: Sig) {
        unimplemented!()
    }

    /// Set the signal handler to default for the process.
    pub fn set_sig_handler_default(&self, _sig: Sig) {
        unimplemented!()
    }

    pub fn maybe_restore_original_syscall_registers(&self) {
        unimplemented!()
    }

    /// Retrieve the tid of this task from the tracee and store it
    fn update_own_namespace_tid(&self) {
        unimplemented!()
    }

    /// Wait for `futex` in this address space to have the value
    /// `val`.
    ///
    /// WARNING: this implementation semi-busy-waits for the value
    /// change.  This must only be used in contexts where the futex
    /// will change "soon".
    fn futex_wait(&self, _futex: RemotePtr<i32>, _val: i32, _ok: Option<&mut bool>) {
        unimplemented!()
    }

    /// Called when this task is able to receive a SIGCHLD (e.g. because
    /// we completed delivery of a signal). Sends a new synthetic
    /// SIGCHLD to the task if there are still tasks that need a SIGCHLD
    /// sent for them.
    /// May queue signals for specific tasks.
    fn send_synthetic_sigchld_if_necessary(&self) {
        unimplemented!()
    }

    /// Call this when SYS_sigaction is finishing with `regs`.
    fn update_sigaction(&self, _regs: &Registers) {
        unimplemented!()
    }

    /// Update the futex robust list head pointer to `list` (which
    /// is of size `len`).
    fn set_robust_list(&self, _list: RemotePtr<Void>, _len: usize) {
        unimplemented!()
    }

    fn on_syscall_exit_arch<Arch: Architecture>(&self, _syscallno: i32, _regs: &Registers) {
        unimplemented!()
    }

    /// Helper function for update_sigaction.
    fn update_sigaction_arch<Arch: Architecture>(&mut self, regs: &Registers) {
        let sig = Sig::try_from(regs.arg1_signed() as i32).unwrap();
        let new_sigaction_addr = RemotePtr::<Arch::kernel_sigaction>::new_from_val(regs.arg2());
        if 0 == regs.syscall_result() && !new_sigaction_addr.is_null() {
            // A new sighandler was installed.  Update our
            // sighandler table.
            // TODO: discard attempts to handle or ignore signals
            // that can't be by POSIX
            let mut sa: Arch::kernel_sigaction = Arch::kernel_sigaction::default();
            read_bytes_helper_for::<Self, Arch::kernel_sigaction>(
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
    fn set_tid_addr(&self, _tid_addr: RemotePtr<i32>) {
        unimplemented!()
    }
}

fn is_unstoppable_signal(sig: Sig) -> bool {
    sig == sig::SIGSTOP || sig == sig::SIGKILL
}

impl Drop for RecordTask {
    fn drop(&mut self) {
        task_drop_common(self);
        unimplemented!()
    }
}
