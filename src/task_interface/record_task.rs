use crate::remote_code_ptr::RemoteCodePtr;
use crate::remote_ptr::{RemotePtr, Void};

#[derive(Clone)]
pub struct Sighandlers {
    /// @TODO Keep as opaque for now. Need to ensure correct visibility.
    /// Need a compile time constant here.
    handlers: [Sighandler; 32],
}

/// NOTE that the struct is NOT pub
#[derive(Clone)]
struct Sighandler {
    pub k_sa_handler: RemotePtr<Void>,
    /// Saved kernel_sigaction; used to restore handler
    pub sa: Vec<u8>,
    pub resethand: bool,
    pub takes_siginfo: bool,
}

/// Different kinds of waits a task can do.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum WaitType {
    // Not waiting for anything
    WaitTypeNone,
    // Waiting for any child process
    WaitTypeAny,
    // Waiting for any child with the same process group ID
    WaitTypeSamePgid,
    // Waiting for any child with a specific process group ID
    WaitTypePgid,
    // Waiting for a specific process ID
    WaitTypePid,
}

/// Reasons why we simulate stopping of a task (see ptrace(2) man page).
pub enum EmulatedStopType {
    NotStopped,
    /// stopped by a signal. This applies to non-ptracees too.
    GroupStop,
    /// Stopped before delivering a signal. ptracees only.
    SignalDeliveryStop,
}

/// Pass UseSysgood to emulate_ptrace_stop to add 0x80 to the signal
/// if PTRACE_O_TRACESYSGOOD is in effect.
pub enum AddSysgoodFlag {
    IgnoreSysgood,
    UseSysgood,
}

pub struct SyscallbufCodeLayout {
    pub syscallbuf_code_start: RemoteCodePtr,
    pub syscallbuf_code_end: RemoteCodePtr,
    pub get_pc_thunks_start: RemoteCodePtr,
    pub get_pc_thunks_end: RemoteCodePtr,
    pub syscallbuf_final_exit_instruction: RemoteCodePtr,
}

pub enum SignalDisposition {
    SignalDefault,
    SignalIgnore,
    SignalHandler,
}

pub mod record_task {
    use super::*;
    use crate::event::{Event, SignalDeterministic};
    use crate::kernel_abi::SupportedArch;
    use crate::kernel_supplement::sig_set_t;
    use crate::registers::Registers;
    use crate::remote_ptr::{RemotePtr, Void};
    use crate::scoped_fd::ScopedFd;
    use crate::session_interface::SessionInterface;
    use crate::task_interface::task::task::{CloneReason, Task};
    use crate::task_interface::TaskInterface;
    use crate::ticks::Ticks;
    use crate::trace_frame::FrameTime;
    use crate::wait_status::WaitStatus;
    use libc::{pid_t, siginfo_t};
    use std::cell::RefCell;
    use std::collections::{HashSet, VecDeque};
    use std::rc::Rc;

    pub struct StashedSignal {
        siginfo: siginfo_t,
        deterministic: SignalDeterministic,
    }

    pub struct RecordTask {
        pub task: Task,
        pub ticks_at_last_recorded_syscall_exit: Ticks,

        /// Scheduler state
        pub registers_at_start_of_last_timeslice: Registers,
        pub time_at_start_of_last_timeslice: FrameTime,
        /// Task 'nice' value set by setpriority(2).
        ///
        /// We use this to drive scheduling decisions. rd's scheduler is
        /// deliberately simple and unfair; a task never runs as long as there's
        /// another runnable task with a lower nice value. */
        pub priority: i32,
        /// Tasks with in_round_robin_queue set are in the session's
        /// in_round_robin_queue instead of its task_priority_set.
        pub in_round_robin_queue: bool,

        /// ptrace emulation state

        /// Task for which we're emulating ptrace of this task, or null
        pub emulated_ptracer: Option<*mut RecordTask>,
        pub emulated_ptrace_tracees: HashSet<*mut RecordTask>,
        pub emulated_ptrace_event_msg: usize,
        /// Saved emulated-ptrace signals
        pub saved_ptrace_siginfos: Vec<siginfo_t>,
        /// Code to deliver to ptracer/waiter when it waits. Note that zero can be a
        /// valid code! Reset to zero when leaving the stop due to PTRACE_CONT etc.
        pub emulated_stop_code: WaitStatus,
        /// Always zero while no ptracer is attached.
        pub emulated_ptrace_options: i32,
        /// One of PTRACE_CONT, PTRACE_SYSCALL --- or 0 if the tracee has not been
        /// continued by its ptracer yet, or has no ptracer.
        pub emulated_ptrace_cont_command: i32,
        /// true when a ptracer/waiter wait() can return |emulated_stop_code|.
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
        /// next available slow (taking |desched| into
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
        /// Futex list passed to |set_robust_list()|.  We could keep a
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
        /// Note this is a bare int in rr. Also should this be a u32?
        pub termination_signal: Option<i32>,

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

    impl TaskInterface for RecordTask {
        fn as_task(&self) -> &Task {
            &self.task
        }

        fn as_task_mut(&mut self) -> &mut Task {
            &mut self.task
        }

        fn on_syscall_exit(&self, syscallno: i32, arch: SupportedArch, regs: &Registers) {
            unimplemented!()
        }

        fn at_preload_init(&self) {
            unimplemented!()
        }

        fn clone_task(
            &self,
            reason: CloneReason,
            flags: i32,
            stack: RemotePtr<u8>,
            tls: RemotePtr<u8>,
            cleartid_addr: RemotePtr<i32>,
            new_tid: i32,
            new_rec_tid: i32,
            new_serial: u32,
            other_session: Option<&dyn SessionInterface>,
        ) -> &Task {
            unimplemented!()
        }
    }
}
