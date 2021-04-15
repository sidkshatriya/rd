use super::{
    address_space::{address_space::AddressSpace, Privileged},
    on_create_task_common,
    session_common::kill_all_tasks,
    session_inner::PtraceSyscallSeccompOrdering,
    task::{
        record_task::{
            self, AllowSyscallbufReset, EmulatedStopType, FlushSyscallbuf, RecordTask,
            StashedSignal,
        },
        task_common::{read_val_mem, write_val_mem},
        task_inner::{
            PtraceData, ResumeRequest, SaveTraceeFdNumber, TaskInner, TicksRequest, WaitRequest,
        },
        TaskSharedWeakPtr,
    },
    SessionSharedPtr,
};
use crate::{
    arch::{Architecture, NativeArch},
    arch_structs,
    arch_structs::{robust_list, robust_list_head, siginfo_t as arch_siginfo_t},
    bindings::{
        audit::{AUDIT_ARCH_I386, AUDIT_ARCH_X86_64},
        kernel::{FUTEX_OWNER_DIED, FUTEX_TID_MASK, FUTEX_WAITERS},
        ptrace::{
            ptrace, PTRACE_EVENT_EXEC, PTRACE_EVENT_EXIT, PTRACE_EVENT_SECCOMP, PTRACE_GETEVENTMSG,
            PTRACE_SINGLESTEP, PTRACE_SYSCALL, PTRACE_SYSEMU, PTRACE_SYSEMU_SINGLESTEP,
        },
        signal::{siginfo_t, POLL_IN, SI_KERNEL, SI_MESGQ, SI_QUEUE, SI_TIMER, SI_TKILL, SI_USER},
    },
    commands::record_command::RecordCommand,
    event::{Event, EventType, SignalDeterministic, Switchable, SyscallEventData, SyscallState},
    file_monitor::virtual_perf_counter_monitor::VirtualPerfCounterMonitor,
    flags::Flags,
    kernel_abi::{
        is_at_syscall_instruction, is_exit_group_syscall, is_pause_syscall,
        is_rdcall_notify_syscall_hook_exit_syscall, is_restart_syscall_syscall, is_write_syscall,
        native_arch, syscall_number_for_gettid, syscall_number_for_restart_syscall, SupportedArch,
    },
    kernel_metadata::{errno_name, is_sigreturn, ptrace_event_name, signal_name, syscall_name},
    kernel_supplement::{
        ERESTARTNOHAND, ERESTARTNOINTR, ERESTARTSYS, ERESTART_RESTARTBLOCK,
        PTRACE_EVENT_SECCOMP_OBSOLETE, SECCOMP_RET_ACTION, SECCOMP_RET_DATA, SECCOMP_RET_ERRNO,
        SECCOMP_RET_KILL, SECCOMP_RET_TRAP, SYS_SECCOMP,
    },
    log::{LogDebug, LogError, LogInfo, LogWarn},
    perf_counters::{self, TicksSemantics},
    preload_interface::{
        syscallbuf_hdr, syscallbuf_record, SYSCALLBUF_ENABLED_ENV_VAR, SYSCALLBUF_LIB_FILENAME,
        SYSCALLBUF_LIB_FILENAME_PADDED,
    },
    record_signal::{
        arm_desched_event, disarm_desched_event, handle_signal, handle_syscallbuf_breakpoint,
        SignalBlocked, SignalHandled,
    },
    record_syscall::{rec_prepare_restart_syscall, rec_prepare_syscall, rec_process_syscall},
    registers::Registers,
    remote_ptr::{RemotePtr, Void},
    scheduler::Scheduler,
    scoped_fd::ScopedFd,
    seccomp_filter_rewriter::{SeccompFilterRewriter, SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO},
    session::{
        session_inner::SessionInner,
        task::{Task, TaskSharedPtr},
        Session,
    },
    sig::{self, Sig},
    thread_group::ThreadGroupSharedPtr,
    ticks::Ticks,
    trace::{
        trace_stream::TraceStream,
        trace_task_event::TraceTaskEvent,
        trace_writer::{CloseStatus, TraceWriter},
    },
    util::{
        choose_cpu, find, good_random, is_deterministic_signal, resource_path, signal_bit,
        u8_slice_mut, xsave_area_size, CPUIDData, CPUID_GETEXTENDEDFEATURES, CPUID_GETFEATURES,
        CPUID_GETXSAVE,
    },
    wait_status::{MaybeStopSignal, WaitStatus},
};
use goblin::elf::Elf;
use libc::{
    pid_t, CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD, CLONE_VM, ENOSYS,
    SIGBUS, SIGCHLD, SIGFPE, SIGILL, SIGIO, SIGSEGV, SIGSYS, SIGTRAP,
};
use mem::size_of;
use nix::{
    fcntl::{open, OFlag},
    sys::stat::{stat, Mode, SFlag},
    unistd::{access, read, AccessFlags},
};
use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    cmp::max,
    convert::{TryFrom, TryInto},
    env,
    ffi::{OsStr, OsString},
    fs, mem,
    ops::{Deref, DerefMut},
    os::unix::ffi::{OsStrExt, OsStringExt},
    rc::Rc,
};

const CPUID_RDRAND_FLAG: u32 = 1 << 30;
const CPUID_RTM_FLAG: u32 = 1 << 11;
const CPUID_RDSEED_FLAG: u32 = 1 << 18;
const CPUID_XSAVEOPT_FLAG: u32 = 1 << 0;

#[derive(Clone, Eq, PartialEq)]
pub struct DisableCPUIDFeatures {
    /// in: EAX=0x01
    features_ecx: u32,
    features_edx: u32,
    /// in: EAX=0x07 ECX=0
    extended_features_ebx: u32,
    extended_features_ecx: u32,
    extended_features_edx: u32,
    /// in: EAX=0x0D ECX=1
    xsave_features_eax: u32,
}

impl Default for DisableCPUIDFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl DisableCPUIDFeatures {
    pub fn new() -> Self {
        Self {
            features_ecx: 0,
            features_edx: 0,
            extended_features_ebx: 0,
            extended_features_ecx: 0,
            extended_features_edx: 0,
            xsave_features_eax: 0,
        }
    }

    pub fn from(features: (u32, u32), features_ext: (u32, u32, u32), features_xsave: u32) -> Self {
        Self {
            features_ecx: features.0,
            features_edx: features.1,
            extended_features_ebx: features_ext.0,
            extended_features_ecx: features_ext.1,
            extended_features_edx: features_ext.2,
            xsave_features_eax: features_xsave,
        }
    }

    pub fn any_features_disabled(&self) -> bool {
        self.features_ecx != 0
            || self.features_edx != 0
            || self.extended_features_ebx != 0
            || self.extended_features_ecx != 0
            || self.extended_features_edx != 0
            || self.xsave_features_eax != 0
    }

    pub fn amend_cpuid_data(&self, eax_in: u32, ecx_in: u32, cpuid_data: &mut CPUIDData) {
        match eax_in {
            CPUID_GETFEATURES => {
                cpuid_data.ecx &= !(CPUID_RDRAND_FLAG | self.features_ecx);
                cpuid_data.edx &= !self.features_edx;
            }
            CPUID_GETEXTENDEDFEATURES => {
                if ecx_in == 0 {
                    cpuid_data.ebx &=
                        !(CPUID_RDSEED_FLAG | CPUID_RTM_FLAG | self.extended_features_ebx);
                    cpuid_data.ecx &= !self.extended_features_ecx;
                    cpuid_data.edx &= !self.extended_features_edx;
                }
            }
            CPUID_GETXSAVE => {
                if ecx_in == 1 {
                    // Always disable XSAVEOPT because it's nondeterministic,
                    // possibly depending on context switching behavior. Intel
                    // recommends not using it from user space.
                    cpuid_data.eax &= !(CPUID_XSAVEOPT_FLAG | self.xsave_features_eax);
                }
            }
            _ => (),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TraceUuid {
    pub bytes: [u8; 16],
}

impl TraceUuid {
    pub fn inner_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn generate_new() -> TraceUuid {
        let mut bytes = [0u8; 16];
        good_random(&mut bytes);
        TraceUuid { bytes }
    }

    pub fn zero() -> TraceUuid {
        let bytes = [0u8; 16];
        TraceUuid { bytes }
    }

    pub fn from_array(bytes: [u8; 16]) -> TraceUuid {
        TraceUuid { bytes }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SyscallBuffering {
    EnableSycallBuf,
    DisableSyscallBuf,
}

/// DIFF NOTE: Subsumes RecordResult and RecordStatus from rr
#[derive(Clone, Eq, PartialEq)]
pub enum RecordResult {
    /// Some execution was recorded. record_step() can be called again.
    StepContinue,
    /// All tracees are dead. record_step() should not be called again.
    StepExited(WaitStatus),
    /// Spawning the initial tracee failed. The OsString represents the error message.
    StepSpawnFailed(OsString),
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ContinueType {
    DontContinue,
    Continue,
    ContinueSyscall,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct StepState {
    continue_type: ContinueType,
}

pub struct RecordSession {
    session_inner: SessionInner,
    trace_out: RefCell<TraceWriter>,
    scheduler_: Scheduler,
    initial_thread_group: Option<ThreadGroupSharedPtr>,
    seccomp_filter_rewriter_: RefCell<SeccompFilterRewriter>,
    trace_id: Box<TraceUuid>,
    disable_cpuid_features_: DisableCPUIDFeatures,
    /// DIFF NOTE: In rr, a None is indicated by value 0
    ignore_sig: Option<Sig>,
    /// DIFF NOTE: In rr, a None is indicated by value 0
    continue_through_sig: Option<Sig>,
    last_task_switchable: Cell<Switchable>,
    syscall_buffer_size_: usize,
    syscallbuf_desched_sig_: Sig,
    use_syscall_buffer_: bool,

    use_file_cloning_: bool,
    use_read_cloning_: bool,
    /// When true, try to increase the probability of finding bugs.
    enable_chaos_: bool,
    asan_active_: bool,
    /// When true, wait for all tracees to exit before finishing recording.
    wait_for_all_: bool,

    /// DIFF NOTE: This is simply a normal string in rr.
    /// `None` means the user did not provide any trace dir options and we need
    /// to use the default trace dir.
    output_trace_dir: Option<OsString>,
}

impl Drop for RecordSession {
    fn drop(&mut self) {
        // @TODO Make sure no more stuff needs to go in here
        // Compare with impl Drop for ReplaySession
        self.kill_all_tasks();
        // DIFF NOTE: These debug_asserts!() not present in rr
        // However they are present in rr ~ReplaySession()
        debug_assert!(self.task_map.borrow().is_empty());
        debug_assert!(self.vm_map.borrow().is_empty());
        log!(
            LogDebug,
            "RecordSession {:?} destroyed",
            self as *const Self
        );
    }
}

impl RecordSession {
    /// DIFF NOTE:
    /// - The param list is much simpler than rr RecordSession::RecordSession. Takes the
    ///   whole RecordCommand for simplicity.
    /// - This method also incorporates functionality from rr setup_session_from_flags()
    ///   method
    pub fn new(
        exe_path: &OsStr,
        // We don't use flags.extra_env. We augment flags.extra_env producing `envp`.
        envp: &[(OsString, OsString)],
        flags: &RecordCommand,
        asan_active: bool,
    ) -> SessionSharedPtr {
        let sched = Scheduler::new(flags.max_ticks, flags.always_switch);

        if flags.scarce_fds {
            for _ in 0..950 {
                // DIFF NOTE: rr swallows any errors on open. We don't for now.
                open("/dev/null", OFlag::O_RDONLY, Mode::empty()).unwrap();
            }
        }

        let mut rec_sess = RecordSession {
            session_inner: SessionInner::new(),
            trace_out: RefCell::new(TraceWriter::new(
                &flags.args[0],
                choose_cpu(flags.bind_cpu),
                flags.output_trace_dir.as_deref(),
                TicksSemantics::default(),
            )),
            scheduler_: sched,
            initial_thread_group: Default::default(),
            seccomp_filter_rewriter_: Default::default(),
            trace_id: flags.trace_id.clone(),
            disable_cpuid_features_: flags.disable_cpuid_features.clone(),
            ignore_sig: flags.ignore_sig,
            continue_through_sig: flags.continue_through_sig,
            last_task_switchable: Cell::new(Switchable::PreventSwitch),
            syscall_buffer_size_: flags.syscall_buffer_size,
            syscallbuf_desched_sig_: flags.syscallbuf_desched_sig,
            use_syscall_buffer_: flags.use_syscall_buffer == SyscallBuffering::EnableSycallBuf,
            use_file_cloning_: flags.use_file_cloning,
            use_read_cloning_: flags.use_read_cloning,
            enable_chaos_: Default::default(),
            asan_active_: asan_active,
            wait_for_all_: flags.wait_for_all,
            output_trace_dir: flags.output_trace_dir.clone(),
        };

        if !SessionInner::has_cpuid_faulting()
            && rec_sess.disable_cpuid_features_.any_features_disabled()
        {
            fatal!("CPUID faulting required to disable CPUID features");
        }

        // CPU affinity has been set.
        rec_sess.trace_out.borrow_mut().setup_cpuid_records(
            SessionInner::has_cpuid_faulting(),
            &flags.disable_cpuid_features,
        );

        let env: Vec<OsString> = envp
            .iter()
            .map(|(k, v)| -> OsString {
                let mut kv = k.clone();
                kv.push("=");
                kv.push(v);
                kv
            })
            .collect();
        let error_fd: ScopedFd = rec_sess.create_spawn_task_error_pipe();
        let socket_fd = rec_sess.tracee_socket_fd();

        let mut rc: SessionSharedPtr = Rc::new(Box::new(rec_sess));
        let weak_self = Rc::downgrade(&rc);
        // We never change the weak_self pointer so its a good idea to use
        // a bit of unsafe here otherwise we would unecessarily need a RefCell.
        let rs = unsafe {
            let s = Rc::get_mut_unchecked(&mut rc);
            s.weak_self = weak_self.clone();
            // Use this to also set things that shouldn't change.
            s.as_record_mut().unwrap()
        };

        rs.scheduler().set_session_weak_ptr(weak_self);

        if flags.chaos {
            rs.scheduler().set_enable_chaos(flags.chaos);
        }

        match flags.num_cores {
            Some(num_cores) => {
                // Set the number of cores reported, possibly overriding the chaos mode
                // setting.
                rs.scheduler().set_num_cores(num_cores);
            }
            // This is necessary for the default case
            None => rs.scheduler().regenerate_affinity_mask(),
        }

        let t = TaskInner::spawn(
            (*rc).as_ref(),
            &error_fd,
            socket_fd,
            SaveTraceeFdNumber::SaveToSession,
            exe_path,
            &flags.args,
            &env,
            None,
        );
        // The initial_thread_group is set only once so its worth it to use
        // unsafe
        unsafe {
            Rc::get_mut_unchecked(&mut rc)
                .as_record_mut()
                .unwrap()
                .initial_thread_group = Some(t.thread_group());
        }
        rc.on_create_task(t);
        rc
    }

    /// Create a recording session for the initial command line argv.
    ///
    /// DIFF NOTE: Param list very different from rr.
    /// Takes the whole &RecordCommand for simplicity.
    pub fn create(options: &RecordCommand) -> SessionSharedPtr {
        // The syscallbuf library interposes some critical
        // external symbols like XShmQueryExtension(), so we
        // preload it whether or not syscallbuf is enabled. Indicate here whether
        // syscallbuf is enabled.
        if options.use_syscall_buffer == SyscallBuffering::DisableSyscallBuf {
            env::remove_var(SYSCALLBUF_ENABLED_ENV_VAR);
        } else {
            env::set_var(SYSCALLBUF_ENABLED_ENV_VAR, "1");
            check_perf_event_paranoid();
        }

        let mut env: Vec<(OsString, OsString)> = env::vars_os().collect();
        env.extend_from_slice(&options.extra_env);

        let full_path = lookup_by_path(&options.args[0]);
        let exe_info: ExeInfo = read_exe_info(&full_path);

        // LD_PRELOAD the syscall interception lib
        let maybe_syscall_buffer_lib_path = find_helper_library(SYSCALLBUF_LIB_FILENAME);
        match maybe_syscall_buffer_lib_path {
            Some(syscall_buffer_lib_path) => {
                let mut ld_preload = Vec::<u8>::new();
                match &exe_info.libasan_path {
                    Some(asan_path) => {
                        log!(LogDebug, "Prepending {:?} to LD_PRELOAD", asan_path);
                        // Put an LD_PRELOAD entry for it before our preload library, because
                        // it checks that it's loaded first
                        ld_preload.extend_from_slice(asan_path.as_bytes());
                        ld_preload.push(b':');
                    }
                    None => (),
                }

                ld_preload.extend_from_slice(syscall_buffer_lib_path.as_bytes());
                ld_preload.extend_from_slice(SYSCALLBUF_LIB_FILENAME_PADDED.as_bytes());
                inject_ld_helper_library(&mut env, &OsStr::new("LD_PRELOAD"), ld_preload);
            }
            None => (),
        }

        env.push(("RUNNING_UNDER_RD".into(), "1".into()));
        // Stop Mesa using the GPU
        env.push(("LIBGL_ALWAYS_SOFTWARE".into(), "1".into()));
        env.push(("GBM_ALWAYS_SOFTWARE".into(), "1".into()));
        env.push(("SDL_RENDER_DRIVER".into(), "software".into()));
        // Stop sssd from using shared-memory with its daemon
        env.push(("SSS_NSS_USE_MEMCACHE".into(), "NO".into()));

        // Disable Gecko's "wait for gdb to attach on process crash" behavior, since
        // it is useless when running under rr.
        env.push(("MOZ_GDB_SLEEP".into(), "0".into()));

        // If we have CPUID faulting, don't use these environment hacks. We don't
        // need them and the user might want to use them themselves for other reasons.
        if !SessionInner::has_cpuid_faulting() {
            // OpenSSL uses RDRAND, but we can disable it. These bitmasks are inverted
            // and ANDed with the results of CPUID. The number below is 2^62, which is the
            // bit for RDRAND support.
            env.push(("OPENSSL_ia32cap".into(), "~4611686018427387904:~0".into()));
            // Disable Qt's use of RDRAND/RDSEED/RTM
            env.push(("QT_NO_CPU_FEATURE".into(), "rdrnd rdseed rtm".into()));
            // Disable systemd's use of RDRAND
            env.push(("SYSTEMD_RDRAND".into(), "0".into()));
        }

        RecordSession::new(
            &full_path,
            &env,
            options,
            exe_info.has_asan_symbols || exe_info.libasan_path.is_some(),
        )
    }

    pub fn disable_cpuid_features(&self) -> &DisableCPUIDFeatures {
        &self.disable_cpuid_features_
    }

    pub fn use_syscall_buffer(&self) -> bool {
        self.use_syscall_buffer_
    }

    pub fn syscall_buffer_size(&self) -> usize {
        self.syscall_buffer_size_
    }

    pub fn syscallbuf_desched_sig(&self) -> Sig {
        self.syscallbuf_desched_sig_
    }

    pub fn use_read_cloning(&self) -> bool {
        self.use_read_cloning_
    }

    pub fn use_file_cloning(&self) -> bool {
        self.use_file_cloning_
    }

    pub fn set_ignore_sig(&mut self, maybe_sig: Option<Sig>) {
        self.ignore_sig = maybe_sig;
    }

    pub fn get_ignore_sig(&self) -> Option<Sig> {
        self.ignore_sig
    }

    pub fn set_continue_through_sig(&mut self, maybe_sig: Option<Sig>) {
        self.continue_through_sig = maybe_sig;
    }

    pub fn get_continue_through_sig(&self) -> Option<Sig> {
        self.continue_through_sig
    }

    pub fn set_asan_active(&mut self, active: bool) {
        self.asan_active_ = active;
    }

    pub fn asan_active(&self) -> bool {
        self.asan_active_
    }

    pub fn rd_signal_mask(&self) -> u64 {
        signal_bit(perf_counters::TIME_SLICE_SIGNAL) | signal_bit(self.syscallbuf_desched_sig_)
    }

    /// Record some tracee execution.
    /// This may block. If blocking is interrupted by a signal, will return
    /// StepContinue.
    /// Typically you'd call this in a loop until it returns something other than
    /// StepContinue.
    /// Note that when this returns, some tasks may be running (not in a ptrace-
    /// stop). In particular, up to one task may be executing user code and any
    /// number of tasks may be blocked in syscalls.
    pub fn record_step(&self) -> RecordResult {
        let mut result = RecordResult::StepContinue;

        if self.can_end() {
            result = RecordResult::StepExited(
                self.initial_thread_group
                    .as_ref()
                    .unwrap()
                    .borrow()
                    .exit_status,
            );

            return result;
        }

        let maybe_prev_task = self.scheduler().current();
        let rescheduled = self.scheduler().reschedule(self.last_task_switchable.get());
        if rescheduled.interrupted_by_signal {
            // The scheduler was waiting for some task to become active, but was
            // interrupted by a signal. Yield to our caller now to give the caller
            // a chance to do something triggered by the signal
            // (e.g. terminate the recording).
            return result;
        }

        // @TODO This assumes that unwrap() will always succeed
        let mut t = self.scheduler().current().unwrap();
        match maybe_prev_task {
            Some(prev_task)
                if prev_task.as_record_task().unwrap().ev().event_type() == EventType::EvSched =>
            {
                if !Rc::ptr_eq(&prev_task, &t) {
                    // We did do a context switch, so record the SCHED event. Otherwise
                    // we'll just discard it.
                    prev_task.as_record_task().unwrap().record_current_event();
                }

                prev_task
                    .as_record_task()
                    .unwrap()
                    .pop_event(EventType::EvSched);
            }
            _ => (),
        }

        if rescheduled.started_new_timeslice {
            let regs = t.regs();
            *t.as_record_task()
                .unwrap()
                .registers_at_start_of_last_timeslice
                .borrow_mut() = regs;
            t.as_record_task()
                .unwrap()
                .time_at_start_of_last_timeslice
                .set(self.trace_writer().time());
        }

        // Have to disable context-switching until we know it's safe
        // to allow switching the context.
        self.last_task_switchable.set(Switchable::PreventSwitch);

        log!(
            LogDebug,
            "trace time {}: Active task is {}. Events:",
            t.trace_time(),
            t.tid()
        );

        if is_logging!(LogDebug) {
            t.log_pending_events();
        }

        if handle_ptrace_exit_event(t.as_rec_unwrap()) {
            // t is dead and has been deleted.
            return result;
        }

        if t.unstable.get() {
            // Do not record non-ptrace-exit events for tasks in
            // an unstable exit. We can't replay them. This happens in the
            // signal_deferred test; the signal gets re-reported to us.
            log!(
                LogDebug,
                "Task in unstable exit; refusing to record non-ptrace events"
            );
            // Resume the task so hopefully we'll get to its exit.
            self.last_task_switchable.set(Switchable::AllowSwitch);
            return result;
        }

        let mut step_state = StepState {
            continue_type: ContinueType::Continue,
        };

        let mut did_enter_syscall: bool = false;
        if rescheduled.by_waitpid
            && self.handle_ptrace_event(
                &mut t,
                &mut step_state,
                &mut result,
                &mut did_enter_syscall,
            )
        {
            if result != RecordResult::StepContinue
                || step_state.continue_type == ContinueType::DontContinue
            {
                return result;
            }

            if did_enter_syscall
                && t.as_record_task().unwrap().ev().event_type() == EventType::EvSyscall
            {
                self.syscall_state_changed(t.as_rec_unwrap(), &mut step_state);
            }
        } else if rescheduled.by_waitpid && self.handle_signal_event(&mut t, &mut step_state) {
            // @TODO Is this what we want here?
            // Do nothing
        } else {
            self.runnable_state_changed(
                t.as_rec_unwrap(),
                &mut step_state,
                &mut result,
                rescheduled.by_waitpid,
            );

            if result != RecordResult::StepContinue
                || step_state.continue_type == ContinueType::DontContinue
            {
                return result;
            }

            let event_type = t.as_rec_unwrap().ev().event_type();
            match event_type {
                EventType::EvDesched => {
                    self.desched_state_changed(t.as_rec_unwrap());
                }
                EventType::EvSyscall => {
                    self.syscall_state_changed(t.as_rec_unwrap(), &mut step_state);
                }
                EventType::EvSignal | EventType::EvSignalDelivery => {
                    self.signal_state_changed(t.as_rec_unwrap(), &mut step_state);
                }
                _ => (),
            }
        }

        t.as_rec_unwrap().verify_signal_states();

        // We try to inject a signal if there's one pending; otherwise we continue
        // task execution.
        if !self.prepare_to_inject_signal(&t, &mut step_state)
            && step_state.continue_type != ContinueType::DontContinue
        {
            // Ensure that we aren't allowing switches away from a running task.
            // Only tasks blocked in a syscall can be switched away from, otherwise
            // we have races.
            ed_assert!(
                &t,
                self.last_task_switchable.get() == Switchable::PreventSwitch
                    || t.unstable.get()
                    || t.as_record_task().unwrap().may_be_blocked()
            );

            debug_exec_state("EXEC_START", &**t);

            self.task_continue(step_state);
        }

        result
    }

    fn handle_signal_event(&self, mut t: &mut TaskSharedPtr, step_state: &mut StepState) -> bool {
        let maybe_sig = t.maybe_stop_sig();
        if !maybe_sig.is_sig() {
            return false;
        }

        let sig = maybe_sig.unwrap_sig();

        if !self.done_initial_exec() {
            // If the initial tracee isn't prepared to handle
            // signals yet, then us ignoring the ptrace
            // notification here will have the side effect of
            // declining to deliver the signal.
            //
            // This doesn't really occur in practice, only in
            // tests that force a degenerately low time slice.
            log!(
                LogWarn,
                "Dropping {} because it can't be delivered yet",
                maybe_sig
            );

            // These signals might have effects on the sigmask.
            t.as_rec_unwrap().invalidate_sigmask();
            // No events to be recorded, so no syscallbuf updates
            // needed.
            return true;
        }

        if maybe_sig == sig::SIGTRAP && handle_syscallbuf_breakpoint(t.as_rec_unwrap()) {
            return true;
        }

        let deterministic: SignalDeterministic = is_deterministic_signal(&***t);
        // The kernel might have forcibly unblocked the signal. Check whether it
        // was blocked now, before we update our cached sigmask.
        let signal_was_blocked = if t.as_rec_unwrap().is_sig_blocked(sig) {
            SignalBlocked::SigBlocked
        } else {
            SignalBlocked::SigUnblocked
        };

        if deterministic == SignalDeterministic::DeterministicSig
            || sig == t.session().as_record().unwrap().syscallbuf_desched_sig()
        {
            // Don't stash these signals; deliver them immediately.
            // We don't want them to be reordered around other signals.
            // invalidate_sigmask() must not be called before we reach handle_signal!
            let si = t.get_siginfo();
            let res = handle_signal(t.as_rec_unwrap(), si, deterministic, signal_was_blocked);
            match res {
                (SignalHandled::SignalPtraceStop, new_si) => {
                    t.pending_siginfo.set(new_si);
                    // Emulated ptrace-stop. Don't run the task again yet.
                    self.last_task_switchable.set(Switchable::AllowSwitch);
                    step_state.continue_type = ContinueType::DontContinue;
                    return true;
                }
                (SignalHandled::DeferSignal, new_si) => {
                    t.pending_siginfo.set(new_si);
                    ed_assert!(
                        &t,
                        false,
                        "Can't defer deterministic or internal signal {} at ip {}",
                        t.get_siginfo(),
                        t.ip()
                    );
                }
                (SignalHandled::SignalHandled, new_si) => {
                    t.pending_siginfo.set(new_si);
                    if t.maybe_ptrace_event() == PTRACE_EVENT_SECCOMP {
                        // `handle_desched_event` detected a spurious desched followed
                        // by a SECCOMP event, which it left pending. Handle that SECCOMP
                        // event now.
                        let mut dummy_did_enter_syscall = false;

                        // DIFF NOTE: handle_ptrace_event() in rr passes in a nullptr
                        // @TODO Use an option?
                        let mut dummy_result_ignore = RecordResult::StepContinue;
                        self.handle_ptrace_event(
                            &mut t,
                            step_state,
                            &mut dummy_result_ignore,
                            &mut dummy_did_enter_syscall,
                        );
                        ed_assert!(&t, !dummy_did_enter_syscall);
                    }
                }
            }

            return false;
        }

        let rt = t.as_rec_unwrap();
        // Conservatively invalidate the sigmask in case just accepting a signal has
        // sigmask effects.
        rt.invalidate_sigmask();
        if sig == perf_counters::TIME_SLICE_SIGNAL {
            if rt.next_pmc_interrupt_is_for_user.get() {
                let maybe_vpmc = VirtualPerfCounterMonitor::interrupting_virtual_pmc_for_task(rt);
                ed_assert!(rt, maybe_vpmc.is_some());

                // Synthesize the requested signal.
                maybe_vpmc
                    .unwrap()
                    .borrow_mut()
                    .as_virtual_perf_counter_monitor_mut()
                    .unwrap()
                    .synthesize_signal(rt);

                rt.next_pmc_interrupt_is_for_user.set(false);
                return true;
            }

            let si = rt.get_siginfo();
            // This implementation will of course fall over if rr tries to
            // record itself.
            //
            // NB: we can't check that the ticks is >= the programmed
            // target, because this signal may have become pending before
            // we reset the HPC counters.  There be a way to handle that
            // more elegantly, but bridge will be crossed in due time.
            //
            // We can't check that the fd matches t.hpc.ticks_fd() because this
            // signal could have been queued quite a long time ago and the PerfCounters
            // might have been stopped (and restarted!), perhaps even more than once,
            // since the signal was queued. possibly changing its fd. We could check
            // against all fds the PerfCounters have ever used, but that seems like
            // overkill.
            ed_assert!(
                rt,
                perf_counters::TIME_SLICE_SIGNAL.as_raw() == si.si_signo
                    && (record_task::SYNTHETIC_TIME_SLICE_SI_CODE == si.si_code
                        || POLL_IN as i32 == si.si_code),
                "Tracee is using SIGSTKFLT??? (code={}, fd={})",
                si.si_code,
                unsafe { si._sifields._sigpoll.si_fd }
            );
        }
        rt.stash_sig();

        true
    }

    fn handle_ptrace_event(
        &self,
        t: &mut TaskSharedPtr,
        step_state: &mut StepState,
        result: &mut RecordResult,
        did_enter_syscall: &mut bool,
    ) -> bool {
        *did_enter_syscall = false;
        if t.status().maybe_group_stop_sig().is_sig() || t.as_rec_unwrap().has_stashed_group_stop()
        {
            t.as_rec_unwrap().clear_stashed_group_stop();
            self.last_task_switchable.set(Switchable::AllowSwitch);
            step_state.continue_type = ContinueType::DontContinue;
            return true;
        }

        if !t.maybe_ptrace_event().is_ptrace_event() {
            return false;
        }

        log!(
            LogDebug,
            "  {}: handle_ptrace_event {}: event {}",
            t.tid(),
            t.maybe_ptrace_event(),
            t.as_rec_unwrap().ev()
        );
        let event = t.maybe_ptrace_event().unwrap_event();

        match event {
            PTRACE_EVENT_SECCOMP_OBSOLETE | PTRACE_EVENT_SECCOMP => {
                if self.syscall_seccomp_ordering()
                    == PtraceSyscallSeccompOrdering::SyscallBeforeSeccompUnknown
                {
                    self.syscall_seccomp_ordering_
                        .set(PtraceSyscallSeccompOrdering::SeccompBeforeSyscall);
                }

                let seccomp_data: u16 = t.as_rec_unwrap().get_ptrace_eventmsg_seccomp_data();
                let syscallno = t.regs_ref().original_syscallno() as i32;
                if seccomp_data as u32 == SECCOMP_RET_DATA {
                    log!(
                        LogDebug,
                        "  traced syscall entered: {}",
                        syscall_name(syscallno, t.arch())
                    );
                    self.handle_seccomp_traced_syscall(
                        t.as_rec_unwrap(),
                        step_state,
                        result,
                        did_enter_syscall,
                    );
                } else {
                    // Note that we make no attempt to patch the syscall site when the
                    // user handle does not return ALLOW. Apart from the ERRNO case,
                    // handling these syscalls is necessarily slow anyway.
                    let mut real_result: u32 = 0;
                    if !self
                        .seccomp_filter_rewriter()
                        .map_filter_data_to_real_result(
                            t.as_rec_unwrap(),
                            seccomp_data,
                            &mut real_result,
                        )
                    {
                        log!(
                            LogDebug,
                            "Process terminated unexpectedly during PTRACE_GETEVENTMSG"
                        );
                        step_state.continue_type = ContinueType::Continue;
                    } else {
                        let real_result_data: u16 = (real_result & SECCOMP_RET_DATA) as u16;
                        match real_result & SECCOMP_RET_ACTION {
                            SECCOMP_RET_TRAP => {
                                log!(
                                    LogDebug,
                                    "  seccomp trap for syscall: {}",
                                    syscall_name(syscallno, t.arch())
                                );
                                handle_seccomp_trap(
                                    t.as_rec_unwrap(),
                                    step_state,
                                    real_result_data,
                                );
                            }
                            SECCOMP_RET_ERRNO => {
                                log!(
                                    LogDebug,
                                    "  seccomp errno {} for syscall: {}",
                                    errno_name(real_result_data as i32),
                                    syscall_name(syscallno, t.arch())
                                );
                                handle_seccomp_errno(
                                    t.as_rec_unwrap(),
                                    step_state,
                                    real_result_data,
                                );
                            }
                            SECCOMP_RET_KILL => {
                                log!(
                                    LogDebug,
                                    "  seccomp kill for syscall: {}",
                                    syscall_name(syscallno, t.arch())
                                );

                                let tg = t.thread_group();
                                for tt in tg.borrow().task_set().iter() {
                                    // Record robust futex changes now in case the taskgroup dies
                                    // synchronously without a regular PTRACE_EVENT_EXIT (as seems
                                    // to happen on Ubuntu 4.2.0-42-generic)
                                    record_robust_futex_changes(tt.as_rec_unwrap());
                                }
                                t.as_rec_unwrap().tgkill(sig::SIGKILL);
                                step_state.continue_type = ContinueType::Continue;
                            }
                            _ => ed_assert!(&t, false, "Seccomp result not handled"),
                        }
                    }
                }
            }

            PTRACE_EVENT_EXEC => {
                let thread_group_len = t.thread_group().borrow().task_set().len();
                if thread_group_len > 1 {
                    // All tasks but the task that did the execve should have exited by
                    // now and notified us of their exits. However, it's possible that
                    // while running the thread-group leader, our PTRACE_CONT raced with its
                    // PTRACE_EVENT_EXIT and it exited, and the next event we got is this
                    // PTRACE_EVENT_EXEC after the exec'ing task changed its tid to the
                    // leader's tid. Or maybe there are kernel bugs; on
                    // 4.2.0-42-generic running exec_from_other_thread, we reproducibly
                    // enter PTRACE_EVENT_EXEC for the thread-group leader without seeing
                    // its PTRACE_EVENT_EXIT.

                    // So, record this task's exit and destroy it.
                    // XXX We can't do record_robust_futex_changes here because the address
                    // space has already gone. That would only matter if some of them were
                    // in memory accessible to another process even after exec, i.e. a
                    // shared-memory mapping or two different thread-groups sharing the same
                    // address space.
                    let tid = t.rec_tid();
                    let status: WaitStatus = t.status();
                    // Mark task as unstable so we don't wait on its futex. This matches
                    // what the kernel would do.
                    t.unstable.set(true);
                    record_exit(t.as_rec_unwrap(), WaitStatus::default());

                    // DIFF NOTE: OK to call destroy(). We just ask it to skip PTRACE_DETACH.
                    t.destroy(Some(false));
                    // Steal the exec'ing task and make it the thread-group leader, and
                    // carry on!
                    *t = self.revive_task_for_exec(tid);
                    self.scheduler().set_current(Some(Rc::downgrade(&t)));
                    // Tell t that it is actually stopped, because the stop we got is really
                    // for this task, not the old dead task.
                    t.did_waitpid(status);
                }

                t.as_rec_unwrap().post_exec();

                // Skip past the ptrace event.
                step_state.continue_type = ContinueType::ContinueSyscall;
            }

            _ => ed_assert!(
                &t,
                false,
                "Unhandled ptrace event {}({})",
                event,
                ptrace_event_name(event)
            ),
        }

        true
    }

    fn runnable_state_changed(
        &self,
        t: &RecordTask,
        step_state: &mut StepState,
        step_result: &mut RecordResult,
        can_consume_wait_status: bool,
    ) {
        let event_type = t.ev().event_type();
        match event_type {
            EventType::EvNoop => {
                t.pop_noop();
            }
            EventType::EvInstructionTrap => {
                t.record_current_event();
                t.pop_event(event_type);
            }
            EventType::EvSentinel
            | EventType::EvSignalHandler
            | EventType::EvSyscallInterruption => {
                if !can_consume_wait_status {
                    return;
                }

                let syscall_arch = t.detect_syscall_arch();
                t.canonicalize_regs(syscall_arch);
                self.process_syscall_entry(t, step_state, step_result, syscall_arch);
            }

            _ => (),
        }
    }

    /// `t` is at a desched event and some relevant aspect of its state
    /// changed.  (For now, changes except the original desched'd syscall
    /// being restarted.)
    fn desched_state_changed(&self, t: &RecordTask) {
        log!(LogDebug, "desched: IN_SYSCALL");
        // We need to ensure that the syscallbuf code doesn't
        // try to commit the current record; we've already
        // recorded that syscall.  The following event sets
        // the abort-commit bit.
        let syscallbuf_child = t.syscallbuf_child.get();
        write_val_mem(
            t,
            RemotePtr::<u8>::cast(syscallbuf_child) + offset_of!(syscallbuf_hdr, abort_commit),
            &1u8,
            None,
        );
        t.record_event(Some(Event::syscallbuf_abort_commit()), None, None, None);

        advance_to_disarm_desched_syscall(t);

        t.pop_desched();

        // The tracee has just finished sanity-checking the
        // aborted record, and won't touch the syscallbuf
        // during this (aborted) transaction again.  So now
        // is a good time for us to reset the record counter.
        t.delay_syscallbuf_reset_for_desched.set(false);
        // Run the syscallbuf exit hook. This ensures we'll be able to reset
        // the syscallbuf before trying to buffer another syscall.
        write_val_mem(
            t,
            RemotePtr::<u8>::cast(syscallbuf_child)
                + offset_of!(syscallbuf_hdr, notify_on_syscall_hook_exit),
            &1u8,
            None,
        );
    }

    /// `t` is being delivered a signal, and its state changed.
    /// Must call t.stashed_signal_processed() once we're ready to unmask signals.
    fn signal_state_changed(&self, t: &RecordTask, step_state: &mut StepState) {
        let sig = Sig::try_from(t.ev().signal_event().siginfo.si_signo).unwrap();
        let event_type = t.ev().event_type();
        match event_type {
            EventType::EvSignal => {
                // This event is used by the replayer to advance to
                // the point of signal delivery.
                t.record_current_event();
                t.ev_mut().transform(EventType::EvSignalDelivery);
                let mut sigframe_size = 0;

                let has_handler = t.signal_has_user_handler(sig);
                let mut done = false;
                if has_handler {
                    log!(LogDebug, "  {}: {} has user handler", t.tid(), sig);

                    if !inject_handled_signal(t) {
                        // Signal delivery isn't happening. Prepare to process the new
                        // signal that aborted signal delivery.
                        t.signal_delivered(sig);
                        t.pop_signal_delivery();
                        step_state.continue_type = ContinueType::DontContinue;
                        self.last_task_switchable.set(Switchable::PreventSwitch);
                        done = true;
                    } else {
                        // It's somewhat difficult engineering-wise to
                        // compute the sigframe size at compile time,
                        // and it can vary across kernel versions and CPU
                        // microarchitectures. So this size is an overestimate
                        // of the real size(s).
                        //
                        // If this size becomes too small in the
                        // future, and unit tests that use sighandlers
                        // are run with checksumming enabled, then
                        // they can catch errors here.
                        sigframe_size = 1152 /* Overestimate of kernel sigframe */ +
                        128 /* Redzone */ +
                        /* this returns 512 when XSAVE unsupported */
                        xsave_area_size();

                        t.ev_mut().transform(EventType::EvSignalHandler);
                        t.signal_delivered(sig);
                        // We already continued! Don't continue now, and allow switching.
                        step_state.continue_type = ContinueType::DontContinue;
                        self.last_task_switchable.set(Switchable::AllowSwitch);
                    }
                } else {
                    t.stashed_signal_processed();
                    log!(LogDebug, "  {}: no user handler for {}", t.tid(), sig);
                    // Don't do another task continue. We want to deliver the signal
                    // as the next thing that the task does.
                    step_state.continue_type = ContinueType::DontContinue;
                    // If we didn't set up the sighandler frame, we need
                    // to ensure that this tracee is scheduled next so
                    // that we can deliver the signal normally.  We have
                    // to do that because setting up the sighandler frame
                    // is synchronous, but delivery otherwise is async.
                    // But right after this, we may have to process some
                    // syscallbuf state, so we can't let the tracee race
                    // with us.
                    self.last_task_switchable.set(Switchable::PreventSwitch);
                }

                if !done {
                    // We record this data even if sigframe_size is zero to simplify replay.
                    // Stop recording data if we run off the end of a writable mapping.
                    // Our sigframe size is conservative so we need to do this.
                    let sp = t.regs_ref().sp();
                    t.record_remote_writable(sp, sigframe_size);

                    // This event is used by the replayer to set up the signal handler frame.
                    // But if we don't have a handler, we don't want to record the event
                    // until we deal with the EV_SIGNAL_DELIVERY.
                    if has_handler {
                        t.record_current_event();
                    }
                }
            }
            EventType::EvSignalDelivery => {
                // A fatal signal or SIGSTOP requires us to allow switching to another
                // task.
                let is_fatal = t.is_fatal_signal(sig, t.ev().signal_event().deterministic);
                let mut can_switch: Switchable = if is_fatal || sig == sig::SIGSTOP {
                    Switchable::AllowSwitch
                } else {
                    Switchable::PreventSwitch
                };

                // We didn't record this event above, so do that now.
                // NB: If there is no handler, and we interrupted a syscall, and there are
                // no more actionable signals, the kernel sets us up for a syscall
                // restart. But it does that *after* the ptrace trap. To replay this
                // correctly we need to fake those changes here. But we don't do this
                // if we're going to switch away at the ptrace trap, and for the moment,
                // 'can_switch' is actually 'will_switch'.
                // This is essentially copied from do_signal in arch/x86/kernel/signal.c
                let has_other_signals = t.has_any_actionable_signal();
                let mut r = t.regs_ref().clone();
                if can_switch == Switchable::PreventSwitch
                    && !has_other_signals
                    && r.original_syscallno() >= 0
                    && r.syscall_may_restart()
                {
                    // @TODO Check this
                    match -r.syscall_result_signed() as u32 {
                        ERESTARTNOHAND | ERESTARTSYS | ERESTARTNOINTR => {
                            r.set_syscallno(r.original_syscallno());
                            r.set_ip(r.ip().decrement_by_syscall_insn_length(t.arch()));
                        }
                        ERESTART_RESTARTBLOCK => {
                            r.set_syscallno(syscall_number_for_restart_syscall(t.arch()) as isize);
                            r.set_ip(r.ip().decrement_by_syscall_insn_length(t.arch()));
                        }
                        _ => (),
                    }

                // Now that we've mucked with the registers, we can't switch tasks. That
                // could allow more signals to be generated, breaking our assumption
                // that we are the last signal.
                } else {
                    // But if we didn't touch the registers switching here is ok.
                    can_switch = Switchable::AllowSwitch;
                }

                let event = t.ev().clone();
                t.record_event(
                    Some(event),
                    Some(FlushSyscallbuf::FlushSyscallbuf),
                    Some(AllowSyscallbufReset::AllowResetSyscallbuf),
                    Some(&r),
                );
                // Don't actually set_regs(r), the kernel does these modifications.

                // Only inject fatal signals. Non-fatal signals with signal handlers
                // were taken care of above; for non-fatal signals without signal
                // handlers, there is no need to deliver the signal at all. In fact,
                // there is really no way to inject a non-fatal, non-handled signal
                // without letting the task execute at least one instruction, which
                // we don't want to do here.
                if is_fatal && Some(sig) != self.get_continue_through_sig() {
                    preinject_signal(t);
                    t.resume_execution(
                        ResumeRequest::ResumeCont,
                        WaitRequest::ResumeNonblocking,
                        TicksRequest::ResumeNoTicks,
                        Some(sig),
                    );
                    log!(LogWarn,   "Delivered core-dumping signal; may misrecord CLONE_CHILD_CLEARTID memory race");
                    t.thread_group().borrow().destabilize();
                }

                t.signal_delivered(sig);
                t.pop_signal_delivery();
                self.last_task_switchable.set(can_switch);
                step_state.continue_type = ContinueType::DontContinue;
            }

            _ => {
                fatal!("Unhandled signal state {}", t.ev().event_type());
            }
        }
    }

    fn syscall_state_changed(&self, t: &RecordTask, step_state: &mut StepState) {
        let state = t.ev().syscall_event().state;
        match state {
            SyscallState::EnteringSyscallPtrace => {
                debug_exec_state("EXEC_SYSCALL_ENTRY_PTRACE", t);
                step_state.continue_type = ContinueType::DontContinue;
                self.last_task_switchable.set(Switchable::AllowSwitch);
                if t.emulated_stop_type.get() != EmulatedStopType::NotStopped {
                    // Don't go any further.
                    return;
                }
                if t.ev().syscall_event().in_sysemu {
                    // We'll have recorded just the SyscallState::EnteringSyscall_PTRACE event and
                    // nothing else. Resume with an invalid syscall to ensure no real
                    // syscall runs.
                    t.pop_syscall();
                    let mut r = t.regs_ref().clone();
                    let orig_regs = r.clone();
                    r.set_original_syscallno(-1);
                    t.set_regs(&r);
                    t.resume_execution(
                        ResumeRequest::ResumeSyscall,
                        WaitRequest::ResumeWait,
                        TicksRequest::ResumeNoTicks,
                        None,
                    );
                    ed_assert_eq!(t, t.ip(), r.ip());
                    t.set_regs(&orig_regs);
                    maybe_trigger_emulated_ptrace_syscall_exit_stop(t);
                    return;
                }
                self.last_task_switchable.set(Switchable::PreventSwitch);
                t.ev_mut().syscall_event_mut().regs = t.regs();
                t.ev_mut().syscall_event_mut().state = SyscallState::EnteringSyscall;
                // The syscallno may have been changed by the ptracer
                let osno = t.regs_ref().original_syscallno() as i32;
                t.ev_mut().syscall_event_mut().number = osno;
            }
            SyscallState::EnteringSyscall => {
                debug_exec_state("EXEC_SYSCALL_ENTRY", t);
                ed_assert!(t, !t.emulated_stop_pending.get());

                self.last_task_switchable.set(rec_prepare_syscall(t));
                t.ev_mut().syscall_event_mut().switchable = self.last_task_switchable.get();
                let regs = t.ev().syscall_event().regs.clone();
                let event = t.ev().clone();
                t.record_event(
                    Some(event),
                    Some(FlushSyscallbuf::FlushSyscallbuf),
                    Some(AllowSyscallbufReset::AllowResetSyscallbuf),
                    Some(&regs),
                );

                debug_exec_state("after cont", t);
                t.ev_mut().syscall_event_mut().state = SyscallState::ProcessingSyscall;

                if t.emulated_stop_pending.get() {
                    step_state.continue_type = ContinueType::DontContinue;
                } else {
                    // Resume the syscall execution in the kernel context.
                    step_state.continue_type = ContinueType::ContinueSyscall;
                }

                if t.session().done_initial_exec() && Flags::get().check_cached_mmaps {
                    t.vm().verify(t);
                }

                if !t.desched_rec().is_null()
                    && t.is_in_untraced_syscall()
                    && t.has_any_stashed_sig()
                {
                    // We have a signal to deliver but we're about to (re?)enter an untraced
                    // syscall that may block and the desched event has been disarmed.
                    // Rearm the desched event so if the syscall blocks, it will be
                    // interrupted and we'll have a chance to deliver our signal.
                    log!(
                        LogDebug,
                        "Rearming desched event so we'll get a chance to deliver stashed signal"
                    );
                    arm_desched_event(t);
                }
            }

            SyscallState::ProcessingSyscall => {
                debug_exec_state("EXEC_IN_SYSCALL", t);

                // Linux kicks tasks out of syscalls before delivering
                // signals.
                ed_assert!(
                    t,
                    !t.maybe_stop_sig().is_sig(),
                    "Signal {} pending while in syscall???",
                    t.maybe_stop_sig()
                );

                t.ev_mut().syscall_event_mut().state = SyscallState::ExitingSyscall;
                step_state.continue_type = ContinueType::DontContinue;
            }
            SyscallState::ExitingSyscall => {
                debug_exec_state("EXEC_SYSCALL_DONE", t);

                debug_assert!(!t.maybe_stop_sig().is_sig());

                let syscall_arch = t.ev().syscall_event().arch();
                let syscallno = t.ev().syscall_event().number;
                let retval = t.regs_ref().syscall_result_signed();

                if !t.desched_rec().is_null() {
                    // If we enabled the desched event above, disable it.
                    disarm_desched_event(t);
                    // Write syscall return value to the syscallbuf now. This lets replay
                    // get the correct value even though we're aborting the commit. This
                    // value affects register values in the preload code (which must be
                    // correct since register values may escape).
                    save_interrupted_syscall_ret_in_syscallbuf(t, retval);
                }

                // sigreturn is a special snowflake, because it
                // doesn't actually return.  Instead, it undoes the
                // setup for signal delivery, which possibly includes
                // preparing the tracee for a restart-syscall.  So we
                // take this opportunity to possibly pop an
                // interrupted-syscall event.
                if is_sigreturn(syscallno, syscall_arch) {
                    ed_assert_eq!(t, t.regs_ref().original_syscallno(), -1);
                    t.record_current_event();
                    t.pop_syscall();

                    // We've finished processing this signal now.
                    t.pop_signal_handler();
                    t.invalidate_sigmask();

                    maybe_discard_syscall_interruption(t, retval);

                    if EventType::EvSeccompTrap == t.ev().event_type() {
                        log!(LogDebug, "  exiting seccomp trap");
                        save_interrupted_syscall_ret_in_syscallbuf(t, retval);
                        seccomp_trap_done(t);
                    }

                    if EventType::EvDesched == t.ev().event_type() {
                        log!(LogDebug, "  exiting desched critical section");
                        // The signal handler could have modified the apparent syscall
                        // return handler. Save that value into the syscall buf again so
                        // replay will pick it up later.
                        save_interrupted_syscall_ret_in_syscallbuf(t, retval);
                        self.desched_state_changed(t);
                    }
                } else {
                    log!(
                        LogDebug,
                        "  original_syscallno:{} ({}); return val:{:#x} ({})",
                        t.regs_ref().original_syscallno(),
                        syscall_name(syscallno, syscall_arch),
                        t.regs_ref().syscall_result(),
                        t.regs_ref().syscall_result_signed()
                    );

                    // a syscall_restart ending is equivalent to the
                    // restarted syscall ending
                    if t.ev().syscall_event().is_restart {
                        log!(
                            LogDebug,
                            "  exiting restarted {}",
                            syscall_name(syscallno, syscall_arch)
                        );
                    }

                    // TODO: is there any reason a restart_syscall can't
                    // be interrupted by a signal and itself restarted?
                    let may_restart = !is_restart_syscall_syscall(syscallno, t.arch())
                           // SYS_pause is either interrupted or
                           // never returns.  It doesn't restart.
                           && !is_pause_syscall(syscallno, t.arch()) &&
                           t.regs_ref().syscall_may_restart();
                    // no need to process the syscall in case its
                    // restarted this will be done in the exit from the
                    // restart_syscall
                    if !may_restart {
                        rec_process_syscall(t);
                        if t.session().done_initial_exec() && Flags::get().check_cached_mmaps {
                            t.vm().verify(t);
                        }
                    } else {
                        log!(
                            LogDebug,
                            "  may restart {} (from retval {:#x})",
                            syscall_name(syscallno, syscall_arch),
                            retval
                        );

                        rec_prepare_restart_syscall(t);
                        // If we may restart this syscall, we've most
                        // likely fudged some of the argument
                        // registers with scratch pointers.  We don't
                        // want to record those fudged registers,
                        // because scratch doesn't exist in replay.
                        // So cover our tracks here.
                        let mut r = t.regs_ref().clone();
                        copy_syscall_arg_regs(&mut r, &t.ev().syscall_event().regs);
                        t.set_regs(&r);
                    }
                    t.record_current_event();

                    // If we're not going to restart this syscall, we're
                    // done with it.  But if we are, "freeze" it on the
                    // event stack until the execution point where it
                    // might be restarted.
                    if !may_restart {
                        t.pop_syscall();
                        if EventType::EvDesched == t.ev().event_type() {
                            log!(LogDebug, "  exiting desched critical section");
                            self.desched_state_changed(t);
                        }
                    } else {
                        t.ev_mut().transform(EventType::EvSyscallInterruption);
                        t.ev_mut().syscall_event_mut().is_restart = true;
                    }

                    t.canonicalize_regs(syscall_arch);
                }

                self.last_task_switchable.set(Switchable::AllowSwitch);
                step_state.continue_type = ContinueType::DontContinue;

                if !is_in_privileged_syscall(t) {
                    maybe_trigger_emulated_ptrace_syscall_exit_stop(t);
                }
            }

            _ => fatal!("Unknown exec state {}", t.ev().syscall_event().state),
        }
    }

    fn prepare_to_inject_signal(&self, t_shr: &TaskSharedPtr, step_state: &mut StepState) -> bool {
        if !self.done_initial_exec() || step_state.continue_type != ContinueType::Continue {
            return false;
        }

        let mut si: USiginfo = unsafe { mem::zeroed() };
        let mut ssig: StashedSignal;
        let mut sig: Sig;
        let mut ssig_addr: *const StashedSignal;

        {
            let t = t_shr.as_rec_unwrap();
            loop {
                match t.peek_stashed_sig_to_deliver() {
                    Some(ssig_obtained) => {
                        ssig_addr = ssig_obtained;
                        ssig = unsafe { (*ssig_obtained).clone() };
                        si.linux_api = ssig.siginfo;
                        sig = Sig::try_from(unsafe { si.linux_api.si_signo }).unwrap();
                        if Some(sig) == self.get_ignore_sig() {
                            log!(LogDebug, "Declining to deliver {} by user request", sig);
                            t.pop_stash_sig(ssig_addr);
                            t.stashed_signal_processed();
                        } else {
                            break;
                        }
                    }
                    None => return false,
                }
            }

            if ssig.deterministic == SignalDeterministic::DeterministicSig
                && ssig.siginfo.si_signo == SIGSYS
                && t.is_sig_blocked(sig::SIGSYS)
            {
                // Our synthesized deterministic SIGSYS (seccomp trap) needs to match the
                // kernel behavior of unblocking the signal and resetting disposition to
                // default.
                t.unblock_signal(sig::SIGSYS);
                t.set_sig_handler_default(sig::SIGSYS);
            }
        }

        let res = handle_signal(
            t_shr.as_rec_unwrap(),
            unsafe { si.linux_api },
            ssig.deterministic,
            SignalBlocked::SigUnblocked,
        );

        match res {
            (SignalHandled::SignalPtraceStop, new_si) => {
                si.linux_api = new_si;
                // Emulated ptrace-stop. Don't run the task again yet.
                self.last_task_switchable.set(Switchable::AllowSwitch);
                log!(LogDebug, "{}, emulating ptrace stop", sig);
            }
            (SignalHandled::DeferSignal, new_si) => {
                si.linux_api = new_si;
                log!(
                    LogDebug,
                    "{} deferred",
                    signal_name(unsafe { si.linux_api.si_signo })
                );
                // Leave signal on the stack and continue task execution. We'll try again
                // later.
                return false;
            }
            (SignalHandled::SignalHandled, new_si) => {
                si.linux_api = new_si;
                log!(
                    LogDebug,
                    "{} handled",
                    signal_name(unsafe { si.linux_api.si_signo })
                );
                // Signal is now a pending event on `t`'s event stack

                if t_shr.as_rec_unwrap().ev().event_type() == EventType::EvSched {
                    if t_shr.as_rec_unwrap().maybe_in_spinlock() {
                        // So that we can provide a shared pointer to the scheduler
                        log!(
                            LogDebug,
                            "Detected possible spinlock, forcing one round-robin"
                        );
                        self.scheduler()
                            .schedule_one_round_robin(t_shr.as_rec_unwrap());
                    }
                    // Allow switching after a SCHED. We'll flush the SCHED if and only
                    // if we really do a switch.
                    self.last_task_switchable.set(Switchable::AllowSwitch);
                }
            }
        }

        step_state.continue_type = ContinueType::DontContinue;
        t_shr.as_rec_unwrap().pop_stash_sig(ssig_addr);
        if t_shr.as_rec_unwrap().ev().event_type() != EventType::EvSignal {
            t_shr.as_rec_unwrap().stashed_signal_processed();
        }

        true
    }

    fn task_continue(&self, step_state: StepState) {
        let t = self.scheduler().current().unwrap().clone();

        ed_assert!(&t, step_state.continue_type != ContinueType::DontContinue);
        // A task in an emulated ptrace-stop must really stay stopped
        ed_assert!(&t, !t.as_rec_unwrap().emulated_stop_pending.get());

        let may_restart = t.as_rec_unwrap().at_may_restart_syscall();

        if may_restart && t.seccomp_bpf_enabled.get() {
            log!(
                LogDebug,
                "  PTRACE_SYSCALL to possibly-restarted {}",
                t.as_rec_unwrap().ev()
            );
        }

        if t.vm().first_run_event() == 0 {
            let time = self.trace_writer().time();
            t.vm().set_first_run_event(time);
        }

        let mut ticks_request: TicksRequest;
        let resume: ResumeRequest;
        if step_state.continue_type == ContinueType::ContinueSyscall {
            ticks_request = TicksRequest::ResumeNoTicks;
            resume = ResumeRequest::ResumeSyscall;
        } else {
            if t.as_rec_unwrap()
                .has_stashed_sig(perf_counters::TIME_SLICE_SIGNAL)
            {
                // timeslice signal already stashed, no point in generating another one
                // (and potentially slow)
                ticks_request = TicksRequest::ResumeUnlimitedTicks;
            } else {
                let end = self.scheduler().current_timeslice_end();
                let tick_count = t.tick_count();
                // @TODO What about stipulation that ResumeWithTicksRequest must have > 0 as
                // request?? Its possible for end to be less than tick_count.
                let num_ticks_request = if tick_count > end {
                    0
                } else {
                    end - tick_count
                };
                ticks_request = TicksRequest::ResumeWithTicksRequest(num_ticks_request);
            }

            // Clear any lingering state, then see if we need to stop earlier for a
            // tracee-requested pmc interrupt on the virtualized performance counter.
            t.as_rec_unwrap().next_pmc_interrupt_is_for_user.set(false);
            let maybe_vpmc = VirtualPerfCounterMonitor::interrupting_virtual_pmc_for_task(&**t);

            match maybe_vpmc {
                Some(vpmc) => {
                    ed_assert!(
                        &t,
                        vpmc.borrow()
                            .as_virtual_perf_counter_monitor()
                            .unwrap()
                            .target_tuid()
                            == t.tuid()
                    );

                    let after: Ticks = max(
                        vpmc.borrow()
                            .as_virtual_perf_counter_monitor()
                            .unwrap()
                            .target_ticks()
                            - t.tick_count(),
                        0,
                    );

                    match ticks_request {
                        TicksRequest::ResumeWithTicksRequest(num_ticks_request)
                            if after < num_ticks_request =>
                        {
                            debug_assert!(after > 0);
                            let after_ticks_request = TicksRequest::ResumeWithTicksRequest(after);
                            log!(
                                LogDebug,
                                "ticks_request constrained from {:?} to {:?} for vpmc",
                                ticks_request,
                                after_ticks_request
                            );
                            ticks_request = after_ticks_request;
                            t.as_rec_unwrap().next_pmc_interrupt_is_for_user.set(true);
                        }
                        _ => (),
                    }
                }
                None => (),
            }

            let mut singlestep = t.as_rec_unwrap().emulated_ptrace_cont_command.get()
                == PTRACE_SINGLESTEP
                || t.as_rec_unwrap().emulated_ptrace_cont_command.get() == PTRACE_SYSEMU_SINGLESTEP;

            let t_at_ip = t.ip();
            if singlestep && is_at_syscall_instruction(&**t, t_at_ip) {
                // We're about to singlestep into a syscall instruction.
                // Act like we're NOT singlestepping since doing a PTRACE_SINGLESTEP would
                // skip over the system call.
                log!(
                    LogDebug,
                    "Clearing singlestep because we're about to enter a syscall"
                );

                singlestep = false;
            }

            if singlestep {
                resume = ResumeRequest::ResumeSinglestep;
            } else {
                // We won't receive PTRACE_EVENT_SECCOMP events until
                // the seccomp filter is installed by the
                // syscall_buffer lib in the child, therefore we must
                // record in the traditional way (with PTRACE_SYSCALL)
                // until it is installed.
                // Kernel commit
                //   https://github.com/torvalds/linux/commit/93e35efb8de45393cf61ed07f7b407629bf698ea
                //   makes PTRACE_SYSCALL traps be delivered *before* seccomp RET_TRACE
                //   traps.
                //   Detect and handle this.
                if !t.seccomp_bpf_enabled.get()
                    || may_restart
                    || self.syscall_seccomp_ordering_.get()
                        == PtraceSyscallSeccompOrdering::SyscallBeforeSeccompUnknown
                {
                    resume = ResumeRequest::ResumeSyscall;
                } else {
                    // When the seccomp filter is on, instead of capturing
                    // syscalls by using PTRACE_SYSCALL, the filter will
                    // generate the ptrace events. This means we allow the
                    // process to run using PTRACE_CONT, and rely on the
                    // seccomp filter to generate the special
                    // PTRACE_EVENT_SECCOMP event once a syscall happens.
                    // This event is handled here by simply allowing the
                    // process to continue to the actual entry point of
                    // the syscall (using cont_syscall_block()) and then
                    // using the same logic as before.
                    resume = ResumeRequest::ResumeCont;
                }
            }
        }

        t.resume_execution(resume, WaitRequest::ResumeNonblocking, ticks_request, None);
    }

    /// Returns false if the task exits during processing
    fn process_syscall_entry(
        &self,
        t: &RecordTask,
        step_state: &mut StepState,
        step_result: &mut RecordResult,
        syscall_arch: SupportedArch,
    ) -> bool {
        if let Some(si) = t.stashed_sig_not_synthetic_sigchld() {
            // The only four cases where we allow a stashed signal to be pending on
            // syscall entry are:
            // -- the signal is a ptrace-related signal, in which case if it's generated
            // during a blocking syscall, it does not interrupt the syscall
            // -- rrcall_notify_syscall_hook_exit, which is effectively a noop and
            // lets us dispatch signals afterward
            // -- when we're entering a blocking untraced syscall. If it really blocks,
            // we'll get the desched-signal notification and dispatch our stashed
            // signal.
            // -- when we're doing a privileged syscall that's internal to the preload
            // logic
            // We do not generally want to have stashed signals pending when we enter
            // a syscall, because that will execute with a hacked signal mask
            // (see RecordTask::will_resume_execution) which could make things go wrong.
            ed_assert!(
                t,
                !t.desched_rec().is_null()
                    || is_rdcall_notify_syscall_hook_exit_syscall(
                        t.regs_ref().original_syscallno() as i32,
                        t.arch()
                    )
                    || t.ip()
                        == t.vm()
                            .privileged_traced_syscall_ip()
                            // @TODO Not fully sure about unwrap() here
                            // Is it possible to call this method before the value is filled in?
                            .unwrap()
                            .increment_by_syscall_insn_length(t.arch()),
                "Stashed signal pending on syscall entry when it shouldn't be: {}; IP={}",
                t.ip(),
                si
            );
        }

        // We just entered a syscall.
        if !maybe_restart_syscall(t) {
            // Emit FLUSH_SYSCALLBUF if necessary before we do any patching work
            t.maybe_flush_syscallbuf();

            if self.syscall_seccomp_ordering_.get()
                == PtraceSyscallSeccompOrdering::SyscallBeforeSeccompUnknown
                && t.seccomp_bpf_enabled.get()
            {
                // We received a PTRACE_SYSCALL notification before the seccomp
                // notification. Ignore it and continue to the seccomp notification.
                self.syscall_seccomp_ordering_
                    .set(PtraceSyscallSeccompOrdering::SyscallBeforeSeccomp);
                step_state.continue_type = ContinueType::Continue;
                return true;
            }

            // Don't ever patch a sigreturn syscall. These can't go through the syscallbuf.
            if !is_sigreturn(t.regs_ref().original_syscallno() as i32, t.arch()) {
                if t.vm()
                    .monkeypatcher()
                    .unwrap()
                    .borrow_mut()
                    .try_patch_syscall(t)
                {
                    // Syscall was patched. Emit event and continue execution.
                    t.record_event(Some(Event::patch_syscall()), None, None, None);
                    return true;
                }
            }

            if t.maybe_ptrace_event() == PTRACE_EVENT_EXIT {
                // task exited while we were trying to patch it.
                // Make sure that this exit event gets processed
                step_state.continue_type = ContinueType::DontContinue;
                return false;
            }

            let osno = t.regs_ref().original_syscallno() as i32;
            t.push_event(Event::new_syscall_event(SyscallEventData::new(
                osno,
                syscall_arch,
            )));
        }

        self.check_initial_task_syscalls(t, step_result);
        note_entering_syscall(t);
        if (t.emulated_ptrace_cont_command.get() == PTRACE_SYSCALL
            || t.emulated_ptrace_cont_command.get() == PTRACE_SYSEMU
            || t.emulated_ptrace_cont_command.get() == PTRACE_SYSEMU_SINGLESTEP)
            && !is_in_privileged_syscall(t)
        {
            // There MUST be an emulated ptracer
            let _emulated_ptracer = t.emulated_ptracer_unwrap();
            t.ev_mut().syscall_event_mut().state = SyscallState::EnteringSyscallPtrace;
            t.emulate_ptrace_stop(WaitStatus::for_syscall(t), None, None);
            t.record_current_event();

            t.ev_mut().syscall_event_mut().in_sysemu = t.emulated_ptrace_cont_command.get()
                == PTRACE_SYSEMU
                || t.emulated_ptrace_cont_command.get() == PTRACE_SYSEMU_SINGLESTEP;
        }

        true
    }

    /// If the perf counters seem to be working return, otherwise don't return.
    fn check_initial_task_syscalls(&self, t: &RecordTask, step_result: &mut RecordResult) {
        if self.done_initial_exec() {
            return;
        }

        if is_write_syscall(t.ev().syscall_event().number, t.arch())
            && t.regs_ref().arg1_signed() == -1
        {
            let ticks: Ticks = t.tick_count();
            log!(LogDebug, "ticks on entry to dummy write: {}", ticks);
            if ticks == 0 {
                *step_result = RecordResult::StepSpawnFailed(
                    "rd internal recorder error: Performance counter doesn't seem to \n\
                     be working. Are you perhaps running rr in a VM but didn't enable \n\
                     perf-counter virtualization?"
                        .into(),
                );
            }
        }

        if is_exit_group_syscall(t.ev().syscall_event().number, t.arch()) {
            *step_result = RecordResult::StepSpawnFailed(self.read_spawned_task_error());
        }
    }

    /// Flush buffers and write a termination record to the trace. Don't call
    /// record_step() after this.
    pub fn terminate_recording(&self) {
        match self.scheduler().current() {
            Some(t) => {
                t.as_rec_unwrap().maybe_flush_syscallbuf();
            }
            None => (),
        }

        log!(LogInfo, "Processing termination request ...");

        // This will write unstable exit events for all tasks.
        self.kill_all_tasks();
        self.close_trace_writer(CloseStatus::CloseOk);
    }

    /// Close trace output without flushing syscall buffers or writing
    /// task exit/termination records to the trace.
    pub fn close_trace_writer(&self, status: CloseStatus) {
        self.trace_out
            .borrow_mut()
            .close(status, Some(*self.trace_id.clone()));
    }

    pub fn trace_writer(&self) -> Ref<'_, TraceWriter> {
        self.trace_out.borrow()
    }

    pub fn trace_writer_mut(&self) -> RefMut<'_, TraceWriter> {
        self.trace_out.borrow_mut()
    }

    pub fn scheduler(&self) -> &Scheduler {
        &self.scheduler_
    }

    pub fn seccomp_filter_rewriter(&self) -> Ref<'_, SeccompFilterRewriter> {
        self.seccomp_filter_rewriter_.borrow()
    }

    pub fn seccomp_filter_rewriter_mut(&self) -> RefMut<'_, SeccompFilterRewriter> {
        self.seccomp_filter_rewriter_.borrow_mut()
    }

    pub fn set_enable_chaos(&mut self, enable_chaos: bool) {
        self.scheduler().set_enable_chaos(enable_chaos);
        self.enable_chaos_ = enable_chaos;
    }

    pub fn enable_chaos(&self) -> bool {
        self.enable_chaos_
    }

    pub fn set_num_cores(&mut self, num_cores: u32) {
        self.scheduler().set_num_cores(num_cores);
    }

    pub fn set_use_read_cloning(&mut self, enable: bool) {
        self.use_read_cloning_ = enable;
    }

    pub fn set_use_file_cloning(&mut self, enable: bool) {
        self.use_file_cloning_ = enable;
    }

    pub fn set_syscall_buffer_size(&mut self, size: usize) {
        self.syscall_buffer_size_ = size;
    }

    pub fn set_wait_for_all(&mut self, wait_for_all: bool) {
        self.wait_for_all_ = wait_for_all;
    }

    /// This gets called when we detect that a task has been revived from the
    /// dead with a PTRACE_EVENT_EXEC. See ptrace man page under "execve(2) under
    /// ptrace" for the horrid details.
    ///
    /// The task in the thread-group that triggered the successful execve has changed
    /// its tid to `rec_tid`. We mirror that, and emit TraceTaskEvents to make it
    /// look like a new task was spawned and the old task exited.
    pub fn revive_task_for_exec(&self, rec_tid: pid_t) -> TaskSharedPtr {
        let mut msg: usize = 0;
        let ret = unsafe { ptrace(PTRACE_GETEVENTMSG, rec_tid, 0, &mut msg) } as i32;
        if ret < 0 {
            fatal!("Can't get old tid for execve (leader={})", rec_tid);
        }

        let maybe_t = self.find_task_from_rec_tid(msg as pid_t);
        if maybe_t.is_none() {
            fatal!("Can't find old task for execve");
        }

        let t = maybe_t.unwrap();
        let tid = t.tid();
        ed_assert_eq!(&t, rec_tid, t.tgid());
        let own_namespace_tid = t.thread_group().borrow().real_tgid_own_namespace;

        log!(LogDebug, "Changing task tid from {} to {}", tid, rec_tid);

        // Pretend the old task cloned a new task with the right tid, and then exited
        self.trace_writer_mut()
            .write_task_event(&TraceTaskEvent::for_clone(
                rec_tid,
                tid,
                own_namespace_tid,
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM,
            ));

        self.trace_writer_mut()
            .write_task_event(&TraceTaskEvent::for_exit(tid, WaitStatus::for_exit_code(0)));

        // Account for tid change
        self.task_map.borrow_mut().remove(&tid);
        self.task_map.borrow_mut().insert(rec_tid, t.clone());
        // t probably would have been marked for unstable-exit when the old
        // thread-group leader died.
        t.unstable.set(false);
        // Update the serial as if this task was really created by cloning the old
        // task.
        t.as_rec_unwrap()
            .set_tid_and_update_serial(rec_tid, own_namespace_tid);

        t
    }

    fn can_end(&self) -> bool {
        if self.wait_for_all_ {
            return self.task_map.borrow().is_empty();
        }

        self.initial_thread_group
            .as_ref()
            .unwrap()
            .borrow()
            .task_set()
            .is_empty()
    }

    fn handle_seccomp_traced_syscall(
        &self,
        t: &RecordTask,
        step_state: &mut StepState,
        result: &mut RecordResult,
        did_enter_syscall: &mut bool,
    ) {
        *did_enter_syscall = false;
        let syscallno = t.regs_ref().original_syscallno() as i32;
        if syscallno < 0 {
            // negative syscall numbers after a SECCOMP event
            // are treated as "skip this syscall". There will be one syscall event
            // reported instead of two. So fake an enter-syscall event now.
            // It doesn't really matter what the syscall-arch is.
            let arch = t.arch();
            t.canonicalize_regs(arch);
            if self.syscall_seccomp_ordering_.get()
                == PtraceSyscallSeccompOrdering::SeccompBeforeSyscall
            {
                // If the ptrace entry stop hasn't happened yet, we're at a weird
                // intermediate state where the behavior of the next PTRACE_SYSCALL
                // will depend on the register state (i.e. whether we see an entry
                // trap or proceed right to the exit trap). To make things easier
                // on the rest of the system, do a fake syscall entry, then reset
                // the register state.
                let orig_regs: Registers = t.regs_ref().clone();
                let mut r: Registers = orig_regs.clone();
                r.set_original_syscallno(syscall_number_for_gettid(arch) as isize);
                t.set_regs(&r);
                t.resume_execution(
                    ResumeRequest::ResumeSyscall,
                    WaitRequest::ResumeWait,
                    TicksRequest::ResumeNoTicks,
                    None,
                );
                t.set_regs(&orig_regs);
            }

            // Don't continue yet. At the next iteration of record_step, we'll
            // enter syscall_state_changed and that will trigger a continue to
            // the syscall exit.
            step_state.continue_type = ContinueType::DontContinue;
            if !self.process_syscall_entry(t, step_state, result, arch) {
                return;
            }

            *did_enter_syscall = true;
            return;
        }

        if self.syscall_seccomp_ordering_.get()
            == PtraceSyscallSeccompOrdering::SeccompBeforeSyscall
        {
            // The next continue needs to be a PTRACE_SYSCALL to observe
            // the enter-syscall event.
            step_state.continue_type = ContinueType::ContinueSyscall;
        } else {
            ed_assert_eq!(
                t,
                self.syscall_seccomp_ordering_.get(),
                PtraceSyscallSeccompOrdering::SyscallBeforeSeccomp
            );
            if t.ev().is_syscall_event()
                && t.ev().syscall_event().state == SyscallState::ProcessingSyscall
            {
                // We did PTRACE_SYSCALL and already saw a syscall trap. Just ignore this.
                log!(
                    LogDebug,
                    "Ignoring SECCOMP syscall trap since we already got a PTRACE_SYSCALL trap"
                );
                // The next continue needs to be a PTRACE_SYSCALL to observe
                // the exit-syscall event.
                step_state.continue_type = ContinueType::ContinueSyscall;
                // Need to restore last_task_switchable since it will have been
                // reset to Switchable::PreventSwitch
                self.last_task_switchable
                    .set(t.ev().syscall_event().switchable);
            } else {
                // We've already passed the PTRACE_SYSCALL trap for syscall entry, so
                // we need to handle that now.
                let syscall_arch: SupportedArch = t.detect_syscall_arch();
                t.canonicalize_regs(syscall_arch);
                if !self.process_syscall_entry(t, step_state, result, syscall_arch) {
                    step_state.continue_type = ContinueType::DontContinue;
                    return;
                }
                *did_enter_syscall = true;
            }
        }
    }
}

/// Get `t` into a state where resume_execution with a signal will actually work.
fn preinject_signal(t: &RecordTask) -> bool {
    let sig = Sig::try_from(t.ev().signal_event().siginfo.si_signo).unwrap();
    let desched_sig = t.session().as_record().unwrap().syscallbuf_desched_sig();

    // Signal injection is tricky. Per the ptrace(2) man page, injecting
    // a signal while the task is not in a signal-stop is not guaranteed to work
    // (and indeed, we see that the kernel sometimes ignores such signals).
    // But some signals must be delayed until after the signal-stop thatSome( notified
    // us of them.
    // So, first we check if we're in a signal-stop that we can use to inject
    // a signal. Some (all?) SIGTRAP stops are *not* usable for signal injection.
    if t.maybe_stop_sig().is_sig() && t.maybe_stop_sig() != sig::SIGTRAP {
        log!(LogDebug, "    in signal-stop for {}", t.maybe_stop_sig());
    } else {
        // We're not in a usable signal-stop. Force a signal-stop by sending
        // a new signal with tgkill (as the ptrace(2) man page recommends).
        log!(
            LogDebug,
            "    maybe not in signal-stop (status {}); doing tgkill(SYSCALLBUF_DESCHED_SIGNAL)",
            t.status()
        );

        // Always send SYSCALLBUF_DESCHED_SIGNAL because other signals (except
        // TIME_SLICE_SIGNAL) will be blocked by
        // RecordTask::will_resume_execution().
        t.tgkill(desched_sig);

        // Now singlestep the task until we're in a signal-stop for the signal
        // we've just sent. We must absorb and forget that signal here since we
        // don't want it delivered to the task for real.
        let old_ip = t.ip();
        loop {
            t.resume_execution(
                ResumeRequest::ResumeSinglestep,
                WaitRequest::ResumeWait,
                TicksRequest::ResumeNoTicks,
                None,
            );

            ed_assert_eq!(
                t,
                old_ip,
                t.ip(),
                "Singlestep actually advanced when we just expected a signal; was at {} now at {} with status {}",
                old_ip,
                t.ip(),
                t.status()
            );

            // Ignore any pending TIME_SLICE_SIGNALs and continue until we get our
            // SYSCALLBUF_DESCHED_SIGNAL.
            if t.maybe_stop_sig() != perf_counters::TIME_SLICE_SIGNAL {
                break;
            }
        }

        if t.status().maybe_ptrace_event() == PTRACE_EVENT_EXIT {
            // We raced with an exit (e.g. due to a pending SIGKILL)
            return false;
        }

        ed_assert_eq!(
            t,
            t.maybe_stop_sig(),
            desched_sig,
            "Expected SYSCALLBUF_DESCHED_SIGNAL, got {}",
            t.status()
        );

        // We're now in a signal-stop
    }

    // Now that we're in a signal-stop, we can inject our signal and advance
    // to the signal handler with one single-step.
    log!(LogDebug, "    injecting signal {}", sig);
    let si = t.ev().signal_event().siginfo;
    t.set_siginfo(&si);

    true
}

/// Returns true if the signal should be delivered.
/// Returns false if this signal should not be delivered because another signal
/// occurred during delivery.
/// Must call t->stashed_signal_processed() once we're ready to unmask signals.
fn inject_handled_signal(t: &RecordTask) -> bool {
    if !preinject_signal(t) {
        // Task prematurely exited.
        return false;
    }
    // If there aren't any more stashed signals, it's OK to stop blocking all
    // signals.
    t.stashed_signal_processed();
    let desched_sig = t.session().as_record().unwrap().syscallbuf_desched_sig();
    let sig = Sig::try_from(t.ev().signal_event().siginfo.si_signo).unwrap();
    loop {
        // We are ready to inject our signal.
        // XXX we assume the kernel won't respond by notifying us of a different
        // signal. We don't want to do this with signals blocked because that will
        // save a bogus signal mask in the signal frame.
        t.resume_execution(
            ResumeRequest::ResumeSinglestep,
            WaitRequest::ResumeWait,
            TicksRequest::ResumeNoTicks,
            Some(sig),
        );
        // Signal injection can change the sigmask due to sa_mask effects, lack of
        // SA_NODEFER, and signal frame construction triggering a synchronous
        // SIGSEGV.
        t.invalidate_sigmask();
        // Repeat injection if we got a desched signal. We observe in Linux 4.14.12
        // that we get SYSCALLBUF_DESCHED_SIGNAL here once in a while.

        if t.maybe_stop_sig() != desched_sig {
            break;
        }
    }

    if t.maybe_stop_sig() == sig::SIGSEGV {
        // Constructing the signal handler frame must have failed. The kernel will
        // kill the process after this. Stash the signal and make sure
        // we know to treat it as fatal when we inject it. Also disable the
        // signal handler to match what the kernel does.
        t.did_set_sig_handler_default(sig::SIGSEGV);
        t.stash_sig();
        t.thread_group().borrow_mut().received_sigframe_sigsegv = true;
        return false;
    }

    // We stepped into a user signal handler.
    ed_assert_eq!(
        t,
        t.maybe_stop_sig(),
        sig::SIGTRAP,
        "Got unexpected status {}",
        t.status()
    );
    ed_assert_eq!(
        t,
        t.get_signal_user_handler(sig),
        Some(t.ip()),
        "Expected handler IP {:?}, got {}; actual signal mask={} (cached {})",
        t.get_signal_user_handler(sig),
        t.ip(),
        t.read_sigmask_from_process(),
        t.get_sigmask(),
    );

    if t.signal_handler_takes_siginfo(sig) {
        // The kernel copied siginfo into userspace so it can pass a pointer to
        // the signal handler. Replace the contents of that siginfo with
        // the exact data we want to deliver. (We called Task::set_siginfo
        // above to set that data, but the kernel sanitizes the passed-in data
        // which wipes out certain fields; e.g. we can't set SI_KERNEL in si_code.)
        let mut siginfo = t.ev().signal_event().siginfo;
        setup_sigframe_siginfo(t, &mut siginfo);
        t.ev_mut().signal_event_mut().siginfo = siginfo;
    }

    // The kernel clears the FPU state on entering the signal handler, but prior
    // to 4.7 or thereabouts ptrace can still return stale values. Fix that here.
    // This also sets bit 0 of the XINUSE register to 1 to avoid issues where it
    // get set to 1 nondeterministically.
    let mut e = t.extra_regs_ref().clone();
    e.reset();
    t.set_extra_regs(&e);

    true
}

fn setup_sigframe_siginfo(t: &RecordTask, siginfo: &mut siginfo_t) {
    let arch = t.arch();
    rd_arch_function_selfless!(setup_sigframe_siginfo_arch, arch, t, siginfo)
}

fn setup_sigframe_siginfo_arch<Arch: Architecture>(t: &RecordTask, siginfo: &siginfo_t) {
    let dest: RemotePtr<arch_siginfo_t<Arch>>;
    match Arch::arch() {
        SupportedArch::X86 => {
            let sp = t.regs_ref().sp();
            let p = RemotePtr::<Arch::unsigned_word>::cast(sp) + 2usize;
            dest = RemotePtr::from(read_val_mem(t, p, None).try_into().unwrap());
        }
        SupportedArch::X64 => {
            dest = RemotePtr::new(t.regs_ref().si());
        }
    }
    let mut si: arch_siginfo_t<Arch> = read_val_mem(t, dest, None);
    set_arch_siginfo::<Arch>(siginfo, &mut si);
    write_val_mem(t, dest, &si, None);
}

pub fn set_arch_siginfo<Arch: Architecture>(siginfo: &siginfo_t, si: &mut arch_siginfo_t<Arch>) {
    unsafe { set_arch_siginfo_arch::<Arch>(siginfo, si) }
}

union UASiginfo {
    native_api: arch_siginfo_t<NativeArch>,
    linux_api: siginfo_t,
}

/// DIFF NOTE: Does not take the dest_size argument as in rr
unsafe fn set_arch_siginfo_arch<Arch: Architecture>(
    src: &siginfo_t,
    si: &mut arch_siginfo_t<Arch>,
) {
    // Copying this structure field-by-field instead of just memcpy'ing
    // siginfo into si serves two purposes: performs 64.32 conversion if
    // necessary, and ensures garbage in any holes in siginfo isn't copied to the
    // tracee.
    let mut u: UASiginfo = mem::zeroed();
    u.linux_api = *src;
    let siginfo = &mut u.native_api;

    si.si_signo = siginfo.si_signo;
    si.si_errno = siginfo.si_errno;
    si.si_code = siginfo.si_code;
    match siginfo.si_code {
        SI_USER | SI_TKILL => {
            si._sifields._kill.si_pid_ = siginfo._sifields._kill.si_pid_;
            si._sifields._kill.si_uid_ = siginfo._sifields._kill.si_uid_;
        }
        SI_QUEUE | SI_MESGQ => {
            si._sifields._rt.si_pid_ = siginfo._sifields._rt.si_pid_;
            si._sifields._rt.si_uid_ = siginfo._sifields._rt.si_uid_;
            assign_sigval::<Arch>(
                &mut si._sifields._rt.si_sigval_,
                &siginfo._sifields._rt.si_sigval_,
            );
        }
        SI_TIMER => {
            si._sifields._timer.si_overrun_ = siginfo._sifields._timer.si_overrun_;
            si._sifields._timer.si_tid_ = siginfo._sifields._timer.si_tid_;
            assign_sigval::<Arch>(
                &mut si._sifields._timer.si_sigval_,
                &siginfo._sifields._timer.si_sigval_,
            );
        }
        _ => match siginfo.si_signo {
            SIGCHLD => {
                si._sifields._sigchld.si_pid_ = siginfo._sifields._sigchld.si_pid_;
                si._sifields._sigchld.si_uid_ = siginfo._sifields._sigchld.si_uid_;
                si._sifields._sigchld.si_status_ = siginfo._sifields._sigchld.si_status_;
                si._sifields._sigchld.si_utime_ =
                    Arch::as_sigchld_clock_t_truncated(siginfo._sifields._sigchld.si_utime_ as i64);
                si._sifields._sigchld.si_stime_ =
                    Arch::as_sigchld_clock_t_truncated(siginfo._sifields._sigchld.si_stime_ as i64);
            }
            SIGILL | SIGBUS | SIGFPE | SIGSEGV | SIGTRAP => {
                si._sifields._sigfault.si_addr_ =
                    Arch::from_remote_ptr(siginfo._sifields._sigfault.si_addr_.rptr());
                si._sifields._sigfault.si_addr_lsb_ =
                    Arch::as_signed_short(siginfo._sifields._sigfault.si_addr_lsb_);
            }
            SIGIO => {
                si._sifields._sigpoll.si_band_ =
                    Arch::as_signed_long_truncated(siginfo._sifields._sigpoll.si_band_ as i64);
                si._sifields._sigpoll.si_fd_ = siginfo._sifields._sigpoll.si_fd_;
            }
            SIGSYS => {
                si._sifields._sigsys._call_addr =
                    Arch::from_remote_ptr(siginfo._sifields._sigsys._call_addr.rptr());
                si._sifields._sigsys._syscall = siginfo._sifields._sigsys._syscall;
                si._sifields._sigsys._arch = siginfo._sifields._sigsys._arch;
            }
            _ => (),
        },
    }
}

/// Copy the registers used for syscall arguments (not including
/// syscall number) from `from` to `to`.
fn copy_syscall_arg_regs(to: &mut Registers, from: &Registers) {
    to.set_arg1(from.arg1());
    to.set_arg2(from.arg2());
    to.set_arg3(from.arg3());
    to.set_arg4(from.arg4());
    to.set_arg5(from.arg5());
    to.set_arg6(from.arg6());
}

fn seccomp_trap_done(t: &RecordTask) {
    t.pop_seccomp_trap();

    // It's safe to reset the syscall buffer now.
    t.delay_syscallbuf_reset_for_seccomp_trap.set(false);

    let syscallbuf_child = t.syscallbuf_child.get();
    write_val_mem(
        t,
        syscallbuf_child.as_rptr_u8() + offset_of!(syscallbuf_hdr, failed_during_preparation),
        &1u8,
        None,
    );
    t.record_local_for(
        syscallbuf_child.as_rptr_u8() + offset_of!(syscallbuf_hdr, failed_during_preparation),
        &1u8,
    );

    if EventType::EvDesched == t.ev().event_type() {
        // Desched processing will do the rest for us
        return;
    }

    // Abort the current syscallbuf record, which corresponds to the syscall that
    // wasn't actually executed due to seccomp.
    write_val_mem(
        t,
        syscallbuf_child.as_rptr_u8() + offset_of!(syscallbuf_hdr, abort_commit),
        &1u8,
        None,
    );
    t.record_event(Some(Event::syscallbuf_abort_commit()), None, None, None);

    // In fact, we need to. Running the syscall exit hook will ensure we
    // reset the buffer before we try to buffer another a syscall.
    write_val_mem(
        t,
        syscallbuf_child.as_rptr_u8() + offset_of!(syscallbuf_hdr, notify_on_syscall_hook_exit),
        &1u8,
        None,
    );
}

/// After a SYS_sigreturn "exit" of task `t` with return value `ret`,
/// check to see if there's an interrupted syscall that /won't/ be
/// restarted, and if so, pop it off the pending event stack.
fn maybe_discard_syscall_interruption(t: &RecordTask, ret: isize) {
    let syscallno: i32;

    if EventType::EvSyscallInterruption != t.ev().event_type() {
        // We currently don't track syscalls interrupted with
        // ERESTARTSYS or ERESTARTNOHAND, so it's possible for
        // a sigreturn not to affect the event stack.
        log!(LogDebug, "  (no interrupted syscall to retire)");
        return;
    }

    syscallno = t.ev().syscall_event().number;
    if 0 > ret {
        syscall_not_restarted(t);
    } else {
        ed_assert_eq!(
            t,
            syscallno as isize,
            ret,
            "Interrupted call was {} and sigreturn claims to be restarting {}",
            t.ev().syscall_event().syscall_name(),
            syscall_name(ret.try_into().unwrap(), t.ev().syscall_event().arch())
        );
    }
}

fn save_interrupted_syscall_ret_in_syscallbuf(t: &RecordTask, retval: isize) {
    // Record storing the return value in the syscallbuf record, where
    // we expect to find it during replay.
    let child_rec = t.next_syscallbuf_record();
    let ret: i64 = retval as i64;
    t.record_local_for(
        RemotePtr::<i64>::cast(child_rec.as_rptr_u8() + offset_of!(syscallbuf_record, ret)),
        &ret,
    );
}

fn maybe_trigger_emulated_ptrace_syscall_exit_stop(t: &RecordTask) {
    if t.emulated_ptrace_cont_command.get() == PTRACE_SYSCALL {
        // We MUST have an emulated ptracer
        let _emulated_ptracer = t.emulated_ptracer_unwrap();
        t.emulate_ptrace_stop(WaitStatus::for_syscall(t), None, None);
    } else if t.emulated_ptrace_cont_command.get() == PTRACE_SINGLESTEP
        || t.emulated_ptrace_cont_command.get() == PTRACE_SYSEMU_SINGLESTEP
    {
        // We MUST have an emulated ptracer
        let _emulated_ptracer = t.emulated_ptracer_unwrap();
        // Deliver the singlestep trap now that we've finished executing the
        // syscall.
        t.emulate_ptrace_stop(
            WaitStatus::for_stop_sig(sig::SIGTRAP),
            None,
            Some(SI_KERNEL as i32),
        );
    }
}

fn debug_exec_state(msg: &str, t: &dyn Task) {
    log!(LogDebug, "{}: status={}", msg, t.status());
}

impl Deref for RecordSession {
    type Target = SessionInner;

    fn deref(&self) -> &Self::Target {
        &self.session_inner
    }
}

impl DerefMut for RecordSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session_inner
    }
}

impl Session for RecordSession {
    fn as_record(&self) -> Option<&RecordSession> {
        Some(self)
    }

    fn as_record_mut(&mut self) -> Option<&mut RecordSession> {
        Some(self)
    }

    /// Forwarded method
    fn kill_all_tasks(&self) {
        kill_all_tasks(self)
    }

    fn on_destroy_task(&self, t: &dyn Task) {
        self.scheduler().on_destroy_task(t.as_rec_unwrap())
    }

    fn as_session_inner(&self) -> &SessionInner {
        &self.session_inner
    }

    fn as_session_inner_mut(&mut self) -> &mut SessionInner {
        &mut self.session_inner
    }

    fn new_task(
        &self,
        tid: pid_t,
        _rec_tid: Option<pid_t>,
        serial: u32,
        a: SupportedArch,
        weak_self: TaskSharedWeakPtr,
    ) -> Box<dyn Task> {
        RecordTask::new(self, tid, serial, a, weak_self)
    }

    fn on_create_task(&self, t: TaskSharedPtr) {
        on_create_task_common(self, t.clone());
        self.scheduler().on_create_task(t);
    }

    fn trace_stream(&self) -> Option<Ref<'_, TraceStream>> {
        let r = self.trace_out.borrow();
        Some(Ref::map(r, |t| t.deref()))
    }

    fn trace_stream_mut(&self) -> Option<RefMut<'_, TraceStream>> {
        let r = self.trace_out.borrow_mut();
        Some(RefMut::map(r, |t| t.deref_mut()))
    }
}

fn check_perf_event_paranoid() {
    let fd = ScopedFd::open_path("/proc/sys/kernel/perf_event_paranoid", OFlag::O_RDONLY);
    if fd.is_open() {
        let mut buf = [0u8; 100];
        match read(fd.as_raw(), &mut buf) {
            Ok(0) => {
                clean_fatal!(
                    "Read 0 bytes from `/proc/sys/kernel/perf_event_paranoid`.\n\
                     Need to read non-zero number of bytes."
                );
            }
            Ok(siz) => {
                let int_str = String::from_utf8_lossy(&buf[0..siz]);
                let maybe_val = int_str.trim().parse::<isize>();
                match maybe_val {
                    Ok(val) if val > 1 => {
                        clean_fatal!("rd needs `/proc/sys/kernel/perf_event_paranoid` <= 1, but it is {}.\n\
                                      Change it to 1, or use 'rd record -n' (slow).\n\
                                      Consider putting 'kernel.perf_event_paranoid = 1' in /etc/sysctl.conf", val);
                    }
                    Err(e) => {
                        clean_fatal!(
                            "Error while parsing file `/proc/sys/kernel/perf_event_paranoid`: {:?}",
                            e
                        );
                    }
                    _ => (),
                }
            }
            Err(e) => {
                clean_fatal!(
                    "Error while reading file `/proc/sys/kernel/perf_event_paranoid`: {:?}",
                    e
                );
            }
        }
    } else {
        log!(
            LogError,
            "Could not open `/proc/sys/kernel/perf_event_paranoid`. Continuing anyway."
        );
    }
}

fn find_helper_library<T: AsRef<OsStr>>(basepath: T) -> Option<OsString> {
    for suffix in &["lib64/rd/", "lib/rd/"] {
        let mut lib_path = OsString::from(resource_path());
        lib_path.push(suffix);
        let mut file_name = OsString::from(lib_path.clone());
        file_name.push(basepath.as_ref());
        if access(file_name.as_bytes(), AccessFlags::F_OK).is_ok() {
            return Some(lib_path);
        }
    }
    // File does not exist. Assume install put it in LD_LIBRARY_PATH.
    None
}

#[derive(Clone, Debug, Default)]
struct ExeInfo {
    libasan_path: Option<OsString>,
    has_asan_symbols: bool,
}

fn read_exe_info<T: AsRef<OsStr>>(full_path: T) -> ExeInfo {
    let maybe_data = fs::read(full_path.as_ref());

    let data = match maybe_data {
        Err(e) => fatal!("Error while reading {:?}: {:?}", full_path.as_ref(), e),
        Ok(data) => data,
    };

    match Elf::parse(&data) {
        Err(e) => {
            log!(
                LogDebug,
                "Skipping trying to reading exe info as {:?} was not an elf file: {:?}",
                full_path.as_ref(),
                e
            );
            ExeInfo {
                libasan_path: None,
                has_asan_symbols: false,
            }
        }
        Ok(elf_obj) => match elf_obj.dynamic {
            Some(dyns) => {
                let mut maybe_libasan_path = None;
                let mut has_asan_init = false;
                for lib in dyns.get_libraries(&elf_obj.dynstrtab) {
                    // @TODO Is contains() OK?
                    if lib.contains("libasan") {
                        maybe_libasan_path = Some(OsString::from(lib));
                        break;
                    }
                }
                for s in elf_obj.dynsyms.iter() {
                    match elf_obj.dynstrtab.get(s.st_name) {
                        Some(name_res) => match name_res {
                            Ok(name) => {
                                if name == "__asan_init" {
                                    has_asan_init = true;
                                    break;
                                }
                            }
                            Err(_) => (),
                        },
                        None => {}
                    }
                }
                ExeInfo {
                    libasan_path: maybe_libasan_path,
                    has_asan_symbols: has_asan_init,
                }
            }
            None => ExeInfo {
                libasan_path: None,
                has_asan_symbols: false,
            },
        },
    }
}

fn lookup_by_path<T: AsRef<OsStr>>(file: T) -> OsString {
    let file_ostr = file.as_ref();
    if find(file_ostr.as_bytes(), b"/").is_some() {
        return file_ostr.to_owned();
    }
    match env::var_os("PATH") {
        Some(path) => {
            let path_vec = path.into_vec();
            let dirs = path_vec.split(|&c| c == b':');
            for dir in dirs {
                let mut full_path = Vec::<u8>::new();
                full_path.extend_from_slice(dir);
                full_path.push(b'/');
                full_path.extend_from_slice(file_ostr.as_bytes());

                match stat(full_path.as_slice()) {
                    Ok(st) if SFlag::from_bits_truncate(st.st_mode).contains(SFlag::S_IFREG) => {
                        if access(full_path.as_slice(), AccessFlags::X_OK).is_ok() {
                            return OsString::from_vec(full_path);
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                }
            }
            file_ostr.to_owned()
        }
        None => file_ostr.to_owned(),
    }
}

fn inject_ld_helper_library(env: &mut Vec<(OsString, OsString)>, name: &OsStr, val: Vec<u8>) {
    // Our preload lib should come first if possible, because that will speed up
    // the loading of the other libraries; it's also a good idea to put our audit
    // library at the head of the list, since there's only sixteen possible link
    // namespaces on glibc and each audit library uses up one.
    //
    // We supply a placeholder which is then mutated to the correct filename in
    // Monkeypatcher::patch_after_exec.
    let mut found = false;
    for (key, curr_value) in env.iter_mut() {
        if key == name {
            let mut new_value = Vec::new();
            new_value.extend_from_slice(&val);
            new_value.push(b':');
            new_value.extend_from_slice(curr_value.as_bytes());
            curr_value.clear();
            curr_value.push(OsStr::from_bytes(&new_value));
            found = true;
            break;
        }
    }

    if !found {
        env.push((OsString::from(name), OsString::from_vec(val)))
    }
}

pub union USiginfo {
    pub native_api: native_arch::siginfo_t,
    pub linux_api: siginfo_t,
}

fn handle_seccomp_errno(t: &RecordTask, step_state: &mut StepState, seccomp_data: u16) {
    let arch = t.detect_syscall_arch();
    t.canonicalize_regs(arch);

    let mut r: Registers = t.regs_ref().clone();
    let syscallno = r.original_syscallno() as i32;
    // Cause kernel processing to skip the syscall
    r.set_original_syscallno(SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO);
    t.set_regs(&r);

    if !t.is_in_untraced_syscall() {
        t.push_syscall_event(syscallno);
        // Note that the syscall failed. prepare_clone() needs to know
        // this during replay of the syscall entry.
        t.ev_mut().syscall_event_mut().failed_during_preparation = true;
        note_entering_syscall(t);
    }

    r.set_syscall_result_signed(-(seccomp_data as isize));
    t.set_regs(&r);
    // Don't continue yet. At the next iteration of record_step, if we
    // recorded the syscall-entry we'll enter syscall_state_changed and
    // that will trigger a continue to the syscall exit.
    step_state.continue_type = ContinueType::DontContinue;
}

fn handle_seccomp_trap(t: &RecordTask, step_state: &mut StepState, seccomp_data: u16) {
    // The architecture may be wrong, but that's ok, because an actual syscall
    // entry did happen, so the registers are already updated according to the
    // architecture of the system call.
    let arch = t.detect_syscall_arch();
    t.canonicalize_regs(arch);

    let mut r = t.regs_ref().clone();
    let syscallno = r.original_syscallno() as i32;
    // Cause kernel processing to skip the syscall
    r.set_original_syscallno(SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO);
    t.set_regs(&r);

    let mut syscall_entry_already_recorded = false;
    if t.ev().is_syscall_event() {
        // A syscall event was already pushed, probably because we did a
        // PTRACE_SYSCALL to enter the syscall during handle_desched_event. Cancel
        // that event now since the seccomp SIGSYS aborts it completely.
        ed_assert_eq!(t, t.ev().syscall_event().number, syscallno);
        // Make sure any prepared syscall state is discarded and any temporary
        // effects (e.g. redirecting pointers to scratch) undone.
        rec_abort_prepared_syscall(t);
        if t.ev().event_type() == EventType::EvSyscallInterruption {
            // The event could be a syscall-interruption if it was pushed by
            // `handle_desched_event`. In that case, it has not been recorded yet.
            t.pop_syscall_interruption();
        } else {
            t.pop_syscall();
            syscall_entry_already_recorded = true;
        }
    }

    if t.is_in_untraced_syscall() {
        ed_assert!(t, !t.delay_syscallbuf_reset_for_seccomp_trap.get());
        // Don't reset the syscallbuf immediately after delivering the trap. We have
        // to wait until this buffered syscall aborts completely before resetting
        // the buffer.
        t.delay_syscallbuf_reset_for_seccomp_trap.set(true);

        t.push_event(Event::seccomp_trap());

        // desched may be armed but we're not going to execute the syscall, let
        // alone block. If it fires, ignore it.
        let syscallbuf_child = t.syscallbuf_child.get();
        write_val_mem(
            t,
            RemotePtr::<u8>::cast(syscallbuf_child)
                + offset_of!(syscallbuf_hdr, desched_signal_may_be_relevant),
            &0u8,
            None,
        );
    }

    t.push_syscall_event(syscallno);
    t.ev_mut().syscall_event_mut().failed_during_preparation = true;
    note_entering_syscall(t);

    if t.is_in_untraced_syscall() && !syscall_entry_already_recorded {
        t.record_current_event();
    }

    // Use NativeArch here because different versions of system headers
    // have inconsistent field naming.
    let mut si: USiginfo = unsafe { mem::zeroed() };
    si.native_api.si_signo = SIGSYS;
    si.native_api.si_errno = seccomp_data as i32;
    si.native_api.si_code = SYS_SECCOMP as i32;
    match r.arch() {
        SupportedArch::X86 => si.native_api._sifields._sigsys._arch = AUDIT_ARCH_I386,
        SupportedArch::X64 => si.native_api._sifields._sigsys._arch = AUDIT_ARCH_X86_64,
    }
    si.native_api._sifields._sigsys._syscall = syscallno;
    // Documentation says that si_call_addr is the address of the syscall
    // instruction, but in tests it's immediately after the syscall
    // instruction.
    si.native_api._sifields._sigsys._call_addr =
        native_arch::ptr::<Void>::from_remote_ptr(t.ip().to_data_ptr::<Void>());
    log!(LogDebug, "Synthesizing {}", unsafe { si.linux_api });
    t.stash_synthetic_sig(
        unsafe { &si.linux_api },
        SignalDeterministic::DeterministicSig,
    );

    // Tests show that the current registers are preserved (on x86, eax/rax
    // retains the syscall number).
    r.set_syscallno(syscallno as isize);
    t.set_regs(&r);
    t.maybe_restore_original_syscall_registers();

    if t.is_in_untraced_syscall() {
        // For buffered syscalls, go ahead and record the exit state immediately.
        t.ev_mut().syscall_event_mut().state = SyscallState::ExitingSyscall;
        t.record_current_event();
        t.pop_syscall();

        // The tracee is currently in the seccomp ptrace-stop. Advance it to the
        // syscall-exit stop so that when we try to deliver the SIGSYS via
        // PTRACE_SINGLESTEP, that doesn't trigger a SIGTRAP stop.
        t.resume_execution(
            ResumeRequest::ResumeSyscall,
            WaitRequest::ResumeWait,
            TicksRequest::ResumeNoTicks,
            None,
        );
    }

    // Don't continue yet. At the next iteration of record_step, if we
    // recorded the syscall-entry we'll enter syscall_state_changed and
    // that will trigger a continue to the syscall exit. If we recorded the
    // syscall-exit we'll go straight into signal delivery.
    step_state.continue_type = ContinueType::DontContinue;
}

fn note_entering_syscall(t: &RecordTask) {
    ed_assert_eq!(t, EventType::EvSyscall, t.ev().event_type());
    t.ev_mut().syscall_event_mut().state = SyscallState::EnteringSyscall;
    if !t.ev().syscall_event().is_restart {
        // Save a copy of the arg registers so that we
        // can use them to detect later restarted
        // syscalls, if this syscall ends up being
        // restarted.  We have to save the registers
        // in this rather awkward place because we
        // need the original registers; the restart
        // (if it's not a SYS_restart_syscall restart)
        // will use the original registers.
        let regs = t.regs_ref().clone();
        t.ev_mut().syscall_event_mut().regs = regs;
    }
}

fn rec_abort_prepared_syscall(t: &RecordTask) {
    let shared_ptr = t.syscall_state.clone();
    shared_ptr.borrow_mut().as_mut().map(|state| {
        state.abort_syscall_results(t);
    });
    *t.syscall_state.borrow_mut() = None;
}

/// Return true if we handle a ptrace exit event for task t. When this returns
/// true, t has been deleted and cannot be referenced again.
fn handle_ptrace_exit_event(t: &RecordTask) -> bool {
    if t.maybe_ptrace_event() != PTRACE_EVENT_EXIT {
        return false;
    }

    if t.stable_exit.get() {
        log!(LogDebug, "stable exit");
    } else {
        if !t.may_be_blocked() {
            // might have been hit by a SIGKILL or a SECCOMP_RET_KILL, in which case
            // there might be some execution since its last recorded event that we
            // need to replay.
            // There's a weird case (in 4.13.5-200.fc26.x86_64 at least) where the
            // task can enter the kernel but instead of receiving a syscall ptrace
            // event, we receive a PTRACE_EXIT_EVENT due to a concurrent execve
            // (and probably a concurrent SIGKILL could do the same). The task state
            // has been updated to reflect syscall entry. If we record a SCHED in
            // that state replay of the SCHED will fail. So detect that state and fix
            // it up.
            if t.regs_ref().original_syscallno() >= 0
                && t.regs_ref().syscall_result_signed() == -ENOSYS as isize
            {
                // Either we're in a syscall, or we're immediately after a syscall
                // and it exited with ENOSYS.
                if t.ticks_at_last_recorded_syscall_exit.get() == t.tick_count() {
                    log!(LogDebug, "Nothing to record after PTRACE_EVENT_EXIT");
                // It's the latter case; do nothing.
                } else {
                    // It's the former case ... probably. Theoretically we could have
                    // re-executed a syscall without any ticks in between, but that seems
                    // highly improbable.
                    // Record the syscall-entry event that we otherwise failed to record.
                    let arch = t.arch();
                    t.canonicalize_regs(arch);
                    // Assume it's a native-arch syscall. If it isn't, it doesn't matter
                    // all that much since we aren't actually going to do anything with it
                    // in this task.
                    // Avoid calling detect_syscall_arch here since it could fail if the
                    // task is already completely dead and gone.
                    let mut event = Event::new_syscall_event(SyscallEventData::new(
                        t.regs_ref().original_syscallno() as i32,
                        t.arch(),
                    ));
                    event.syscall_event_mut().state = SyscallState::EnteringSyscall;
                    t.record_event(Some(event), None, None, None);
                }
            } else {
                // Don't try to reset the syscallbuf here. The task may be exiting
                // while in arbitrary syscallbuf code. And of course, because it's
                // exiting, it doesn't matter if we don't reset the syscallbuf.
                // XXX flushing the syscallbuf may be risky too...
                t.record_event(
                    Some(Event::sched()),
                    Some(FlushSyscallbuf::FlushSyscallbuf),
                    Some(AllowSyscallbufReset::DontResetSyscallbuf),
                    None,
                );
            }
        }
        log!(
            LogWarn,
            "unstable exit; may misrecord CLONE_CHILD_CLEARTID memory race"
        );
        t.thread_group().borrow().destabilize();
    }

    record_robust_futex_changes(t);

    let exit_status: WaitStatus;
    let mut msg: usize = 0;
    // We can get ESRCH here if the child was killed by SIGKILL and
    // we made a synthetic PTRACE_EVENT_EXIT to handle it.
    if t.ptrace_if_alive(
        PTRACE_GETEVENTMSG,
        RemotePtr::null(),
        &mut PtraceData::WriteInto(u8_slice_mut(&mut msg)),
    ) {
        exit_status = WaitStatus::new(msg as i32);
    } else {
        exit_status = WaitStatus::for_fatal_sig(sig::SIGKILL);
    }

    record_exit(t, exit_status);
    // Delete t. t's destructor writes the final EV_EXIT.
    t.destroy(None);

    true
}

fn record_robust_futex_changes(t: &RecordTask) {
    rd_arch_function_selfless!(record_robust_futex_changes_arch, t.arch(), t);
}

/// Any user-space writes performed by robust futex handling are captured here.
/// They must be emulated during replay; the kernel will not do it for us
/// during replay because the TID value in each futex is the recorded
/// TID, not the actual TID of the dying task.
fn record_robust_futex_changes_arch<Arch: Architecture>(t: &RecordTask) {
    if t.did_record_robust_futex_changes.get() {
        return;
    }
    t.did_record_robust_futex_changes.set(true);

    let head_ptr = RemotePtr::<robust_list_head<Arch>>::cast(t.robust_list());
    if head_ptr.is_null() {
        return;
    }

    ed_assert_eq!(t, t.robust_list_len(), size_of::<robust_list_head<Arch>>());
    let mut ok = true;
    let head = read_val_mem(t, head_ptr, Some(&mut ok));
    if !ok {
        return;
    }
    record_robust_futex_change::<Arch>(t, head, mask_low_bit(Arch::as_rptr(head.list_op_pending)));

    let mut current = mask_low_bit(Arch::as_rptr(head.list.next));
    loop {
        if current.as_usize() == head_ptr.as_usize() {
            break;
        }
        record_robust_futex_change::<Arch>(t, head, current);
        let next = read_val_mem(t, current, Some(&mut ok));
        if !ok {
            return;
        }
        current = mask_low_bit(Arch::as_rptr(next.next));
    }
}

fn record_robust_futex_change<Arch: Architecture>(
    t: &RecordTask,
    head: robust_list_head<Arch>,
    base: RemotePtr<robust_list<Arch>>,
) {
    if base.is_null() {
        return;
    }
    let futex_void_ptr: RemotePtr<Void> =
        RemotePtr::<Void>::cast(base) + Arch::long_as_isize(head.futex_offset);
    let futex_ptr = RemotePtr::<u32>::cast(futex_void_ptr);
    // We can't just record the current futex value because at this point
    // in task exit the robust futex handling has not happened yet. So we have
    // to emulate what the kernel will do!
    let mut ok = true;
    let mut val: u32 = read_val_mem(t, futex_ptr, Some(&mut ok));
    if !ok {
        return;
    }
    if val & FUTEX_TID_MASK != t.own_namespace_rec_tid.get() as u32 {
        return;
    }
    val = (val & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    // Update memory now so that the kernel doesn't decide to do it later, at
    // a time that might race with other tracee execution.
    write_val_mem(t, futex_ptr, &val, None);
    t.record_local_for(futex_ptr, &val);
}

fn mask_low_bit<T>(p: RemotePtr<T>) -> RemotePtr<T> {
    RemotePtr::from(p.as_usize() & !1usize)
}

/// "Thaw" a frozen interrupted syscall if `t` is restarting it.
/// Return true if a syscall is indeed restarted.
///
/// A postcondition of this function is that `t.ev()` is no longer a
/// syscall interruption, whether or whether not a syscall was
/// restarted.
fn maybe_restart_syscall(t: &RecordTask) -> bool {
    let arch = t.arch();
    if is_restart_syscall_syscall(t.regs_ref().original_syscallno() as i32, arch) {
        log!(
            LogDebug,
            "  {}: SYS_restart_syscall'ing {}",
            t.tid(),
            t.ev()
        );
    }

    if t.is_syscall_restart() {
        t.ev_mut().transform(EventType::EvSyscall);
        let mut regs = t.regs_ref().clone();
        regs.set_original_syscallno(t.ev().syscall_event().regs.original_syscallno());
        t.set_regs(&regs);
        t.canonicalize_regs(arch);
        return true;
    }

    if EventType::EvSyscallInterruption == t.ev().event_type() {
        syscall_not_restarted(t);
    }

    false
}

fn syscall_not_restarted(t: &RecordTask) {
    log!(
        LogDebug,
        "  {}: popping abandoned interrupted {}; pending events:",
        t.tid(),
        t.ev()
    );

    if is_logging!(LogDebug) {
        t.log_pending_events();
    }

    t.pop_syscall_interruption();
}

fn is_in_privileged_syscall(t: &RecordTask) -> bool {
    let maybe_syscall_type = AddressSpace::rd_page_syscall_from_exit_point(t.ip());
    match maybe_syscall_type {
        Some(syscall_type) if syscall_type.privileged == Privileged::Privileged => true,
        _ => false,
    }
}

fn record_exit(t: &RecordTask, exit_status: WaitStatus) {
    t.session()
        .as_record()
        .unwrap()
        .trace_writer_mut()
        .write_task_event(&TraceTaskEvent::for_exit(t.tid(), exit_status));

    if t.thread_group().borrow().tgid == t.tid() {
        t.thread_group().borrow_mut().exit_status = exit_status;
    }
}

/// Step `t` forward until the tracee syscall that disarms the desched
/// event. If a signal becomes pending in the interim, we stash it.
/// This allows the caller to deliver the signal after this returns.
/// (In reality the desched event will already have been disarmed before we
/// enter this function.)
fn advance_to_disarm_desched_syscall(t: &RecordTask) {
    let mut old_maybe_sig = MaybeStopSignal::new_sig(0);
    let desched_sig =
        MaybeStopSignal::new(t.session().as_record().unwrap().syscallbuf_desched_sig());

    log!(LogDebug, "desched: DISARMING_DESCHED_EVENT");
    // TODO: send this through main loop.
    // TODO: mask off signals and avoid this loop.
    loop {
        t.resume_execution(
            ResumeRequest::ResumeSyscall,
            WaitRequest::ResumeWait,
            TicksRequest::ResumeUnlimitedTicks,
            None,
        );

        // We can safely ignore TIME_SLICE_SIGNAL while trying to
        // reach the disarm-desched ioctl: once we reach it,
        // the desched'd syscall will be "done" and the tracee
        // will be at a preemption point.  In fact, we *want*
        // to ignore this signal.  Syscalls like read() can
        // have large buffers passed to them, and we have to
        // copy-out the buffered out data to the user's
        // buffer.  This happens in the interval where we're
        // reaching the disarm-desched ioctl, so that code is
        // susceptible to receiving TIME_SLICE_SIGNAL. */
        let maybe_sig = t.maybe_stop_sig();
        if MaybeStopSignal::new(perf_counters::TIME_SLICE_SIGNAL) == maybe_sig {
            continue;
        }

        // We should not receive SYSCALLBUF_DESCHED_SIGNAL since it should already
        // have been disarmed. However, we observe these being received here when
        // we arm the desched signal before we restart a blocking syscall, which
        // completes successfully, then we disarm, then we see a desched signal
        // here.
        if desched_sig == maybe_sig {
            continue;
        }

        if maybe_sig.is_sig() && maybe_sig == old_maybe_sig {
            log!(LogDebug, "  coalescing pending {}", maybe_sig);
            continue;
        }

        if maybe_sig.is_sig() {
            log!(LogDebug, "  {} now pending", maybe_sig);
            t.stash_sig();
        }

        // DIFF NOTE: @TODO Not sure about this
        old_maybe_sig = maybe_sig;

        if t.is_disarm_desched_event_syscall() {
            break;
        }
    }

    // Exit the syscall.
    t.resume_execution(
        ResumeRequest::ResumeSyscall,
        WaitRequest::ResumeWait,
        TicksRequest::ResumeNoTicks,
        None,
    );
}

unsafe fn assign_sigval<Arch: Architecture>(
    to: &mut arch_structs::sigval_t<Arch>,
    from: &arch_structs::sigval_t<NativeArch>,
) {
    // si_ptr/si_int are a union and we don't know which part is valid.
    // The only case where it matters is when we're mapping 64->32, in which
    // case we can just assign the ptr first (which is bigger) and then the
    // int (to be endian-independent).
    to.sival_ptr = Arch::from_remote_ptr(from.sival_ptr.rptr());
    to.sival_int = from.sival_int;
}
