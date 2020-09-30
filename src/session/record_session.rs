use super::{
    address_space::{address_space::AddressSpace, Privileged},
    on_create_task_common,
    session_common::kill_all_tasks,
    session_inner::PtraceSyscallSeccompOrdering,
    task::{
        record_task::{AllowSyscallbufReset, EmulatedStopType, FlushSyscallbuf, RecordTask},
        task_common::write_val_mem,
        task_inner::{ResumeRequest, SaveTraceeFdNumber, TaskInner, TicksRequest, WaitRequest},
    },
    SessionSharedPtr,
};
use crate::{
    bindings::{
        audit::{AUDIT_ARCH_I386, AUDIT_ARCH_X86_64},
        ptrace::{
            PTRACE_EVENT_EXIT,
            PTRACE_SINGLESTEP,
            PTRACE_SYSCALL,
            PTRACE_SYSEMU,
            PTRACE_SYSEMU_SINGLESTEP,
        },
        signal::siginfo_t,
    },
    commands::record_command::RecordCommand,
    event::{Event, EventType, SignalDeterministic, Switchable, SyscallEventData, SyscallState},
    file_monitor::virtual_perf_counter_monitor::VirtualPerfCounterMonitor,
    flags::Flags,
    kernel_abi::{
        is_at_syscall_instruction,
        is_exit_group_syscall,
        is_pause_syscall,
        is_rdcall_notify_syscall_hook_exit_syscall,
        is_restart_syscall_syscall,
        is_write_syscall,
        native_arch,
        SupportedArch,
    },
    kernel_metadata::{is_sigreturn, syscall_name},
    kernel_supplement::SYS_SECCOMP,
    log::{LogDebug, LogError, LogWarn},
    perf_counters::{self, TicksSemantics},
    preload_interface::{
        syscallbuf_hdr,
        SYSCALLBUF_ENABLED_ENV_VAR,
        SYSCALLBUF_LIB_FILENAME,
        SYSCALLBUF_LIB_FILENAME_PADDED,
    },
    record_signal::{arm_desched_event, disarm_desched_event, handle_syscallbuf_breakpoint},
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
    taskish_uid::TaskUid,
    thread_group::ThreadGroupSharedPtr,
    ticks::Ticks,
    trace::{
        trace_stream::TraceStream,
        trace_writer::{CloseStatus, TraceWriter},
    },
    util::{
        choose_cpu,
        find,
        good_random,
        resource_path,
        signal_bit,
        CPUIDData,
        CPUID_GETEXTENDEDFEATURES,
        CPUID_GETFEATURES,
        CPUID_GETXSAVE,
    },
    wait_status::WaitStatus,
};
use goblin::elf::Elf;
use libc::{pid_t, SIGSYS, S_IFREG};
use nix::{
    fcntl::{open, OFlag},
    sys::stat::{stat, Mode},
    unistd::{access, read, AccessFlags},
};
use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    cmp::max,
    env,
    ffi::{OsStr, OsString},
    fs,
    mem,
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
    scheduler_: RefCell<Scheduler>,
    initial_thread_group: Option<ThreadGroupSharedPtr>,
    seccomp_filter_rewriter_: SeccompFilterRewriter,
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
        unimplemented!()
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
            scheduler_: RefCell::new(sched),
            initial_thread_group: Default::default(),
            seccomp_filter_rewriter_: SeccompFilterRewriter,
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

        rs.scheduler_mut().set_session_weak_ptr(weak_self);

        if flags.chaos {
            rs.scheduler_mut().set_enable_chaos(flags.chaos);
        }

        match flags.num_cores {
            Some(num_cores) => {
                // Set the number of cores reported, possibly overriding the chaos mode
                // setting.
                rs.scheduler_mut().set_num_cores(num_cores);
            }
            // This is necessary for the default case
            None => rs.scheduler_mut().regenerate_affinity_mask(),
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
                .initial_thread_group = Some(t.borrow().thread_group_shr_ptr());
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
            env.push(("QT_NO_CPU_FEATURE".into(), "rdrand rdseed rtm".into()));
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

        let maybe_prev_task = self.scheduler().current().cloned();
        let rescheduled = self
            .scheduler_mut()
            .reschedule(self.last_task_switchable.get());
        if rescheduled.interrupted_by_signal {
            // The scheduler was waiting for some task to become active, but was
            // interrupted by a signal. Yield to our caller now to give the caller
            // a chance to do something triggered by the signal
            // (e.g. terminate the recording).
            return result;
        }

        // @TODO This assumes that unwrap() will always succeed
        let mut t = self.scheduler().current().cloned().unwrap();
        match maybe_prev_task {
            Some(prev_task)
                if prev_task
                    .borrow()
                    .as_record_task()
                    .unwrap()
                    .ev()
                    .event_type()
                    == EventType::EvSched =>
            {
                if !Rc::ptr_eq(&prev_task, &t) {
                    // We did do a context switch, so record the SCHED event. Otherwise
                    // we'll just discard it.
                    prev_task
                        .borrow_mut()
                        .as_record_task_mut()
                        .unwrap()
                        .record_current_event();
                }

                prev_task
                    .borrow_mut()
                    .as_record_task_mut()
                    .unwrap()
                    .pop_event(EventType::EvSched);
            }
            _ => (),
        }

        if rescheduled.started_new_timeslice {
            let regs = t.borrow().regs_ref().clone();
            t.borrow_mut()
                .as_record_task_mut()
                .unwrap()
                .registers_at_start_of_last_timeslice = regs;
            t.borrow_mut()
                .as_record_task_mut()
                .unwrap()
                .time_at_start_of_last_timeslice = self.trace_writer().time();
        }

        // Have to disable context-switching until we know it's safe
        // to allow switching the context.
        self.last_task_switchable.set(Switchable::PreventSwitch);

        log!(
            LogDebug,
            "trace time {}: Active task is {}. Events:",
            t.borrow().trace_time(),
            t.borrow().tid
        );

        if is_logging!(LogDebug) {
            t.borrow().log_pending_events();
        }

        if handle_ptrace_exit_event(&t) {
            // t is dead and has been deleted.
            return result;
        }

        if t.borrow().unstable.get() {
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
                && t.borrow().as_record_task().unwrap().ev().event_type() == EventType::EvSyscall
            {
                self.syscall_state_changed(t.borrow_mut().as_rec_mut_unwrap(), &mut step_state);
            }
        } else if rescheduled.by_waitpid && self.handle_signal_event(&t, &mut step_state) {
        } else {
            self.runnable_state_changed(&t, &mut step_state, &mut result, rescheduled.by_waitpid);

            if result != RecordResult::StepContinue
                || step_state.continue_type == ContinueType::DontContinue
            {
                return result;
            }

            match t.borrow().as_record_task().unwrap().ev().event_type() {
                EventType::EvDesched => {
                    self.desched_state_changed(t.borrow().as_rec_unwrap());
                }
                EventType::EvSyscall => {
                    self.syscall_state_changed(t.borrow_mut().as_rec_mut_unwrap(), &mut step_state);
                }
                EventType::EvSignal | EventType::EvSignalDelivery => {
                    self.signal_state_changed(&t, &mut step_state);
                }
                _ => (),
            }
        }

        t.borrow_mut().as_rec_mut_unwrap().verify_signal_states();

        // We try to inject a signal if there's one pending; otherwise we continue
        // task execution.
        if !self.prepare_to_inject_signal(&t, &mut step_state)
            && step_state.continue_type != ContinueType::DontContinue
        {
            // Ensure that we aren't allowing switches away from a running task.
            // Only tasks blocked in a syscall can be switched away from, otherwise
            // we have races.
            ed_assert!(
                &t.borrow(),
                self.last_task_switchable.get() == Switchable::PreventSwitch
                    || t.borrow().unstable.get()
                    || t.borrow().as_record_task().unwrap().may_be_blocked()
            );

            debug_exec_state("EXEC_START", t.borrow().as_ref());

            self.task_continue(step_state);
        }

        return result;
    }

    fn handle_signal_event(&self, t: &TaskSharedPtr, _step_state: &mut StepState) -> bool {
        let maybe_sig = t.borrow().maybe_stop_sig();
        if !maybe_sig.is_sig() {
            return false;
        }

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
            t.borrow_mut().as_rec_mut_unwrap().invalidate_sigmask();
            // No events to be recorded, so no syscallbuf updates
            // needed.
            return true;
        }

        if maybe_sig == sig::SIGTRAP
            && handle_syscallbuf_breakpoint(t.borrow_mut().as_rec_mut_unwrap())
        {
            return true;
        }

        unimplemented!()
    }

    fn handle_ptrace_event(
        &self,
        t: &mut TaskSharedPtr,
        step_state: &mut StepState,
        _result: &RecordResult,
        did_enter_syscall: &mut bool,
    ) -> bool {
        *did_enter_syscall = false;

        if t.borrow().status().maybe_group_stop_sig().is_sig()
            || t.borrow().as_rec_unwrap().has_stashed_group_stop()
        {
            t.borrow_mut()
                .as_rec_mut_unwrap()
                .clear_stashed_group_stop();
            self.last_task_switchable.set(Switchable::AllowSwitch);
            step_state.continue_type = ContinueType::DontContinue;
            return true;
        }

        if !t.borrow().maybe_ptrace_event().is_ptrace_event() {
            return false;
        }

        unimplemented!()
    }

    fn runnable_state_changed(
        &self,
        t: &TaskSharedPtr,
        step_state: &mut StepState,
        step_result: &mut RecordResult,
        can_consume_wait_status: bool,
    ) {
        let event_type = t.borrow().as_rec_unwrap().ev().event_type();
        match event_type {
            EventType::EvNoop => {
                t.borrow_mut().as_rec_mut_unwrap().pop_noop();
                return;
            }
            EventType::EvInstructionTrap => {
                t.borrow_mut().as_rec_mut_unwrap().record_current_event();
                t.borrow_mut().as_rec_mut_unwrap().pop_event(event_type);
                return;
            }
            EventType::EvSentinel
            | EventType::EvSignalHandler
            | EventType::EvSyscallInterruption => {
                if !can_consume_wait_status {
                    return;
                }

                let syscall_arch = t.borrow_mut().detect_syscall_arch();
                t.borrow_mut().canonicalize_regs(syscall_arch);
                self.process_syscall_entry(t, step_state, step_result, syscall_arch);
                return;
            }

            _ => (),
        }
    }

    /// |t| is at a desched event and some relevant aspect of its state
    /// changed.  (For now, changes except the original desched'd syscall
    /// being restarted.)
    fn desched_state_changed(&self, _t: &RecordTask) {
        unimplemented!()
    }

    fn signal_state_changed(&self, _t: &TaskSharedPtr, _step_state: &mut StepState) {
        unimplemented!()
    }

    fn syscall_state_changed(&self, t: &mut RecordTask, step_state: &mut StepState) {
        match t.ev().syscall().state {
            SyscallState::EnteringSyscallPtrace => {
                debug_exec_state("EXEC_SYSCALL_ENTRY_PTRACE", t);
                step_state.continue_type = ContinueType::DontContinue;
                self.last_task_switchable.set(Switchable::AllowSwitch);
                if t.emulated_stop_type != EmulatedStopType::NotStopped {
                    // Don't go any further.
                    return;
                }
                if t.ev().syscall().in_sysemu {
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
                t.ev_mut().syscall_mut().regs = t.regs_ref().clone();
                t.ev_mut().syscall_mut().state = SyscallState::EnteringSyscall;
                // The syscallno may have been changed by the ptracer
                t.ev_mut().syscall_mut().number = t.regs_ref().original_syscallno() as i32;
                return;
            }
            SyscallState::EnteringSyscall => {
                debug_exec_state("EXEC_SYSCALL_ENTRY", t);
                ed_assert!(t, !t.emulated_stop_pending);

                self.last_task_switchable.set(rec_prepare_syscall(t));
                t.ev_mut().syscall_mut().switchable = self.last_task_switchable.get();
                let regs = t.ev().syscall().regs.clone();
                let event = t.ev().clone();
                t.record_event(
                    Some(event),
                    Some(FlushSyscallbuf::FlushSyscallbuf),
                    Some(AllowSyscallbufReset::AllowResetSyscallbuf),
                    Some(&regs),
                );

                debug_exec_state("after cont", t);
                t.ev_mut().syscall_mut().state = SyscallState::ProcessingSyscall;

                if t.emulated_stop_pending {
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

                return;
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

                t.ev_mut().syscall_mut().state = SyscallState::ExitingSyscall;
                step_state.continue_type = ContinueType::DontContinue;
                return;
            }
            SyscallState::ExitingSyscall => {
                debug_exec_state("EXEC_SYSCALL_DONE", t);

                debug_assert!(!t.maybe_stop_sig().is_sig());

                let syscall_arch = t.ev().syscall().arch();
                let syscallno = t.ev().syscall().number;
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

                    maybe_discard_syscall_interruption(t, retval as i32);

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
                        "  original_syscallno:{} ({}); return val:{:#x}",
                        t.regs_ref().original_syscallno(),
                        syscall_name(syscallno, syscall_arch),
                        t.regs_ref().syscall_result()
                    );

                    // a syscall_restart ending is equivalent to the
                    // restarted syscall ending
                    if t.ev().syscall().is_restart {
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
                        copy_syscall_arg_regs(&mut r, &t.ev().syscall().regs);
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
                        t.ev_mut().syscall_mut().is_restart = true;
                    }

                    t.canonicalize_regs(syscall_arch);
                }

                self.last_task_switchable.set(Switchable::AllowSwitch);
                step_state.continue_type = ContinueType::DontContinue;

                if !is_in_privileged_syscall(t) {
                    maybe_trigger_emulated_ptrace_syscall_exit_stop(t);
                }
                return;
            }

            _ => fatal!("Unknown exec state {}", t.ev().syscall().state),
        }
    }

    fn prepare_to_inject_signal(&self, _t: &TaskSharedPtr, step_state: &mut StepState) -> bool {
        if !self.done_initial_exec() || step_state.continue_type != ContinueType::Continue {
            return false;
        }

        unimplemented!()
    }

    fn task_continue(&self, step_state: StepState) {
        let t = self.scheduler().current().unwrap().clone();

        ed_assert!(
            &t.borrow(),
            step_state.continue_type != ContinueType::DontContinue
        );
        // A task in an emulated ptrace-stop must really stay stopped
        ed_assert!(
            &t.borrow(),
            !t.borrow().as_rec_unwrap().emulated_stop_pending
        );

        let may_restart = t.borrow().as_rec_unwrap().at_may_restart_syscall();

        if may_restart && t.borrow().seccomp_bpf_enabled {
            log!(
                LogDebug,
                "  PTRACE_SYSCALL to possibly-restarted {}",
                t.borrow().as_rec_unwrap().ev()
            );
        }

        if t.borrow().vm().first_run_event() == 0 {
            let time = self.trace_writer().time();
            t.borrow().vm().set_first_run_event(time);
        }

        let mut ticks_request: TicksRequest;
        let resume: ResumeRequest;
        if step_state.continue_type == ContinueType::ContinueSyscall {
            ticks_request = TicksRequest::ResumeNoTicks;
            resume = ResumeRequest::ResumeSyscall;
        } else {
            if t.borrow()
                .as_rec_unwrap()
                .has_stashed_sig(perf_counters::TIME_SLICE_SIGNAL)
            {
                // timeslice signal already stashed, no point in generating another one
                // (and potentially slow)
                ticks_request = TicksRequest::ResumeUnlimitedTicks;
            } else {
                let num_ticks_request = max(
                    0,
                    self.scheduler().current_timeslice_end() - t.borrow().tick_count(),
                );
                debug_assert!(num_ticks_request > 0);
                ticks_request = TicksRequest::ResumeWithTicksRequest(num_ticks_request);
            }

            // Clear any lingering state, then see if we need to stop earlier for a
            // tracee-requested pmc interrupt on the virtualized performance counter.
            t.borrow_mut()
                .as_rec_mut_unwrap()
                .next_pmc_interrupt_is_for_user = false;
            let maybe_vpmc =
                VirtualPerfCounterMonitor::interrupting_virtual_pmc_for_task(t.borrow().as_ref());

            match maybe_vpmc {
                Some(vpmc) => {
                    ed_assert!(
                        &t.borrow(),
                        vpmc.borrow()
                            .as_virtual_perf_counter_monitor()
                            .unwrap()
                            .target_tuid()
                            == t.borrow().tuid()
                    );

                    let after: Ticks = max(
                        vpmc.borrow()
                            .as_virtual_perf_counter_monitor()
                            .unwrap()
                            .target_ticks()
                            - t.borrow().tick_count(),
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
                            t.borrow_mut()
                                .as_rec_mut_unwrap()
                                .next_pmc_interrupt_is_for_user = true;
                        }
                        _ => (),
                    }
                }
                None => (),
            }

            let mut singlestep = t.borrow().as_rec_unwrap().emulated_ptrace_cont_command
                == PTRACE_SINGLESTEP
                || t.borrow().as_rec_unwrap().emulated_ptrace_cont_command
                    == PTRACE_SYSEMU_SINGLESTEP;

            if singlestep && is_at_syscall_instruction(t.borrow_mut().as_mut(), t.borrow().ip()) {
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
                if !t.borrow().seccomp_bpf_enabled
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

        t.borrow_mut().resume_execution(
            resume,
            WaitRequest::ResumeNonblocking,
            ticks_request,
            None,
        );
    }

    /// Returns false if the task exits during processing
    fn process_syscall_entry(
        &self,
        ts: &TaskSharedPtr,
        step_state: &mut StepState,
        step_result: &mut RecordResult,
        syscall_arch: SupportedArch,
    ) -> bool {
        let mut tb = ts.borrow_mut();
        let t: &mut RecordTask = tb.as_rec_mut_unwrap();
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
                *si
            );
        }

        // We just entered a syscall.
        if !maybe_restart_syscall(t) {
            // Emit FLUSH_SYSCALLBUF if necessary before we do any patching work
            t.maybe_flush_syscallbuf();

            if self.syscall_seccomp_ordering_.get()
                == PtraceSyscallSeccompOrdering::SyscallBeforeSeccompUnknown
                && t.seccomp_bpf_enabled
            {
                // We received a PTRACE_SYSCALL notification before the seccomp
                // notification. Ignore it and continue to the seccomp notification.
                self.syscall_seccomp_ordering_
                    .set(PtraceSyscallSeccompOrdering::SyscallBeforeSeccomp);
                step_state.continue_type = ContinueType::Continue;
                return true;
            }

            if t.vm().monkeypatcher().unwrap().try_patch_syscall(t) {
                // Syscall was patched. Emit event and continue execution.
                t.record_event(Some(Event::patch_syscall()), None, None, None);
                return true;
            }

            if t.maybe_ptrace_event() == PTRACE_EVENT_EXIT {
                // task exited while we were trying to patch it.
                // Make sure that this exit event gets processed
                step_state.continue_type = ContinueType::DontContinue;
                return false;
            }

            t.push_event(Event::new_syscall_event(SyscallEventData::new(
                t.regs_ref().original_syscallno() as i32,
                syscall_arch,
            )));
        }

        self.check_initial_task_syscalls(t, step_result);
        note_entering_syscall(t);
        if t.emulated_ptrace_cont_command == PTRACE_SYSCALL
            || t.emulated_ptrace_cont_command == PTRACE_SYSEMU
            || t.emulated_ptrace_cont_command == PTRACE_SYSEMU_SINGLESTEP
                && !is_in_privileged_syscall(t)
        {
            t.ev_mut().syscall_mut().state = SyscallState::EnteringSyscallPtrace;
            t.emulate_ptrace_stop(WaitStatus::for_syscall(t), None, None);
            t.record_current_event();

            t.ev_mut().syscall_mut().in_sysemu = t.emulated_ptrace_cont_command == PTRACE_SYSEMU
                || t.emulated_ptrace_cont_command == PTRACE_SYSEMU_SINGLESTEP;
        }

        true
    }

    /// If the perf counters seem to be working return, otherwise don't return.
    fn check_initial_task_syscalls(&self, t: &mut RecordTask, step_result: &mut RecordResult) {
        if self.done_initial_exec() {
            return;
        }

        if is_write_syscall(t.ev().syscall().number, t.arch()) && t.regs_ref().arg1_signed() == -1 {
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

        if is_exit_group_syscall(t.ev().syscall().number, t.arch()) {
            *step_result = RecordResult::StepSpawnFailed(self.read_spawned_task_error());
        }
    }

    /// Flush buffers and write a termination record to the trace. Don't call
    /// record_step() after this.
    pub fn terminate_recording(&self) {
        unimplemented!()
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

    pub fn scheduler(&self) -> Ref<'_, Scheduler> {
        self.scheduler_.borrow()
    }

    pub fn scheduler_mut(&self) -> RefMut<'_, Scheduler> {
        self.scheduler_.borrow_mut()
    }

    pub fn seccomp_filter_rewriter(&self) -> &SeccompFilterRewriter {
        &self.seccomp_filter_rewriter_
    }

    pub fn set_enable_chaos(&mut self, enable_chaos: bool) {
        self.scheduler_mut().set_enable_chaos(enable_chaos);
        self.enable_chaos_ = enable_chaos;
    }

    pub fn enable_chaos(&self) -> bool {
        self.enable_chaos_
    }

    pub fn set_num_cores(&mut self, num_cores: u32) {
        self.scheduler_mut().set_num_cores(num_cores);
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
    /// its tid to |rec_tid|. We mirror that, and emit TraceTaskEvents to make it
    /// look like a new task was spawned and the old task exited.
    pub fn revive_task_for_exec(&self, _rec_tid: pid_t) -> TaskSharedPtr {
        unimplemented!()
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
}

/// Copy the registers used for syscall arguments (not including
/// syscall number) from |from| to |to|.
fn copy_syscall_arg_regs(to: &mut Registers, from: &Registers) {
    to.set_arg1(from.arg1());
    to.set_arg2(from.arg2());
    to.set_arg3(from.arg3());
    to.set_arg4(from.arg4());
    to.set_arg5(from.arg5());
    to.set_arg6(from.arg6());
}

fn seccomp_trap_done(_t: &RecordTask) {
    unimplemented!()
}

/// After a SYS_sigreturn "exit" of task |t| with return value |ret|,
/// check to see if there's an interrupted syscall that /won't/ be
/// restarted, and if so, pop it off the pending event stack.
fn maybe_discard_syscall_interruption(_t: &RecordTask, _syscallno: i32) {
    unimplemented!()
}

fn save_interrupted_syscall_ret_in_syscallbuf(_t: &RecordTask, _retval: isize) {
    unimplemented!()
}

fn maybe_trigger_emulated_ptrace_syscall_exit_stop(_t: &RecordTask) {
    unimplemented!()
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

    fn on_destroy_task(&self, _t: TaskUid) {
        unimplemented!()
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
    ) -> Box<dyn Task> {
        RecordTask::new(self, tid, serial, a)
    }

    fn on_create_task(&self, t: TaskSharedPtr) {
        on_create_task_common(self, t.clone());
        self.scheduler_mut().on_create_task(t);
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
            Ok(siz) if siz != 0 => {
                let int_str = String::from_utf8_lossy(&buf[0..siz]);
                let maybe_val = int_str.trim().parse::<usize>();
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
            // @TODO This should actually be just Ok(0) but Rust doesn't accept it and says
            // patterns are not exhaustive.
            Ok(_) => {
                clean_fatal!(
                    "Read 0 bytes from `/proc/sys/kernel/perf_event_paranoid`.\n\
                             Need to read non-zero number of bytes."
                );
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
    for suffix in &["lib64/rd/", "lib64/rr/", "lib/rd/", "lib/rr"] {
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
        Err(e) => fatal!("Error while Elf parsing {:?}: {:?}", full_path.as_ref(), e),
        Ok(elf_file) => match elf_file.dynamic {
            Some(dyns) => {
                let mut maybe_libasan_path = None;
                let mut has_asan_init = false;
                for lib in dyns.get_libraries(&elf_file.dynstrtab) {
                    // @TODO Is contains() OK?
                    if lib.contains("libasan") {
                        maybe_libasan_path = Some(OsString::from(lib));
                        break;
                    }
                }
                for s in elf_file.dynsyms.iter() {
                    match elf_file.dynstrtab.get(s.st_name) {
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
                    Ok(st) if st.st_mode & S_IFREG == S_IFREG => {
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
            new_value.extend_from_slice(&val);
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

union USiginfo {
    native_api: native_arch::siginfo_t,
    linux_api: siginfo_t,
}

fn handle_seccomp_trap(t: &mut RecordTask, step_state: &mut StepState, seccomp_data: u16) {
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
        ed_assert_eq!(t, t.ev().syscall().number, syscallno);
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
        ed_assert!(t, !t.delay_syscallbuf_reset_for_seccomp_trap);
        // Don't reset the syscallbuf immediately after delivering the trap. We have
        // to wait until this buffered syscall aborts completely before resetting
        // the buffer.
        t.delay_syscallbuf_reset_for_seccomp_trap = true;

        t.push_event(Event::seccomp_trap());

        // desched may be armed but we're not going to execute the syscall, let
        // alone block. If it fires, ignore it.
        let syscallbuf_child = t.syscallbuf_child;
        write_val_mem(
            t,
            RemotePtr::<u8>::cast(syscallbuf_child)
                + offset_of!(syscallbuf_hdr, desched_signal_may_be_relevant),
            &0u8,
            None,
        );
    }

    t.push_syscall_event(syscallno);
    t.ev_mut().syscall_mut().failed_during_preparation = true;
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
        t.ev_mut().syscall_mut().state = SyscallState::ExitingSyscall;
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

fn note_entering_syscall(t: &mut RecordTask) {
    ed_assert_eq!(t, EventType::EvSyscall, t.ev().event_type());
    t.ev_mut().syscall_mut().state = SyscallState::EnteringSyscall;
    if !t.ev().syscall().is_restart {
        // Save a copy of the arg registers so that we
        // can use them to detect later restarted
        // syscalls, if this syscall ends up being
        // restarted.  We have to save the registers
        // in this rather awkward place because we
        // need the original registers; the restart
        // (if it's not a SYS_restart_syscall restart)
        // will use the original registers.
        let regs = t.regs_ref().clone();
        t.ev_mut().syscall_mut().regs = regs;
    }
}

fn rec_abort_prepared_syscall(_t: &mut RecordTask) {
    unimplemented!()
}

/// Return true if we handle a ptrace exit event for task t. When this returns
/// true, t has been deleted and cannot be referenced again.
fn handle_ptrace_exit_event(t: &TaskSharedPtr) -> bool {
    if t.borrow().maybe_ptrace_event() != PTRACE_EVENT_EXIT {
        return false;
    }

    unimplemented!()
}

/// "Thaw" a frozen interrupted syscall if |t| is restarting it.
/// Return true if a syscall is indeed restarted.
///
/// A postcondition of this function is that |t->ev| is no longer a
/// syscall interruption, whether or whether not a syscall was
/// restarted.
fn maybe_restart_syscall(t: &mut RecordTask) -> bool {
    let arch = t.arch();
    if is_restart_syscall_syscall(t.regs_ref().original_syscallno() as i32, arch) {
        log!(LogDebug, "  {}: SYS_restart_syscall'ing {}", t.tid, t.ev());
    }

    if t.is_syscall_restart() {
        t.ev_mut().transform(EventType::EvSyscall);
        let mut regs = t.regs_ref().clone();
        regs.set_original_syscallno(t.ev().syscall().regs.original_syscallno());
        t.set_regs(&regs);
        t.canonicalize_regs(arch);
        return true;
    }

    if EventType::EvSyscallInterruption == t.ev().event_type() {
        syscall_not_restarted(t);
    }

    false
}

fn syscall_not_restarted(t: &mut RecordTask) {
    log!(
        LogDebug,
        "  {}: popping abandoned interrupted {}; pending events:",
        t.tid,
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
