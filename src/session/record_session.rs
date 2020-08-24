use super::{session_common::kill_all_tasks, SessionSharedPtr};
use crate::{
    commands::record_command::RecordCommand,
    event::Switchable,
    kernel_abi::SupportedArch,
    scheduler::Scheduler,
    seccomp_filter_rewriter::SeccompFilterRewriter,
    session::{
        session_inner::session_inner::SessionInner,
        task::{Task, TaskSharedPtr},
        Session,
    },
    taskish_uid::TaskUid,
    thread_group::ThreadGroupSharedPtr,
    trace::{trace_stream::TraceStream, trace_writer::TraceWriter},
    util::{good_random, CPUIDData, CPUID_GETEXTENDEDFEATURES, CPUID_GETFEATURES, CPUID_GETXSAVE},
    wait_status::WaitStatus,
};
use libc::pid_t;
use std::{
    cell::{Ref, RefCell, RefMut},
    ffi::OsString,
    ops::{Deref, DerefMut},
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

pub struct RecordSession {
    session_inner: SessionInner,
    trace_out: TraceWriter,
    scheduler_: RefCell<Scheduler>,
    initial_thread_group: ThreadGroupSharedPtr,
    seccomp_filter_rewriter_: SeccompFilterRewriter,
    trace_id: Box<TraceUuid>,
    disable_cpuid_features_: DisableCPUIDFeatures,
    ignore_sig: i32,
    continue_through_sig: i32,
    last_task_switchable: Switchable,
    syscall_buffer_size_: usize,
    syscallbuf_desched_sig_: u8,
    use_syscall_buffer_: bool,

    use_file_cloning_: bool,
    use_read_cloning_: bool,
    /// When true, try to increase the probability of finding bugs.
    enable_chaos_: bool,
    asan_active_: bool,
    /// When true, wait for all tracees to exit before finishing recording.
    wait_for_all_: bool,

    output_trace_dir: OsString,
}

impl Drop for RecordSession {
    fn drop(&mut self) {
        unimplemented!()
    }
}

impl RecordSession {
    pub fn trace_writer(&self) -> &TraceWriter {
        &self.trace_out
    }

    pub fn trace_writer_mut(&mut self) -> &mut TraceWriter {
        &mut self.trace_out
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
        unimplemented!()
    }

    /// Flush buffers and write a termination record to the trace. Don't call
    /// record_step() after this.
    pub fn terminate_recording(&self) {
        unimplemented!()
    }

    /// DIFF NOTE: Param list very different from rr.
    /// Takes the whole &RecordCommand for simplicity.
    pub fn create(_options: &RecordCommand) -> SessionSharedPtr {
        unimplemented!()
    }

    pub fn scheduler(&self) -> Ref<'_, Scheduler> {
        self.scheduler_.borrow()
    }

    pub fn scheduler_mut(&self) -> RefMut<'_, Scheduler> {
        self.scheduler_.borrow_mut()
    }

    pub fn syscallbuf_desched_sig(&self) -> u8 {
        self.syscallbuf_desched_sig_
    }

    pub fn use_file_cloning(&self) -> bool {
        self.use_file_cloning_
    }
    pub fn use_syscall_buffer(&self) -> bool {
        self.use_syscall_buffer_
    }
    pub fn trace_stream(&self) -> Option<&TraceStream> {
        Some(&self.trace_out)
    }
    pub fn trace_stream_mut(&mut self) -> Option<&mut TraceStream> {
        Some(&mut self.trace_out)
    }
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
        _tid: pid_t,
        _rec_tid: Option<pid_t>,
        _serial: u32,
        _a: SupportedArch,
    ) -> Box<dyn Task> {
        unimplemented!()
    }

    fn on_create(&self, _t: TaskSharedPtr) {
        unimplemented!()
    }
}
