use crate::{
    event::Switchable,
    kernel_abi::SupportedArch,
    scheduler::Scheduler,
    seccomp_filter_rewriter::SeccompFilterRewriter,
    session::{session_inner::session_inner::SessionInner, Session},
    task::Task,
    thread_group::ThreadGroupSharedPtr,
    trace::{trace_stream::TraceStream, trace_writer::TraceWriter},
    util::{good_random, CPUIDData, CPUID_GETEXTENDEDFEATURES, CPUID_GETFEATURES, CPUID_GETXSAVE},
};
use std::{
    cell::{Ref, RefCell, RefMut},
    ops::{Deref, DerefMut},
};

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

const CPUID_RDRAND_FLAG: u32 = 1 << 30;
const CPUID_RTM_FLAG: u32 = 1 << 11;
const CPUID_RDSEED_FLAG: u32 = 1 << 18;
const CPUID_XSAVEOPT_FLAG: u32 = 1 << 0;

impl Default for DisableCPUIDFeatures {
    fn default() -> Self {
        Self::new()
    }
}

impl DisableCPUIDFeatures {
    pub fn new() -> DisableCPUIDFeatures {
        DisableCPUIDFeatures {
            features_ecx: 0,
            features_edx: 0,
            extended_features_ebx: 0,
            extended_features_ecx: 0,
            extended_features_edx: 0,
            xsave_features_eax: 0,
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

#[derive(Clone)]
pub struct TraceUuid {
    pub bytes: [u8; 16],
}

impl TraceUuid {
    pub fn inner_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn new() -> TraceUuid {
        let mut bytes = [0u8; 16];
        good_random(&mut bytes);
        TraceUuid { bytes }
    }

    pub fn from_array(bytes: [u8; 16]) -> TraceUuid {
        TraceUuid { bytes }
    }
}

pub struct RecordSession {
    session_inner: SessionInner,
    trace_out: TraceWriter,
    scheduler_: RefCell<Scheduler>,
    initial_thread_group: ThreadGroupSharedPtr,
    seccomp_filter_rewriter_: SeccompFilterRewriter,
    // DIFF NOTE: This is a unique_ptr in rr
    trace_id: TraceUuid,
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

    output_trace_dir: String,
}

impl RecordSession {
    pub fn scheduler(&self) -> Ref<'_, Scheduler> {
        self.scheduler_.borrow()
    }
    pub fn scheduler_mut(&self) -> RefMut<'_, Scheduler> {
        self.scheduler_.borrow_mut()
    }

    pub fn syscallbuf_desched_sig(&self) -> i32 {
        unimplemented!()
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
    fn as_session_inner(&self) -> &SessionInner {
        &self.session_inner
    }

    fn as_session_inner_mut(&mut self) -> &mut SessionInner {
        &mut self.session_inner
    }

    fn on_destroy(&self, _t: &dyn Task) {
        unimplemented!()
    }

    fn new_task(&self, _tid: i32, _rec_tid: i32, _serial: u32, _a: SupportedArch) -> Box<dyn Task> {
        unimplemented!()
    }

    fn on_create(&mut self, _t: Box<dyn Task>) {
        unimplemented!()
    }
}
