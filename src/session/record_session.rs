use crate::kernel_abi::SupportedArch;
use crate::session::session_inner::session_inner::SessionInner;
use crate::session::Session;
use crate::task::Task;
use crate::trace::trace_stream::TraceStream;
use std::ops::{Deref, DerefMut};

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

impl DisableCPUIDFeatures {
    // @TODO
}

pub struct TraceUuid {
    bytes: [u8; 16],
}

pub struct RecordSession {
    session_inner: SessionInner,
}

impl RecordSession {
    pub fn syscallbuf_desched_sig(&self) -> i32 {
        unimplemented!()
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
        unimplemented!()
    }

    fn as_session_inner_mut(&self) -> &mut SessionInner {
        unimplemented!()
    }

    fn on_destroy(&self, t: &dyn Task) {
        unimplemented!()
    }

    fn new_task(&self, tid: i32, rec_tid: i32, serial: u32, a: SupportedArch) {
        unimplemented!()
    }

    fn cpu_binding(&self, trace: &TraceStream) -> Option<u32> {
        unimplemented!()
    }

    fn on_create(&self, t: &dyn Task) {
        unimplemented!()
    }
}
