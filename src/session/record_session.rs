use crate::kernel_abi::SupportedArch;
use crate::session::session_inner::session_inner::SessionInner;
use crate::session::Session;
use crate::task::Task;
use crate::trace::trace_stream::TraceStream;
use std::ops::{Deref, DerefMut};

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
