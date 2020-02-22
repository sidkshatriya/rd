use crate::diversion_session::DiversionSession;
use crate::kernel_abi::SupportedArch;
use crate::record_session::RecordSession;
use crate::replay_session::ReplaySession;
use crate::task::task::Task;
use crate::trace_stream::TraceStream;
use libc::pid_t;

pub trait SessionInterface {
    fn on_destroy(&self, t: &Task);
    fn as_record(&self) -> Option<&RecordSession> {
        None
    }
    fn as_replay(&self) -> Option<&ReplaySession> {
        None
    }
    fn as_diversion(&self) -> Option<&DiversionSession> {
        None
    }
    fn is_recording(&self) -> bool {
        self.as_record().is_some()
    }
    fn is_replaying(&self) -> bool {
        self.as_replay().is_some()
    }
    fn is_diversion(&self) -> bool {
        self.as_diversion().is_some()
    }
    fn new_task(&self, tid: pid_t, rec_tid: pid_t, serial: u32, a: SupportedArch);
    fn trace_stream(&self) -> Option<&TraceStream> {
        None
    }
    fn cpu_binding(&self, trace: &TraceStream) -> i32;
    fn on_create(&self, t: &Task);
}
