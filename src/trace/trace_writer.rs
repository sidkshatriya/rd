use crate::trace::trace_stream::TraceStream;
use std::ops::{Deref, DerefMut};

pub struct TraceWriter {
    trace_stream: TraceStream,
}

impl Deref for TraceWriter {
    type Target = TraceStream;

    fn deref(&self) -> &Self::Target {
        &self.trace_stream
    }
}

impl DerefMut for TraceWriter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.trace_stream
    }
}
