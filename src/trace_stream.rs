pub struct TraceStream;

pub mod trace_reader {
    use crate::remote_ptr::{RemotePtr, Void};
    use crate::trace_stream::TraceStream;
    use libc::pid_t;
    use std::ops::{Deref, DerefMut};

    /// A parcel of recorded tracee data.  |data| contains the data read
    /// from |addr| in the tracee.
    ///
    /// We DONT want Copy
    #[derive(Clone)]
    pub struct RawData {
        pub data: Vec<u8>,
        pub addr: RemotePtr<Void>,
        pub rec_tid: pid_t,
    }

    pub struct TraceReader {
        trace_stream: TraceStream,
    }

    impl TraceReader {
        /// Read the next raw data record for this frame and return it. Aborts if
        /// there are no more raw data records for this frame.
        pub fn read_raw_data(&self) -> RawData {
            unimplemented!()
        }
    }

    impl Deref for TraceReader {
        type Target = TraceStream;

        fn deref(&self) -> &Self::Target {
            &self.trace_stream
        }
    }

    impl DerefMut for TraceReader {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.trace_stream
        }
    }
}

pub mod trace_writer {
    use crate::trace_stream::TraceStream;
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
}
