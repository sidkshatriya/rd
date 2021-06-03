use crate::trace::{
    compressed_writer::CompressedWriter,
    trace_stream::{make_trace_dir, substream, substreams_data, Substream, TraceStream},
    trace_writer::TraceWriterBackend,
};
use capnp::{message, serialize_packed::write_message};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::Write,
    ops::{Deref, DerefMut},
    os::unix::ffi::{OsStrExt, OsStringExt},
};

pub struct TraceWriterFileBackend {
    trace_stream: TraceStream,
    /// @TODO This does not need to be be dynamic as the number of entries is known at
    /// compile time. This could be a [CompressedWriter; SUBSTREAM_COUNT] or a Box of
    /// the same.
    writers: HashMap<Substream, CompressedWriter>,
}

impl Deref for TraceWriterFileBackend {
    type Target = TraceStream;

    fn deref(&self) -> &Self::Target {
        &self.trace_stream
    }
}

impl DerefMut for TraceWriterFileBackend {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.trace_stream
    }
}

impl TraceWriterFileBackend {
    pub fn new(
        file_name: &OsStr,
        output_trace_dir: Option<&OsStr>,
        bind_to_cpu: Option<u32>,
    ) -> TraceWriterFileBackend {
        let trace_stream =
            TraceStream::new(&make_trace_dir(file_name, output_trace_dir), 1, bind_to_cpu);
        let mut tw = TraceWriterFileBackend {
            trace_stream,
            writers: HashMap::new(),
        };

        for s in substreams_data() {
            let filename = tw.path(s.substream);
            tw.writers.insert(
                s.substream,
                CompressedWriter::new(&filename, s.block_size, s.threads),
            );
        }

        tw
    }

    fn writer(&self, s: Substream) -> &CompressedWriter {
        self.writers.get(&s).unwrap()
    }

    fn writer_mut(&mut self, s: Substream) -> &mut CompressedWriter {
        self.writers.get_mut(&s).unwrap()
    }

    /// Return true iff all trace files are "good".
    pub fn good(&self) -> bool {
        for w in self.writers.values() {
            if !w.good() {
                return false;
            }
        }
        true
    }

    /// Return the path of the file for the given substream.
    fn path(&self, s: Substream) -> OsString {
        let mut path_vec: Vec<u8> = Vec::from(self.trace_dir.as_bytes());
        path_vec.extend_from_slice(b"/");
        path_vec.extend_from_slice(substream(s).name.as_bytes());
        OsString::from_vec(path_vec)
    }
}

impl TraceWriterBackend for TraceWriterFileBackend {
    fn close(&mut self) {
        for s in substreams_data() {
            let mut w = self.writers.remove(&s.substream).unwrap();
            w.close(None);
        }
    }

    fn write_message(
        &mut self,
        stream: Substream,
        msg: &message::Builder<message::HeapAllocator>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let events = self.writer_mut(stream);
        match write_message(events, msg) {
            Ok(()) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn write_data(
        &mut self,
        stream: Substream,
        buf: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let raw_stream = self.writer_mut(stream);
        match raw_stream.write_all(buf) {
            Ok(()) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }
}
