use crate::trace::{
    compressed_reader::{CompressedReader, CompressedReaderState},
    trace_reader::{resolve_trace_name, TraceReaderBackend},
    trace_stream::{substreams_data, Substream, TraceStream},
};
use capnp::{message, message::ReaderOptions, serialize, serialize_packed::read_message};
use std::{
    collections::HashMap,
    io::Read,
    ops::{Deref, DerefMut},
    path::Path,
};

impl TraceReaderBackend for TraceReaderFileBackend {
    fn rewind(&mut self) {
        for w in self.readers.values_mut() {
            w.rewind();
        }
        self.global_time = 0;
    }

    fn uncompressed_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for w in self.readers.values() {
            total += w.uncompressed_bytes().unwrap();
        }
        total
    }

    fn compressed_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for w in self.readers.values() {
            total += w.compressed_bytes().unwrap();
        }
        total
    }

    fn make_clone(&self) -> Box<dyn TraceReaderBackend> {
        Box::new(self.clone())
    }

    fn read_message(
        &mut self,
        substream: Substream,
    ) -> Result<message::Reader<serialize::OwnedSegments>, Box<dyn std::error::Error>> {
        let mut stream = self.reader_mut(substream);
        match read_message(&mut stream, ReaderOptions::new()) {
            Ok(res) => Ok(res),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn read_data_exact(
        &mut self,
        substream: Substream,
        size: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; size];
        match self.reader_mut(substream).read_exact(&mut buf) {
            Ok(()) => Ok(buf),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn at_end(&self, substream: Substream) -> bool {
        self.reader(substream).at_end()
    }

    fn skip(
        &mut self,
        substream: Substream,
        size: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self.reader_mut(substream).skip(size) {
            Ok(()) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn discard_state(&mut self, substream: Substream) {
        let cr = self.reader_mut(substream);
        cr.saved_state.take();
    }

    fn save_state(&mut self, substream: Substream) {
        let cr = self.reader_mut(substream);
        debug_assert!(cr.saved_state.is_none());
        let state = CompressedReaderState {
            saved_fd_offset: cr.fd_offset,
            saved_buffer: cr.buffer.clone(),
            saved_buffer_read_pos: cr.buffer_read_pos,
        };

        cr.saved_state = Some(state);
    }

    fn restore_state(&mut self, substream: Substream) {
        let state = self.reader_mut(substream).saved_state.take().unwrap();
        let cr = self.reader_mut(substream);
        if state.saved_fd_offset < cr.fd_offset {
            cr.eof = false;
        }
        cr.fd_offset = state.saved_fd_offset;
        cr.buffer = state.saved_buffer;
        cr.buffer_read_pos = state.saved_buffer_read_pos;
    }
}

impl Deref for TraceReaderFileBackend {
    type Target = TraceStream;

    fn deref(&self) -> &Self::Target {
        &self.trace_stream
    }
}

impl DerefMut for TraceReaderFileBackend {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.trace_stream
    }
}

#[derive(Clone)]
pub struct TraceReaderFileBackend {
    trace_stream: TraceStream,
    readers: HashMap<Substream, CompressedReader>,
}

impl TraceReaderFileBackend {
    pub fn new<T: AsRef<Path>>(maybe_dir: Option<T>) -> TraceReaderFileBackend {
        // Set the global time at 0, so that when we tick it for the first
        // event, it matches the initial global time at recording, 1.
        // We don't know bind_to_cpu right now, will calculate it later and set it
        let trace_stream = TraceStream::new(&resolve_trace_name(maybe_dir), 0, None);

        let mut readers: HashMap<Substream, CompressedReader> = HashMap::new();
        for s in substreams_data() {
            readers.insert(
                s.substream,
                CompressedReader::new(&trace_stream.path(s.substream)),
            );
        }

        TraceReaderFileBackend {
            trace_stream,
            readers,
        }
    }

    fn reader(&self, s: Substream) -> &CompressedReader {
        self.readers.get(&s).unwrap()
    }

    fn reader_mut(&mut self, s: Substream) -> &mut CompressedReader {
        self.readers.get_mut(&s).unwrap()
    }
}
