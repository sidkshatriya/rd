use super::{
    trace_stream::{
        make_trace_dir, substream, substreams_data, Substream, TraceStream, SUBSTREAM_COUNT,
    },
    trace_writer::TraceWriterBackend,
};
use crate::{trace::lexical_key::LexicalKey128, util::get_num_cpus};
use capnp::{message, serialize_packed};
use rocksdb::{ColumnFamily, DB};
use std::{
    ffi::OsStr,
    mem,
    ops::{Deref, DerefMut},
    path::PathBuf,
};

pub struct TraceWriterRocksDBBackend {
    trace_stream: TraceStream,
    db: DB,
    current_seq: [u64; SUBSTREAM_COUNT],
}

impl Deref for TraceWriterRocksDBBackend {
    type Target = TraceStream;

    fn deref(&self) -> &Self::Target {
        &self.trace_stream
    }
}

impl DerefMut for TraceWriterRocksDBBackend {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.trace_stream
    }
}

impl TraceWriterRocksDBBackend {
    pub fn new(
        file_name: &OsStr,
        output_trace_dir: Option<&OsStr>,
        bind_to_cpu: Option<u32>,
    ) -> TraceWriterRocksDBBackend {
        let trace_stream =
            TraceStream::new(&make_trace_dir(file_name, output_trace_dir), 1, bind_to_cpu);

        let mut rocks_db_folder = PathBuf::from(trace_stream.dir());
        rocks_db_folder.push("rocksdb");
        let mut options = rocksdb::Options::default();
        options.set_compression_type(rocksdb::DBCompressionType::Zstd);
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        options.increase_parallelism(get_num_cpus() as i32);
        let db = DB::open_cf(
            &options,
            &rocks_db_folder,
            substreams_data().iter().map(|d| d.name),
        )
        .unwrap();

        TraceWriterRocksDBBackend {
            trace_stream,
            current_seq: unsafe { mem::zeroed() },
            db,
        }
    }

    fn cf(&self, s: Substream) -> &ColumnFamily {
        self.db.cf_handle(substream(s).name).unwrap()
    }

    fn current_seq(&self, s: Substream) -> u64 {
        self.current_seq[s as usize]
    }

    fn incr_current_seq(&mut self, s: Substream) -> u64 {
        let curr = self.current_seq[s as usize];
        self.current_seq[s as usize] += 1;
        curr
    }
}

impl TraceWriterBackend for TraceWriterRocksDBBackend {
    fn close(&mut self) {
        // Do nothing
    }

    fn write_message(
        &mut self,
        stream: Substream,
        msg: &message::Builder<message::HeapAllocator>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = LexicalKey128::new(self.global_time, self.incr_current_seq(stream));
        let mut value = Vec::new();
        serialize_packed::write_message(&mut value, msg).unwrap();
        match self.db.put_cf(self.cf(stream), key, value) {
            Ok(()) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn write_data(
        &mut self,
        stream: Substream,
        buf: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = LexicalKey128::new(self.global_time, self.incr_current_seq(stream));
        match self.db.put_cf(self.cf(stream), key, buf) {
            Ok(()) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }
}
