use super::{
    trace_stream::{make_trace_dir, substreams_data, Substream, TraceStream, SUBSTREAM_COUNT},
    trace_writer::TraceWriterBackend,
};
use crate::{trace::lexical_key::LexicalKey128, util::get_num_cpus};
use capnp::{message, serialize_packed};
use owning_ref::{OwningRef, RcRef};
use rocksdb::{ColumnFamily, WriteOptions, DB};
use std::{
    ffi::OsStr,
    ops::{Deref, DerefMut},
    path::PathBuf,
    rc::Rc,
};

pub struct TraceWriterRocksDBBackend {
    default_write_options: WriteOptions,
    trace_stream: TraceStream,
    // @TODO Make this into an array
    cf_handles: Vec<OwningRef<Rc<DB>, ColumnFamily>>,
    db: RcRef<DB>,
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

        let mut woptions = WriteOptions::default();
        woptions.set_sync(false);
        woptions.disable_wal(true);

        let mut rocks_db_folder = PathBuf::from(trace_stream.dir());
        rocks_db_folder.push("rocksdb");
        let mut options = rocksdb::Options::default();
        options.set_compression_type(rocksdb::DBCompressionType::Zstd);
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        options.increase_parallelism(get_num_cpus() as i32 / 2);
        // @TODO Not sure about these
        options.set_num_levels(1);
        options.set_compression_options(24, 9, 7, 32768);

        let db = RcRef::new(Rc::new(
            DB::open_cf(
                &options,
                &rocks_db_folder,
                substreams_data().iter().map(|d| d.name),
            )
            .unwrap(),
        ));

        let mut cf_handles = Vec::new();
        for s in substreams_data() {
            cf_handles.push(db.clone().map(|d| d.cf_handle(s.name).unwrap()));
        }

        TraceWriterRocksDBBackend {
            default_write_options: woptions,
            trace_stream,
            current_seq: Default::default(),
            db,
            cf_handles,
        }
    }

    fn cf(&self, s: Substream) -> &ColumnFamily {
        &self.cf_handles[s as usize]
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
        match self
            .db
            .put_cf_opt(self.cf(stream), key, value, &self.default_write_options)
        {
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
        match self
            .db
            .put_cf_opt(self.cf(stream), key, buf, &self.default_write_options)
        {
            Ok(()) => Ok(()),
            Err(e) => Err(Box::new(e)),
        }
    }
}
