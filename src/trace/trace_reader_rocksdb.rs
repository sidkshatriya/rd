use super::{
    trace_reader::{resolve_trace_name, TraceReaderBackend},
    trace_stream::{substreams_data, Substream, TraceStream, SUBSTREAM_COUNT},
};
use crate::{trace::lexical_key::LexicalKey128, util::get_num_cpus};
use capnp::{message, serialize_packed};
use owning_ref::{OwningRef, RcRef};
use rocksdb::{
    ColumnFamily, DBIteratorWithThreadMode, DBRawIteratorWithThreadMode, Direction, IteratorMode,
    ReadOptions, WriteOptions, DB,
};
use std::{
    convert::AsRef,
    ffi::OsStr,
    ops::{Deref, DerefMut},
    path::PathBuf,
    rc::Rc,
};

pub struct TraceReaderRocksDBBackend {
    default_read_options: ReadOptions,
    trace_stream: TraceStream,
    // @TODO Make this into an array
    cf_handles: Vec<OwningRef<Rc<DB>, ColumnFamily>>,
    db: RcRef<DB>,
    current_keys: [Option<LexicalKey128>; SUBSTREAM_COUNT],
    saved_states: [Option<Option<LexicalKey128>>; SUBSTREAM_COUNT],
}

impl Deref for TraceReaderRocksDBBackend {
    type Target = TraceStream;

    fn deref(&self) -> &Self::Target {
        &self.trace_stream
    }
}

impl DerefMut for TraceReaderRocksDBBackend {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.trace_stream
    }
}

impl TraceReaderRocksDBBackend {
    pub fn new<T: AsRef<OsStr>>(maybe_dir: Option<T>) -> TraceReaderRocksDBBackend {
        // We don't know bind_to_cpu right now, will calculate it later and set it
        let trace_stream = TraceStream::new(&resolve_trace_name(maybe_dir), 0, None);
        let roptions = ReadOptions::default();

        let mut rocks_db_folder = PathBuf::from(trace_stream.dir());
        rocks_db_folder.push("rocksdb");

        let mut options = rocksdb::Options::default();

        options.set_compression_type(rocksdb::DBCompressionType::Zstd);
        options.increase_parallelism(get_num_cpus() as i32 / 2);

        // @TODO Not sure about these
        options.set_num_levels(1);
        options.set_compression_options(24, 9, 7, 32768);

        let db = RcRef::new(Rc::new(
            DB::open_cf_for_read_only(
                &options,
                &rocks_db_folder,
                substreams_data().iter().map(|d| d.name),
                false,
            )
            .unwrap(),
        ));

        let mut cf_handles = Vec::new();
        for s in substreams_data() {
            cf_handles.push(db.clone().map(|d| d.cf_handle(s.name).unwrap()));
        }

        TraceReaderRocksDBBackend {
            current_keys: Default::default(),
            default_read_options: roptions,
            saved_states: Default::default(),
            trace_stream,
            db,
            cf_handles,
        }
    }

    fn iter(&self, substream: Substream) -> DBIteratorWithThreadMode<DB> {
        if let Some(lexical_key) = self.current_keys[substream as usize] {
            let mut it = self.db.iterator_cf_opt(
                self.cf(substream),
                ReadOptions::default(),
                IteratorMode::From(lexical_key.as_ref(), Direction::Forward),
            );
            it.next();
            it
        } else {
            self.db.iterator_cf_opt(
                self.cf(substream),
                ReadOptions::default(),
                IteratorMode::Start,
            )
        }
    }

    fn cf(&self, s: Substream) -> &ColumnFamily {
        &self.cf_handles[s as usize]
    }
}

impl TraceReaderBackend for TraceReaderRocksDBBackend {
    fn make_clone(&self) -> Box<dyn TraceReaderBackend> {
        let b = TraceReaderRocksDBBackend {
            default_read_options: ReadOptions::default(),
            trace_stream: self.trace_stream.clone(),
            cf_handles: self.cf_handles.clone(),
            db: self.db.clone(),
            current_keys: self.current_keys.clone(),
            saved_states: self.saved_states,
        };
        Box::new(b)
    }

    /// @TODO pinned read
    fn read_message(
        &mut self,
        substream: Substream,
    ) -> Result<message::Reader<capnp::serialize::OwnedSegments>, Box<dyn std::error::Error>> {
        let (key, value) = self.iter(substream).next().unwrap();
        self.current_keys[substream as usize] = Some(LexicalKey128::from(&*key));
        Ok(serialize_packed::read_message(&*value, message::ReaderOptions::new()).unwrap())
    }

    fn read_data_exact(
        &mut self,
        substream: Substream,
        buf: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (key, value) = self.iter(substream).next().unwrap();
        self.current_keys[substream as usize] = Some(LexicalKey128::from(&*key));
        assert_eq!(value.len(), buf.len());
        buf.copy_from_slice(&*value);
        Ok(())
    }

    fn at_end(&self, substream: Substream) -> bool {
        self.iter(substream).next().is_none()
    }

    fn discard_state(&mut self, substream: Substream) {
        self.saved_states[substream as usize] = None;
    }

    fn save_state(&mut self, substream: Substream) {
        self.saved_states[substream as usize] = Some(self.current_keys[substream as usize]);
    }

    fn restore_state(&mut self, substream: Substream) {
        self.current_keys[substream as usize] = self.saved_states[substream as usize].unwrap();
    }

    fn rewind(&mut self) {
        self.global_time = 0;
        self.current_keys = Default::default();
    }

    fn uncompressed_bytes(&self) -> u64 {
        todo!()
    }

    fn compressed_bytes(&self) -> u64 {
        todo!()
    }

    fn skip(
        &mut self,
        substream: Substream,
        size: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (key, value) = self.iter(substream).next().unwrap();
        assert_eq!(size, value.len());
        self.current_keys[substream as usize] = Some(LexicalKey128::from(&*key));
        Ok(())
    }
}
