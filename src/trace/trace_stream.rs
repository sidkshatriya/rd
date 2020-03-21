use crate::remote_ptr::{RemotePtr, Void};
use crate::taskish_uid::TaskUid;
use crate::trace::trace_frame::FrameTime;
use libc::pid_t;
use std::ffi::{OsStr, OsString};

/// Update `substreams` and TRACE_VERSION when you update this list.
#[repr(usize)]
pub enum Substream {
    /// Substream that stores events (trace frames).
    Events = 0,
    RawData = 1,
    /// Substream that stores metadata about files mmap'd during
    /// recording.
    Mmaps = 2,
    /// Substream that stores task creation and exec events
    Tasks = 3,
}

pub const SUBSTREAM_COUNT: usize = 4;

/// For REMAP_MAPPING maps, the memory contents are preserved so we don't
/// need a source. We use SourceZero for that case and it's ignored.
pub enum MappedDataSource {
    SourceTrace,
    SourceFile,
    SourceZero,
}

/// TraceStream stores all the data common to both recording and
/// replay.  TraceWriter deals with recording-specific logic, and
/// TraceReader handles replay-specific details.
/// writing code together for easier coordination.
impl TraceStream {
    /// Return the directory storing this trace's files.
    pub fn dir(&self) -> &OsStr {
        &self.trace_dir
    }

    pub fn bound_to_cpu(&self) -> i32 {
        self.bind_to_cpu
    }
    pub fn set_bound_cpu(&mut self, bound: i32) {
        self.bind_to_cpu = bound;
    }

    /// Return the current "global time" (event count) for this
    /// trace.
    pub fn time(&self) -> FrameTime {
        self.global_time
    }

    pub fn file_data_clone_file_name(&self, tuid: &TaskUid) -> OsString {
        unimplemented!()
    }

    pub fn mmaps_block_size() -> usize {
        unimplemented!()
    }

    fn new(trace_dir: &OsStr, initial_time: FrameTime) -> TraceStream {
        unimplemented!()
    }

    /// Return the path of the file for the given substream.
    fn path(&self, s: Substream) -> &OsStr {
        unimplemented!()
    }

    /// Return the path of "version" file, into which the current
    /// trace format version of rr is stored upon creation of the
    /// trace.
    fn version_path(&self) -> &OsStr {
        unimplemented!()
    }

    /// While the trace is being built, the version file is stored under this name.
    /// When the trace is closed we rename it to the correct name. This lets us
    /// detect incomplete traces.
    fn incomplete_version_path(&self) -> &OsStr {
        unimplemented!()
    }

    /// Increment the global time and return the incremented value.
    fn tick_time(&mut self) {
        self.global_time += 1
    }
}

/// TraceStream stores all the data common to both recording and
/// replay.  TraceWriter deals with recording-specific logic, and
/// TraceReader handles replay-specific details.
///
/// These classes are all in the same .h/.cc file to keep trace reading and
/// writing code together for easier coordination.
pub struct TraceStream {
    /// Directory into which we're saving the trace files.
    trace_dir: OsString,
    /// CPU core# that the tracees are bound to
    bind_to_cpu: i32,
    /// Arbitrary notion of trace time, ticked on the recording of
    /// each event (trace frame).
    global_time: FrameTime,
}

pub struct RawDataMetadata {
    pub addr: RemotePtr<Void>,
    pub size: usize,
    pub rec_tid: pid_t,
}

pub struct TraceRemoteFd {
    pub tid: pid_t,
    pub fd: i32,
}

/// Where to obtain data for the mapped region.
pub struct MappedData {
    pub time: FrameTime,
    pub source: MappedDataSource,
    /// Name of file to map the data from.
    pub filename: OsString,
    /// Data offset within `filename`.
    pub data_offset_bytes: usize,
    /// Original size of mapped file.
    pub file_size_bytes: usize,
}
