use crate::remote_ptr::{RemotePtr, Void};
use crate::trace::trace_frame::FrameTime;
use libc::pid_t;
use std::ffi::OsString;

pub struct TraceStream;

pub struct RawDataMetadata {
    pub addr: RemotePtr<Void>,
    pub size: usize,
    pub rec_tid: pid_t,
}

pub struct TraceRemoteFd {
    pub tid: pid_t,
    pub fd: i32,
}

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
