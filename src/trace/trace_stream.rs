use crate::kernel_abi::SupportedArch;
use crate::remote_ptr::{RemotePtr, Void};
use crate::taskish_uid::TaskUid;
use crate::trace::trace_frame::FrameTime;
use crate::trace_capnp::Arch as TraceArch;
use libc::pid_t;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::slice::Iter;

pub const TRACE_VERSION: u32 = 85;

/// Update `substreams` and TRACE_VERSION when you update this list.
#[repr(usize)]
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
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

/// This needs to be kept in sync with the enum above
pub const SUBSTREAMS: [Substream; SUBSTREAM_COUNT] = [
    Substream::Events,
    Substream::RawData,
    Substream::Mmaps,
    Substream::Tasks,
];

impl Substream {
    pub fn iter() -> Iter<'static, Substream> {
        SUBSTREAMS.iter()
    }
}

pub(super) struct SubstreamData {
    pub(super) name: &'static str,
    pub(super) block_size: usize,
    pub(super) threads: usize,
}

pub const SUBSTREAM_COUNT: usize = 4;

pub(super) const SUBSTREAMS_DATA: [SubstreamData; SUBSTREAM_COUNT] = [
    SubstreamData {
        name: "events",
        block_size: 1024 * 1024,
        threads: 1,
    },
    SubstreamData {
        name: "data",
        block_size: 1024 * 1024,
        // @TODO Hardcoded for now
        threads: 8,
    },
    SubstreamData {
        name: "mmaps",
        block_size: 64 * 1024,
        threads: 1,
    },
    SubstreamData {
        name: "tasks",
        block_size: 64 * 1024,
        threads: 1,
    },
];

pub(super) fn substream(s: Substream) -> &'static SubstreamData {
    // @TODO This method is incomplete
    &SUBSTREAMS_DATA[s as usize]
}

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

    pub fn file_data_clone_file_name(&self, _tuid: &TaskUid) -> OsString {
        unimplemented!()
    }

    pub fn mmaps_block_size() -> usize {
        unimplemented!()
    }

    pub(super) fn new(_trace_dir: &OsStr, _initial_time: FrameTime) -> TraceStream {
        unimplemented!()
    }

    /// Return the path of the file for the given substream.
    pub(super) fn path(&self, _s: Substream) -> &OsStr {
        unimplemented!()
    }

    /// Return the path of "version" file, into which the current
    /// trace format version of rr is stored upon creation of the
    /// trace.
    pub(super) fn version_path(&self) -> OsString {
        let mut version_path: Vec<u8> = self.trace_dir.clone().into_vec();
        version_path.copy_from_slice(b"/version");
        OsString::from_vec(version_path)
    }

    /// While the trace is being built, the version file is stored under this name.
    /// When the trace is closed we rename it to the correct name. This lets us
    /// detect incomplete traces.
    pub(super) fn incomplete_version_path(&self) -> OsString {
        let mut version_path: Vec<u8> = self.trace_dir.clone().into_vec();
        version_path.copy_from_slice(b"/incomplete");
        OsString::from_vec(version_path)
    }

    /// Increment the global time and return the incremented value.
    pub(super) fn tick_time(&mut self) {
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
    pub(super) trace_dir: OsString,
    /// CPU core# that the tracees are bound to
    pub(super) bind_to_cpu: i32,
    /// Arbitrary notion of trace time, ticked on the recording of
    /// each event (trace frame).
    pub(super) global_time: FrameTime,
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

pub(super) fn make_trace_dir(_exe_path: &OsStr, _output_trace_dir: &OsStr) -> OsString {
    unimplemented!()
}

pub(super) fn default_rd_trace_dir() -> OsString {
    unimplemented!()
}

pub(super) fn trace_save_dir() {
    unimplemented!()
}

pub(super) fn latest_trace_symlink() -> OsString {
    unimplemented!()
}

pub(super) fn to_trace_arch(arch: SupportedArch) -> TraceArch {
    match arch {
        SupportedArch::X86 => TraceArch::X86,
        SupportedArch::X64 => TraceArch::X8664,
    }
}
