use crate::{
    kernel_abi::SupportedArch,
    remote_ptr::{RemotePtr, Void},
    taskish_uid::TaskUid,
    trace::trace_frame::FrameTime,
    trace_capnp::Arch as TraceArch,
    util::{dir_exists, ensure_dir, get_num_cpus, real_path},
};
use libc::{pid_t, EEXIST};
use nix::{errno::errno, sys::stat::Mode, unistd::mkdir};
use std::{
    cmp::min,
    env,
    ffi::{OsStr, OsString},
    io::Write,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
    slice::Iter,
};

pub const TRACE_VERSION: u32 = 85;

pub const SUBSTREAM_COUNT: usize = 4;

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

/// @TODO static mut should be OK but avoid it??
/// NOTE: This needs to be kept in sync with the enum above
pub(super) static mut SUBSTREAMS_DATA: [SubstreamData; SUBSTREAM_COUNT] = [
    SubstreamData {
        name: "events",
        block_size: 1024 * 1024,
        threads: 1,
    },
    SubstreamData {
        name: "data",
        block_size: 1024 * 1024,
        // Will be set later. See the substream() fn.
        threads: 0,
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
    if unsafe { SUBSTREAMS_DATA[Substream::RawData as usize].threads } == 0 {
        unsafe {
            SUBSTREAMS_DATA[Substream::RawData as usize].threads = min(8, get_num_cpus() as usize)
        };
    }
    unsafe { &SUBSTREAMS_DATA[s as usize] }
}

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

/// For REMAP_MAPPING maps, the memory contents are preserved so we don't
/// need a source. We use SourceZero for that case and it's ignored.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MappedDataSource {
    SourceTrace,
    SourceFile,
    SourceZero,
}

impl Default for MappedDataSource {
    fn default() -> Self {
        MappedDataSource::SourceTrace
    }
}

/// TraceStream stores all the data common to both recording and
/// replay.  TraceWriter deals with recording-specific logic, and
/// TraceReader handles replay-specific details.
/// writing code together for easier coordination.
impl TraceStream {
    /// Return the directory storing this trace's files.
    pub fn dir(&self) -> OsString {
        self.trace_dir.to_owned()
    }

    pub fn bound_to_cpu(&self) -> Option<u32> {
        self.bind_to_cpu
    }
    pub fn set_bound_cpu(&mut self, bound: Option<u32>) {
        self.bind_to_cpu = bound;
    }

    /// Return the current "global time" (event count) for this
    /// trace.
    pub fn time(&self) -> FrameTime {
        self.global_time
    }

    pub fn file_data_clone_file_name(&self, tuid: TaskUid) -> OsString {
        let mut ss: Vec<u8> = Vec::from(self.trace_dir.as_bytes());
        write!(ss, "/cloned_data_{}_{}", tuid.tid(), tuid.serial()).unwrap();
        OsString::from_vec(ss)
    }

    pub fn mmaps_block_size() -> usize {
        substream(Substream::Mmaps).block_size
    }

    pub(super) fn new(trace_dir: &OsStr, initial_time: FrameTime) -> TraceStream {
        TraceStream {
            trace_dir: real_path(trace_dir),
            // @TODO Is this what we want?
            bind_to_cpu: Some(0),
            global_time: initial_time,
        }
    }

    /// Return the path of the file for the given substream.
    pub(super) fn path(&self, s: Substream) -> OsString {
        let mut path_vec: Vec<u8> = Vec::from(self.trace_dir.as_bytes());
        path_vec.extend_from_slice(b"/");
        path_vec.extend_from_slice(substream(s).name.as_bytes());
        OsString::from_vec(path_vec)
    }

    /// Return the path of "version" file, into which the current
    /// trace format version of rd is stored upon creation of the
    /// trace.
    pub(super) fn version_path(&self) -> OsString {
        let mut version_path: Vec<u8> = self.trace_dir.clone().into_vec();
        version_path.extend_from_slice(b"/version");
        OsString::from_vec(version_path)
    }

    /// While the trace is being built, the version file is stored under this name.
    /// When the trace is closed we rename it to the correct name. This lets us
    /// detect incomplete traces.
    pub(super) fn incomplete_version_path(&self) -> OsString {
        let mut version_path: Vec<u8> = self.trace_dir.clone().into_vec();
        version_path.extend_from_slice(b"/incomplete");
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
#[derive(Clone)]
pub struct TraceStream {
    /// Directory into which we're saving the trace files.
    pub(super) trace_dir: OsString,
    /// DIFF NOTE: This is an i32 in rr
    /// CPU core# that the tracees are bound to. `None` if not bound to any core.
    pub(super) bind_to_cpu: Option<u32>,
    /// Arbitrary notion of trace time, ticked on the recording of
    /// each event (trace frame).
    pub(super) global_time: FrameTime,
}

#[derive(Clone, Default)]
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
#[derive(Default)]
pub struct MappedData {
    pub time: FrameTime,
    pub source: MappedDataSource,
    /// Name of file to map the data from.
    pub filename: OsString,
    /// Data offset within `filename`.
    /// NOTE: This is unsigned and NOT signed
    pub data_offset_bytes: usize,
    /// Original size of mapped file.
    pub file_size_bytes: usize,
}

pub(super) fn make_trace_dir(exe_path: &OsStr, maybe_output_trace_dir: Option<&OsStr>) -> OsString {
    match maybe_output_trace_dir {
        Some(output_trace_dir) => {
            // DIFF NOTE: Make trace dirs only S_IRWXU to be conservative. rr adds Mode::S_IRWXG also.
            // save trace dir in given output trace dir with option -o
            let ret = mkdir(output_trace_dir, Mode::S_IRWXU);
            match ret {
                Ok(_) => output_trace_dir.to_owned(),
                Err(e) if EEXIST == errno() => {
                    // directory already exists
                    fatal!("Directory {:?} already exists: {:?}", output_trace_dir, e)
                }
                Err(e) => fatal!(
                    "Unable to create trace directory {:?}: {:?}",
                    output_trace_dir,
                    e
                ),
            }
        }
        None => {
            // save trace dir set in _RD_TRACE_DIR/_RR_TRACE_DIR or in the default trace dir
            ensure_dir(
                trace_save_dir().as_os_str(),
                "trace directory",
                Mode::S_IRWXU,
            );

            // Find a unique trace directory name.
            let mut nonce = 0;
            let mut ret;
            let mut dir;
            let mut ss: Vec<u8> = Vec::from(trace_save_dir().as_bytes());
            ss.push(b'/');
            ss.extend_from_slice(Path::new(exe_path).file_name().unwrap().as_bytes());
            loop {
                dir = Vec::from(ss.as_slice());
                write!(dir, "-{}", nonce).unwrap();
                nonce += 1;
                // DIFF NOTE: Make trace dirs only S_IRWXU to be conservative. rr adds Mode::S_IRWXG also.
                ret = mkdir(dir.as_slice(), Mode::S_IRWXU);
                if ret.is_ok() || EEXIST != errno() {
                    break;
                }
            }

            let os_dir = OsString::from_vec(dir);
            match ret {
                Err(e) => fatal!("Unable to create trace directory {:?}: {:?}", os_dir, e),
                Ok(_) => os_dir,
            }
        }
    }
}

/// @TODO Look at logic again carefully
pub(super) fn default_rd_trace_dir() -> OsString {
    let cached_dir: OsString;
    let mut dot_dir: Vec<u8> = Vec::new();
    let maybe_home = env::var_os("HOME");
    let home: OsString;
    match maybe_home {
        Some(found_home) if !found_home.is_empty() => {
            dot_dir.extend_from_slice(found_home.as_bytes());
            dot_dir.extend_from_slice(b"/.rd");
            home = found_home;
        }
        // @TODO This seems to be an implicit outcome of what we have in rr
        _ => home = OsString::new(),
    }

    let mut xdg_dir: Vec<u8> = Vec::new();
    let maybe_xdg_data_home = env::var_os("XDG_DATA_HOME");
    match maybe_xdg_data_home {
        Some(xdg_data_home) if !xdg_data_home.is_empty() => {
            xdg_dir.extend_from_slice(xdg_data_home.as_bytes());
            xdg_dir.extend_from_slice(b"/rd");
        }
        _ => {
            xdg_dir.extend_from_slice(home.as_bytes());
            xdg_dir.extend_from_slice(b"/.local/share/rd");
        }
    }

    // If XDG dir does not exist but ~/.rd does, prefer ~/.rd for backwards
    // compatibility.
    if dir_exists(xdg_dir.as_slice()) {
        cached_dir = OsString::from_vec(xdg_dir);
    } else if dir_exists(dot_dir.as_slice()) {
        cached_dir = OsString::from_vec(dot_dir);
    } else if !xdg_dir.is_empty() {
        cached_dir = OsString::from_vec(xdg_dir);
    } else {
        cached_dir = OsStr::from_bytes(b"/tmp/rd").to_os_string();
    }

    cached_dir
}

pub(super) fn trace_save_dir() -> OsString {
    let maybe_output_dir = env::var_os("_RD_TRACE_DIR");
    let maybe_output_dir2 = env::var_os("_RR_TRACE_DIR");
    match maybe_output_dir {
        Some(dir) if !dir.is_empty() => dir,
        _ => match maybe_output_dir2 {
            Some(dir2) if !dir2.is_empty() => dir2,
            _ => default_rd_trace_dir(),
        },
    }
}

pub(super) fn latest_trace_symlink() -> OsString {
    let mut sym: Vec<u8> = Vec::from(trace_save_dir().as_bytes());
    sym.extend_from_slice(b"/latest-trace");
    OsString::from_vec(sym)
}

pub(super) fn to_trace_arch(arch: SupportedArch) -> TraceArch {
    match arch {
        SupportedArch::X86 => TraceArch::X86,
        SupportedArch::X64 => TraceArch::X8664,
    }
}
