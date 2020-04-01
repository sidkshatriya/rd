use crate::address_space::kernel_mapping::KernelMapping;
use crate::perf_counters::TicksSemantics;
use crate::remote_ptr::{RemotePtr, Void};
use crate::session::record_session::TraceUuid;
use crate::trace::compressed_reader::CompressedReader;
use crate::trace::trace_frame::{FrameTime, TraceFrame};
use crate::trace::trace_stream::{
    MappedData, RawDataMetadata, Substream, TraceRemoteFd, TraceStream, SUBSTREAM_COUNT,
};
use crate::trace::trace_task_event::TraceTaskEvent;
use crate::util::CPUIDRecord;
use libc::pid_t;
use std::ffi::OsStr;
use std::ops::{Deref, DerefMut};

/// Read the next mapped region descriptor and return it.
/// Also returns where to get the mapped data in `data`, if it's not `None`.
/// If `found` is not `None`, set `found` to indicate whether a descriptor
/// was found for the current event.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ValidateSourceFile {
    Validate,
    DontValidate,
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum TimeConstraint {
    CurrentTimeOnly,
    AnyTime,
}

/// A parcel of recorded tracee data.  `data` contains the data read
/// from `addr` in the tracee.
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
    xcr0_: u64,
    readers: Box<[CompressedReader; SUBSTREAM_COUNT]>,
    cpuid_records_: Vec<CPUIDRecord>,
    raw_recs: Vec<RawDataMetadata>,
    ticks_semantics_: TicksSemantics,
    monotonic_time_: f64,
    /// @TODO This is a unique ptr in rr. Do we need a Box here?
    uuid_: TraceUuid,
    trace_uses_cpuid_faulting: bool,
    preload_thread_locals_recorded_: bool,
}

/// Create a copy of this stream that has exactly the same
/// state as 'other', but for which mutations of this
/// clone won't affect the state of 'other' (and vice versa).
impl Clone for TraceReader {
    fn clone(&self) -> Self {
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

impl TraceReader {
    /// Read relevant data from the trace.
    ///
    /// NB: reading a trace frame has the side effect of ticking
    /// the global time to match the time recorded in the trace
    /// frame.
    pub fn read_frame(&self) -> TraceFrame {
        unimplemented!()
    }

    pub fn read_mapped_region(
        &self,
        _data: Option<&mut MappedData>,
        _found: Option<&mut bool>,
        _validate: Option<ValidateSourceFile>,
        _time_constraint: Option<TimeConstraint>,
        _extra_fds: Option<&mut Vec<TraceRemoteFd>>,
        _skip_monitoring_mapped_fd: Option<&mut bool>,
    ) -> KernelMapping {
        unimplemented!()
    }

    /// Read a task event (clone or exec record) from the trace.
    /// Returns a record of type NONE at the end of the trace.
    /// Sets `time` (if non-None) to the global time of the event.
    pub fn read_task_event(&self, _time: Option<&mut FrameTime>) -> TraceTaskEvent {
        unimplemented!()
    }

    /// Read the next raw data record for this frame and return it. Aborts if
    /// there are no more raw data records for this frame.
    pub fn read_raw_data(&self) -> RawData {
        unimplemented!()
    }

    /// Reads the next raw data record for last-read frame. If there are no more
    /// raw data records for this frame, return false.
    pub fn read_raw_data_for_frame(&self, _d: &mut RawData) -> bool {
        unimplemented!()
    }

    /// Like read_raw_data_for_frame, but doesn't actually read the data bytes.
    /// The array is resized but the data is not filled in.
    pub fn read_raw_data_metadata_for_frame(&self, _d: &mut RawDataMetadata) -> bool {
        unimplemented!()
    }

    /// Return true iff all trace files are "good".
    pub fn good(&self) -> bool {
        unimplemented!()
    }

    /// Return true if we're at the end of the trace file.
    pub fn at_end(&self) -> bool {
        self.reader(Substream::Events).at_end()
    }

    /// Return the next trace frame, without mutating any stream
    /// state.
    pub fn peek_frame(&self) -> TraceFrame {
        unimplemented!()
    }

    /// Restore the state of this to what it was just after
    /// `open()`.
    pub fn rewind() {
        unimplemented!()
    }

    pub fn uncompressed_bytes(&self) -> u64 {
        unimplemented!()
    }
    pub fn compressed_bytes(&self) -> u64 {
        unimplemented!()
    }

    /// Open the trace in 'dir'. When 'dir' is the empty string, open the
    /// latest trace.
    pub fn new(&self, _dir: &OsStr) -> TraceReader {
        unimplemented!()
    }

    pub fn cpuid_records(&self) -> &[CPUIDRecord] {
        &self.cpuid_records_
    }
    pub fn uses_cpuid_faulting(&self) -> bool {
        self.trace_uses_cpuid_faulting
    }
    pub fn xcr0() -> u64 {
        unimplemented!()
    }

    /// Prior to rr issue 2370, we did not emit mapping into the trace for the
    /// preload_thread_locals mapping if it was created by a clone(2) without
    /// CLONE_VM. This is true if that has been fixed.
    pub fn preload_thread_locals_recorded(&self) -> bool {
        self.preload_thread_locals_recorded_
    }
    pub fn uuid(&self) -> &TraceUuid {
        &self.uuid_
    }

    pub fn ticks_semantics(&self) -> TicksSemantics {
        self.ticks_semantics_
    }

    pub fn recording_time(&self) -> f64 {
        self.monotonic_time_
    }

    fn reader(&self, s: Substream) -> &CompressedReader {
        &self.readers[s as usize]
    }
    fn reader_mut(&mut self, s: Substream) -> &mut CompressedReader {
        &mut self.readers[s as usize]
    }
}
