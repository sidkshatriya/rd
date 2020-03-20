use crate::address_space::kernel_mapping::KernelMapping;
use crate::event::Event;
use crate::extra_registers::ExtraRegisters;
use crate::perf_counters::TicksSemantics;
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::session::record_session::{DisableCPUIDFeatures, TraceUuid};
use crate::task::record_task::record_task::RecordTask;
use crate::trace::compressed_writer::CompressedWriter;
use crate::trace::trace_stream::{
    MappedData, RawDataMetadata, Substream, TraceRemoteFd, TraceStream, SUBSTREAM_COUNT,
};
use crate::trace::trace_task_event::TraceTaskEvent;
use crate::util::CPUIDRecord;
use libc::{dev_t, ino_t, pid_t};
use std::collections::HashMap;
use std::ffi::c_void;
use std::ffi::{OsStr, OsString};
use std::ops::{Deref, DerefMut};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum RecordInTrace {
    DontRecordInTrace,
    RecordInTrace,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MappingOrigin {
    SyscallMapping,
    /// Just memory moved from one place to another, so no recording needed.
    RemapMapping,
    ExecMapping,
    PatchMapping,
    RdBufferMapping,
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum CloseStatus {
    /// Trace completed normally and can be replayed.
    CloseOk,
    /// Trace completed abnormally due to rr error.
    CloseError,
}

/// Trace writing takes the trace directory through a defined set of states.
/// These states can be usefully observed by external programs.
///
/// -- Initially the trace directory does not exist.
/// -- The trace directory is created. It is empty.
/// -- A file `incomplete` is created in the trace directory. It is empty.
/// -- rr takes an exclusive flock() lock on `incomplete`.
/// -- rr writes data to `incomplete` so it is no longer empty. (At this
/// point the data is undefined.) rr may write to the file at any
/// time during recording.
/// -- At the end of trace recording, rr renames `incomplete` to `version`.
/// At this point the trace is complete and ready to replay.
/// -- rr releases its flock() lock on `version`.
///
/// Thus:
/// -- If the trace directory contains the file `version` the trace is valid
/// and ready for replay.
/// -- If the trace directory contains the file `incomplete`, and there is an
/// exclusive flock() lock on that file, rr is still recording (or something
/// is messing with us).
/// -- If the trace directory contains the file `incomplete`, that file
/// does not have an exclusive `flock()` lock on it, and the file is non-empty,
/// rr must have died before the recording was complete.
/// -- If the trace directory contains the file `incomplete`, that file
/// does not have an exclusive `flock()` lock on it, and the file is empty,
/// rr has just started recording (or perhaps died during startup).
/// -- If the trace directory does not contain the file `incomplete`,
/// rr has just started recording (or perhaps died during startup) (or perhaps
/// that isn't a trace directory at all).
pub struct TraceWriter {
    trace_stream: TraceStream,
    /// @TODO Is a box necessary here?
    writers: Box<[CompressedWriter; SUBSTREAM_COUNT]>,
    /// Files that have already been mapped without being copied to the trace,
    /// i.e. that we have already assumed to be immutable.
    /// We store the file name under which we assumed it to be immutable, since
    /// a file may be accessed through multiple names, only some of which
    /// are immutable.
    files_assumed_immutable: HashMap<(dev_t, ino_t), OsString>,
    raw_recs: Vec<RawDataMetadata>,
    cpuid_records: Vec<CPUIDRecord>,
    ticks_semantics_: TicksSemantics,
    /// Keep the 'incomplete' (later renamed to 'version') file open until we
    /// rename it, so our flock() lock stays held on it.
    version_fd: ScopedFd,
    mmap_count: u32,
    has_cpuid_faulting_: bool,
    supports_file_data_cloning_: bool,
}

impl Deref for TraceWriter {
    type Target = TraceStream;

    fn deref(&self) -> &Self::Target {
        &self.trace_stream
    }
}

impl DerefMut for TraceWriter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.trace_stream
    }
}

impl TraceWriter {
    pub fn supports_file_data_cloning(&self) -> bool {
        self.supports_file_data_cloning_
    }

    /// Write trace frame to the trace.
    ///
    /// Recording a trace frame has the side effect of ticking
    /// the global time.
    pub fn write_frame(
        &self,
        t: &RecordTask,
        ev: &Event,
        registers: &Registers,
        extra_registers: &ExtraRegisters,
    ) {
        unimplemented!()
    }

    /// Write mapped-region record to the trace.
    /// If this returns `RecordInTrace`, then the data for the map should be
    /// recorded in the trace raw-data.
    pub fn write_mapped_region(
        &self,
        t: RecordTask,
        map: &KernelMapping,
        stat: &libc::stat,
        extra_fds: &[TraceRemoteFd],
        origin: Option<MappingOrigin>,
        skip_monitoring_mapped_fd: Option<bool>,
    ) -> RecordInTrace {
        unimplemented!()
    }

    pub fn write_mapped_region_to_alternative_stream(
        mmaps: &CompressedWriter,
        data: &MappedData,
        km: &KernelMapping,
        extra_fds: &[TraceRemoteFd],
        skip_monitoring_mapped_fd: bool,
    ) {
        unimplemented!()
    }

    /// Write a raw-data record to the trace.
    /// 'addr' is the address in the tracee where the data came from/will be
    /// restored to.
    pub fn write_raw(&self, tid: pid_t, data: *const c_void, len: usize, addr: RemotePtr<Void>) {
        unimplemented!()
    }

    /// Write a task event (clone or exec record) to the trace.
    pub fn write_task_event(event: &TraceTaskEvent) {
        unimplemented!()
    }

    /// Return true iff all trace files are "good".
    pub fn good() -> bool {
        unimplemented!()
    }

    /// Create a trace where the tracess are bound to cpu |bind_to_cpu|. This
    /// data is recorded in the trace. If |bind_to_cpu| is -1 then the tracees
    /// were not bound.
    /// The trace name is determined by |file_name| and _RR_TRACE_DIR (if set)
    /// or by setting -o=<OUTPUT_TRACE_DIR>.
    pub fn new(
        file_name: &OsStr,
        bind_to_cpu: usize,
        output_trace_dir: &OsStr,
        ticks_semantics_: TicksSemantics,
    ) {
        unimplemented!()
    }

    /// Called after the calling thread is actually bound to |bind_to_cpu|.
    pub fn setup_cpuid_records(
        has_cpuid_faulting: bool,
        disable_cpuid_features: &DisableCPUIDFeatures,
    ) {
        unimplemented!()
    }

    /// Call close() on all the relevant trace files.
    ///  Normally this will be called by the destructor. It's helpful to
    ///  call this before a crash that won't call the destructor, to ensure
    ///  buffered data is flushed.
    pub fn close(&self, status: CloseStatus, uuid: &TraceUuid) {
        unimplemented!()
    }

    /// We got far enough into recording that we should set this as the latest
    /// trace.
    pub fn make_latest_trace(&self) {
        unimplemented!()
    }

    pub fn ticks_semantics(&self) -> TicksSemantics {
        self.ticks_semantics_
    }

    fn try_hardlink_file(&self, file_name: &OsStr, new_name: &OsStr) -> bool {
        unimplemented!()
    }
    fn try_clone_file(&self, t: &RecordTask, file_name: &OsStr, new_name: &OsStr) {
        unimplemented!()
    }
    fn copy_file(&self, file_name: &OsStr, new_name: &OsStr) {
        unimplemented!()
    }

    fn writer(&self, s: Substream) -> &CompressedWriter {
        &self.writers[s as usize]
    }
    fn writer_mut(&mut self, s: Substream) -> &mut CompressedWriter {
        &mut self.writers[s as usize]
    }
}
