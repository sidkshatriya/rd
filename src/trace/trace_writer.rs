use crate::address_space::kernel_mapping::KernelMapping;
use crate::event::{Event, EventType, SignalDeterministic, SignalResolvedDisposition};
use crate::extra_registers::ExtraRegisters;
use crate::kernel_abi::common::preload_interface::mprotect_record;
use crate::kernel_abi::RD_NATIVE_ARCH;
use crate::perf_counters::TicksSemantics;
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::session::record_session::{DisableCPUIDFeatures, TraceUuid};
use crate::task::record_task::record_task::RecordTask;
use crate::trace::compressed_writer::CompressedWriter;
use crate::trace::trace_stream::to_trace_arch;
use crate::trace::trace_stream::{
    MappedData, RawDataMetadata, Substream, TraceRemoteFd, TraceStream, SUBSTREAM_COUNT,
};
use crate::trace::trace_task_event::TraceTaskEvent;
use crate::trace_capnp::SignalDisposition as TraceSignalDisposition;
use crate::trace_capnp::{frame, signal};
use crate::util::{monotonic_now_sec, CPUIDRecord};
use capnp::message;
use libc::{dev_t, ino_t, pid_t};
use std::collections::HashMap;
use std::ffi::c_void;
use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::slice;

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
        &mut self,
        t: &RecordTask,
        ev: &Event,
        maybe_registers: Option<&Registers>,
        maybe_extra_registers: Option<&ExtraRegisters>,
    ) {
        let mut frame_msg = message::Builder::new_default();
        let mut frame = frame_msg.init_root::<frame::Builder>();
        frame.set_tid(t.tid);
        // @TODO In rr ticks are signed. In rd they are not.
        frame.set_ticks(t.tick_count() as i64);
        frame.set_monotonic_sec(monotonic_now_sec());

        {
            let mut mem_writes = frame.reborrow().init_mem_writes(self.raw_recs.len() as u32);
            for (i, r) in self.raw_recs.iter().enumerate() {
                let mut w = mem_writes.reborrow().get(i as u32);
                w.set_tid(r.rec_tid);
                w.set_addr(r.addr.as_usize() as u64);
                w.set_size(r.size as u64);
            }
        }
        self.raw_recs.clear();
        frame.set_arch(to_trace_arch(t.arch()));
        {
            match maybe_registers {
                Some(registers) => {
                    let raw_regs = registers.get_ptrace_for_self_arch();
                    frame.reborrow().init_registers().set_raw(raw_regs);
                }
                None => (),
            }
        }
        {
            match maybe_extra_registers {
                Some(extra_registers) => {
                    let raw_regs = extra_registers.data_bytes();
                    frame.reborrow().init_extra_registers().set_raw(raw_regs);
                }
                None => (),
            }
        }

        {
            let mut event = frame.reborrow().init_event();
            match ev.event_type() {
                EventType::EvInstructionTrap => {
                    event.set_instruction_trap(());
                }
                EventType::EvPatchSyscall => {
                    event.set_patch_syscall(());
                }
                EventType::EvSyscallbufAbortCommit => {
                    event.set_syscallbuf_abort_commit(());
                }
                EventType::EvSyscallbufReset => {
                    event.set_syscallbuf_reset(());
                }
                EventType::EvSched => {
                    event.set_sched(());
                }
                EventType::EvGrowMap => {
                    event.set_grow_map(());
                }
                EventType::EvSignal => {
                    to_trace_signal(event.init_signal(), ev);
                }
                EventType::EvSignalDelivery => {
                    to_trace_signal(event.init_signal_delivery(), ev);
                }
                EventType::EvSignalHandler => {
                    to_trace_signal(event.init_signal_handler(), ev);
                }
                EventType::EvExit => {
                    event.set_exit(());
                }
                EventType::EvSyscallbufFlush => {
                    let e = ev.syscallbuf_flush_event();
                    let data = unsafe {
                        slice::from_raw_parts::<u8>(
                            e.mprotect_records.as_ptr() as *const u8,
                            e.mprotect_records.len() * size_of::<mprotect_record>(),
                        )
                    };

                    event.init_syscallbuf_flush().set_mprotect_records(data);
                }
                EventType::EvSyscall => {
                    // @TODO
                }
                _ => fatal!("Event type not recordable"),
            }
        }
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

    /// Create a trace where the tracess are bound to cpu `bind_to_cpu`. This
    /// data is recorded in the trace. If `bind_to_cpu` is -1 then the tracees
    /// were not bound.
    /// The trace name is determined by |file_name| and _RR_TRACE_DIR (if set)
    /// or by setting -o=<OUTPUT_TRACE_DIR>.
    pub fn new(
        file_name: &OsStr,
        bind_to_cpu: i32,
        output_trace_dir: &OsStr,
        ticks_semantics_: TicksSemantics,
    ) {
        unimplemented!()
    }

    /// Called after the calling thread is actually bound to `bind_to_cpu`.
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

fn to_trace_signal(mut signal: signal::Builder, ev: &Event) {
    let sig_ev = ev.signal_event();
    signal.set_siginfo_arch(to_trace_arch(RD_NATIVE_ARCH));
    let siginfo_data = unsafe {
        slice::from_raw_parts::<u8>(
            &sig_ev.siginfo as *const _ as *const u8,
            size_of::<libc::siginfo_t>(),
        )
    };

    signal.set_siginfo(siginfo_data);
    signal.set_deterministic(sig_ev.deterministic == SignalDeterministic::DeterministicSig);
    signal.set_disposition(to_trace_disposition(sig_ev.disposition));
}

fn to_trace_disposition(disposition: SignalResolvedDisposition) -> TraceSignalDisposition {
    match disposition {
        SignalResolvedDisposition::DispositionFatal => TraceSignalDisposition::Fatal,
        SignalResolvedDisposition::DispositionIgnored => TraceSignalDisposition::Ignored,
        SignalResolvedDisposition::DispositionUserHandler => TraceSignalDisposition::UserHandler,
    }
}
