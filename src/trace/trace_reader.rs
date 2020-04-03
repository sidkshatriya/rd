use crate::address_space::kernel_mapping::KernelMapping;
use crate::event::EventExtraData::SyscallbufFlushEvent;
use crate::event::SignalDeterministic::{DeterministicSig, NondeterministicSig};
use crate::event::{
    Event, EventType, OpenedFd, SignalEventData, SyscallEventData, SyscallbufFlushEventData,
};
use crate::event::{SignalResolvedDisposition, SyscallState};
use crate::extra_registers::{ExtraRegisters, Format};
use crate::kernel_abi::common::preload_interface::mprotect_record;
use crate::kernel_abi::{SupportedArch, RD_NATIVE_ARCH};
use crate::perf_counters::TicksSemantics;
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::session::record_session::TraceUuid;
use crate::trace::compressed_reader::CompressedReader;
use crate::trace::compressed_reader_input_stream::CompressedReaderInputStream;
use crate::trace::trace_frame::{FrameTime, TraceFrame};
use crate::trace::trace_stream::{
    to_trace_arch, MappedData, RawDataMetadata, Substream, TraceRemoteFd, TraceStream,
};
use crate::trace::trace_task_event::TraceTaskEvent;
use crate::trace_capnp::m_map::source::Which::Trace;
use crate::trace_capnp::Arch as TraceArch;
use crate::trace_capnp::{
    frame, header, m_map, signal, task_event, SignalDisposition as TraceSignalDisposition,
    SyscallState as TraceSyscallState, TicksSemantics as TraceTicksSemantics,
};
use crate::util::{xsave_layout_from_trace, CPUIDRecord};
use capnp::message;
use capnp::message::ReaderOptions;
use libc::pid_t;
use static_assertions::_core::intrinsics::copy_nonoverlapping;
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::{OsStr, OsString};
use std::mem::{size_of, zeroed};
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt;

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
    readers: HashMap<Substream, CompressedReader>,
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
    pub fn read_frame(&mut self) -> TraceFrame {
        let events = self.reader(Substream::Events);
        let stream = CompressedReaderInputStream::new(events);
        let frame_msg = message::Reader::new(stream, ReaderOptions::new());
        let frame: frame::Reader = frame_msg.get_root::<frame::Reader>().unwrap();

        self.tick_time();

        let mem_writes = frame.get_mem_writes().unwrap();
        self.raw_recs
            .resize(mem_writes.len() as usize, Default::default());
        let mut it = mem_writes.iter().enumerate();
        while let Some((i, w)) = it.next_back() {
            // Build list in reverse order so we can efficiently pull records from it
            self.raw_recs[i] = RawDataMetadata {
                addr: RemotePtr::new_from_val(w.get_addr().try_into().unwrap()),
                size: w.get_size().try_into().unwrap(),
                rec_tid: w.get_tid(),
            };
        }

        let mut ret = TraceFrame::new();
        ret.global_time = self.time();
        ret.tid_ = i32_to_tid(frame.get_tid());
        if frame.get_ticks() < 0 {
            fatal!("Invalid ticks value");
        }
        ret.ticks_ = frame.get_ticks() as u64;
        ret.monotonic_time_ = frame.get_monotonic_sec();
        self.monotonic_time_ = ret.monotonic_time_;

        let arch = from_trace_arch(frame.get_arch().unwrap());
        ret.recorded_regs = Registers::new(arch);
        let reg_data = frame.get_registers().unwrap().get_raw().unwrap();
        if reg_data.len() > 0 {
            ret.recorded_regs.set_from_ptrace_for_arch(arch, reg_data);
        }
        let extra_reg_data = frame.get_extra_registers().unwrap().get_raw().unwrap();
        if extra_reg_data.len() > 0 {
            let ok = ret.recorded_extra_regs.set_to_raw_data(
                arch,
                Format::XSave,
                extra_reg_data,
                xsave_layout_from_trace(self.cpuid_records()),
            );
            if !ok {
                fatal!("Invalid XSAVE data in trace");
            }
        } else {
            ret.recorded_extra_regs = ExtraRegisters::new(arch);
        }

        let event = frame.get_event();
        let which = event.which().unwrap();
        match which {
            frame::event::InstructionTrap(()) => ret.ev = Event::instruction_trap(),
            frame::event::PatchSyscall(()) => ret.ev = Event::patch_syscall(),
            frame::event::SyscallbufAbortCommit(()) => ret.ev = Event::syscallbuf_abort_commit(),
            frame::event::SyscallbufReset(()) => ret.ev = Event::syscallbuf_reset(),
            frame::event::Sched(()) => ret.ev = Event::sched(),
            frame::event::GrowMap(()) => ret.ev = Event::grow_map(),
            frame::event::Signal(Ok(s)) => ret.ev = from_trace_signal(EventType::EvSignal, s),
            frame::event::SignalDelivery(Ok(s)) => {
                ret.ev = from_trace_signal(EventType::EvSignalDelivery, s)
            }
            frame::event::SignalHandler(Ok(s)) => {
                ret.ev = from_trace_signal(EventType::EvSignalHandler, s)
            }
            frame::event::Exit(()) => ret.ev = Event::exit(),
            frame::event::SyscallbufFlush(r) => {
                ret.ev = Event::new_syscallbuf_flush_event(SyscallbufFlushEventData::new());
                let mprotect_records = r.get_mprotect_records().unwrap();
                let records = &mut ret.ev.syscallbuf_flush_event_mut().mprotect_records;
                records.resize(
                    mprotect_records.len() / size_of::<mprotect_record>(),
                    Default::default(),
                );
                unsafe {
                    copy_nonoverlapping(
                        mprotect_records as *const _ as *const u8,
                        records.as_mut_ptr() as *mut _ as *mut u8,
                        records.len() * size_of::<mprotect_record>(),
                    );
                }
            }
            frame::event::Syscall(r) => {
                ret.ev = Event::new_syscall_event(SyscallEventData::new(
                    r.get_number(),
                    from_trace_arch(r.get_arch().unwrap()),
                ));
                let syscall_ev = ret.ev.syscall_event_mut();
                syscall_ev.state = from_trace_syscall_state(r.get_state().unwrap());
                syscall_ev.failed_during_preparation = r.get_failed_during_preparation();
                let data = r.get_extra();
                match data.which().unwrap() {
                    frame::event::syscall::extra::None(()) => (),
                    frame::event::syscall::extra::WriteOffset(offset) => {
                        if offset < 0 {
                            fatal!("Write offset out of range");
                        }
                        syscall_ev.write_offset = Some(offset as u64);
                    }
                    frame::event::syscall::extra::ExecFdsToClose(Ok(fds_reader)) => {
                        let fds: Vec<i32> = fds_reader.iter().collect();
                        syscall_ev.exec_fds_to_close.extend_from_slice(&fds);
                    }
                    frame::event::syscall::extra::OpenedFds(Ok(rr)) => {
                        for fd in rr.iter() {
                            let opened_fd = OpenedFd {
                                path: OsStr::from_bytes(fd.get_path().unwrap()).to_os_string(),
                                fd: fd.get_fd(),
                                device: fd.get_device(),
                                inode: fd.get_inode(),
                            };
                            syscall_ev.opened.push(opened_fd);
                        }
                    }
                    _ => fatal!("Unknown syscall type or error encountered in decode"),
                }
            }
            _ => fatal!("Event type not supported or error encountered in decode"),
        }

        ret
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
        &self.readers.get(&s).unwrap()
    }
    fn reader_mut(&mut self, s: Substream) -> &mut CompressedReader {
        self.readers.get_mut(&s).unwrap()
    }
}

fn from_trace_arch(arch: TraceArch) -> SupportedArch {
    match arch {
        TraceArch::X86 => SupportedArch::X86,
        TraceArch::X8664 => SupportedArch::X64,
    }
}

fn from_trace_disposition(disposition: TraceSignalDisposition) -> SignalResolvedDisposition {
    match disposition {
        TraceSignalDisposition::Fatal => SignalResolvedDisposition::DispositionFatal,
        TraceSignalDisposition::Ignored => SignalResolvedDisposition::DispositionIgnored,
        TraceSignalDisposition::UserHandler => SignalResolvedDisposition::DispositionUserHandler,
    }
}

fn from_trace_syscall_state(state: TraceSyscallState) -> SyscallState {
    match state {
        TraceSyscallState::EnteringPtrace => SyscallState::EnteringSyscallPtrace,
        TraceSyscallState::Entering => SyscallState::EnteringSyscall,
        TraceSyscallState::Exiting => SyscallState::ExitingSyscall,
    }
}

fn from_trace_signal(event_type: EventType, signal: signal::Reader) -> Event {
    let native: TraceArch = to_trace_arch(RD_NATIVE_ARCH);
    match signal.get_siginfo_arch() {
        Ok(arch) if arch == native => (),
        _ => {
            // XXX if we want to handle consumption of rr traces created on a different
            // architecture rr build than we're running now, we should convert siginfo
            // formats here.
            fatal!("Could not obtain signal architecture or unsupported siginfo arch");
        }
    }
    let siginfo_data = signal.get_siginfo().unwrap();
    if siginfo_data.len() != size_of::<libc::siginfo_t>() {
        fatal!("Bad siginfo");
    }
    let mut siginfo: libc::siginfo_t = unsafe { zeroed() };
    unsafe {
        copy_nonoverlapping(
            siginfo_data.as_ptr(),
            &mut siginfo as *mut _ as *mut u8,
            size_of::<libc::siginfo_t>(),
        );
    }

    let deterministic = if signal.get_deterministic() {
        DeterministicSig
    } else {
        NondeterministicSig
    };

    let sig_event = SignalEventData::new(
        &siginfo,
        deterministic,
        from_trace_disposition(signal.get_disposition().unwrap()),
    );
    Event::new_signal_event(event_type, sig_event)
}

fn from_trace_ticks_semantics(semantics: TraceTicksSemantics) -> TicksSemantics {
    match semantics {
        TraceTicksSemantics::RetiredConditionalBranches => {
            TicksSemantics::TicksRetiredConditionalBranches
        }
        TraceTicksSemantics::TakenBranches => TicksSemantics::TicksTakenBranches,
    }
}

fn i32_to_tid(tid: i32) -> pid_t {
    if tid <= 0 {
        fatal!("Invalid tid");
    }
    tid
}
