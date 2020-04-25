use crate::address_space::kernel_mapping::KernelMapping;
use crate::event::SignalDeterministic::{DeterministicSig, NondeterministicSig};
use crate::event::{
    Event, EventType, OpenedFd, SignalEventData, SyscallEventData, SyscallbufFlushEventData,
};
use crate::event::{SignalResolvedDisposition, SyscallState};
use crate::extra_registers::{ExtraRegisters, Format};
use crate::kernel_abi::common::preload_interface::mprotect_record;
use crate::kernel_abi::{SupportedArch, RD_NATIVE_ARCH};
use crate::log::LogLevel::{LogDebug, LogError};
use crate::perf_counters::TicksSemantics;
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::session::record_session::TraceUuid;
use crate::trace::compressed_reader::{CompressedReader, CompressedReaderState};
use crate::trace::trace_frame::{FrameTime, TraceFrame};
use crate::trace::trace_stream::MappedDataSource::{SourceFile, SourceTrace, SourceZero};
use crate::trace::trace_stream::{
    latest_trace_symlink, to_trace_arch, trace_save_dir, MappedData, RawDataMetadata, Substream,
    TraceRemoteFd, TraceStream, SUBSTREAMS, TRACE_VERSION,
};
use crate::trace::trace_task_event::{
    TraceTaskEvent, TraceTaskEventClone, TraceTaskEventExec, TraceTaskEventExit,
    TraceTaskEventVariant,
};
use crate::trace_capnp::{
    frame, m_map, signal, task_event, SignalDisposition as TraceSignalDisposition,
    SyscallState as TraceSyscallState, TicksSemantics as TraceTicksSemantics,
};
use crate::trace_capnp::{header, Arch as TraceArch};
use crate::util::{
    dir_exists, find, find_cpuid_record, xsave_layout_from_trace, CPUIDRecord, CPUID_GETXSAVE,
};
use crate::wait_status::WaitStatus;
use capnp::message::ReaderOptions;
use capnp::serialize_packed::read_message;
use libc::{ino_t, pid_t, time_t};
use nix::errno::errno;
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::stat::stat;
use nix::sys::stat::FileStat;
use nix::unistd::access;
use nix::unistd::AccessFlags;
use static_assertions::_core::intrinsics::copy_nonoverlapping;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::stderr;
use std::io::Read;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::mem::{size_of, zeroed};
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::process::exit;

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

/// Create a copy of this stream that has exactly the same
/// state as 'other', but for which mutations of this
/// clone won't affect the state of 'other' (and vice versa).
/// @TODO: Currently doing a derive Clone. In case the semantics are not exactly
/// what we want, we will need to implement Clone manually.
#[derive(Clone)]
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
        let mut stream = self.reader_mut(Substream::Events);
        let frame_msg = read_message(&mut stream, ReaderOptions::new()).unwrap();
        let frame: frame::Reader = frame_msg.get_root::<frame::Reader>().unwrap();

        self.tick_time();

        let mem_writes = frame.get_mem_writes().unwrap();
        self.raw_recs = Vec::new();
        let mut it = mem_writes.iter();
        while let Some(w) = it.next_back() {
            self.raw_recs.push(RawDataMetadata {
                addr: RemotePtr::new_from_val(w.get_addr().try_into().unwrap()),
                size: w.get_size().try_into().unwrap(),
                rec_tid: w.get_tid(),
            });
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
                        records.as_mut_ptr() as *mut u8,
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
                                // On x86 ino_t is a u32 and on x86_64 ino_t is a u64
                                inode: fd.get_inode().try_into().unwrap(),
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

    /// DIFF NOTE: `found` param as in rr seems to be unnecessary as we return an Option<KernelMapping>
    pub fn read_mapped_region(
        &mut self,
        maybe_data: Option<&mut MappedData>,
        maybe_validate: Option<ValidateSourceFile>,
        maybe_time_constraint: Option<TimeConstraint>,
        maybe_extra_fds: Option<&mut Vec<TraceRemoteFd>>,
        skip_monitoring_mapped_fd: Option<&mut bool>,
    ) -> Option<KernelMapping> {
        let time_constraint = maybe_time_constraint.unwrap_or(TimeConstraint::CurrentTimeOnly);
        let saved_global_time = self.global_time;
        let validate = maybe_validate.unwrap_or(ValidateSourceFile::Validate);
        let mmaps = self.reader_mut(Substream::Mmaps);
        if mmaps.at_end() {
            return None;
        }

        let mut state: CompressedReaderState = Default::default();
        if time_constraint == TimeConstraint::CurrentTimeOnly {
            state = mmaps.get_state();
        }

        let mut restore = false;
        {
            let map_msg = read_message(mmaps, ReaderOptions::new()).unwrap();

            let map = map_msg.get_root::<m_map::Reader>().unwrap();
            if time_constraint == TimeConstraint::CurrentTimeOnly {
                if map.get_frame_time() as u64 != saved_global_time {
                    restore = true;
                }
            }

            if !restore {
                if maybe_data.is_some() {
                    let data = maybe_data.unwrap();
                    if map.get_frame_time() < 0 {
                        fatal!("Invalid frameTime");
                    }
                    data.time = map.get_frame_time() as u64;
                    data.data_offset_bytes = 0;
                    if map.get_stat_size() < 0 {
                        fatal!("Invalid stat size");
                    }
                    data.file_size_bytes = map.get_stat_size() as usize;
                    if maybe_extra_fds.is_some() {
                        let extra_fds = maybe_extra_fds.unwrap();
                        if map.has_extra_fds() {
                            let fds_reader = map.get_extra_fds().unwrap();
                            for fd in fds_reader.iter() {
                                extra_fds.push(TraceRemoteFd {
                                    tid: fd.get_tid(),
                                    fd: fd.get_fd(),
                                });
                            }
                        }
                    }

                    skip_monitoring_mapped_fd.map(|fd| *fd = map.get_skip_monitoring_mapped_fd());
                    let src = map.get_source();
                    match src.which().unwrap() {
                        m_map::source::Zero(()) => data.source = SourceZero,
                        m_map::source::Trace(()) => data.source = SourceTrace,
                        m_map::source::File(f) => {
                            data.source = SourceFile;
                            let backing_file_name_int = f.get_backing_file_name().unwrap();
                            let is_clone = backing_file_name_int.starts_with(b"mmap_clone_");
                            let is_copy = backing_file_name_int.starts_with(b"mmap_copy_");
                            let mut backing_file_name_vec: Vec<u8> = Vec::new();
                            if backing_file_name_int[0] != b'/' {
                                backing_file_name_vec.extend_from_slice(self.dir().as_bytes());
                                backing_file_name_vec.extend_from_slice(b"/");
                                backing_file_name_vec.extend_from_slice(backing_file_name_int);
                            } else {
                                backing_file_name_vec.extend_from_slice(backing_file_name_int);
                            }
                            let backing_file_name = OsStr::from_bytes(&backing_file_name_vec);
                            let uid = map.get_stat_uid();
                            let gid = map.get_stat_gid();
                            let mode = map.get_stat_mode();
                            let mtime = map.get_stat_m_time();
                            if map.get_stat_size() < 0 {
                                fatal!("Invalid stat size");
                            }
                            let size = map.get_stat_size() as u64;
                            let has_stat_buf = mode != 0 || uid != 0 || gid != 0 || mtime != 0;
                            if !is_clone
                                && !is_copy
                                && validate == ValidateSourceFile::Validate
                                && has_stat_buf
                            {
                                let maybe_file_stat = stat(backing_file_name_vec.as_slice());
                                if maybe_file_stat.is_err() {
                                    fatal!(
                                        "Failed to stat {:?}: replay is impossible",
                                        backing_file_name
                                    );
                                }
                                let backing_stat: FileStat = maybe_file_stat.unwrap();
                                // On x86 ino_t is a u32 and on x86_64 ino_t is a u64
                                if backing_stat.st_ino != ino_t::try_from(map.get_inode()).unwrap()
                                    || backing_stat.st_mode != mode
                                    || backing_stat.st_uid != uid
                                    || backing_stat.st_gid != gid
                                    || backing_stat.st_size as u64 != size
                                    // On x86 mtime is an i32 and on x86_64 it is an i64
                                    || backing_stat.st_mtime != time_t::try_from(mtime).unwrap()
                                {
                                    log!(
                                        LogError,
                                        "Metadata of {:?} changed: replay divergence likely, but continuing anyway.\n\
                                 inode: {}/{}; mode: {}/{}; uid: {}/{}; gid: {}/{}; size: {}/{}; mtime: {}/{}",
                                        OsStr::from_bytes(map.get_fsname().unwrap()),
                                        backing_stat.st_ino,
                                        map.get_inode(),
                                        backing_stat.st_mode,
                                        mode,
                                        backing_stat.st_uid,
                                        uid,
                                        backing_stat.st_gid,
                                        gid,
                                        backing_stat.st_size,
                                        size,
                                        backing_stat.st_mtime,
                                        mtime
                                    );
                                }
                            }
                            data.filename = backing_file_name.to_os_string();
                            let file_offset_bytes = map.get_file_offset_bytes();
                            if file_offset_bytes < 0 {
                                fatal!("Invalid file offset bytes");
                            }
                            data.data_offset_bytes = file_offset_bytes.try_into().unwrap();
                        }
                    }
                }
                return Some(KernelMapping::new_with_opts(
                    map.get_start().into(),
                    map.get_end().into(),
                    OsStr::from_bytes(map.get_fsname().unwrap()),
                    map.get_device(),
                    // On x86 ino_t is a u32 and on x86_64 ino_t is a u64
                    map.get_inode().try_into().unwrap(),
                    ProtFlags::from_bits(map.get_prot()).unwrap(),
                    MapFlags::from_bits(map.get_flags()).unwrap(),
                    map.get_file_offset_bytes() as u64,
                ));
            }
        }

        // This code triggers when `restore` is `true`
        let mmaps_again = self.reader_mut(Substream::Mmaps);
        mmaps_again.restore_state(state);
        None
    }

    /// Read a task event (clone or exec record) from the trace.
    /// Returns `None` at the end of the trace.
    /// Sets `time` (if non-None) to the global time of the event.
    pub fn read_task_event(
        &mut self,
        maybe_time: Option<&mut FrameTime>,
    ) -> Option<TraceTaskEvent> {
        let tasks = self.reader_mut(Substream::Tasks);
        if tasks.at_end() {
            return None;
        }

        let task_msg = read_message(tasks, ReaderOptions::new()).unwrap();

        let task: task_event::Reader = task_msg.get_root::<task_event::Reader>().unwrap();
        let tid_ = i32_to_tid(task.get_tid());
        maybe_time.map(|frame_time| *frame_time = task.get_frame_time() as u64);
        let te: TraceTaskEvent;
        match task.which().unwrap() {
            task_event::Clone(r) => {
                let clone_flags_ = r.get_flags();
                let parent_tid_ = i32_to_tid(r.get_parent_tid());
                let own_ns_tid_ = i32_to_tid(r.get_own_ns_tid());
                log!(
                    LogDebug,
                    "Reading event for {}: parent={} tid={}",
                    task.get_frame_time(),
                    parent_tid_,
                    tid_
                );
                te = TraceTaskEvent {
                    variant: TraceTaskEventVariant::Clone(TraceTaskEventClone {
                        parent_tid_,
                        own_ns_tid_,
                        clone_flags_,
                    }),
                    tid_,
                }
            }
            task_event::Exec(r) => {
                let file_name_ = r.get_file_name().unwrap();
                let cmd_line_reader = r.get_cmd_line().unwrap();
                let mut cmd_line_: Vec<OsString> = Vec::new();
                for cmd in cmd_line_reader.iter() {
                    cmd_line_.push(OsStr::from_bytes(cmd.unwrap()).to_os_string());
                }
                let exe_base_ = r.get_exe_base().into();
                te = TraceTaskEvent {
                    variant: TraceTaskEventVariant::Exec(TraceTaskEventExec {
                        file_name_: OsStr::from_bytes(file_name_).to_os_string(),
                        cmd_line_,
                        exe_base_,
                    }),
                    tid_,
                }
            }
            task_event::Exit(r) => {
                let exit_status_ = WaitStatus::new(r.get_exit_status());
                te = TraceTaskEvent {
                    variant: TraceTaskEventVariant::Exit(TraceTaskEventExit { exit_status_ }),
                    tid_,
                }
            }
        }

        Some(te)
    }

    /// Read the next raw data record for this frame and return it. Aborts if
    /// there are no more raw data records for this frame.
    pub fn read_raw_data(&mut self) -> RawData {
        if let Some(raw_data) = self.read_raw_data_for_frame() {
            raw_data
        } else {
            fatal!("Expected raw data, found none");
            unreachable!()
        }
    }

    /// Return the next raw data record for last-read frame. If there are no more
    /// raw data records for this frame, return `None`.
    pub fn read_raw_data_for_frame(&mut self) -> Option<RawData> {
        if self.raw_recs.is_empty() {
            return None;
        }
        let rec = self.raw_recs.pop().unwrap();
        let mut d = RawData {
            data: Vec::<u8>::new(),
            addr: rec.addr,
            rec_tid: rec.rec_tid,
        };
        d.data.resize(rec.size, 0);
        let nread = self
            .reader_mut(Substream::RawData)
            .read(&mut d.data)
            .unwrap();
        debug_assert_eq!(nread, d.data.len());
        Some(d)
    }

    /// Like read_raw_data_for_frame, but doesn't actually read the data bytes.
    /// Simply return the raw metadata or `None` if there are no records left.
    pub fn read_raw_data_metadata_for_frame(&mut self) -> Option<RawDataMetadata> {
        if self.raw_recs.is_empty() {
            return None;
        }
        let d = self.raw_recs.pop().unwrap();
        self.reader_mut(Substream::RawData).skip(d.size).unwrap();
        Some(d)
    }

    /// Return true if we're at the end of the trace file.
    pub fn at_end(&self) -> bool {
        self.reader(Substream::Events).at_end()
    }

    /// Return the next trace frame, without mutating any stream
    /// state.
    pub fn peek_frame(&mut self) -> Option<TraceFrame> {
        if !self.at_end() {
            let saved_time = self.global_time;
            let state: CompressedReaderState;
            {
                let events = self.reader_mut(Substream::Events);
                state = events.get_state();
            }
            let frame = self.read_frame();
            {
                let events = self.reader_mut(Substream::Events);
                events.restore_state(state);
            }
            self.global_time = saved_time;
            Some(frame)
        } else {
            return None;
        }
    }

    /// Restore the state of this to what it was just after
    /// `open()`.
    pub fn rewind(&mut self) {
        for w in self.readers.values_mut() {
            w.rewind();
        }
        self.global_time = 0;
    }

    pub fn uncompressed_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for w in self.readers.values() {
            total += w.uncompressed_bytes().unwrap();
        }
        total
    }
    pub fn compressed_bytes(&self) -> u64 {
        let mut total: u64 = 0;
        for w in self.readers.values() {
            total += w.compressed_bytes().unwrap();
        }
        total
    }

    /// Open the trace in 'dir'. When 'dir' is the `None`, open the
    /// latest trace.
    ///
    /// @TODO We are writing to stderr() in this method in various places and then exit() with
    /// an error code. This is different from other places where we simply use fatal!(). Need to
    /// review this again.
    pub fn new<T: AsRef<OsStr>>(maybe_dir: Option<&T>) -> TraceReader {
        let mut trace_stream = TraceStream::new(&resolve_trace_name(maybe_dir), 1);

        let mut readers: HashMap<Substream, CompressedReader> = HashMap::new();
        for &s in SUBSTREAMS.iter() {
            readers.insert(s, CompressedReader::new(&trace_stream.path(s)));
        }

        let path = trace_stream.version_path();
        let version_file = File::open(&path);
        if version_file.is_err() {
            if errno() == libc::ENOENT {
                let incomplete_path = trace_stream.incomplete_version_path();
                if access(incomplete_path.as_os_str(), AccessFlags::F_OK).is_ok() {
                    write!(
                        stderr(),
                        "\nrd: Trace file `{:?}' found.\n\
                         rd recording terminated abnormally and the trace is incomplete.\n\n",
                        incomplete_path
                    )
                    .unwrap();
                } else {
                    write!(
                        stderr(),
                        "\nrr: Trace file `{:?}' not found. There is no trace there.\n\n",
                        path
                    )
                    .unwrap();
                }
            } else {
                write!(stderr(), "\nrd: Trace file `{:?}' not readable.\n\n", path).unwrap();
            }
            // @TODO Check if logging flush etc. works as intended
            // @TODO EX_DATAERR = 65
            exit(65);
        }
        let mut version_str = String::new();
        let mut buf_reader = BufReader::new(version_file.unwrap());
        let res = buf_reader.read_line(&mut version_str);
        if res.is_err() {
            write!(
                stderr(),
                "Could not read from the version file `{:?}'",
                path
            )
            .unwrap();
            // @TODO Check if logging flush etc. works as intended
            // @TODO EX_DATAERR = 65
            exit(65);
        }

        let maybe_version = version_str.trim().parse::<u32>();
        let version: u32;
        match maybe_version {
            Ok(ver) => version = ver,
            Err(_) => {
                fatal!("Could not successfully parse version file");
                unreachable!()
            }
        }

        if TRACE_VERSION != version {
            write!(
                stderr(),
                "\nrd: error: Recorded trace `{:?}' has an incompatible version {}; expected\n\
                 {}.  Did you record `{:?}' with an older version of rd?  If so,\n\
                 you'll need to replay `{:?}' with that older version.  Otherwise,\n\
                 your trace is likely corrupted.\n\n",
                path,
                version,
                TRACE_VERSION,
                path,
                path
            )
            .unwrap();
            // @TODO Check if logging flush etc. works as intended
            // @TODO EX_DATAERR = 65
            exit(65);
        }

        let res = read_message(&mut buf_reader, ReaderOptions::new());
        if res.is_err() {
            fatal!("Could not read version file {:?}", path);
        }

        let header_msg = res.unwrap();
        let header = header_msg.get_root::<header::Reader>().unwrap();
        let bind_to_cpu = header.get_bind_to_cpu();
        debug_assert!(bind_to_cpu >= 0);
        // DIFF NOTE: In rd the bound cpu is unsigned. In rr it is signed.
        trace_stream.bind_to_cpu = bind_to_cpu as u32;
        let trace_uses_cpuid_faulting = header.get_has_cpuid_faulting();
        // @TODO Are we sure we an unwrap here?
        let cpuid_records_bytes = header.get_cpuid_records().unwrap();
        let len = cpuid_records_bytes.len() / size_of::<CPUIDRecord>();
        if cpuid_records_bytes.len() != len * size_of::<CPUIDRecord>() {
            fatal!("Invalid CPUID records length");
        }
        let mut cpuid_records_: Vec<CPUIDRecord> = Vec::with_capacity(len);
        cpuid_records_.resize(len, Default::default());
        unsafe {
            copy_nonoverlapping(
                cpuid_records_bytes.as_ptr(),
                cpuid_records_.as_mut_ptr() as *mut u8,
                len * size_of::<CPUIDRecord>(),
            );
        }
        let xcr0_ = header.get_xcr0();
        let preload_thread_locals_recorded_ = header.get_preload_thread_locals_recorded();
        let ticks_semantics_ = from_trace_ticks_semantics(header.get_ticks_semantics().unwrap());
        let uuid_from_trace = header.get_uuid().unwrap();
        let mut uuid_ = TraceUuid::new();
        if uuid_from_trace.len() != uuid_.bytes.len() {
            fatal!("Invalid UUID length");
        }
        uuid_.bytes = uuid_from_trace.try_into().unwrap();

        // Set the global time at 0, so that when we tick it for the first
        // event, it matches the initial global time at recording, 1.
        trace_stream.global_time = 0;
        TraceReader {
            trace_stream,
            xcr0_,
            readers,
            cpuid_records_,
            ticks_semantics_,
            uuid_,
            trace_uses_cpuid_faulting,
            preload_thread_locals_recorded_,
            // @TODO Is this what we want?
            monotonic_time_: 0.0,
            raw_recs: vec![],
        }
    }

    pub fn cpuid_records(&self) -> &[CPUIDRecord] {
        &self.cpuid_records_
    }
    pub fn uses_cpuid_faulting(&self) -> bool {
        self.trace_uses_cpuid_faulting
    }
    pub fn xcr0(&mut self) -> u64 {
        if self.xcr0_ != 0 {
            return self.xcr0_;
        }
        // All valid XCR0 values have bit 0 (x87) == 1. So this is the default
        // value for traces that didn't store XCR0. Assume that the OS enabled
        // all CPU-supported XCR0 bits.
        let maybe_record = find_cpuid_record(&self.cpuid_records_, CPUID_GETXSAVE, 0);
        match maybe_record {
            None => {
                // No XSAVE support at all on the recording CPU??? Assume just
                // x87/SSE enabled.
                3
            }
            Some(record) => ((record.out.edx as u64) << 32) | record.out.eax as u64,
        }
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
            &raw mut siginfo as *mut u8,
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

fn resolve_trace_name<T: AsRef<OsStr>>(maybe_trace_name: Option<&T>) -> OsString {
    if maybe_trace_name.is_none() {
        return latest_trace_symlink();
    }

    let trace_name = maybe_trace_name.unwrap().as_ref();
    // Single-component paths are looked up first in the current directory, next
    // in the default trace dir.
    if find(trace_name, b"/").is_none() {
        if dir_exists(trace_name) {
            return trace_name.to_os_string();
        }

        let mut resolved_trace_name: Vec<u8> = Vec::from(trace_save_dir().as_bytes());
        resolved_trace_name.push(b'/');
        resolved_trace_name.extend_from_slice(trace_name.as_bytes());
        if dir_exists(resolved_trace_name.as_slice()) {
            return OsString::from_vec(resolved_trace_name);
        }
    }

    trace_name.to_os_string()
}
