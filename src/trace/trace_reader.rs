#![allow(clippy::useless_conversion)]

#[cfg(not(feature = "rocksdb"))]
use super::trace_reader_file::TraceReaderFileBackend;

#[cfg(feature = "rocksdb")]
use super::trace_reader_rocksdb::TraceReaderRocksDBBackend;

use crate::{
    bindings::{signal::siginfo_t, sysexits::EX_DATAERR},
    event::{
        Event, EventType, OpenedFd,
        SignalDeterministic::{DeterministicSig, NondeterministicSig},
        SignalEventData, SignalResolvedDisposition, SyscallEventData, SyscallState,
        SyscallbufFlushEventData,
    },
    extra_registers::{ExtraRegisters, Format},
    kernel_abi::{SupportedArch, RD_NATIVE_ARCH},
    log::LogLevel::{LogDebug, LogError},
    perf_counters::TicksSemantics,
    preload_interface::mprotect_record,
    registers::Registers,
    remote_ptr::{RemotePtr, Void},
    session::{address_space::kernel_mapping::KernelMapping, record_session::TraceUuid},
    trace::{
        trace_frame::{FrameTime, TraceFrame},
        trace_stream::{
            latest_trace_symlink, to_trace_arch, trace_save_dir, MappedData,
            MappedDataSource::{SourceFile, SourceTrace, SourceZero},
            RawDataMetadata, Substream, TraceRemoteFd, TraceStream, TRACE_VERSION,
        },
        trace_task_event::{
            TraceTaskEvent, TraceTaskEventClone, TraceTaskEventExec, TraceTaskEventExit,
            TraceTaskEventVariant,
        },
    },
    trace_capnp::{
        frame, header, m_map, signal, task_event, Arch as TraceArch,
        SignalDisposition as TraceSignalDisposition, SyscallState as TraceSyscallState,
        TicksSemantics as TraceTicksSemantics,
    },
    util::{
        dir_exists, find, find_cpuid_record, xsave_layout_from_trace, CPUIDRecord, CPUID_GETXSAVE,
    },
    wait_status::WaitStatus,
};
use capnp::{
    message::{self, ReaderOptions},
    serialize,
    serialize_packed::read_message,
};
use libc::{ino_t, pid_t, time_t, ENOENT};
use nix::{
    errno::errno,
    sys::{
        mman::{MapFlags, ProtFlags},
        stat::{stat, FileStat},
    },
    unistd::{access, AccessFlags},
};
use std::{
    convert::{TryFrom, TryInto},
    ffi::{OsStr, OsString},
    fs::File,
    io::{BufRead, BufReader},
    mem::{size_of, swap},
    ops::{Deref, DerefMut},
    os::unix::ffi::{OsStrExt, OsStringExt},
    process::exit,
    ptr::copy_nonoverlapping,
};

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
pub struct TraceReader {
    trace_reader_backend: Box<dyn TraceReaderBackend>,
    xcr0_: u64,
    cpuid_records_: Vec<CPUIDRecord>,
    raw_recs: Vec<RawDataMetadata>,
    ticks_semantics_: TicksSemantics,
    monotonic_time_: f64,
    uuid_: TraceUuid,
    trace_uses_cpuid_faulting: bool,
    preload_thread_locals_recorded_: bool,
}

impl Clone for TraceReader {
    fn clone(&self) -> Self {
        TraceReader {
            trace_reader_backend: self.trace_reader_backend.make_clone(),
            xcr0_: self.xcr0_,
            cpuid_records_: self.cpuid_records_.clone(),
            raw_recs: self.raw_recs.clone(),
            ticks_semantics_: self.ticks_semantics_,
            monotonic_time_: self.monotonic_time_,
            uuid_: self.uuid_.clone(),
            trace_uses_cpuid_faulting: self.trace_uses_cpuid_faulting,
            preload_thread_locals_recorded_: self.preload_thread_locals_recorded_,
        }
    }
}

impl TraceReader {
    pub fn time(&self) -> FrameTime {
        self.trace_reader_backend.time()
    }

    pub fn trace_stream(&self) -> &TraceStream {
        self.trace_reader_backend.deref()
    }

    pub fn trace_stream_mut(&mut self) -> &mut TraceStream {
        self.trace_reader_backend.deref_mut()
    }

    /// Read relevant data from the trace.
    ///
    /// NB: reading a trace frame has the side effect of ticking
    /// the global time to match the time recorded in the trace
    /// frame.
    pub fn read_frame(&mut self) -> TraceFrame {
        let frame_msg = self
            .trace_reader_backend
            .read_message(Substream::Events)
            .unwrap();
        let frame: frame::Reader = frame_msg.get_root::<frame::Reader>().unwrap();

        self.trace_reader_backend.tick_time();

        let mem_writes = frame.get_mem_writes().unwrap();
        self.raw_recs = Vec::new();
        let mut it = mem_writes.iter();
        while let Some(w) = it.next_back() {
            self.raw_recs.push(RawDataMetadata {
                addr: RemotePtr::new(w.get_addr().try_into().unwrap()),
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
        if !reg_data.is_empty() {
            ret.recorded_regs.set_from_ptrace_for_arch(arch, reg_data);
        }
        let extra_reg_data = frame.get_extra_registers().unwrap().get_raw().unwrap();
        if !extra_reg_data.is_empty() {
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
        let saved_global_time = self.time();
        let validate = maybe_validate.unwrap_or(ValidateSourceFile::Validate);
        if self.trace_reader_backend.at_end(Substream::Mmaps) {
            return None;
        }

        if time_constraint == TimeConstraint::CurrentTimeOnly {
            self.trace_reader_backend.save_state(Substream::Mmaps);
        }

        let map_msg = self
            .trace_reader_backend
            .read_message(Substream::Mmaps)
            .unwrap();

        let map = map_msg.get_root::<m_map::Reader>().unwrap();
        if time_constraint == TimeConstraint::CurrentTimeOnly {
            if map.get_frame_time() as u64 != saved_global_time {
                self.trace_reader_backend.restore_state(Substream::Mmaps);
                return None;
            } else {
                self.trace_reader_backend.discard_state(Substream::Mmaps);
            }
        }

        if let Some(data) = maybe_data {
            if map.get_frame_time() < 0 {
                fatal!("Invalid frameTime");
            }
            data.time = map.get_frame_time() as u64;
            data.data_offset_bytes = 0;
            if map.get_stat_size() < 0 {
                fatal!("Invalid stat size");
            }
            data.file_size_bytes = map.get_stat_size() as usize;
            if let Some(extra_fds) = maybe_extra_fds {
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

            if let Some(fd) = skip_monitoring_mapped_fd {
                *fd = map.get_skip_monitoring_mapped_fd()
            }
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
                        backing_file_name_vec
                            .extend_from_slice(self.trace_stream().dir().as_bytes());
                        backing_file_name_vec.extend_from_slice(b"/");
                    }
                    backing_file_name_vec.extend_from_slice(backing_file_name_int);
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
                        let backing_stat: FileStat;
                        let maybe_file_stat = stat(backing_file_name_vec.as_slice());
                        match maybe_file_stat {
                            Err(e) => fatal!(
                                "Failed to stat {:?}: Replay is impossible. Error: {:?}",
                                backing_file_name,
                                e
                            ),
                            Ok(file_stat) => backing_stat = file_stat,
                        }

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

        Some(KernelMapping::new_with_opts(
            map.get_start().into(),
            map.get_end().into(),
            OsStr::from_bytes(map.get_fsname().unwrap()),
            map.get_device(),
            // On x86 ino_t is a u32 and on x86_64 ino_t is a u64
            map.get_inode().try_into().unwrap(),
            ProtFlags::from_bits(map.get_prot()).unwrap(),
            MapFlags::from_bits(map.get_flags()).unwrap(),
            map.get_file_offset_bytes() as u64,
        ))
    }

    /// Read a task event (clone or exec record) from the trace.
    /// Returns `None` at the end of the trace.
    /// Sets `time` (if non-None) to the global time of the event.
    pub fn read_task_event(
        &mut self,
        maybe_time: Option<&mut FrameTime>,
    ) -> Option<TraceTaskEvent> {
        if self.trace_reader_backend.at_end(Substream::Tasks) {
            return None;
        }

        let task_msg = self
            .trace_reader_backend
            .read_message(Substream::Tasks)
            .unwrap();

        let task: task_event::Reader = task_msg.get_root::<task_event::Reader>().unwrap();
        let tid_ = i32_to_tid(task.get_tid());
        if let Some(frame_time) = maybe_time {
            *frame_time = task.get_frame_time() as u64
        }
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
            data: vec![0u8; rec.size],
            addr: rec.addr,
            rec_tid: rec.rec_tid,
        };
        self.trace_reader_backend
            .read_data_exact(Substream::RawData, &mut d.data)
            .unwrap();
        Some(d)
    }

    /// Like read_raw_data_for_frame, but doesn't actually read the data bytes.
    /// Simply return the raw metadata or `None` if there are no records left.
    pub fn read_raw_data_metadata_for_frame(&mut self) -> Option<RawDataMetadata> {
        if self.raw_recs.is_empty() {
            return None;
        }
        let d = self.raw_recs.pop().unwrap();
        self.trace_reader_backend
            .skip(Substream::RawData, d.size)
            .unwrap();
        Some(d)
    }

    /// Return true if we're at the end of the trace file.
    pub fn at_end(&self) -> bool {
        self.trace_reader_backend.at_end(Substream::Events)
    }

    /// Return the next trace frame, without mutating any stream
    /// state.
    pub fn peek_frame(&mut self) -> Option<TraceFrame> {
        if !self.at_end() {
            let saved_time = self.time();
            self.trace_reader_backend.save_state(Substream::Events);
            let mut saved_raw_recs = Vec::new();
            // self.read_frame() sets self.raw_recs to Vec::new() anyways so this is OK to do
            swap(&mut saved_raw_recs, &mut self.raw_recs);
            let frame = self.read_frame();
            self.trace_reader_backend.restore_state(Substream::Events);
            self.trace_reader_backend.global_time = saved_time;
            self.raw_recs = saved_raw_recs;
            Some(frame)
        } else {
            None
        }
    }

    /// Restore the state of this to what it was just after
    /// `open()`.
    pub fn rewind(&mut self) {
        self.trace_reader_backend.rewind()
    }

    pub fn uncompressed_bytes(&self) -> u64 {
        self.trace_reader_backend.uncompressed_bytes()
    }

    pub fn compressed_bytes(&self) -> u64 {
        self.trace_reader_backend.compressed_bytes()
    }

    /// Open the trace in 'dir'. When 'dir' is the `None`, open the
    /// latest trace.
    pub fn new<T: AsRef<OsStr>>(maybe_dir: Option<T>) -> TraceReader {
        #[cfg(feature = "rocksdb")]
        let mut trace_reader_backend: Box<dyn TraceReaderBackend> =
            Box::new(TraceReaderRocksDBBackend::new(maybe_dir));

        #[cfg(not(feature = "rocksdb"))]
        let mut trace_reader_backend: Box<dyn TraceReaderBackend> =
            Box::new(TraceReaderFileBackend::new(maybe_dir));

        let path = trace_reader_backend.version_path();
        let version_file: File = match File::open(&path) {
            Err(e) => {
                if errno() == ENOENT {
                    let incomplete_path = trace_reader_backend.incomplete_version_path();
                    if access(incomplete_path.as_os_str(), AccessFlags::F_OK).is_ok() {
                        eprintln!(
                            "\nrd: Trace file {:?} found.\n\
                             rd recording terminated abnormally and the trace is incomplete: {:?}.\n",
                            incomplete_path, e
                        );
                    } else {
                        eprintln!(
                            "\nrd: Trace file {:?} not found. There is no trace there: {:?}.\n",
                            path, e
                        );
                    }
                } else {
                    eprintln!("\nrd: Trace file {:?} not readable: {:?}\n", path, e);
                }
                exit(EX_DATAERR as i32);
            }
            Ok(f) => f,
        };
        let mut version_str = String::new();
        let mut buf_reader = BufReader::new(version_file);
        let res = buf_reader.read_line(&mut version_str);
        match res {
            Err(e) => {
                eprintln!("Could not read from the version file {:?}: {:?}", path, e);
                exit(EX_DATAERR as i32);
            }
            Ok(_) => (),
        }

        let maybe_version = version_str.trim().parse::<u32>();
        let version: u32 = match maybe_version {
            Ok(ver) => ver,
            Err(e) => {
                fatal!(
                    "Could not successfully parse version file {:?}: {:?}",
                    path,
                    e
                );
            }
        };

        if TRACE_VERSION != version {
            eprintln!(
                "\nrd: error: Recorded trace {:?} has an incompatible version {}; expected\n\
                 {}.  Did you record {:?} with an older version of rd?  If so,\n\
                 you'll need to replay {:?} with that older version.  Otherwise,\n\
                 your trace is likely corrupted.\n",
                path, version, TRACE_VERSION, path, path
            );
            exit(EX_DATAERR as i32);
        }

        let maybe_res = read_message(&mut buf_reader, ReaderOptions::new());
        let header_msg = match maybe_res {
            Ok(res) => res,
            Err(e) => {
                fatal!("Could not read version file {:?}: {:?}", path, e);
            }
        };

        let header = header_msg.get_root::<header::Reader>().unwrap();
        let bind_to_cpu = header.get_bind_to_cpu();
        debug_assert!(bind_to_cpu >= 0);
        // DIFF NOTE: In rd the bound cpu is Option<u32>.
        // In rr it is signed with -1 denoting unbound.
        trace_reader_backend.bind_to_cpu = if bind_to_cpu == -1 {
            None
        } else if bind_to_cpu >= 0 {
            Some(bind_to_cpu as u32)
        } else {
            fatal!("Unexpected value of `{}` for bound cpu", bind_to_cpu);
        };
        let trace_uses_cpuid_faulting = header.get_has_cpuid_faulting();
        let cpuid_records_bytes = header.get_cpuid_records().unwrap();
        let len = cpuid_records_bytes.len() / size_of::<CPUIDRecord>();
        if cpuid_records_bytes.len() != len * size_of::<CPUIDRecord>() {
            fatal!("Invalid CPUID records length");
        }
        let mut cpuid_records_: Vec<CPUIDRecord> = vec![Default::default(); len];
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
        let mut uuid_ = TraceUuid::zero();
        if uuid_from_trace.len() != uuid_.bytes.len() {
            fatal!("Invalid UUID length");
        }
        uuid_.bytes = uuid_from_trace.try_into().unwrap();

        TraceReader {
            trace_reader_backend,
            xcr0_,
            cpuid_records_,
            ticks_semantics_,
            uuid_,
            trace_uses_cpuid_faulting,
            preload_thread_locals_recorded_,
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

    pub fn xcr0(&self) -> u64 {
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
            // XXX if we want to handle consumption of rd traces created on a different
            // architecture rr build than we're running now, we should convert siginfo
            // formats here.
            fatal!("Could not obtain signal architecture or unsupported siginfo arch");
        }
    }
    let siginfo_data = signal.get_siginfo().unwrap();
    if siginfo_data.len() != size_of::<siginfo_t>() {
        fatal!("Bad siginfo");
    }
    let mut siginfo: siginfo_t = Default::default();
    unsafe {
        copy_nonoverlapping(
            siginfo_data.as_ptr(),
            &raw mut siginfo as *mut u8,
            size_of::<siginfo_t>(),
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

pub(super) fn resolve_trace_name<T: AsRef<OsStr>>(maybe_trace_name: Option<T>) -> OsString {
    if maybe_trace_name.is_none() {
        return latest_trace_symlink();
    }

    let trace_name = maybe_trace_name.unwrap().as_ref().to_os_string();
    // Single-component paths are looked up first in the current directory, next
    // in the default trace dir.
    if find(trace_name.as_bytes(), b"/").is_none() {
        if dir_exists(trace_name.as_os_str()) {
            return trace_name;
        }

        let mut resolved_trace_name: Vec<u8> = Vec::from(trace_save_dir().as_bytes());
        resolved_trace_name.push(b'/');
        resolved_trace_name.extend_from_slice(trace_name.as_bytes());
        if dir_exists(resolved_trace_name.as_slice()) {
            return OsString::from_vec(resolved_trace_name);
        }
    }

    trace_name
}

pub(super) trait TraceReaderBackend: DerefMut<Target = TraceStream> {
    fn make_clone(&self) -> Box<dyn TraceReaderBackend>;

    fn read_message(
        &mut self,
        substream: Substream,
    ) -> Result<message::Reader<serialize::OwnedSegments>, Box<dyn std::error::Error>>;

    fn read_data_exact(
        &mut self,
        substream: Substream,
        buf: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>>;

    fn at_end(&self, substream: Substream) -> bool;

    fn discard_state(&mut self, substream: Substream);

    fn save_state(&mut self, substream: Substream);

    fn restore_state(&mut self, substream: Substream);

    /// Restore the state of this to what it was just after `open()`.
    fn rewind(&mut self);

    fn uncompressed_bytes(&self) -> u64;

    fn compressed_bytes(&self) -> u64;

    fn skip(&mut self, substream: Substream, size: usize)
        -> Result<(), Box<dyn std::error::Error>>;

    fn tick_time(&mut self) {
        self.global_time += 1;
    }
}
