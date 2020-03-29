use crate::address_space::kernel_mapping::KernelMapping;
use crate::event::{
    Event, EventType, SignalDeterministic, SignalResolvedDisposition, SyscallState,
};
use crate::extra_registers::ExtraRegisters;
use crate::kernel_abi::common::preload_interface::mprotect_record;
use crate::kernel_abi::syscall_number_for_restart_syscall;
use crate::kernel_abi::RD_NATIVE_ARCH;
use crate::kernel_supplement::BTRFS_IOC_CLONE_;
use crate::perf_counters::TicksSemantics;
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::session::record_session::{DisableCPUIDFeatures, TraceUuid};
use crate::task::record_task::record_task::RecordTask;
use crate::trace::compressed_writer::CompressedWriter;
use crate::trace::compressed_writer_output_stream::CompressedWriterOutputStream;
use crate::trace::trace_stream::to_trace_arch;
use crate::trace::trace_stream::MappedDataSource;
use crate::trace::trace_stream::{
    MappedData, RawDataMetadata, Substream, TraceRemoteFd, TraceStream, SUBSTREAM_COUNT,
};
use crate::trace::trace_task_event::TraceTaskEvent;
use crate::trace_capnp::m_map::source::Which::Trace;
use crate::trace_capnp::SignalDisposition as TraceSignalDisposition;
use crate::trace_capnp::SyscallState as TraceSyscallState;
use crate::trace_capnp::{frame, m_map, signal};
use crate::util::{copy_file, monotonic_now_sec, should_copy_mmap_region, CPUIDRecord};
use capnp::private::layout::ListBuilder;
use capnp::serialize_packed::write_message;
use capnp::{message, primitive_list};
use libc::ioctl;
use libc::{dev_t, ino_t, pid_t};
use nix::fcntl::OFlag;
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::stat::Mode;
use nix::unistd::unlink;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::hard_link;
use std::io::Write;
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
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
                    let e = ev.syscall_event();
                    let mut syscall = event.init_syscall();
                    syscall.set_arch(to_trace_arch(e.arch()));
                    let syscall_num = if e.is_restart {
                        syscall_number_for_restart_syscall(t.arch())
                    } else {
                        e.number
                    };

                    syscall.set_number(syscall_num);
                    syscall.set_state(to_trace_syscall_state(e.state));
                    syscall.set_failed_during_preparation(e.failed_during_preparation);
                    let mut data = syscall.init_extra();
                    if e.write_offset.is_some() {
                        // @TODO Offsets in rd are u64 and in rr i64
                        data.set_write_offset(e.write_offset.unwrap() as i64);
                    } else if e.exec_fds_to_close.len() > 0 {
                        let lb = ListBuilder::new_default();
                        let mut primitive_list = primitive_list::Builder::new(lb);
                        for (i, fd) in e.exec_fds_to_close.iter().enumerate() {
                            primitive_list.set(i as u32, *fd);
                        }
                        data.set_exec_fds_to_close(primitive_list.into_reader())
                            .unwrap();
                    } else if e.opened.len() > 0 {
                        let mut open = data.init_opened_fds(e.opened.len() as u32);
                        for i in 0..e.opened.len() {
                            let mut o = open.reborrow().get(i as u32);
                            let opened = &e.opened[i];
                            o.set_fd(opened.fd);
                            o.set_path(opened.path.as_bytes());
                            o.set_device(opened.device);
                            o.set_inode(opened.inode);
                        }
                    }
                }
                _ => fatal!("Event type not recordable"),
            }
        }
    }

    /// Write mapped-region record to the trace.
    /// If this returns `RecordInTrace::RecordInTrace`, then the data for the map should be
    /// recorded in the trace raw-data.
    pub fn write_mapped_region(
        &mut self,
        t: &RecordTask,
        km: &KernelMapping,
        stat: &libc::stat,
        extra_fds: &[TraceRemoteFd],
        maybe_origin: Option<MappingOrigin>,
        maybe_skip_monitoring_mapped_fd: Option<bool>,
    ) -> RecordInTrace {
        let skip_monitoring_mapped_fd = maybe_skip_monitoring_mapped_fd.unwrap_or(false);
        let origin = maybe_origin.unwrap_or(MappingOrigin::SyscallMapping);

        let mut map_msg = message::Builder::new_default();
        let record_in_trace: RecordInTrace;
        {
            let mut map = map_msg.init_root::<m_map::Builder>();
            // @TODO global_time is a u64 in rd and i64 on rr
            map.set_frame_time(self.global_time as i64);
            map.set_start(km.start().as_usize() as u64);
            map.set_end(km.end().as_usize() as u64);
            map.set_fsname(km.fsname().as_bytes());
            map.set_device(km.device());
            map.set_inode(km.inode());
            map.set_prot(km.prot().bits());
            map.set_flags(km.flags().bits());
            // @TODO file offset is a u64 in rr and i64 in rd
            map.set_file_offset_bytes(km.file_offset_bytes() as i64);
            map.set_stat_mode(stat.st_mode);
            map.set_stat_uid(stat.st_uid);
            map.set_stat_gid(stat.st_gid);
            map.set_stat_size(stat.st_size);
            map.set_stat_m_time(stat.st_mtime);
            let mut fds = map.reborrow().init_extra_fds(extra_fds.len() as u32);
            for (i, _) in extra_fds.iter().enumerate() {
                let mut e = fds.reborrow().get(i as u32);
                let r = &extra_fds[i];
                e.set_tid(r.tid);
                e.set_fd(r.fd);
            }
            map.set_skip_monitoring_mapped_fd(skip_monitoring_mapped_fd);
            let mut src = map.get_source();
            let mut backing_file_name = OsString::new();

            if origin == MappingOrigin::RemapMapping
                || origin == MappingOrigin::PatchMapping
                || origin == MappingOrigin::RdBufferMapping
            {
                src.reborrow().set_zero(());
            } else if km.fsname().as_bytes().starts_with(b"/SYSV") {
                src.reborrow().set_trace(());
            } else if origin == MappingOrigin::SyscallMapping
                && (km.inode() == 0 || km.fsname() == "/dev/zero (deleted)")
            {
                src.reborrow().set_zero(());
            } else if !km.fsname().as_bytes().starts_with(b"/") {
                src.reborrow().set_trace(());
            } else {
                let file_name = try_make_process_file_name(t, km.fsname());
                let assumed_immutable = self
                    .files_assumed_immutable
                    .get(&(stat.st_dev, stat.st_ino));

                if assumed_immutable.is_some() {
                    src.reborrow()
                        .init_file()
                        .set_backing_file_name(assumed_immutable.unwrap().as_bytes());
                } else if km.flags().contains(MapFlags::MAP_PRIVATE)
                    && self.try_clone_file(t, &file_name, &mut backing_file_name)
                {
                    src.reborrow()
                        .init_file()
                        .set_backing_file_name(backing_file_name.as_bytes());
                } else if should_copy_mmap_region(km, stat) {
                    // Make executable files accessible to debuggers by copying the whole
                    // thing into the trace directory. We don't get to compress the data and
                    // the entire file is copied, not just the used region, which is why we
                    // don't do this for all files.
                    // Don't bother trying to copy [vdso].
                    // Don't try to copy files that use shared mappings. We do not want to
                    // create a shared mapping of a file stored in the trace. This means
                    // debuggers can't find the file, but the Linux loader doesn't create
                    // shared mappings so situations where a shared-mapped executable contains
                    // usable debug info should be very rare at best...
                    if km.prot().contains(ProtFlags::PROT_EXEC)
                        && self.copy_file(&file_name, &mut backing_file_name)
                        && !km.flags().contains(MapFlags::MAP_SHARED)
                    {
                        src.reborrow()
                            .init_file()
                            .set_backing_file_name(backing_file_name.as_bytes());
                    } else {
                        src.reborrow().set_trace(());
                    }
                } else {
                    // should_copy_mmap_region's heuristics determined it was OK to just map
                    // the file here even if it's MAP_SHARED. So try cloning again to avoid
                    // the possibility of the file changing between recording and replay.
                    if !self.try_clone_file(t, &file_name, &mut backing_file_name) {
                        // Try hardlinking file into the trace directory. This will avoid
                        // replay failures if the original file is deleted or replaced (but not
                        // if it is overwritten in-place). If try_hardlink_file fails it
                        // just returns the original file name.
                        // A relative backing_file_name is relative to the trace directory.
                        if !self.try_hardlink_file(&file_name, &mut backing_file_name) {
                            // Don't ever use `file_name` for the `backing_file_name` because it
                            // contains the pid of a recorded process and will not work!
                            backing_file_name = km.fsname().to_owned();
                        }
                        self.files_assumed_immutable
                            .insert((stat.st_dev, stat.st_ino), backing_file_name.clone());
                    }
                    src.reborrow()
                        .init_file()
                        .set_backing_file_name(backing_file_name.as_bytes());
                }
            }

            record_in_trace = if let Trace(_) = src.which().unwrap() {
                RecordInTrace::RecordInTrace
            } else {
                RecordInTrace::DontRecordInTrace
            }
        }
        let mmaps = self.writer_mut(Substream::Mmaps);
        let mut stream = CompressedWriterOutputStream::new(mmaps);
        if write_message(&mut stream, &map_msg).is_err() {
            fatal!("Unable to write mmaps");
        }

        self.mmap_count += 1;
        record_in_trace
    }

    pub fn write_mapped_region_to_alternative_stream(
        mmaps: &mut CompressedWriter,
        data: &MappedData,
        km: &KernelMapping,
        extra_fds: &[TraceRemoteFd],
        skip_monitoring_mapped_fd: bool,
    ) {
        let mut map_msg = message::Builder::new_default();
        {
            let mut map = map_msg.init_root::<m_map::Builder>();
            // @TODO global_time is a u64 in rd and i64 on rr
            map.set_frame_time(data.time as i64);
            map.set_start(km.start().as_usize() as u64);
            map.set_end(km.end().as_usize() as u64);
            map.set_fsname(km.fsname().as_bytes());
            map.set_device(km.device());
            map.set_inode(km.inode());
            map.set_prot(km.prot().bits());
            map.set_flags(km.flags().bits());
            // @TODO file offset is a u64 in rr and i64 in rd
            map.set_file_offset_bytes(km.file_offset_bytes() as i64);
            map.set_stat_size(data.file_size_bytes as i64);
            let mut fds = map.reborrow().init_extra_fds(extra_fds.len() as u32);
            for (i, _) in extra_fds.iter().enumerate() {
                let mut e = fds.reborrow().get(i as u32);
                let r = &extra_fds[i];
                e.set_tid(r.tid);
                e.set_fd(r.fd);
            }
            map.set_skip_monitoring_mapped_fd(skip_monitoring_mapped_fd);
            let mut src = map.get_source();
            match data.source {
                MappedDataSource::SourceFile => src
                    .init_file()
                    .set_backing_file_name(data.filename.as_bytes()),
                MappedDataSource::SourceTrace => src.set_trace(()),
                MappedDataSource::SourceZero => src.set_zero(()),
            }
        }

        let mut stream = CompressedWriterOutputStream::new(mmaps);
        if write_message(&mut stream, &map_msg).is_err() {
            fatal!("Unable to write mmaps");
        }
    }

    /// Write a raw-data record to the trace.
    /// 'addr' is the address in the tracee where the data came from/will be
    /// restored to.
    pub fn write_raw(&mut self, rec_tid: pid_t, d: &[u8], addr: RemotePtr<Void>) {
        let data = self.writer_mut(Substream::RawData);
        data.write(d);
        self.raw_recs.push(RawDataMetadata {
            addr,
            rec_tid,
            size: d.len(),
        });
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

    fn try_hardlink_file(&self, file_name: &OsStr, new_name: &mut OsString) -> bool {
        let base_file_name = Path::new(file_name).file_name().unwrap();
        let mut path: Vec<u8> = Vec::new();
        write!(path, "mmap_hardlink_{}_", self.mmap_count).unwrap();
        path.copy_from_slice(base_file_name.as_bytes());

        let mut dest_path = Vec::<u8>::new();
        dest_path.copy_from_slice(self.dir().as_bytes());
        write!(dest_path, "/").unwrap();
        dest_path.copy_from_slice(&path);

        let ret = hard_link(file_name, OsStr::from_bytes(&dest_path));
        if ret.is_err() {
            return false;
        }

        new_name.clear();
        new_name.push(OsStr::from_bytes(&path));
        true
    }
    fn try_clone_file(&self, t: &RecordTask, file_name: &OsStr, new_name: &mut OsString) -> bool {
        if !t.session().borrow().as_record().unwrap().use_file_cloning() {
            return false;
        }

        let base_file_name = Path::new(file_name).file_name().unwrap();
        let mut path: Vec<u8> = Vec::new();
        write!(path, "mmap_clone_{}_", self.mmap_count).unwrap();
        path.copy_from_slice(base_file_name.as_bytes());

        let src = ScopedFd::open_path(file_name, OFlag::O_RDONLY);
        if !src.is_open() {
            return false;
        }
        let mut dest_path = Vec::<u8>::new();
        dest_path.copy_from_slice(self.dir().as_bytes());
        write!(dest_path, "/").unwrap();
        dest_path.copy_from_slice(&path);

        let dest = ScopedFd::open_path_with_mode(
            dest_path.as_slice(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::S_IRWXU,
        );
        if !dest.is_open() {
            return false;
        }

        let ret = unsafe { ioctl(dest.as_raw(), BTRFS_IOC_CLONE_, src.as_raw()) };
        if ret < 0 {
            // maybe not on the same filesystem, or filesystem doesn't support clone?
            // @TODO rr swallows an unlink error but we dont for now.
            unlink(dest_path.as_slice()).unwrap();
            return false;
        }

        new_name.clear();
        new_name.push(OsStr::from_bytes(&path));
        true
    }

    fn copy_file(&self, file_name: &OsStr, new_name: &mut OsString) -> bool {
        let base_file_name = Path::new(file_name).file_name().unwrap();
        let mut path: Vec<u8> = Vec::new();
        write!(path, "mmap_clone_{}_", self.mmap_count).unwrap();
        path.copy_from_slice(base_file_name.as_bytes());

        let src = ScopedFd::open_path(file_name, OFlag::O_RDONLY);
        if !src.is_open() {
            return false;
        }
        let mut dest_path = Vec::<u8>::new();
        dest_path.copy_from_slice(self.dir().as_bytes());
        write!(dest_path, "/").unwrap();
        dest_path.copy_from_slice(&path);

        let dest = ScopedFd::open_path_with_mode(
            dest_path.as_slice(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::S_IRWXU,
        );
        if !dest.is_open() {
            return false;
        }

        new_name.clear();
        new_name.push(OsStr::from_bytes(&path));
        copy_file(dest.as_raw(), src.as_raw())
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

fn to_trace_syscall_state(state: SyscallState) -> TraceSyscallState {
    match state {
        SyscallState::EnteringSyscallPtrace => TraceSyscallState::EnteringPtrace,
        SyscallState::EnteringSyscall => TraceSyscallState::Entering,
        SyscallState::ExitingSyscall => TraceSyscallState::Exiting,
        _ => {
            fatal!("Unknown syscall state");
            unreachable!()
        }
    }
}

/// Given `file_name`, where `file_name` is relative to our root directory
/// but is in the mount namespace of `t`, try to make it a file we can read.
fn try_make_process_file_name(t: &RecordTask, file_name: &OsStr) -> OsString {
    unimplemented!()
}
