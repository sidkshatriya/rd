#![allow(clippy::useless_conversion)]

#[cfg(feature = "rocksdb")]
use super::trace_writer_rocksdb::TraceWriterRocksDBBackend;

#[cfg(not(feature = "rocksdb"))]
use super::trace_writer_file::TraceWriterFileBackend;

use crate::{
    bindings::signal::siginfo_t,
    event::{Event, EventType, SignalDeterministic, SignalResolvedDisposition, SyscallState},
    extra_registers::ExtraRegisters,
    kernel_abi::{syscall_number_for_restart_syscall, RD_NATIVE_ARCH},
    kernel_supplement::{btrfs_ioctl_clone_range_args, BTRFS_IOC_CLONE_, BTRFS_IOC_CLONE_RANGE_},
    log::LogLevel::LogDebug,
    perf_counters::{PerfCounters, TicksSemantics},
    preload_interface::{mprotect_record, SYSCALLBUF_PROTOCOL_VERSION},
    registers::Registers,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::kernel_mapping::KernelMapping,
        record_session::{DisableCPUIDFeatures, TraceUuid},
        task::record_task::RecordTask,
    },
    trace::{
        trace_frame::FrameTime,
        trace_stream::{
            latest_trace_symlink, to_trace_arch, RawDataMetadata, Substream, TraceRemoteFd,
            TraceStream, TRACE_VERSION,
        },
        trace_task_event::{TraceTaskEvent, TraceTaskEventVariant},
    },
    trace_capnp::{
        frame, header, m_map, m_map::source::Which::Trace, signal, task_event,
        SignalDisposition as TraceSignalDisposition, SyscallState as TraceSyscallState,
        TicksSemantics as TraceTicksSemantics,
    },
    util::{
        all_cpuid_records, copy_file, monotonic_now_sec, probably_not_interactive,
        should_copy_mmap_region, write_all, xcr0, CPUIDRecord,
    },
};
use capnp::{message, serialize_packed::write_message};
use libc::{dev_t, ino_t, ioctl, pid_t, EEXIST, STDOUT_FILENO};
use nix::{
    errno::{errno, Errno},
    fcntl::{flock, readlink, FlockArg::LockExclusiveNonblock, OFlag},
    sys::{
        mman::{MapFlags, ProtFlags},
        stat::Mode,
    },
    unistd::unlink,
    Error,
};
use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::{OsStr, OsString},
    fs::{hard_link, rename, File},
    io::Write,
    mem::size_of,
    ops::{Deref, DerefMut},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::symlink,
        io::FromRawFd,
    },
    path::Path,
    slice,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
    /// Trace completed abnormally due to rd error.
    CloseError,
}

/// Trace writing takes the trace directory through a defined set of states.
/// These states can be usefully observed by external programs.
///
/// -- Initially the trace directory does not exist.
/// -- The trace directory is created. It is empty.
/// -- A file `incomplete` is created in the trace directory. It is empty.
/// -- rd takes an exclusive flock() lock on `incomplete`.
/// -- rd writes data to `incomplete` so it is no longer empty. (At this
/// point the data is undefined.) rd may write to the file at any
/// time during recording.
/// -- At the end of trace recording, rd renames `incomplete` to `version`.
/// At this point the trace is complete and ready to replay.
/// -- rd releases its flock() lock on `version`.
///
/// Thus:
/// -- If the trace directory contains the file `version` the trace is valid
/// and ready for replay.
/// -- If the trace directory contains the file `incomplete`, and there is an
/// exclusive flock() lock on that file, rd is still recording (or something
/// is messing with us).
/// -- If the trace directory contains the file `incomplete`, that file
/// does not have an exclusive `flock()` lock on it, and the file is non-empty,
/// rd must have died before the recording was complete.
/// -- If the trace directory contains the file `incomplete`, that file
/// does not have an exclusive `flock()` lock on it, and the file is empty,
/// rd has just started recording (or perhaps died during startup).
/// -- If the trace directory does not contain the file `incomplete`,
/// rd has just started recording (or perhaps died during startup) (or perhaps
/// that isn't a trace directory at all).
pub struct TraceWriter {
    trace_writer_backend: Box<dyn TraceWriterBackend>,
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

impl TraceWriter {
    pub fn time(&self) -> FrameTime {
        self.trace_writer_backend.time()
    }

    pub fn trace_stream(&self) -> &TraceStream {
        self.trace_writer_backend.deref()
    }

    pub fn trace_stream_mut(&mut self) -> &mut TraceStream {
        self.trace_writer_backend.deref_mut()
    }

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
        frame.set_tid(t.tid());
        // DIFF NOTE: In rr ticks are signed. In rd they are not.
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
                            e.mprotect_records.as_ptr().cast::<u8>(),
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
                    match e.write_offset {
                        Some(offset) => {
                            // DIFF NOTE: Offsets in rd are u64 and i64 in rr
                            data.set_write_offset(offset as i64);
                        }
                        None if !e.exec_fds_to_close.is_empty() => {
                            let mut list =
                                data.init_exec_fds_to_close(e.exec_fds_to_close.len() as u32);
                            for (i, &fd) in e.exec_fds_to_close.iter().enumerate() {
                                list.set(i as u32, fd);
                            }
                        }
                        None if !e.opened.is_empty() => {
                            let mut open = data.init_opened_fds(e.opened.len() as u32);
                            for i in 0..e.opened.len() {
                                let mut o = open.reborrow().get(i as u32);
                                let opened = &e.opened[i];
                                o.set_fd(opened.fd);
                                o.set_path(opened.path.as_bytes());
                                o.set_device(opened.device);
                                o.set_inode(opened.inode.into());
                            }
                        }
                        None => (),
                    }
                }
                _ => fatal!("Event type not recordable"),
            }
        }

        match self
            .trace_writer_backend
            .write_message(Substream::Events, &frame_msg)
        {
            Err(e) => fatal!("Unable to write events: {:?}", e),
            Ok(_) => (),
        }

        self.trace_writer_backend.tick_time()
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
            // DIFF NOTE: global_time is a u64 in rd and i64 on rr
            map.set_frame_time(self.time() as i64);
            map.set_start(km.start().as_usize() as u64);
            map.set_end(km.end().as_usize() as u64);
            map.set_fsname(km.fsname().as_bytes());
            map.set_device(km.device());
            map.set_inode(km.inode().into());
            map.set_prot(km.prot().bits());
            map.set_flags(km.flags().bits());
            // DIFF NOTE: file offset is a u64 in rr and i64 in rd
            map.set_file_offset_bytes(km.file_offset_bytes() as i64);
            map.set_stat_mode(stat.st_mode);
            map.set_stat_uid(stat.st_uid);
            map.set_stat_gid(stat.st_gid);
            map.set_stat_size(stat.st_size.into());
            map.set_stat_m_time(stat.st_mtime.into());
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

                if let Some(name) = assumed_immutable {
                    src.reborrow()
                        .init_file()
                        .set_backing_file_name(name.as_bytes());
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

        match self
            .trace_writer_backend
            .write_message(Substream::Mmaps, &map_msg)
        {
            Err(e) => fatal!("Unable to write mmaps: {:?}", e),
            Ok(_) => (),
        }

        self.mmap_count += 1;
        record_in_trace
    }

    /// Write a raw-data record to the trace.
    /// 'addr' is the address in the tracee where the data came from/will be
    /// restored to.
    pub fn write_raw(&mut self, rec_tid: pid_t, d: &[u8], addr: RemotePtr<Void>) {
        self.trace_writer_backend
            .write_data(Substream::RawData, d)
            .unwrap();
        self.raw_recs.push(RawDataMetadata {
            addr,
            rec_tid,
            size: d.len(),
        });
    }

    /// Write a task event (clone or exec record) to the trace.
    pub fn write_task_event(&mut self, event: &TraceTaskEvent) {
        let mut task_msg = message::Builder::new_default();
        let mut task = task_msg.init_root::<task_event::Builder>();
        // DIFF NOTE: This is a u64 in rd and an i64 in rr
        task.set_frame_time(self.time() as i64);
        task.set_tid(event.tid());

        match event.event_variant() {
            TraceTaskEventVariant::Clone(e) => {
                let mut clone = task.init_clone();
                clone.set_parent_tid(e.parent_tid());
                clone.set_own_ns_tid(e.own_ns_tid());
                clone.set_flags(e.clone_flags());
            }
            TraceTaskEventVariant::Exec(e) => {
                let mut exec = task.init_exec();
                exec.set_file_name(e.file_name().as_bytes());
                let event_cmd_line = e.cmd_line();
                let mut cmd_line = exec.reborrow().init_cmd_line(event_cmd_line.len() as u32);
                for i in 0..event_cmd_line.len() {
                    cmd_line.set(i as u32, event_cmd_line[i].as_bytes());
                }
                exec.set_exe_base(e.exe_base().as_usize() as u64);
            }
            TraceTaskEventVariant::Exit(e) => {
                task.init_exit().set_exit_status(e.exit_status().get());
            }
        }

        if let Err(e) = self
            .trace_writer_backend
            .write_message(Substream::Tasks, &task_msg)
        {
            fatal!("Unable to write tasks: {:?}", e);
        }
    }

    /// Create a trace where the traces are bound to cpu `bind_to_cpu`. This
    /// data is recorded in the trace. If `bind_to_cpu` is `None` then the tracees
    /// were not bound.
    /// The trace name is determined by `file_name` and _RD_TRACE_DIR (if set)
    /// or by setting -o=<OUTPUT_TRACE_DIR>.
    pub fn new(
        file_name: &OsStr,
        bind_to_cpu: Option<u32>,
        output_trace_dir: Option<&OsStr>,
        ticks_semantics_: TicksSemantics,
    ) -> TraceWriter {
        #[cfg(feature = "rocksdb")]
        let mut tw = TraceWriter {
            ticks_semantics_,
            mmap_count: 0,
            has_cpuid_faulting_: false,
            trace_writer_backend: Box::new(TraceWriterRocksDBBackend::new(
                file_name,
                output_trace_dir,
                bind_to_cpu,
            )),
            files_assumed_immutable: Default::default(),
            raw_recs: vec![],
            cpuid_records: vec![],
            version_fd: ScopedFd::new(),
            supports_file_data_cloning_: false,
        };

        #[cfg(not(feature = "rocksdb"))]
        let mut tw = TraceWriter {
            ticks_semantics_,
            mmap_count: 0,
            has_cpuid_faulting_: false,
            trace_writer_backend: Box::new(TraceWriterFileBackend::new(
                file_name,
                output_trace_dir,
                bind_to_cpu,
            )),
            files_assumed_immutable: Default::default(),
            raw_recs: vec![],
            cpuid_records: vec![],
            version_fd: ScopedFd::new(),
            supports_file_data_cloning_: false,
        };

        let ver_path = tw.trace_stream().incomplete_version_path();
        tw.version_fd = ScopedFd::open_path_with_mode(
            ver_path.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::S_IWUSR | Mode::S_IRUSR,
        );
        if !tw.version_fd.is_open() {
            fatal!("Unable to create {:?}", ver_path);
        }

        // Take an exclusive lock and hold it until we rename the file at
        // the end of recording and then close our file descriptor.
        match flock(tw.version_fd.as_raw(), LockExclusiveNonblock) {
            Err(e) => fatal!("Unable to lock {:?}: {:?}", ver_path, e),
            Ok(_) => (),
        }

        let buf = format!("{}\n", TRACE_VERSION);
        write_all(tw.version_fd.as_raw(), buf.as_bytes());

        // Test if file data cloning is supported
        let mut version_clone_path_vec: Vec<u8> = tw.trace_stream().dir().to_owned().into_vec();
        version_clone_path_vec.extend_from_slice(b"/tmp_clone");
        let version_clone_path = OsString::from_vec(version_clone_path_vec);
        let version_clone_fd = ScopedFd::open_path_with_mode(
            version_clone_path.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT,
            Mode::S_IWUSR | Mode::S_IRUSR,
        );
        if !version_clone_fd.is_open() {
            fatal!("Unable to create {:?}", version_clone_path);
        }

        let clone_args = btrfs_ioctl_clone_range_args {
            src_fd: tw.version_fd.as_raw() as i64,
            src_offset: 0,
            src_length: buf.len() as u64,
            dest_offset: 0,
        };
        let ret = unsafe {
            libc::ioctl(
                version_clone_fd.as_raw(),
                BTRFS_IOC_CLONE_RANGE_ as _,
                &raw const clone_args,
            )
        };
        if ret == 0 {
            tw.supports_file_data_cloning_ = true;
        }
        // Swallow any error on unlinking
        unlink(version_clone_path.as_os_str()).unwrap_or(());

        if !probably_not_interactive(Some(STDOUT_FILENO)) {
            println!(
                "rd: Saving execution to trace directory {:?}.",
                tw.trace_stream().dir(),
            );
        }
        tw
    }

    /// Called after the calling thread is actually bound to `bind_to_cpu`.
    pub fn setup_cpuid_records(
        &mut self,
        has_cpuid_faulting: bool,
        disable_cpuid_features: &DisableCPUIDFeatures,
    ) {
        self.has_cpuid_faulting_ = has_cpuid_faulting;
        // We are now bound to the selected CPU (if any), so collect CPUID records
        // (which depend on the bound CPU number).
        self.cpuid_records = all_cpuid_records();
        // Modify the recorded cpuid data only if cpuid faulting is available. If it
        // is not available, the tracee will see unmodified data and should also see
        // that in handle_unrecorded_cpuid_fault (which is sourced from this data).
        if has_cpuid_faulting {
            for r in &mut self.cpuid_records {
                disable_cpuid_features.amend_cpuid_data(r.eax_in, r.ecx_in, &mut r.out);
            }
        }
    }

    /// Call close() on all the relevant trace files.
    ///  Normally this will be called by the destructor. It's helpful to
    ///  call this before a crash that won't call the destructor, to ensure
    ///  buffered data is flushed.
    /// If `uuid` is `None` then a uuid will be generated for you.
    pub fn close(&mut self, status: CloseStatus, maybe_uuid: Option<TraceUuid>) {
        self.trace_writer_backend.close();

        let mut header_msg = message::Builder::new_default();
        let mut header = header_msg.init_root::<header::Builder>();
        // DIFF NOTE: In rd the bound cpu is an Option<u32>. In rr it is signed.
        header.set_bind_to_cpu(
            self.trace_stream()
                .bind_to_cpu
                .map_or(-1, |c| c.try_into().unwrap()),
        );
        header.set_has_cpuid_faulting(self.has_cpuid_faulting_);
        let cpuid_data = unsafe {
            slice::from_raw_parts::<u8>(
                self.cpuid_records.as_ptr().cast::<u8>(),
                self.cpuid_records.len() * size_of::<CPUIDRecord>(),
            )
        };
        header.set_cpuid_records(cpuid_data);
        header.set_xcr0(xcr0());
        header.set_ticks_semantics(to_trace_ticks_semantics(
            PerfCounters::default_ticks_semantics(),
        ));
        header.set_syscallbuf_protocol_version(SYSCALLBUF_PROTOCOL_VERSION);
        header.set_preload_thread_locals_recorded(true);
        // Add a random UUID to the trace metadata. This lets tools identify a trace
        // easily.
        match maybe_uuid {
            None => {
                header.set_uuid(TraceUuid::generate_new().inner_bytes());
            }
            Some(uuid) => {
                header.set_uuid(uuid.inner_bytes());
            }
        }
        header.set_ok(status == CloseStatus::CloseOk);
        let mut f = unsafe { File::from_raw_fd(self.version_fd.as_raw()) };
        match write_message(&mut f, &header_msg) {
            Err(e) => fatal!(
                "Unable to write {:?}: {:?}",
                self.trace_stream().incomplete_version_path(),
                e
            ),
            Ok(_) => (),
        }

        let incomplete_path = self.trace_stream().incomplete_version_path();
        let path = self.trace_stream().version_path();
        match rename(&incomplete_path, &path) {
            Err(e) => fatal!("Unable to create version file {:?}: {:?}", path, e),
            Ok(_) => (),
        }

        self.version_fd.close();
    }

    /// We got far enough into recording that we should set this as the latest
    /// trace.
    pub fn make_latest_trace(&self) {
        let link_name = latest_trace_symlink();
        // Try to update the symlink to `self`.  We only try attempt
        // to set the symlink once.  If the link is re-created after
        // we `unlink()` it, then another rd process is racing with us
        // and it "won".  The link is then valid and points at some
        // very-recent trace, so that's good enough.
        //
        // DIFF NOTE: rr swallows any error on unlink. We don't for now.
        match unlink(link_name.as_os_str()) {
            Err(Error::Sys(Errno::ENOENT)) => (),
            Err(e) => fatal!("Unable to unlink {:?}: {:?}", link_name, e),
            Ok(_) => (),
        }

        // Link only the trace name, not the full path, so moving a directory full
        // of traces around doesn't break the latest-trace link.
        let trace_name_path = Path::new(self.trace_stream().dir());
        let trace_name = trace_name_path.file_name().unwrap();
        match symlink(trace_name, &link_name) {
            Err(e) if errno() != EEXIST => {
                fatal!(
                    "Failed to update symlink {:?} to {:?}: {:?}",
                    link_name,
                    trace_name,
                    e
                );
            }
            _ => (),
        }
    }

    pub fn ticks_semantics(&self) -> TicksSemantics {
        self.ticks_semantics_
    }

    fn try_hardlink_file(&self, file_name: &OsStr, new_name: &mut OsString) -> bool {
        let base_file_name = Path::new(file_name).file_name().unwrap();
        let mut path: Vec<u8> = Vec::new();
        write!(path, "mmap_hardlink_{}_", self.mmap_count).unwrap();
        path.extend_from_slice(base_file_name.as_bytes());

        let mut dest_path = Vec::<u8>::new();
        dest_path.extend_from_slice(self.trace_stream().dir().as_bytes());
        dest_path.extend_from_slice(b"/");
        dest_path.extend_from_slice(&path);

        let ret = hard_link(file_name, OsStr::from_bytes(&dest_path));
        if ret.is_err() {
            return false;
        }

        new_name.clear();
        new_name.push(OsStr::from_bytes(&path));
        true
    }

    fn try_clone_file(&self, t: &RecordTask, file_name: &OsStr, new_name: &mut OsString) -> bool {
        if !t.session().as_record().unwrap().use_file_cloning() {
            return false;
        }

        let base_file_name = Path::new(file_name).file_name().unwrap();
        let mut path: Vec<u8> = Vec::new();
        write!(path, "mmap_clone_{}_", self.mmap_count).unwrap();
        path.extend_from_slice(base_file_name.as_bytes());

        let src = ScopedFd::open_path(file_name, OFlag::O_RDONLY);
        if !src.is_open() {
            return false;
        }
        let mut dest_path = Vec::<u8>::new();
        dest_path.extend_from_slice(self.trace_stream().dir().as_bytes());
        dest_path.extend_from_slice(b"/");
        dest_path.extend_from_slice(&path);

        let dest = ScopedFd::open_path_with_mode(
            dest_path.as_slice(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::S_IRWXU,
        );
        if !dest.is_open() {
            return false;
        }

        let ret = unsafe { ioctl(dest.as_raw(), BTRFS_IOC_CLONE_ as _, src.as_raw()) };
        if ret < 0 {
            // maybe not on the same filesystem, or filesystem doesn't support clone?
            // DIFF NOTE: rr swallows an unlink error but we dont for now.
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
        path.extend_from_slice(base_file_name.as_bytes());

        let src = ScopedFd::open_path(file_name, OFlag::O_RDONLY);
        if !src.is_open() {
            return false;
        }
        let mut dest_path = Vec::<u8>::new();
        dest_path.extend_from_slice(self.trace_stream().dir().as_bytes());
        dest_path.extend_from_slice(b"/");
        dest_path.extend_from_slice(&path);

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
}

fn to_trace_signal(mut signal: signal::Builder, ev: &Event) {
    let sig_ev = ev.signal_event();
    signal.set_siginfo_arch(to_trace_arch(RD_NATIVE_ARCH));
    let siginfo_data = unsafe {
        slice::from_raw_parts::<u8>(
            &raw const sig_ev.siginfo as *const u8,
            size_of::<siginfo_t>(),
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
        }
    }
}

/// Given `file_name`, where `file_name` is relative to our root directory
/// but is in the mount namespace of `t`, try to make it a file we can read.
fn try_make_process_file_name(t: &RecordTask, file_name: &OsStr) -> OsString {
    let proc_root = format!("/proc/{}/root", t.tid());
    // /proc/<pid>/root has magical properties; not only is it a link, but
    // it links to a view of the filesystem as the process sees it, taking into
    // account the process mount namespace etc.
    let maybe_ret = readlink(proc_root.as_bytes());
    if maybe_ret.is_err() {
        fatal!("Could not read link `{}'", proc_root);
    }
    let root = maybe_ret.unwrap();

    if !file_name.as_bytes().starts_with(root.as_bytes()) {
        log!(
            LogDebug,
            "File {:?} is outside known root {}",
            file_name,
            proc_root
        );
        return file_name.to_owned();
    }

    let mut process_file_name: Vec<u8> = Vec::from(proc_root.as_bytes());
    let root_len = root.as_bytes().len();
    // @TODO Not sure about the special case of root_len == 1.
    // We probably should simply have the else case regardless
    if root_len == 1 {
        process_file_name.extend_from_slice(file_name.as_bytes());
    } else {
        process_file_name.extend_from_slice(&file_name.as_bytes()[root_len..])
    }

    OsString::from_vec(process_file_name)
}

fn to_trace_ticks_semantics(semantics: TicksSemantics) -> TraceTicksSemantics {
    match semantics {
        TicksSemantics::TicksRetiredConditionalBranches => {
            TraceTicksSemantics::RetiredConditionalBranches
        }
        TicksSemantics::TicksTakenBranches => TraceTicksSemantics::TakenBranches,
    }
}

pub(super) trait TraceWriterBackend: DerefMut<Target = TraceStream> {
    fn write_message(
        &mut self,
        stream: Substream,
        msg: &message::Builder<message::HeapAllocator>,
    ) -> Result<(), Box<dyn std::error::Error>>;

    fn write_data(
        &mut self,
        stream: Substream,
        buf: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>>;

    fn close(&mut self);

    fn tick_time(&mut self) {
        self.global_time += 1;
    }
}
