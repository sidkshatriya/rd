use crate::address_space::kernel_mapping::KernelMapping;
use crate::event::{
    Event, EventType, SignalDeterministic, SignalResolvedDisposition, SyscallState,
};
use crate::extra_registers::ExtraRegisters;
use crate::kernel_abi::common::preload_interface::{mprotect_record, SYSCALLBUF_PROTOCOL_VERSION};
use crate::kernel_abi::RD_NATIVE_ARCH;
use crate::kernel_abi::{syscall_number_for_restart_syscall, SupportedArch};
use crate::kernel_supplement::{
    btrfs_ioctl_clone_range_args, BTRFS_IOC_CLONE_, BTRFS_IOC_CLONE_RANGE_,
};
use crate::perf_counters::{PerfCounters, TicksSemantics};
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::session::record_session::{DisableCPUIDFeatures, TraceUuid};
use crate::task::record_task::record_task::RecordTask;
use crate::trace::compressed_writer::CompressedWriter;
use crate::trace::compressed_writer_output_stream::CompressedWriterOutputStream;
use crate::trace::trace_stream::TRACE_VERSION;
use crate::trace::trace_stream::{
    latest_trace_symlink, make_trace_dir, substream, MappedDataSource,
};
use crate::trace::trace_stream::{
    MappedData, RawDataMetadata, Substream, TraceRemoteFd, TraceStream,
};
use crate::trace::trace_task_event::{TraceTaskEvent, TraceTaskEventType};
use crate::trace_capnp::m_map::source::Which::Trace;
use crate::trace_capnp::Arch as TraceArch;
use crate::trace_capnp::SyscallState as TraceSyscallState;
use crate::trace_capnp::{frame, m_map, signal};
use crate::trace_capnp::{
    header, task_event, SignalDisposition as TraceSignalDisposition,
    TicksSemantics as TraceTicksSemantics,
};
use crate::util::{
    all_cpuid_records, copy_file, monotonic_now_sec, probably_not_interactive,
    should_copy_mmap_region, write_all, xcr0, CPUIDRecord,
};
use capnp::private::layout::ListBuilder;
use capnp::serialize_packed::write_message;
use capnp::{message, primitive_list};
use libc::ioctl;
use libc::STDOUT_FILENO;
use libc::{dev_t, ino_t, pid_t};
use nix::errno::errno;
use nix::fcntl::FlockArg::LockExclusiveNonblock;
use nix::fcntl::{flock, OFlag};
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::stat::Mode;
use nix::unistd::unlink;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::fs::{hard_link, rename};
use std::io::{BufWriter, Write};
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
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
    /// @TODO This does not need to be be dynamic as the number of entries is known at
    /// compile time. This could be a [CompressedWriter; SUBSTREAM_COUNT] or a Box of
    /// the same.
    writers: HashMap<Substream, CompressedWriter>,
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
                            o.set_inode(opened.inode.into());
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
            map.set_inode(km.inode().into());
            map.set_prot(km.prot().bits());
            map.set_flags(km.flags().bits());
            // @TODO file offset is a u64 in rr and i64 in rd
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
            map.set_inode(km.inode().into());
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
        data.write(d).unwrap();
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
        // @TODO This is a u64 in rd and an i64 in rr
        task.set_frame_time(self.global_time as i64);
        task.set_tid(event.tid());

        match event.event_type() {
            TraceTaskEventType::Clone(e) => {
                let mut clone = task.init_clone();
                clone.set_parent_tid(e.parent_tid());
                clone.set_own_ns_tid(e.own_ns_tid());
                clone.set_flags(e.clone_flags());
            }
            TraceTaskEventType::Exec(e) => {
                let mut exec = task.init_exec();
                exec.set_file_name(e.file_name().as_bytes());
                let event_cmd_line = e.cmd_line();
                let mut cmd_line = exec.reborrow().init_cmd_line(event_cmd_line.len() as u32);
                for i in 0..event_cmd_line.len() {
                    cmd_line.set(i as u32, event_cmd_line[i].as_bytes());
                }
                exec.set_exe_base(e.exe_base().as_usize() as u64);
            }
            TraceTaskEventType::Exit(e) => {
                task.init_exit().set_exit_status(e.exit_status().get());
            }
        }

        let tasks = self.writer_mut(Substream::Tasks);
        let mut stream = CompressedWriterOutputStream::new(tasks);
        if write_message(&mut stream, &task_msg).is_err() {
            fatal!("Unable to write tasks");
        }
    }

    /// Return true iff all trace files are "good".
    pub fn good(&self) -> bool {
        for w in self.writers.values() {
            if !w.good() {
                return false;
            }
        }
        true
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
    ) -> TraceWriter {
        let mut tw = TraceWriter {
            trace_stream: TraceStream::new(&make_trace_dir(file_name, output_trace_dir), 1),
            ticks_semantics_,
            mmap_count: 0,
            has_cpuid_faulting_: false,
            writers: Default::default(),
            files_assumed_immutable: Default::default(),
            raw_recs: vec![],
            cpuid_records: vec![],
            version_fd: ScopedFd::new(),
            supports_file_data_cloning_: false,
        };

        tw.bind_to_cpu = bind_to_cpu;

        for &s in Substream::iter() {
            tw.writers.insert(
                s,
                CompressedWriter::new(tw.path(s), substream(s).block_size, substream(s).threads),
            );
        }

        let ver_path = tw.incomplete_version_path();
        tw.version_fd = ScopedFd::open_path_with_mode(
            ver_path.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::S_IWUSR | Mode::S_IXUSR,
        );
        if !tw.version_fd.is_open() {
            fatal!("Unable to create {:?}", ver_path);
        }

        // Take an exclusive lock and hold it until we rename the file at
        // the end of recording and then close our file descriptor.
        if flock(tw.version_fd.as_raw(), LockExclusiveNonblock).is_err() {
            fatal!("Unable to lock {:?}", ver_path);
        }
        let buf = format!("{}\n", TRACE_VERSION);
        write_all(tw.version_fd.as_raw(), buf.as_bytes());

        // Test if file data cloning is supported
        let mut version_clone_path_vec: Vec<u8> = tw.trace_dir.clone().into_vec();
        version_clone_path_vec.extend_from_slice(b"/tmp_clone");
        let version_clone_path = OsString::from_vec(version_clone_path_vec);
        let version_clone_fd = ScopedFd::open_path_with_mode(
            version_clone_path.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT,
            Mode::S_IWUSR | Mode::S_IXUSR,
        );
        if !version_clone_fd.is_open() {
            fatal!("Unable to create {:?}", version_clone_path);
        }

        let mut clone_args: btrfs_ioctl_clone_range_args = Default::default();
        clone_args.src_fd = tw.version_fd.as_raw() as i64;
        clone_args.src_offset = 0;
        clone_args.src_length = buf.len() as u64;
        clone_args.dest_offset = 0;
        let ret = unsafe {
            libc::ioctl(
                version_clone_fd.as_raw(),
                BTRFS_IOC_CLONE_RANGE_,
                &clone_args,
            )
        };
        if ret == 0 {
            tw.supports_file_data_cloning_ = true;
        }
        // Swallow any error on unlinking
        unlink(version_clone_path.as_os_str()).unwrap_or(());

        if !probably_not_interactive(Some(STDOUT_FILENO)) {
            println!(
                "rr: Saving execution to trace directory `{:?}'.",
                tw.trace_dir,
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
        for (_, w) in &mut self.writers {
            w.close();
        }

        let mut header_msg = message::Builder::new_default();
        let mut header = header_msg.init_root::<header::Builder>();
        header.set_bind_to_cpu(self.bind_to_cpu);
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
                header.set_uuid(TraceUuid::new().inner_bytes());
            }
            Some(uuid) => {
                header.set_uuid(uuid.inner_bytes());
            }
        }
        header.set_ok(status == CloseStatus::CloseOk);
        let f = unsafe { File::from_raw_fd(self.version_fd.as_raw()) };
        let mut buf_writer = BufWriter::new(f);
        if write_message(&mut buf_writer, &header_msg).is_err() {
            fatal!("Unable to write {:?}", self.incomplete_version_path());
        }
        // We don't want the file to be auto closed so extract raw fd back.
        // Implicit flush also happens.
        buf_writer.into_inner().unwrap().into_raw_fd();

        let incomplete_path = self.incomplete_version_path();
        let path = self.version_path();
        if rename(&incomplete_path, &path).is_err() {
            fatal!("Unable to create version file {:?}", path);
        }
        self.version_fd.close();
    }

    /// We got far enough into recording that we should set this as the latest
    /// trace.
    pub fn make_latest_trace(&self) {
        let link_name = latest_trace_symlink();
        // Try to update the symlink to `self`.  We only try attempt
        // to set the symlink once.  If the link is re-created after
        // we `unlink()` it, then another rr process is racing with us
        // and it "won".  The link is then valid and points at some
        // very-recent trace, so that's good enough.
        //
        // @TODO rr swallows any error on unlink. We don't for now.
        if unlink(link_name.as_os_str()).is_err() {
            fatal!("Unable to unlink {:?}", link_name);
        }

        // Link only the trace name, not the full path, so moving a directory full
        // of traces around doesn't break the latest-trace link.
        let trace_name_path = Path::new(&self.trace_dir);
        let trace_name = trace_name_path.file_name().unwrap();
        let ret = symlink(trace_name, &link_name);
        if ret.is_err() && errno() != libc::EEXIST {
            fatal!(
                "Failed to update symlink `{:?}' to `{:?}'.",
                link_name,
                trace_name
            );
        }
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
        self.writers.get(&s).unwrap()
    }
    fn writer_mut(&mut self, s: Substream) -> &mut CompressedWriter {
        self.writers.get_mut(&s).unwrap()
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
fn try_make_process_file_name(_t: &RecordTask, _file_name: &OsStr) -> OsString {
    unimplemented!()
}

fn to_trace_ticks_semantics(semantics: TicksSemantics) -> TraceTicksSemantics {
    match semantics {
        TicksSemantics::TicksRetiredConditionalBranches => {
            TraceTicksSemantics::RetiredConditionalBranches
        }
        TicksSemantics::TicksTakenBranches => TraceTicksSemantics::TakenBranches,
    }
}

fn to_trace_arch(arch: SupportedArch) -> TraceArch {
    match arch {
        SupportedArch::X86 => TraceArch::X86,
        SupportedArch::X64 => TraceArch::X8664,
    }
}
