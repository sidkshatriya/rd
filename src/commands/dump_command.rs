use super::exit_result::ExitResult;
use crate::{
    commands::{
        rd_options::{RdOptions, RdSubCommand},
        RdCommand,
    },
    event::EventType,
    flags::Flags,
    kernel_metadata::syscall_name,
    log::notifying_abort,
    preload_interface::{stored_record_size, syscallbuf_hdr, syscallbuf_record},
    session::address_space::kernel_mapping::KernelMapping,
    trace::{
        trace_frame::{FrameTime, TraceFrame},
        trace_reader::{TraceReader, ValidateSourceFile},
        trace_stream,
        trace_stream::{MappedData, MappedDataSource},
        trace_task_event::{TraceTaskEvent, TraceTaskEventVariant},
    },
};
use nix::sys::mman::{MapFlags, ProtFlags};
use std::{
    collections::HashMap,
    ffi::OsString,
    io,
    io::{stdout, Write},
    mem::size_of,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};

pub struct DumpCommand {
    pub dump_syscallbuf: bool,
    pub dump_task_events: bool,
    pub dump_recorded_data_metadata: bool,
    pub dump_mmaps: bool,
    pub raw_dump: bool,
    pub statistics: bool,
    pub only_tid: Option<libc::pid_t>,
    pub trace_dir: Option<PathBuf>,
    pub event_spec: Option<(FrameTime, Option<FrameTime>)>,
}

impl DumpCommand {
    pub fn new(options: &RdOptions) -> DumpCommand {
        match options.cmd.clone() {
            RdSubCommand::Dump {
                syscallbuf,
                task_events,
                recorded_metadata,
                mmaps,
                raw_dump,
                statistics,
                only_tid,
                trace_dir,
                event_spec,
            } => DumpCommand {
                dump_syscallbuf: syscallbuf,
                dump_task_events: task_events,
                dump_recorded_data_metadata: recorded_metadata,
                dump_mmaps: mmaps,
                raw_dump,
                statistics,
                only_tid,
                trace_dir,
                event_spec,
            },
            _ => panic!("Unexpected RdSubCommand variant. Not a Dump variant!"),
        }
    }

    pub fn dump(&self, f: &mut dyn Write) -> io::Result<()> {
        let mut trace = TraceReader::new(self.trace_dir.as_ref());

        if self.raw_dump {
            writeln!(
                f,
                "global_time tid reason ticks \
            hw_interrupts page_faults instructions \
            eax ebx ecx edx esi edi ebp orig_eax esp eip eflags"
            )?;
        }

        self.dump_events_matching(&mut trace, f)?;

        if self.statistics {
            return self.dump_statistics(&mut trace, f);
        }

        Ok(())
    }

    fn dump_statistics(&self, trace: &mut TraceReader, f: &mut dyn Write) -> io::Result<()> {
        let ub = trace.uncompressed_bytes();
        let cb = trace.compressed_bytes();

        writeln!(
            f,
            "// Uncompressed bytes {}, compressed bytes {}, ratio {:.2}",
            ub,
            cb,
            ub / cb
        )
    }

    /// Dump all events from the current to trace that match `self.event_spec` to `f`.
    ///
    /// This function is side-effect-y, in that the trace file isn't
    /// rewound in between matching each spec.  Therefore specs should be
    /// constructed so as to match properly on a serial linear scan; that
    /// is, they should comprise disjoint and monotonically increasing
    /// event sets.  No attempt is made to enforce this or normalize specs.
    fn dump_events_matching(&self, trace: &mut TraceReader, f: &mut dyn Write) -> io::Result<()> {
        let (start, end): (FrameTime, FrameTime) = match self.event_spec {
            None => (0, FrameTime::MAX),
            Some((s, None)) => (s, s),
            Some((s, Some(e))) => (s, e),
        };

        let mut task_events: HashMap<FrameTime, TraceTaskEvent> = HashMap::new();
        let mut last_time: FrameTime = 0;
        loop {
            let mut the_time: FrameTime = 0;
            let maybe_r = trace.read_task_event(Some(&mut the_time));
            if maybe_r.is_none() {
                break;
            }

            if the_time < last_time {
                fatal!(
                    "TraceTaskEvent times non-monotonic (time:{}, last time:{})",
                    the_time,
                    last_time
                );
            }

            let r = maybe_r.unwrap();
            task_events.insert(the_time, r);
            last_time = the_time;
        }

        let process_raw_data = self.dump_syscallbuf || self.dump_recorded_data_metadata;
        while !trace.at_end() {
            let frame = trace.read_frame();
            if end < frame.time() {
                return Ok(());
            }
            if start <= frame.time()
                && frame.time() <= end
                && (self.only_tid.is_none() || self.only_tid.unwrap() == frame.tid())
            {
                if self.raw_dump {
                    frame.dump_raw(Some(f))?;
                } else {
                    frame.dump(Some(f))?;
                }
                if self.dump_syscallbuf {
                    unsafe {
                        dump_syscallbuf_data(trace, f, &frame)?;
                    }
                }
                if self.dump_task_events {
                    task_events
                        .get(&frame.time())
                        .map(|task_event| dump_task_event(f, task_event));
                }

                loop {
                    let mut data: trace_stream::MappedData = Default::default();
                    let maybe_km: Option<KernelMapping> = trace.read_mapped_region(
                        Some(&mut data),
                        Some(ValidateSourceFile::DontValidate),
                        None,
                        None,
                        None,
                    );
                    if maybe_km.is_none() {
                        break;
                    }

                    let km = maybe_km.unwrap();
                    if self.dump_mmaps {
                        let mut prot_flags = Vec::<u8>::new();
                        prot_flags.extend_from_slice(b"rwxp");
                        if !km.prot().contains(ProtFlags::PROT_READ) {
                            prot_flags[0] = b'-';
                        }
                        if !km.prot().contains(ProtFlags::PROT_WRITE) {
                            prot_flags[1] = b'-';
                        }
                        if !km.prot().contains(ProtFlags::PROT_EXEC) {
                            prot_flags[2] = b'-';
                        }
                        if km.flags().contains(MapFlags::MAP_SHARED) {
                            prot_flags[3] = b's';
                        }
                        let mut fsname = km.fsname().to_os_string();
                        if data.source == MappedDataSource::Zero {
                            fsname = OsString::from("<ZERO>");
                        }

                        // In extra compatibility mode the dump has the characters printed
                        // as-is. Otherwise we get a OsString {:?} render which seems more
                        // reasonable by default
                        if Flags::get().extra_compat {
                            write!(f, "  {{ map_file:\"")?;
                            // For example: if a filename contains a special character line \n then we want it
                            // to be printed literally. See the file_name_newline test for instance
                            f.write_all(fsname.as_bytes())?;
                            // DIFF NOTE: If length is 0 then rr outputs `(nil)` instead of `0x0`
                            write!(
                                f,
                                "\", addr:{:#x}, length:{:#x}, \
                                prot_flags:{:?}, file_offset:{:#x}, \
                                device:{}, inode:{}, \
                                data_file:\"",
                                km.start().as_usize(),
                                km.size(),
                                OsString::from_vec(prot_flags),
                                km.file_offset_bytes(),
                                km.device(),
                                km.inode(),
                            )?;
                            // For example: if a filename contains a special character line \n then we want it
                            // to be printed literally. See the file_name_newline test for instance
                            f.write_all(data.filename.as_bytes())?;
                            writeln!(
                                f,
                                "\", data_offset:{:#x}, file_size:{:#x} }}",
                                data.data_offset_bytes, data.file_size_bytes
                            )?;
                        } else {
                            // DIFF NOTE: If length is 0 then rr outputs `(nil)` instead of `0x0`
                            writeln!(
                                f,
                                "  {{ map_file:{:?}, addr:{:#x}, length:{:#x}, \
                                prot_flags:{:?}, file_offset:{:#x}, \
                                device:{}, inode:{}, \
                                data_file:{:?}, data_offset:{:#x}, \
                                file_size:{:#x} }}",
                                fsname,
                                km.start().as_usize(),
                                km.size(),
                                OsString::from_vec(prot_flags),
                                km.file_offset_bytes(),
                                km.device(),
                                km.inode(),
                                data.filename,
                                data.data_offset_bytes,
                                data.file_size_bytes
                            )?;
                        }
                    }
                }

                while let Some(data) = trace.read_raw_data_metadata_for_frame() {
                    if self.dump_recorded_data_metadata {
                        // DIFF NOTE rr prints `(nil)` if addr is 0 or length is 0.
                        writeln!(
                            f,
                            "  {{ tid:{}, addr:{:#x}, length:{:#x} }}",
                            data.rec_tid,
                            data.addr.as_usize(),
                            data.size
                        )?;
                    }
                }
                if !self.raw_dump {
                    writeln!(f, "}}")?;
                }
            } else {
                loop {
                    let mut data = MappedData::default();
                    let maybe_km = trace.read_mapped_region(
                        Some(&mut data),
                        Some(ValidateSourceFile::DontValidate),
                        None,
                        None,
                        None,
                    );
                    if maybe_km.is_none() {
                        break;
                    }
                }
                while process_raw_data && trace.read_raw_data_metadata_for_frame().is_some() {}
            }
        }
        Ok(())
    }
}

impl RdCommand for DumpCommand {
    fn run(&mut self) -> ExitResult<()> {
        match self.dump(&mut stdout()) {
            Ok(()) => ExitResult::Ok(()),
            Err(e) => ExitResult::err_from(e, 1),
        }
    }
}

fn dump_task_event(out: &mut dyn Write, event: &TraceTaskEvent) -> io::Result<()> {
    match event.event_variant() {
        TraceTaskEventVariant::Clone(ev) => {
            writeln!(
                out,
                "  TraceTaskEvent::CLONE tid={} parent={} clone_flags={:#x}",
                event.tid(),
                ev.parent_tid(),
                ev.clone_flags()
            )?;
        }
        TraceTaskEventVariant::Exec(ev) => {
            write!(out, "  TraceTaskEvent::EXEC tid={} file=", event.tid())?;
            out.write_all(ev.file_name().as_bytes())?;
            out.write_all(b"\n")?;
        }
        TraceTaskEventVariant::Exit(ev) => {
            writeln!(
                out,
                "  TraceTaskEvent::EXIT tid={} status={}",
                event.tid(),
                ev.exit_status().get(),
            )?;
        }
    }

    Ok(())
}

unsafe fn dump_syscallbuf_data(
    trace: &mut TraceReader,
    out: &mut dyn Write,
    frame: &TraceFrame,
) -> io::Result<()> {
    if frame.event().event_type() != EventType::EvSyscallbufFlush {
        return Ok(());
    }
    let buf = trace.read_raw_data();
    let mut bytes_remaining = (buf.data.len() - size_of::<syscallbuf_hdr>()) as u32;
    let flush_hdr_addr = buf.data.as_ptr() as *const syscallbuf_hdr;
    if (*flush_hdr_addr).num_rec_bytes > bytes_remaining {
        eprintln!("Malformed trace file (bad recorded-bytes count)");
        notifying_abort(backtrace::Backtrace::new());
    }
    bytes_remaining = (*flush_hdr_addr).num_rec_bytes;

    let mut record_ptr = flush_hdr_addr.add(1) as *const u8;
    let end_ptr = record_ptr.add(bytes_remaining as usize);
    while record_ptr.lt(&end_ptr) {
        let record = record_ptr as *const syscallbuf_record;
        // Buffered syscalls always use the task arch
        writeln!(
            out,
            "  {{ syscall:'{}', ret:{:#x}, size:{:#x} }}",
            syscall_name((*record).syscallno as i32, frame.regs_ref().arch()),
            (*record).ret,
            (*record).size
        )?;
        if ((*record).size as usize) < size_of::<syscallbuf_record>() {
            eprintln!("Malformed trace file (bad record size)");
            notifying_abort(backtrace::Backtrace::new());
        }
        record_ptr = record_ptr.add(stored_record_size((*record).size) as usize);
    }
    Ok(())
}
