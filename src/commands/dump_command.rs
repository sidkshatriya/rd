use crate::address_space::kernel_mapping::KernelMapping;
use crate::commands::RdCommand;
use crate::event::EventType;
use crate::kernel_abi::common::preload_interface::{
    stored_record_size, syscallbuf_hdr, syscallbuf_record,
};
use crate::kernel_metadata::syscall_name;
use crate::log::notifying_abort;
use crate::trace::trace_frame::{FrameTime, TraceFrame};
use crate::trace::trace_reader::{TraceReader, ValidateSourceFile};
use crate::trace::trace_stream;
use crate::trace::trace_stream::{MappedData, MappedDataSource};
use crate::trace::trace_task_event::{TraceTaskEvent, TraceTaskEventType};
use crate::{RdOptions, RdSubCommand};
use nix::sys::mman::{MapFlags, ProtFlags};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::io::{stderr, stdout, Write};
use std::mem::size_of;
use std::path::PathBuf;

pub struct DumpCommand<'a> {
    options: &'a RdOptions,
    dump_syscallbuf: bool,
    dump_task_events: bool,
    dump_recorded_data_metadata: bool,
    dump_mmaps: bool,
    raw_dump: bool,
    statistics: bool,
    only_tid: Option<libc::pid_t>,
    trace_dir: PathBuf,
    event_spec: Option<(u32, Option<u32>)>,
}

impl<'a> DumpCommand<'a> {
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
                options,
                dump_syscallbuf: syscallbuf,
                dump_task_events: task_events,
                dump_recorded_data_metadata: recorded_metadata,
                dump_mmaps: mmaps,
                raw_dump,
                statistics,
                only_tid,
                // @TODO What if the trace dir was not provided
                trace_dir: trace_dir.unwrap(),
                event_spec,
            },
            _ => panic!("Unexpected RdSubCommand variant. Not a Dump variant!"),
        }
    }

    fn dump(&self, f: &mut dyn Write) -> io::Result<()> {
        let mut trace = TraceReader::new(self.trace_dir.as_os_str());

        if self.raw_dump {
            write!(
                f,
                "global_time tid reason ticks \
            hw_interrupts page_faults instructions \
            eax ebx ecx edx esi edi ebp orig_eax esp eip eflags\n"
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

        write!(
            f,
            "// Uncompressed bytes {}, compressed bytes {}, ratio {:.2}\n",
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
        let (start, end): (u64, u64) = match self.event_spec {
            None => (0, std::u32::MAX as u64),
            Some((s, None)) => (s as u64, s as u64),
            Some((s, Some(e))) => (s as u64, e as u64),
        };

        let mut task_events: HashMap<FrameTime, TraceTaskEvent> = HashMap::new();
        let mut last_time: FrameTime = 0;
        loop {
            let mut the_time: FrameTime = 0;
            let maybe_r = trace.read_task_event(Some(&mut the_time));
            if maybe_r.is_none() {
                break;
            }

            if the_time <= last_time {
                fatal!("TraceTaskEvent times non-increasing");
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
                        if data.source == MappedDataSource::SourceZero {
                            fsname = OsString::from("<ZERO>");
                        }

                        // DIFF NOTE: If length is 0 then rr outputs `nil` instead of `0x0`
                        write!(
                            f,
                            "  {{ map_file:{:?}, addr:{:#x}, length:{:#x}, \
                        prot_flags:\"{}\", file_offset:{:#x}, \
                        device:{}, inode:{}, \
                        data_file:{:?}, data_offset:{:#x}, \
                        file_size:{:#x} }}\n",
                            fsname,
                            km.start().as_usize(),
                            km.size(),
                            unsafe { String::from_utf8_unchecked(prot_flags) },
                            km.file_offset_bytes(),
                            km.device(),
                            km.inode(),
                            data.filename,
                            data.data_offset_bytes,
                            data.file_size_bytes
                        )?;
                    }
                }

                while let Some(data) = trace.read_raw_data_metadata_for_frame() {
                    if self.dump_recorded_data_metadata {
                        write!(
                            f,
                            "  {{ tid:{}, addr:{}, length:{} }}\n",
                            data.rec_tid,
                            data.addr.as_usize(),
                            data.size
                        )?;
                    }
                }
                if !self.raw_dump {
                    write!(f, "}}\n")?;
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

impl<'a> RdCommand for DumpCommand<'a> {
    fn run(&mut self) -> io::Result<()> {
        self.dump(&mut stdout())
    }
}

fn dump_task_event(out: &mut dyn Write, event: &TraceTaskEvent) -> io::Result<()> {
    match event.event_type() {
        TraceTaskEventType::Clone(ev) => {
            write!(
                out,
                "  TraceTaskEvent::CLONE tid={} parent={} clone_flags={:#x}\n",
                event.tid(),
                ev.parent_tid(),
                ev.clone_flags()
            )?;
        }
        TraceTaskEventType::Exec(ev) => {
            let filename = format!("{:?}", ev.file_name());
            // WORKAROUND: rr does not display the quotes which the Debug string representation will
            // unfortunately have. So strip it.
            let filename_trimmed = filename.trim_matches('"');
            write!(
                out,
                "  TraceTaskEvent::EXEC tid={} file={}\n",
                event.tid(),
                filename_trimmed
            )?;
        }
        TraceTaskEventType::Exit(ev) => {
            write!(
                out,
                "  TraceTaskEvent::EXIT tid={} status={}\n",
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
        write!(stderr(), "Malformed trace file (bad recorded-bytes count)")?;
        notifying_abort(backtrace::Backtrace::new());
    }
    bytes_remaining = (*flush_hdr_addr).num_rec_bytes;

    let mut record_ptr = flush_hdr_addr.add(1) as *const u8;
    let end_ptr = record_ptr.add(bytes_remaining as usize);
    while record_ptr.lt(&end_ptr) {
        let record = record_ptr as *const syscallbuf_record;
        // Buffered syscalls always use the task arch
        write!(
            out,
            "  {{ syscall:'{}', ret:{:#x}, size:{:#x} }}\n",
            syscall_name((*record).syscallno as i32, frame.regs_ref().arch()),
            (*record).ret,
            (*record).size
        )?;
        if ((*record).size as usize) < size_of::<syscallbuf_record>() {
            write!(stderr(), "Malformed trace file (bad record size)\n")?;
            notifying_abort(backtrace::Backtrace::new());
        }
        record_ptr = record_ptr.add(stored_record_size((*record).size as usize));
    }
    Ok(())
}
