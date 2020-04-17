use crate::address_space::kernel_mapping::KernelMapping;
use crate::commands::RdCommand;
use crate::trace::trace_frame::FrameTime;
use crate::trace::trace_reader::{TraceReader, ValidateSourceFile};
use crate::trace::trace_stream;
use crate::trace::trace_stream::MappedData;
use crate::trace::trace_task_event::TraceTaskEvent;
use crate::{RdOptions, RdSubCommand};
use std::collections::HashMap;
use std::io;
use std::io::{stdout, Write};
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
                    // @TODO
                }
                if self.dump_task_events {
                    // @TODO
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
                        // @TODO
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
