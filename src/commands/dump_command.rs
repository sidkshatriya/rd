use crate::commands::RdCommand;
use crate::trace::trace_reader::TraceReader;
use crate::{RdOptions, RdSubCommand};
use std::io;
use std::io::{stdout, Write};
use std::path::PathBuf;

pub struct DumpCommand<'a> {
    options: &'a RdOptions,
    syscallbuf: bool,
    task_events: bool,
    recorded_metadata: bool,
    mmaps: bool,
    raw_dump: bool,
    statistics: bool,
    tid: Option<u32>,
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
                tid,
                trace_dir,
                event_spec,
            } => DumpCommand {
                options,
                syscallbuf,
                task_events,
                recorded_metadata,
                mmaps,
                raw_dump,
                statistics,
                tid,
                trace_dir: trace_dir.unwrap(),
                event_spec,
            },
            _ => panic!("Unexpected RdSubCommand variant. Not a Dump variant!"),
        }
    }

    fn dump(&self, f: &mut dyn Write) -> io::Result<()> {
        let trace = TraceReader::new(self.trace_dir.as_os_str());
        write!(f, "Uncompressed: {}\n", trace.uncompressed_bytes())?;
        write!(f, "Compressed: {}\n", trace.compressed_bytes())
    }
}

impl<'a> RdCommand for DumpCommand<'a> {
    fn run(&mut self) -> io::Result<()> {
        self.dump(&mut stdout())
    }
}
