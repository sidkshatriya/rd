use crate::commands::rd_options::{RdOptions, RdSubCommand};
use crate::commands::RdCommand;
use crate::perf_counters::TicksSemantics;
use crate::trace::trace_reader::TraceReader;
use serde::Serialize;
use std::io;
use std::path::PathBuf;

pub struct TraceInfoCommand {
    trace_dir: Option<PathBuf>,
}

impl TraceInfoCommand {
    pub fn new(options: &RdOptions) -> TraceInfoCommand {
        match options.cmd.clone() {
            RdSubCommand::TraceInfo { trace_dir } => TraceInfoCommand { trace_dir },
            _ => panic!("Unexpected RdSubCommand variant. Not a TraceInfo variant!"),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TraceHeader {
    uuid: [u8; 16],
    xcr0: u64,
    bind_to_cpu: u32,
    cpuid_faulting: bool,
    ticks_semantics: String,
    cpuid_records: Vec<[u32; 6]>,
    environ: Vec<String>,
}

impl RdCommand for TraceInfoCommand {
    fn run(&mut self) -> io::Result<()> {
        let mut trace = TraceReader::new(self.trace_dir.as_ref());

        let uuid_bytes = trace.uuid().bytes;
        let xcr0 = trace.xcr0();
        let bind_to_cpu = trace.bound_to_cpu();
        let cpuid_faulting = trace.uses_cpuid_faulting();
        let ticks_semantics = match trace.ticks_semantics() {
            TicksSemantics::TicksRetiredConditionalBranches => "rcb".into(),
            TicksSemantics::TicksTakenBranches => "branches".into(),
        };

        let mut cpuid_records: Vec<[u32; 6]> = Vec::new();
        for r in trace.cpuid_records() {
            cpuid_records.push([
                r.eax_in, r.ecx_in, r.out.eax, r.out.ebx, r.out.ecx, r.out.edx,
            ]);
        }

        let header = TraceHeader {
            uuid: uuid_bytes,
            xcr0,
            bind_to_cpu,
            cpuid_faulting,
            ticks_semantics,
            cpuid_records,
            // @TODO
            environ: vec![],
        };

        let serialized = serde_json::to_string(&header).unwrap();
        println!("{}", serialized);
        Ok(())
    }
}
