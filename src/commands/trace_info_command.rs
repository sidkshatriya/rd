use super::exit_result::ExitResult;
use crate::{
    commands::{
        rd_options::{RdOptions, RdSubCommand},
        RdCommand,
    },
    perf_counters::TicksSemantics,
    session::{
        replay_session::{Flags, ReplaySession, ReplayStatus},
        session_inner::RunCommand,
    },
    trace::trace_reader::TraceReader,
    util::read_env,
};
use serde::Serialize;
use std::{convert::TryInto, ffi::CString, io, path::PathBuf};

pub struct TraceInfoCommand {
    trace_dir: Option<PathBuf>,
}

impl TraceInfoCommand {
    pub fn new(options: &RdOptions) -> TraceInfoCommand {
        match options.cmd.clone() {
            RdSubCommand::TraceInfo { trace_dir } => TraceInfoCommand { trace_dir },
            _ => panic!("Unexpected RdSubCommand variant. Not a `TraceInfo` variant!"),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TraceHeader {
    uuid: [u8; 16],
    xcr0: u64,
    bind_to_cpu: i32,
    cpuid_faulting: bool,
    ticks_semantics: String,
    cpuid_records: Vec<[u32; 6]>,
    environ: Vec<String>,
}

impl RdCommand for TraceInfoCommand {
    fn run(&mut self) -> ExitResult<()> {
        let trace = TraceReader::new(self.trace_dir.as_ref());

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

        let flags = Flags {
            redirect_stdio: false,
            share_private_mappings: false,
            cpu_unbound: true,
        };
        let session = ReplaySession::create(self.trace_dir.as_ref(), flags);
        let replay_session = session.as_replay().unwrap();

        let environ: Vec<CString>;
        loop {
            let result = replay_session.replay_step(RunCommand::RunContinue);
            if replay_session.done_initial_exec() {
                environ = read_env(&**replay_session.current_task().unwrap());
                break;
            }

            if result.status == ReplayStatus::ReplayExited {
                return ExitResult::err_from(
                    io::Error::new(io::ErrorKind::Other, "Replay finished before initial exec!"),
                    1,
                );
            }
        }
        let environ_strings: Vec<String> = environ
            .iter()
            .map(|c_str| c_str.to_string_lossy().into_owned())
            .collect();
        let header = TraceHeader {
            uuid: uuid_bytes,
            xcr0,
            bind_to_cpu: bind_to_cpu.map_or(-1, |c| c.try_into().unwrap()),
            cpuid_faulting,
            ticks_semantics,
            cpuid_records,
            environ: environ_strings,
        };

        let serialized = serde_json::to_string(&header).unwrap();
        println!("{}", serialized);
        ExitResult::Ok(())
    }
}
