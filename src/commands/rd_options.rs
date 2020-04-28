use crate::{
    commands::rerun_command::TraceFields,
    flags::{Checksum, DumpOn},
    trace::trace_frame::FrameTime,
};
use std::{error::Error, num::ParseIntError, path::PathBuf};
use structopt::{clap, clap::AppSettings, StructOpt};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "rd",
    about = "The record and debug tool",
    after_help = "Use RD_LOG to control logging; e.g. RD_LOG=all:warn,Task:debug"
)]
#[structopt(global_settings =
&[AppSettings::AllowNegativeNumbers, AppSettings::UnifiedHelpMessage])]
pub struct RdOptions {
    #[structopt(long, help = "disable use of CPUID faulting.")]
    pub disable_cpuid_faulting: bool,

    #[structopt(
        long = "disable-ptrace-exit_events",
        help = "disable use of PTRACE_EVENT_EXIT"
    )]
    pub disable_ptrace_exit_events: bool,

    /// specify the paths that rd should use to find files such as rd_page_*.  These files
    /// should be located in `<resource-path>/bin`, `<resource-path>/lib[64]`, and
    /// `<resource-path>/share` as appropriate.
    #[structopt(parse(from_os_str), long)]
    pub resource_path: Option<PathBuf>,

    /// force rd to assume it's running on a CPU with microarch <microarch> even if runtime
    /// detection says otherwise. <microarch> should be a string like 'Ivy Bridge'. Note that rd
    /// will not work with Intel Merom or Penryn microarchitectures.
    #[structopt(short = "A", long)]
    pub microarch: Option<String>,

    /// force rd to do some things that don't seem like good ideas, for example launching
    /// an interactive emergency debugger if stderr isn't a tty.
    #[structopt(short = "F", long)]
    pub force_things: bool,

    #[structopt(
        short = "K",
        long,
        help = "verify that cached task mmaps match /proc/maps."
    )]
    pub check_cached_mmaps: bool,

    #[structopt(
        short = "E",
        long,
        help = "any warning or error that is printed is treated as fatal."
    )]
    pub fatal_errors: bool,

    #[structopt(
        short = "M",
        long,
        help = "mark stdio writes with `[rr <pid> <ev>]` where <ev> is the global trace time at \
        which the write occurs and <pid> is the pid of the process it occurs in."
    )]
    pub mark_stdio: bool,

    #[structopt(
        short = "S",
        long,
        help = "suppress warnings about issues in the environment that rd has no control over."
    )]
    pub suppress_environment_warnings: bool,

    #[structopt(short = "T", long, help = "dump memory at global time point <time>.")]
    pub dump_at: Option<FrameTime>,

    #[structopt(
    short = "D",
    long,
    help = "where <dump_on> := `ALL` | `RDTSC` | <syscall-no> | -<signal number> \n\n@TODO more details",
    parse(try_from_str = parse_dump_on)
    )]
    pub dump_on: Option<DumpOn>,

    #[structopt(
    short = "C",
    long,
    parse(try_from_str = parse_checksum),
    help = "where <checksum> := `on-syscalls` | `on-all-events` | <from-time>\n\n\
                compute and store (during recording) or read and verify (during replay) checksums \
                of each of a tracee's memory mappings either at the end of all syscalls (`on-syscalls`), \
                at all events (`on-all-events`), or starting from a global timepoint <from-time> \
                (which is a positive integer).",
    )]
    pub checksum: Option<Checksum>,

    #[structopt(subcommand)]
    pub cmd: RdSubCommand,
}

fn parse_checksum(checksum_s: &str) -> Result<Checksum, Box<dyn Error>> {
    if checksum_s == "on-syscalls" {
        Ok(Checksum::ChecksumSyscall)
    } else if checksum_s == "on-all-events" {
        Ok(Checksum::ChecksumAll)
    } else if checksum_s.chars().all(|c| !c.is_ascii_digit()) {
        Err(Box::new(clap::Error::with_description(
            "Only `on-syscalls` or `on-all-events` or an unsigned integer is valid here",
            clap::ErrorKind::InvalidValue,
        )))
    } else {
        Ok(Checksum::ChecksumAt(checksum_s.parse::<FrameTime>()?))
    }
}

fn parse_dump_on(dump_on_s: &str) -> Result<DumpOn, Box<dyn Error>> {
    if dump_on_s == "ALL" {
        Ok(DumpOn::DumpOnAll)
    } else if dump_on_s == "RDTSC" {
        Ok(DumpOn::DumpOnRdtsc)
    } else if dump_on_s.chars().all(|c| c.is_ascii_digit() || c == '-') {
        let signal_or_syscall = dump_on_s.parse::<i32>()?;
        if signal_or_syscall < 0 {
            Ok(DumpOn::DumpOnSignal(-signal_or_syscall as u32))
        } else {
            Ok(DumpOn::DumpOnSyscall(signal_or_syscall as u32))
        }
    } else {
        Err(Box::new(clap::Error::with_description(
            "Only `ALL` or `RDTSC` or an integer value is valid here",
            clap::ErrorKind::InvalidValue,
        )))
    }
}

#[derive(StructOpt, Debug, Clone)]
pub enum RdSubCommand {
    /// Accepts paths on stdin, prints buildids on stdout. Will terminate when either an empty
    /// line or an invalid path is provided.
    #[structopt(name = "buildid")]
    BuildId,

    /// Print `rd record` command line options that will limit the tracee to CPU features
    /// this machine supports. Useful for trace portability: run `rd cpufeatures` on the machine
    /// you plan to replay on, then add those command-line parameters to `rd record` on the
    /// recording machine.
    #[structopt(name = "cpufeatures")]
    CpuFeatures,

    /// dump data from the recorded trace
    #[structopt(name = "dump")]
    Dump {
        #[structopt(short = "b", long, help = "dump syscallbuf events")]
        syscallbuf: bool,

        #[structopt(short = "e", long, help = "dump task events")]
        task_events: bool,

        #[structopt(short = "m", long, help = "dump recorded data metadata")]
        recorded_metadata: bool,

        #[structopt(short = "p", long, help = "dump mmap data")]
        mmaps: bool,

        /// dump trace frames in a more easily machine-parseable
        /// format instead of the default human-readable format"
        #[structopt(short = "r", long = "raw")]
        raw_dump: bool,

        #[structopt(short = "s", long, help = "dump statistics about the trace")]
        statistics: bool,

        #[structopt(
            short = "t",
            long = "tid",
            help = "dump events only for the specified tid"
        )]
        only_tid: Option<libc::pid_t>,

        /// which directory is the trace data in? If omitted the latest trace dir is used
        trace_dir: Option<PathBuf>,

        /// event specs can be either an event number like `127`, or a range
        /// like `1000-5000`. By default, all events are dumped."
        #[structopt(parse(try_from_str = parse_range))]
        event_spec: Option<(FrameTime, Option<FrameTime>)>,
    },

    /// 'rerun' is intended to be a more powerful form of `rd replay -a`. It does
    /// a replay without debugging support, but it provides options for tracing and
    /// dumping tracee state. Initially it supports singlestepping through a range
    /// of trace events, dumping selected register values after each step.
    #[structopt(name = "rerun")]
    ReRun {
        #[structopt(short = "s", long, help = "start tracing at <trace-start>")]
        trace_start: Option<FrameTime>,

        #[structopt(short = "e", long, help = "end tracing at <trace-end>")]
        trace_end: Option<FrameTime>,

        #[structopt(short = "r", long = "raw", help = "dump registers in raw format")]
        raw: bool,

        /// allow replay to run on any CPU. Default is to run on the CPU stored in the trace.
        /// Note that this may diverge from the recording in some cases.
        #[structopt(short = "u", long)]
        cpu_unbound: bool,

        /// when starting tracing, push sentinel return address and jump to <function-addr>
        /// to fake call
        #[structopt(short = "f", long = "function")]
        function_addr: Option<usize>,

        /// <singlestep-regs> is a comma-separated sequence of `event`, `icount'`, `ip`, `flags`,
        /// `gp_x16`, `xmm_x16`, `ymm_x16`. For the `x16` cases, we always output 16,
        ///  values, the latter 8 of which are zero for x86-32. GP registers are in
        ///  architectural order (AX,CX,DX,BX,SP,BP,SI,DI,R8-R15). All data is output
        ///  in little-endian binary format; records are separated by \\n. String
        ///  instruction repetitions are treated as a single instruction if not
        ///  interrupted. A 'singlestep' includes events such as system-call-exit
        ///  where tracee state changes without any user-level instructions actually
        ///  being executed.
        #[structopt(long = "singlestep", parse(try_from_str = crate::commands::rerun_command::parse_regs))]
        singlestep_regs: Option<TraceFields>,

        /// which directory is the trace data in? If omitted the latest trace dir is used
        trace_dir: Option<PathBuf>,
    },
    /// Dump trace header in JSON format.
    #[structopt(name = "traceinfo")]
    TraceInfo {
        /// which directory is the trace data in? If omitted the latest trace dir is used
        trace_dir: Option<PathBuf>,
    },
    /// Dump information on the processes encountered during recording.
    #[structopt(name = "ps")]
    Ps {
        /// which directory is the trace data in? If omitted the latest trace dir is used
        trace_dir: Option<PathBuf>,
    },
}

fn parse_range(range_or_single: &str) -> Result<(FrameTime, Option<FrameTime>), ParseIntError> {
    let args: Vec<&str> = range_or_single.splitn(2, '-').collect();
    let low = args[0].parse::<FrameTime>()?;
    let mut high: Option<FrameTime> = None;
    if args.len() == 2 {
        high = Some(args[1].parse::<FrameTime>()?);
    }
    Ok((low, high))
}
