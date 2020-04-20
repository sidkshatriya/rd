use crate::flags::{Checksum, DumpOn};
use crate::trace::trace_frame::FrameTime;
use std::error::Error;
use std::num::ParseIntError;
use std::path::PathBuf;
use structopt::clap::AppSettings;
use structopt::{clap, StructOpt};

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
    #[structopt(
        parse(from_os_str),
        long,
        help = "specify the paths that rd should use to find files such as rd_page_*.  These files \
        should be located in `<resource-path>/bin`, `<resource-path>/lib[64]`, and `<resource-path>/share` \
        as appropriate."
    )]
    pub resource_path: Option<PathBuf>,
    #[structopt(
        short = "A",
        long,
        help = "force rd to assume it's running on a CPU with microarch <microarch> even if runtime \
        detection says otherwise. <microarch> should be a string like 'Ivy Bridge'. Note that rd \
        will not work with Intel Merom or Penryn microarchitectures."
    )]
    pub microarch: Option<String>,
    #[structopt(
        short = "F",
        long,
        help = "force rd to do some things that don't seem like good ideas, for example launching \
        an interactive emergency debugger if stderr isn't a tty."
    )]
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
    pub dump_at: Option<u64>,
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
    help = "where <checksum> := on-syscalls | on-all-events | <from-time>\n\n\
                compute and store (during recording) or read and verify (during replay) checksums \
                of each of a tracee's memory mappings either at the end of all syscalls (`on-syscalls'), \
                at all events (`on-all-events'), or starting from a global timepoint <from-time> \
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
        Err(Box::new(clap::Error {
            message: "Only `on-syscalls` or `on-all-events` or an unsigned integer is valid here"
                .to_string(),
            kind: clap::ErrorKind::InvalidValue,
            info: None,
        }))
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
        Err(Box::new(clap::Error {
            message: "Only `ALL` or `RDTSC` or an integer value is valid here".to_string(),
            kind: clap::ErrorKind::InvalidValue,
            info: None,
        }))
    }
}

#[derive(StructOpt, Debug, Clone)]
pub enum RdSubCommand {
    /// Accepts paths on stdin, prints buildids on stdout. Will terminate when either an empty
    /// line or an invalid path is provided.
    #[structopt(
        name = "buildid",
        about = "Accepts paths to elf files from stdin, prints elf build ids on stdout."
    )]
    BuildId,
    /// Print `rd record` command line options that will limit the tracee to CPU features
    /// this machine supports. Useful for trace portability: run `rd cpufeatures` on the machine
    /// you plan to replay on, then add those command-line parameters to `rd record` on the
    /// recording machine.
    #[structopt(
        name = "cpufeatures",
        about = "Print `rd record` command line options that will limit the tracee to CPU features \
        this machine supports."
    )]
    CpuFeatures,
    /// dump data from the recorded trace
    #[structopt(name = "dump", about = "Dump data from the recorded trace")]
    Dump {
        #[structopt(short = "b", long, help = "dump syscallbuf events")]
        syscallbuf: bool,
        #[structopt(short = "e", long, help = "dump task events")]
        task_events: bool,
        #[structopt(short = "m", long, help = "dump recorded data metadata")]
        recorded_metadata: bool,
        #[structopt(short = "p", long, help = "dump mmap data")]
        mmaps: bool,
        #[structopt(
            short = "r",
            long = "raw",
            help = "dump trace frames in a more easily machine-parseable \
                    format instead of the default human-readable format"
        )]
        raw_dump: bool,
        #[structopt(short = "s", long, help = "dump statistics about the trace")]
        statistics: bool,
        #[structopt(
            short = "t",
            long = "tid",
            help = "dump events only for the specified tid"
        )]
        only_tid: Option<libc::pid_t>,
        #[structopt(
            help = "which directory is the trace data in? If omitted the latest trace is used"
        )]
        trace_dir: Option<PathBuf>,
        #[structopt(parse(try_from_str = parse_range))]
        #[structopt(
            help = "event specs can be either an event number like `127`, or a range \
                    like `1000-5000`. By default, all events are dumped."
        )]
        event_spec: Option<(u32, Option<u32>)>,
    },
    /// 'rerun' is intended to be a more powerful form of `rd replay -a`. It does
    /// a replay without debugging support, but it provides options for tracing and
    /// dumping tracee state. Initially it supports singlestepping through a range
    /// of trace events, dumping selected register values after each step.
    #[structopt(name = "rerun")]
    ReRun {},
}

fn parse_range(range_or_single: &str) -> Result<(u32, Option<u32>), ParseIntError> {
    let args: Vec<&str> = range_or_single.splitn(2, '-').collect();
    let low = args[0].parse::<u32>()?;
    let mut high: Option<u32> = None;
    if args.len() == 2 {
        high = Some(args[1].parse::<u32>()?);
    }
    Ok((low, high))
}
