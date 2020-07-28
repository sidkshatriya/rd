use crate::{
    commands::rerun_command::TraceFields,
    flags::{Checksum, DumpOn},
    trace::trace_frame::FrameTime,
};
use libc::pid_t;
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    num::ParseIntError,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};
use structopt::{clap, clap::AppSettings, StructOpt};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "rd",
    about = "The record and debug tool",
    after_help = "Use RD_LOG to control logging; e.g. RD_LOG=all:warn,auto_remote_syscalls:debug"
)]
#[structopt(global_settings =
&[AppSettings::AllowNegativeNumbers, AppSettings::UnifiedHelpMessage])]
pub struct RdOptions {
    #[structopt(long, help = "Disable use of CPUID faulting.")]
    pub disable_cpuid_faulting: bool,

    #[structopt(
        long = "disable-ptrace-exit_events",
        help = "Disable use of PTRACE_EVENT_EXIT"
    )]
    pub disable_ptrace_exit_events: bool,

    /// Specify the paths that rd should use to find files such as rr_page_*.  These files
    /// should be located in `<resource-path>/bin`, `<resource-path>/lib[64]`, and
    /// `<resource-path>/share` as appropriate.
    #[structopt(parse(try_from_os_str = parse_resource_path), long)]
    pub resource_path: Option<PathBuf>,

    /// Force rd to assume it's running on a CPU with microarch <microarch> even if runtime
    /// detection says otherwise. <microarch> should be a string like 'Ivy Bridge'. Note that rd
    /// will not work with Intel Merom or Penryn microarchitectures.
    #[structopt(short = "A", long)]
    pub microarch: Option<String>,

    /// Force rd to do some things that don't seem like good ideas, for example launching
    /// an interactive emergency debugger if stderr isn't a tty.
    #[structopt(short = "F", long)]
    pub force_things: bool,

    #[structopt(
        short = "K",
        long,
        help = "Verify that cached task mmaps match /proc/maps."
    )]
    pub check_cached_mmaps: bool,

    #[structopt(
        short = "E",
        long,
        help = "Any warning or error that is printed is treated as fatal."
    )]
    pub fatal_errors: bool,

    #[structopt(
        short = "M",
        long,
        help = "Mark stdio writes with `[rd <pid> <ev>]` where <ev> is the global trace time at \
        which the write occurs and <pid> is the pid of the process it occurs in."
    )]
    pub mark_stdio: bool,

    #[structopt(
        short = "S",
        long,
        help = "Suppress warnings about issues in the environment that rd has no control over."
    )]
    pub suppress_environment_warnings: bool,

    #[structopt(short = "T", long, help = "Dump memory at global time point <time>.")]
    pub dump_at: Option<FrameTime>,

    #[structopt(
    short = "D",
    long,
    help = "Where <dump_on> := `ALL` | `RDTSC` | <syscall-no> | -<signal number> \n\n@TODO more details",
    parse(try_from_str = parse_dump_on)
    )]
    pub dump_on: Option<DumpOn>,

    #[structopt(
    short = "C",
    long,
    parse(try_from_str = parse_checksum),
    help = "Where <checksum> := `on-syscalls` | `on-all-events` | <from-time>\n\n\
                Compute and store (during recording) or read and verify (during replay) checksums \
                of each of a tracee's memory mappings either at the end of all syscalls (`on-syscalls`), \
                at all events (`on-all-events`), or starting from a global timepoint <from-time> \
                (which is a positive integer).",
    )]
    pub checksum: Option<Checksum>,

    #[structopt(subcommand)]
    pub cmd: RdSubCommand,
}

fn parse_resource_path(res_path: &OsStr) -> Result<PathBuf, OsString> {
    let dir_path = PathBuf::from(res_path);
    match dir_path.canonicalize() {
        Err(e) => Err(OsString::from(format!("{:?}", e))),
        Ok(canonicalized) if canonicalized.is_dir() => {
            let mut can_os_str = canonicalized.into_os_string().into_vec();
            can_os_str.extend_from_slice(b"/");
            Ok(PathBuf::from(OsString::from_vec(can_os_str)))
        }
        Ok(canonicallized) => Err(OsString::from(format!(
            "{:?} is not a directory",
            canonicallized
        ))),
    }
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
            Ok(DumpOn::DumpOnSignal(-signal_or_syscall))
        } else {
            Ok(DumpOn::DumpOnSyscall(signal_or_syscall))
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

    /// Dump data from the recorded trace
    #[structopt(name = "dump")]
    Dump {
        /// Dump syscallbuf events
        #[structopt(short = "b", long)]
        syscallbuf: bool,

        /// Dump task events
        #[structopt(short = "e", long)]
        task_events: bool,

        /// Dump recorded data metadata
        #[structopt(short = "m", long)]
        recorded_metadata: bool,

        /// Dump mmap data
        #[structopt(short = "p", long)]
        mmaps: bool,

        /// Dump trace frames in a more easily machine-parseable
        /// format instead of the default human-readable format
        #[structopt(short = "r", long = "raw")]
        raw_dump: bool,

        /// Dump statistics about the trace
        #[structopt(short = "s")]
        statistics: bool,

        /// Dump events only for the specified tid
        #[structopt(short = "t", long = "tid")]
        only_tid: Option<libc::pid_t>,

        /// Which directory is the trace data in? If omitted the latest trace dir is used
        trace_dir: Option<PathBuf>,

        /// Event specs can be either an event number like `127`, or a range
        /// like `1000-5000`. By default, all events are dumped
        #[structopt(parse(try_from_str = parse_range))]
        event_spec: Option<(FrameTime, Option<FrameTime>)>,
    },

    /// Replay a previously recorded trace.
    #[structopt(name = "replay")]
    Replay {
        /// Replay without debugger server
        #[structopt(short = "a", long = "autopilot")]
        autopilot: bool,

        /// Where <onfork> := <pid>. Start a debug server when <pid> has been fork()-end,
        /// AND target event has been reached
        #[structopt(short = "f", long = "onfork", parse(try_from_str = parse_pid))]
        onfork: Option<pid_t>,

        /// Where <goto-event> := <event-num>. Start a debug server on reaching <event-num>
        /// in the trace.  See -M in the general options
        #[structopt(short = "g", long = "goto", parse(try_from_str = parse_goto_event))]
        goto_event: Option<FrameTime>,

        /// Pass an option to the debugger
        #[structopt(short = "o", long = "debugger-option")]
        debugger_option: Option<OsString>,

        /// Where <onprocess> := <pid> | <command> . Start a debug server when <pid> or
        /// <command> has been exec()d, AND the target event has been reached
        #[structopt(short = "p", long = "onprocess", parse(try_from_os_str = parse_onprocess))]
        onprocess: Option<PidOrCommand>,

        /// This is passed directly to gdb. It is here for convenience to support 'gdb --fullname'
        /// as suggested by GNU Emacs"
        #[structopt(long = "fullname")]
        fullname: bool,

        /// This is passed directly to gdb. It is here for convenience to support 'gdb -i=mi'
        /// as suggested by GNU Emacs
        #[structopt(short = "i", long = "interpreter")]
        interpreter: Option<String>,

        /// Use <debugger-file> as the debugger command
        #[structopt(short = "d", long = "debugger")]
        debugger_file: Option<PathBuf>,

        /// Don't replay writes to stdout/stderr
        #[structopt(short = "q", long = "no-redirect-output")]
        no_redirect_output: bool,

        /// Listen address for the debug server. Default listen address is set to localhost
        #[structopt(short = "h", long = "dbghost")]
        dbghost: Option<String>,

        /// Only start a debug server on <dbgport>, don't automatically launch the debugger
        /// client; set <dbgport> to 0 to automatically probe a port
        #[structopt(short = "s", long = "dbgport")]
        dbgport: Option<u16>,

        /// Keep listening after detaching when using --dbgport (-s) mode
        #[structopt(short = "k", long = "keep-listening")]
        keep_listening: bool,

        /// When true make all private mappings shared with the tracee by default
        /// to test the corresponding code.
        #[structopt(long = "share-private-mappings")]
        share_private_mappings: bool,

        /// Singlestep instructions and dump register states when replaying towards <trace-event> or
        /// later
        #[structopt(short = "t", long = "trace")]
        trace_event: Option<FrameTime>,

        /// Allow replay to run on any CPU. Default is to run on the CPU stored in the trace.
        /// Note that this may cause a diverge from the recording in some cases.
        #[structopt(short = "u", long = "cpu-unbound")]
        cpu_unbound: bool,

        /// Execute gdb commands from <gdb-x-file>
        #[structopt(short = "x", long = "gdb-x")]
        gdb_x_file: Option<OsString>,

        /// Display brief stats every N steps (eg 10000)
        #[structopt(long = "stats", parse(try_from_str = parse_stats))]
        stats: Option<u32>,

        /// Which directory is the trace data in? If omitted the latest trace dir is used
        trace_dir: Option<PathBuf>,
        // @TODO There are extra debugger options also passed after a `--`
        // Revisit.
    },

    /// 'rerun' is intended to be a more powerful form of `rd replay -a`. It does
    /// a replay without debugging support, but it provides options for tracing and
    /// dumping tracee state. Initially it supports singlestepping through a range
    /// of trace events, dumping selected register values after each step.
    #[structopt(name = "rerun")]
    ReRun {
        #[structopt(short = "s", long, help = "Start tracing at <trace-start>")]
        trace_start: Option<FrameTime>,

        #[structopt(short = "e", long, help = "End tracing at <trace-end>")]
        trace_end: Option<FrameTime>,

        #[structopt(short = "r", long = "raw", help = "Dump registers in raw format")]
        raw: bool,

        /// Allow replay to run on any CPU. Default is to run on the CPU stored in the trace.
        /// Note that this may cause a diverge from the recording in some cases
        #[structopt(short = "u", long)]
        cpu_unbound: bool,

        /// When starting tracing, push sentinel return address and jump to <function-addr>
        /// to fake call
        #[structopt(short = "f", long = "function")]
        function_addr: Option<usize>,

        /// Where <singlestep-regs> is a comma-separated sequence of `event`, `icount'`, `ip`, `flags`,
        /// `gp_x16`, `xmm_x16`, `ymm_x16`. For the `x16` cases, we always output 16,
        /// values, the latter 8 of which are zero for x86-32. GP registers are in
        /// architectural order (AX,CX,DX,BX,SP,BP,SI,DI,R8-R15). All data is output
        /// in little-endian binary format; records are separated by `\n`. String
        /// instruction repetitions are treated as a single instruction if not
        /// interrupted. A 'singlestep' includes events such as system-call-exit
        /// where tracee state changes without any user-level instructions actually
        /// being executed
        #[structopt(long = "singlestep", parse(try_from_str = crate::commands::rerun_command::parse_regs))]
        singlestep_regs: Option<TraceFields>,

        /// Which directory is the trace data in? If omitted the latest trace dir is used
        trace_dir: Option<PathBuf>,
    },

    /// Dump trace header in JSON format.
    #[structopt(name = "traceinfo")]
    TraceInfo {
        /// Which directory is the trace data in? If omitted the latest trace dir is used
        trace_dir: Option<PathBuf>,
    },

    /// Dump information on the processes encountered during recording.
    #[structopt(name = "ps")]
    Ps {
        /// Which directory is the trace data in? If omitted the latest trace dir is used
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

fn parse_pid(maybe_pid: &str) -> Result<pid_t, Box<dyn Error>> {
    let pid = maybe_pid.trim().parse::<pid_t>()?;
    if pid < 1 {
        Err(Box::new(clap::Error::with_description(
            "pid cannot be 0 or negative",
            clap::ErrorKind::InvalidValue,
        )))
    } else {
        Ok(pid)
    }
}

fn parse_stats(maybe_stats: &str) -> Result<u32, Box<dyn Error>> {
    let stats = maybe_stats.trim().parse::<u32>()?;
    if stats == 0 {
        Err(Box::new(clap::Error::with_description(
            "Please provide a number greater than 0",
            clap::ErrorKind::InvalidValue,
        )))
    } else {
        Ok(stats)
    }
}

fn parse_goto_event(maybe_goto_event: &str) -> Result<FrameTime, Box<dyn Error>> {
    let goto_event = maybe_goto_event.trim().parse::<FrameTime>()?;
    if goto_event == 0 {
        Err(Box::new(clap::Error::with_description(
            "Please provide a number greater than 0",
            clap::ErrorKind::InvalidValue,
        )))
    } else {
        Ok(goto_event)
    }
}

#[derive(Clone, Debug)]
pub enum PidOrCommand {
    Pid(pid_t),
    Command(OsString),
}

fn parse_onprocess(pid_or_command: &OsStr) -> Result<PidOrCommand, OsString> {
    let maybe_pid = String::from_utf8_lossy(pid_or_command.as_bytes());
    if maybe_pid.chars().all(|c| c.is_ascii_digit()) {
        match parse_pid(&maybe_pid) {
            Ok(pid) => Ok(PidOrCommand::Pid(pid)),
            Err(e) => Err(OsString::from(format!("{}", e))),
        }
    } else {
        Ok(PidOrCommand::Command(pid_or_command.into()))
    }
}
