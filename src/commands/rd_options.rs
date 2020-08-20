use crate::{
    commands::rerun_command::TraceFields,
    flags::{Checksum, DumpOn},
    kernel_metadata::signal_name,
    kernel_supplement::_NSIG,
    scheduler::TicksHowMany,
    session::record_session::TraceUuid,
    ticks::Ticks,
    trace::trace_frame::FrameTime,
    util::find,
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
    #[structopt(
        short = "z",
        long = "output-options-chosen",
        help = "Output the options chosen (for debugging only)."
    )]
    pub output_options_chosen: bool,

    #[structopt(
        long = "disable-cpuid-faulting",
        help = "Disable use of CPUID faulting."
    )]
    pub disable_cpuid_faulting: bool,

    #[structopt(
        long = "disable-ptrace-exit_events",
        help = "Disable use of PTRACE_EVENT_EXIT"
    )]
    pub disable_ptrace_exit_events: bool,

    /// Specify the paths that rd should use to find files such as rr_page_*.  These files
    /// should be located in `<resource-path>/bin`, `<resource-path>/lib[64]`, and
    /// `<resource-path>/share` as appropriate.
    #[structopt(parse(try_from_os_str = parse_resource_path), long="resource-path")]
    pub resource_path: Option<PathBuf>,

    /// Force rd to assume it's running on a CPU with microarch <microarch> even if runtime
    /// detection says otherwise. <microarch> should be a string like 'Ivy Bridge'. Note that rd
    /// will not work with Intel Merom or Penryn microarchitectures.
    #[structopt(short = "A", long = "microarch")]
    pub microarch: Option<String>,

    /// Force rd to do some things that don't seem like good ideas, for example launching
    /// an interactive emergency debugger if stderr isn't a tty.
    #[structopt(short = "F", long = "force-things")]
    pub force_things: bool,

    #[structopt(
        short = "K",
        long = "check-cached-maps",
        help = "Verify that cached task mmaps match /proc/maps."
    )]
    pub check_cached_mmaps: bool,

    #[structopt(
        short = "E",
        long = "fatal-errors",
        help = "Any warning or error that is printed is treated as fatal."
    )]
    pub fatal_errors: bool,

    #[structopt(
        short = "M",
        long = "mark-stdio",
        help = "Mark stdio writes with `[rd <pid> <ev>]` where <ev> is the global trace time at \
        which the write occurs and <pid> is the pid of the process it occurs in."
    )]
    pub mark_stdio: bool,

    #[structopt(
        short = "S",
        long = "suppress-environmental-warnings",
        help = "Suppress warnings about issues in the environment that rd has no control over."
    )]
    pub suppress_environment_warnings: bool,

    #[structopt(
        short = "T",
        long = "dump-at",
        help = "Dump memory at global time point <time>."
    )]
    pub dump_at: Option<FrameTime>,

    #[structopt(
    short = "D",
    long="dump-on",
    help = "Where <dump_on> := `ALL` | `RDTSC` | <syscall-no> | -<signal number> \n\n@TODO more details",
    parse(try_from_str = parse_dump_on)
    )]
    pub dump_on: Option<DumpOn>,

    #[structopt(
    short = "C",
    long="checksum",
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

    /// Record a trace
    #[structopt(name = "record")]
    Record {
        /// Force the syscall buffer preload library to be used, even if that's
        /// probably a bad idea.
        #[structopt(short = "b", long = "force-syscall-buffer")]
        force_syscall_buffer: bool,

        /// Maximum number of 'CPU ticks' (currently retired conditional branches) to allow a
        /// task to run before interrupting it.
        #[structopt(short = "c", long = "num-cpu-ticks", parse(try_from_str = parse_num_cpu_ticks))]
        num_cpu_ticks: Option<Ticks>,

        #[structopt(long="disable-cpuid-features", parse(try_from_str = parse_disable_cpuid_features),
           help="Where <disable-cpuid-features> := <CCC>[,<DDD>]\n\
                 Mask out CPUID EAX=1 feature bits\n\
                 <CCC>: Bitmask of bits to clear from ECX\n\
                 <DDD>: Bitmask of bits to clear from EDX")]
        disable_cpuid_features: Option<(u32, u32)>,

        #[structopt(long="disable-cpuid-features-ext", parse(try_from_str = parse_disable_cpuid_features_ext),
           help="Where <disable-cpuid-features-ext> := <BBB>[,<CCC>[,<DDD>]]\n\
                 Mask out CPUID EAX=7, ECX=0 feature bits\n\
                 <BBB>: Bitmask of bits to clear from EBX\n\
                 <CCC>: Bitmask of bits to clear from ECX\n\
                 <DDD>: Bitmask of bits to clear from EDX")]
        disable_cpuid_features_ext: Option<(u32, u32, u32)>,

        #[structopt(long="disable-cpuid-features-xsave", parse(try_from_str = parse_disable_cpuid_features_xsave),
           help="Where <disable-cpuid-features-xsave> := <AAA>\n\
                 Mask out CPUID EAX=0xD,ECX=1 feature bits\n\
                 <AAA>: Bitmask of bits to clear from EAX")]
        disable_cpuid_features_xsave: Option<u32>,

        /// Randomize scheduling decisions to try reproduce bugs
        #[structopt(short = "h", long = "chaos")]
        chaos_mode: bool,

        /// block <ignore-signal> from being delivered to tracees. Probably only useful
        /// for unit tests.
        #[structopt(short = "i", long = "ignore-signal", parse(try_from_str = parse_signal_name))]
        ignore_signal: Option<i32>,

        /// disable the syscall buffer preload library even if it would otherwise be used
        #[structopt(short = "n", long = "no-syscall-buffer")]
        no_syscall_buffer: bool,

        /// disable file cloning for mmapped files
        #[structopt(long = "no-file-cloning")]
        no_file_cloning: bool,

        /// disable file-block cloning for syscallbuf reads
        #[structopt(long = "no-read-cloning")]
        no_read_cloning: bool,

        /// pretend to have N cores (rd will still only run on a single core). Overrides
        /// random setting from --chaos.
        #[structopt(long = "num-cores")]
        num_cores: Option<u32>,

        /// set the output trace directory. _RR_TRACE_DIR gets ignored.
        /// Directory name is given name, not the application name.
        #[structopt(short = "o", long = "output-trace-dir")]
        output_trace_dir: Option<OsString>,

        /// print trace directory followed by a newline to given file descriptor
        #[structopt(short = "p", long = "print-trace-dir", parse(try_from_str = parse_fd))]
        print_trace_dir_fd: Option<i32>,

        /// Desired size of syscall buffer in kB. Mainly for tests
        #[structopt(long = "syscall-buffer-size")]
        syscall_buffer_size: Option<u32>,

        /// The signal used for communication with the syscall buffer. SIGPWR by default,
        /// unused if --no-syscall-buffer is passed
        #[structopt(long = "syscall-buffer-sig", parse(try_from_str = parse_signal_name))]
        syscall_buffer_sig: Option<i32>,

        /// Try to context switch at every rd event
        #[structopt(short = "s", long = "always-switch")]
        always_switch: bool,

        /// Unhandled <continue-through-signal> signals will be ignored
        /// instead of terminating the program. The signal will still be delivered for user
        /// handlers and debugging.
        #[structopt(short = "t", long = "continue-through-signal", parse(try_from_str = parse_signal_name))]
        continue_through_signal: Option<i32>,

        /// Allow tracees to run on any virtual CPU.
        /// Default is to bind to a random CPU.  This option can cause replay divergence:
        /// use with caution.
        #[structopt(short = "u", long = "cpu-unbound")]
        cpu_unbound: bool,

        /// Bind to a particular CPU instead of a randomly chosen one
        #[structopt(long = "bind-to-cpu")]
        bind_to_cpu: Option<u32>,

        #[structopt(
            short = "v",
            long = "env",
            multiple = true,
            parse(try_from_os_str = parse_env_name_val),
            help = "A value to add to the environment of the tracee.\n\
                    Where <env> := NAME=VALUE\n\
                    There can be any number of --env params each with a single NAME=VALUE."
        )]
        env: Option<Vec<(OsString, OsString)>>,

        /// Wait for all child processes to exit, not just the initial process.
        #[structopt(short = "w", long = "wait")]
        wait: bool,

        /// Directly start child process when running under nested rd recording,
        /// instead of raising an error.
        #[structopt(long = "ignore-error")]
        ignore_error: bool,

        /// Consume 950 fds before recording (for testing purposes)
        #[structopt(long = "scarce-fds")]
        scarce_fds: bool,

        /// If running under sudo, pretend to be the user that ran sudo rather than
        /// root. This allows recording setuid/setcap binaries.
        #[structopt(long = "setuid-sudo")]
        setuid_sudo: bool,

        /// Sets the trace id to the specified id
        #[structopt(long = "trace-id", parse(try_from_str = parse_trace_id))]
        trace_id: Option<TraceUuid>,

        /// Copy preload sources to trace dir
        #[structopt(long = "copy-preload-src")]
        copy_preload_src: bool,
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

fn parse_env_name_val(maybe_name_val: &OsStr) -> Result<(OsString, OsString), OsString> {
    let s = maybe_name_val.as_bytes();
    match find(s, b"=") {
        Some(n) => {
            let name: Vec<u8> = Vec::from(&s[0..n]);
            let value: Vec<u8> = Vec::from(&s[n + 1..]);
            Ok((OsString::from_vec(name), OsString::from_vec(value)))
        }
        None => Err(OsString::from(format!(
            "Could not find `=` separator in {:?}",
            maybe_name_val
        ))),
    }
}

fn parse_trace_id(maybe_trace_id: &str) -> Result<TraceUuid, Box<dyn Error>> {
    const SUM_GROUP_LENS: [u8; 5] = [8, 12, 16, 20, 32];
    // Parse UUIDs from string form optionally with hypens
    let mut digit = 0u8; // This counts only hex digits (i.e. not hypens)
    let mut group = 0usize;
    let mut acc = 0u8;
    let mut it = maybe_trace_id.trim().bytes();
    let err : Result<TraceUuid, Box<dyn Error>> = Err(Box::new(clap::Error::with_description(
          &format!(
              "Could not convert `{}` to Trace UUID.\n\
               A 32 digit hexadecimal number (with any number of hyphens and without a leading `0x`) is required.",
              maybe_trace_id
          ),
          clap::ErrorKind::InvalidValue,
      )));

    let mut buf = TraceUuid::zero();
    while let Some(c) = it.next() {
        if digit > SUM_GROUP_LENS[4] {
            return err;
        }

        if digit % 2 == 0 {
            // First digit of the byte.
            if b'0' <= c && c <= b'9' {
                acc = c - b'0';
            } else if b'a' <= c && c <= b'f' {
                acc = c - b'a' + 10;
            } else if b'A' <= c && c <= b'F' {
                acc = c - b'A' + 10;
            } else if c == b'-' {
                // Group delimiter.
                if SUM_GROUP_LENS[group] != digit {
                    return err;
                }
                group += 1;
                continue;
            } else {
                return err;
            }
        } else {
            // Second digit of the byte.
            acc <<= 4;
            if b'0' <= c && c <= b'9' {
                acc += c - b'0';
            } else if b'a' <= c && c <= b'f' {
                acc += c - b'a' + 10;
            } else if b'A' <= c && c <= b'F' {
                acc += c - b'A' + 10;
            } else {
                return err;
            }

            buf.bytes[digit as usize / 2] = acc;
        }

        digit += 1;
    }

    if SUM_GROUP_LENS[4] != digit {
        err
    } else {
        Ok(buf)
    }
}

fn parse_num_cpu_ticks(maybe_num_ticks: &str) -> Result<Ticks, Box<dyn Error>> {
    match maybe_num_ticks.parse::<Ticks>() {
        Err(e) => Err(Box::new(e)),
        Ok(n) if n == 0 || n > TicksHowMany::MaxMaxTicks as u64 => {
            Err(Box::new(clap::Error::with_description(
                &format!(
                    "Max 'CPU Ticks' cannot be 0 or greater than {}",
                    TicksHowMany::MaxMaxTicks as u64
                ),
                clap::ErrorKind::InvalidValue,
            )))
        }
        Ok(n) => Ok(n),
    }
}

fn parse_fd(maybe_fd: &str) -> Result<i32, Box<dyn Error>> {
    match maybe_fd.parse::<i32>() {
        Err(e) => Err(Box::new(e)),
        Ok(n) if n < 0 => Err(Box::new(clap::Error::with_description(
            &format!("fd value cannot be negative or greater than {}", i32::MAX),
            clap::ErrorKind::InvalidValue,
        ))),
        Ok(n) => Ok(n),
    }
}

fn parse_signal_name(maybe_signal_name: &str) -> Result<i32, Box<dyn Error>> {
    let maybe_sig_trimmed = maybe_signal_name.trim();
    if maybe_sig_trimmed.chars().all(|c| c.is_ascii_digit()) {
        let sig_result = maybe_sig_trimmed.parse::<i32>().map_err(|e| {
            let b: Box<dyn Error> = Box::new(e);
            b
        });
        let sig = sig_result?;
        if sig >= 1 && sig <= _NSIG as i32 {
            return Ok(sig);
        }
    } else {
        for i in 1i32.._NSIG as i32 {
            let sig_name = signal_name(i);
            if maybe_sig_trimmed == &sig_name {
                return Ok(i);
            } else {
                debug_assert_eq!(sig_name[0..3].to_ascii_uppercase(), "SIG");
                if &sig_name[3..] == maybe_sig_trimmed {
                    return Ok(i);
                }
            }
        }
    }
    Err(Box::new(clap::Error::with_description(
        &format!("Unknown signal `{}`", maybe_sig_trimmed),
        clap::ErrorKind::InvalidValue,
    )))
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

fn parse_u32(s: &str) -> Result<u32, Box<dyn Error>> {
    let ts: &str = s.trim();
    if ts.starts_with("0x") {
        u32::from_str_radix(&ts[2..], 16).map_err(|e| {
            let b: Box<dyn Error> = Box::new(e);
            b
        })
    } else if ts.starts_with("0o") {
        u32::from_str_radix(&ts[2..], 8).map_err(|e| {
            let b: Box<dyn Error> = Box::new(e);
            b
        })
    } else if ts.starts_with("0") {
        Err(Box::new(clap::Error::with_description(
            "Octal values should have a prefix of 0o",
            clap::ErrorKind::InvalidValue,
        )))
    } else {
        u32::from_str_radix(ts, 10).map_err(|e| {
            let b: Box<dyn Error> = Box::new(e);
            b
        })
    }
}

fn parse_disable_cpuid_features_xsave(
    disable_cpuid_features_xsave: &str,
) -> Result<u32, ParseIntError> {
    disable_cpuid_features_xsave.trim().parse::<u32>()
}

fn parse_disable_cpuid_features(
    disable_cpuid_features: &str,
) -> Result<(u32, u32), Box<dyn Error>> {
    let feat: Vec<&str> = disable_cpuid_features.trim().splitn(2, ',').collect();
    let u1: u32;
    let u2: u32;
    if feat.len() == 1 {
        u1 = parse_u32(&feat[0])?;
        u2 = 0;
    } else {
        u1 = parse_u32(&feat[0])?;
        u2 = parse_u32(&feat[1])?;
    }
    Ok((u1, u2))
}

fn parse_disable_cpuid_features_ext(
    disable_cpuid_features_ext: &str,
) -> Result<(u32, u32, u32), Box<dyn Error>> {
    let feat: Vec<&str> = disable_cpuid_features_ext.trim().splitn(3, ',').collect();
    let u1: u32;
    let u2: u32;
    let u3: u32;
    if feat.len() == 1 {
        u1 = parse_u32(&feat[0])?;
        u2 = 0;
        u3 = 0;
    } else if feat.len() == 2 {
        u1 = parse_u32(&feat[0])?;
        u2 = parse_u32(&feat[1])?;
        u3 = 0;
    } else {
        u1 = parse_u32(&feat[0])?;
        u2 = parse_u32(&feat[1])?;
        u3 = parse_u32(&feat[2])?;
    }
    Ok((u1, u2, u3))
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
