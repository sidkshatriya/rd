use crate::trace::trace_frame::FrameTime;
use crate::RdOptions;
use std::path::PathBuf;
use structopt::StructOpt;

lazy_static! {
    static ref FLAGS: Flags = init_flags();
}

/// When to generate or check memory checksums. One of CHECKSUM_NONE,
/// CHECKSUM_SYSCALL or CHECKSUM_ALL, or a positive integer representing the
/// event time at which to start checksumming.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Checksum {
    ChecksumSyscall,
    ChecksumAll,
    ChecksumAt(FrameTime),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum DumpOn {
    DumpOnAll,
    DumpOnRdtsc,
    DumpOnSignal(u32),
    DumpOnSyscall(u32),
}

#[derive(Clone)]
pub struct Flags {
    pub checksum: Option<Checksum>,
    pub dump_on: Option<DumpOn>,
    pub dump_at: Option<u64>,
    /// Force rd to do some things that it otherwise wouldn't, for
    /// example launching an emergency debugger when the output
    /// doesn't seem to be a tty.
    pub force_things: bool,
    /// Mark the trace global time along with tracee writes to stdio.
    pub mark_stdio: bool,
    /// Check that cached mmaps match /proc/maps after each event.
    pub check_cached_maps: bool,
    /// Suppress warnings related to environmental features outside rd's
    /// control.
    pub suppress_environment_warnings: bool,
    /// Any warning or error that would be printed is treated as fatal
    pub fatal_errors_and_warnings: bool,
    /// Pretend CPUID faulting support doesn't exist
    pub disable_cpuid_faulting: bool,
    /// Don't listen for PTRACE_EVENT_EXIT events, to test how rd handles
    /// missing PTRACE_EVENT_EXITs.
    pub disable_ptrace_exit_events: bool,
    /// User override for architecture detection, e.g. when running under valgrind.
    pub forced_uarch: Option<String>,
    /// User override for the path to page files and other resources.
    pub resource_path: Option<PathBuf>,
}

impl Flags {
    pub fn get() -> &'static Flags {
        &*FLAGS
    }
}

pub fn init_flags() -> Flags {
    let options = RdOptions::from_args();

    Flags {
        checksum: options.checksum,
        dump_on: options.dump_on,
        dump_at: options.dump_at,
        force_things: options.force_things,
        mark_stdio: options.mark_stdio,
        check_cached_maps: options.check_cached_mmaps,
        suppress_environment_warnings: options.suppress_environment_warnings,
        fatal_errors_and_warnings: options.fatal_errors,
        disable_cpuid_faulting: options.disable_cpuid_faulting,
        disable_ptrace_exit_events: options.disable_ptrace_exit_events,
        forced_uarch: options.microarch,
        resource_path: options.resource_path,
    }
}
