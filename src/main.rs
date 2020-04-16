#![feature(asm)]
#![feature(raw_ref_op)]
// @TODO To many results for "never used". Disable for now.
#![allow(dead_code)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate raw_cpuid;
#[macro_use]
extern crate static_assertions;
#[macro_use]
extern crate memoffset;

#[macro_use]
mod log;
#[macro_use]
mod arch;
#[macro_use]
mod kernel_abi;
#[macro_use]
mod auto_remote_syscalls;
mod bindings;
mod flags;
mod kernel_metadata;
mod perf_counters;
#[macro_use]
mod registers;
mod address_space;
mod commands;
mod core;
mod cpuid_bug_detector;
mod emu_fs;
mod event;
mod extra_registers;
mod fast_forward;
mod fd_table;
mod file_monitor;
mod gdb_register;
mod kernel_supplement;
mod monitored_shared_memory;
mod monkey_patcher;
mod rd;
mod remote_code_ptr;
mod remote_ptr;
mod replay_syscall;
mod scheduler;
mod scoped_fd;
mod seccomp_filter_rewriter;
mod session;
mod task;
mod taskish_uid;
mod thread_group;
mod ticks;
mod trace;
mod trace_capnp;
mod util;
mod wait_status;
mod weak_ptr_set;

use crate::commands::build_id_command::BuildIdCommand;
use crate::commands::dump_command::DumpCommand;
use crate::commands::RdCommand;
use std::error::Error;
use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;
use structopt::{clap, StructOpt};

#[derive(Debug, StructOpt)]
#[structopt(name = "rd", about = "The record and debug tool")]
pub struct RdOptions {
    #[structopt(long, help = "disable use of CPUID faulting")]
    disable_cpuid_faulting: bool,
    #[structopt(
        long = "disable-ptrace-exit_events",
        help = "disable use of PTRACE_EVENT_EXIT"
    )]
    disable_ptrace_exit_events: bool,
    #[structopt(
        parse(from_os_str),
        long,
        help = "specify the paths that rd should use to find files such as rd_page_*.  These files \
        should be located in <resource-path>/bin, <resource-path>/lib[64], and <resource-path>/share \
        as appropriate."
    )]
    resource_path: Option<PathBuf>,
    #[structopt(
        short = "A",
        long,
        help = "force rd to assume it's running on a CPU with microarch <microarch> even if runtime \
        detection says otherwise. <microarch> should be a string like 'Ivy Bridge'. Note that rd \
        will not work with Intel Merom or Penryn microarchitectures."
    )]
    microarch: Option<String>,
    #[structopt(
        short = "F",
        long,
        help = "force rd to do some things that don't seem like good ideas, for example launching \
        an interactive emergency debugger if stderr isn't a tty."
    )]
    force_things: bool,
    #[structopt(
        short = "K",
        long,
        help = "verify that cached task mmaps match /proc/maps."
    )]
    check_cached_mmaps: bool,
    #[structopt(
        short = "E",
        long,
        help = "any warning or error that is printed is treated as fatal"
    )]
    fatal_errors: bool,
    #[structopt(
        short = "M",
        long,
        help = "mark stdio writes with `[rr <pid> <ev>]` where <ev> is the global trace time at \
        which the write occurs and <pid> is the pid of the process it occurs in."
    )]
    mark_stdio: bool,
    #[structopt(
        short = "S",
        long,
        help = "suppress warnings about issues in the environment that rd has no control over"
    )]
    suppress_environment_warnings: bool,
    #[structopt(short = "T", long, help = "dump memory at global time point <time>")]
    dump_at: Option<u64>,
    #[structopt(
        short = "D",
        long,
        help = "dump memory at a syscall number or signal to the file `[trace_dir]/[tid].[time]_{rec,rep}'. \
        Here `_rec' is for dumps during recording, `_rep' for dumps during replay. Note: If you provide a \
        positive number it will be interpreted as a syscall number and if it is negative it is understood \
        as a signal number. e.g -9 for sigKILL"
    )]
    dump_on: Option<i32>,
    #[structopt(
        short = "C",
        long,
        parse(try_from_str = parse_checksum),
        help = "{on-syscalls,on-all-events}|FROM_TIME \
                compute and store (during recording) or \
                read and verify (during replay) checksums \
                of each of a tracee's memory mappings either \
                at the end of all syscalls (`on-syscalls'), \
                at all events (`on-all-events'), or \
                starting from a global timepoint FROM_TIME"
    )]
    checksum: Option<ChecksumSelection>,
    #[structopt(subcommand)]
    cmd: RdSubCommand,
}

/// @TODO Do we want to return some other sort of error?
fn parse_checksum(checksum_s: &str) -> Result<ChecksumSelection, Box<dyn Error>> {
    if checksum_s == "on-syscalls" {
        Ok(ChecksumSelection::OnSyscalls)
    } else if checksum_s == "on-all-events" {
        Ok(ChecksumSelection::OnAllEvents)
    } else if checksum_s.chars().all(|c| !c.is_ascii_digit()) {
        Err(Box::new(clap::Error {
            message: "Only `on-syscalls` or `on-all-events` or an unsigned integer is valid here"
                .to_string(),
            kind: clap::ErrorKind::InvalidValue,
            info: None,
        }))
    } else {
        Ok(ChecksumSelection::FromTime(checksum_s.parse::<u32>()?))
    }
}

#[derive(Debug)]
pub enum ChecksumSelection {
    OnSyscalls,
    OnAllEvents,
    FromTime(u32),
}

#[derive(StructOpt, Debug)]
pub enum RdSubCommand {
    #[structopt(
        name = "buildid",
        about = "Accepts paths to elf files from stdin, prints elf build ids on stdout.",
        help = "Accepts paths on stdin, prints buildids on stdout. Will terminate when either an empty \
                line or an invalid path is provided."
    )]
    BuildId,
    #[structopt(
        name = "cpufeatures",
        about = "Print `rd record` command line options that will limit the tracee to CPU features \
        this machine supports.",
        help = "Print `rd record` command line options that will limit the tracee to CPU features \
        this machine supports. Useful for trace portability: run `rd cpufeatures` on the machine \
        you plan to replay on, then add those command-line parameters to `rd record` on the \
        recording machine."
    )]
    CpuFeatures,
    #[structopt(name = "dump", about = "@TODO", help = "@TODO")]
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
        #[structopt(short = "t", long, help = "dump events only for the specified tid")]
        tid: Option<u32>,
        trace_dir: Option<PathBuf>,
        #[structopt(parse(try_from_str = parse_range))]
        event_spec: Option<(u32, Option<u32>)>,
    },
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

fn main() -> io::Result<()> {
    let options = RdOptions::from_args();
    match &options.cmd {
        RdSubCommand::BuildId => return BuildIdCommand::new().run(),
        RdSubCommand::Dump { .. } => {
            DumpCommand::new().run()?;
            println!("{:?}", options);
        }
        _ => {
            println!("{:?}", options);
        }
    }

    Ok(())
}
