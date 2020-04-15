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
use crate::commands::RdCommand;
use crate::log::LogLevel::LogInfo;
use std::path::PathBuf;
use structopt::StructOpt;

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
    // @TODO -C --checksum
    #[structopt(subcommand)]
    cmd: Option<RdSubCommand>,
}

#[derive(StructOpt, Debug)]
pub enum RdSubCommand {
    // DIFF NOTE: Slightly different from rr which accepts file paths from stdin.
    #[structopt(help = "Accepts paths to elf files, prints elf build ids on stdout.")]
    BuildId {
        #[structopt(parse(from_os_str))]
        elf_files: Vec<PathBuf>,
    },
    #[structopt(
        help = "Print `rd record` command line options that will limit the tracee to CPU features \
        this machine supports. Useful for trace portability: run `rd cpufeatures` on the machine \
        you plan to replay on, then add those command-line parameters to `rd record` on the \
        recording machine."
    )]
    CpuFeatures,
}

fn main() {
    let options = RdOptions::from_args();
    match &options.cmd {
        Some(RdSubCommand::BuildId { elf_files }) => BuildIdCommand::new(elf_files).run(),
        _ => (),
    }

    println!("{:?}", options);
    log!(LogInfo, "Hello World!");
}
