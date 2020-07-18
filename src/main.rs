#![feature(get_mut_unchecked)]
#![feature(map_first_last)]
#![feature(llvm_asm)]
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
mod commands;
mod core;
mod cpuid_bug_detector;
mod emu_fs;
mod event;
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
mod seccomp_bpf;
mod seccomp_filter_rewriter;
mod session;
mod taskish_uid;
mod thread_group;
mod ticks;
mod trace;
mod trace_capnp;
mod util;
mod wait_status;
mod weak_ptr_set;

use crate::{
    commands::{
        build_id_command::BuildIdCommand,
        dump_command::DumpCommand,
        ps_command::PsCommand,
        rd_options::{RdOptions, RdSubCommand},
        rerun_command::ReRunCommand,
        trace_info_command::TraceInfoCommand,
        RdCommand,
    },
    perf_counters::init_pmu,
    util::raise_resource_limits,
};
use nix::sys::utsname::uname;
use std::io;
use structopt::StructOpt;

pub fn assert_prerequisites(maybe_use_syscall_buffer: Option<bool>) {
    let use_syscall_buffer = maybe_use_syscall_buffer.unwrap_or(false);
    let unm = uname();
    let release = unm.release();
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() < 2 {
        fatal!("Could not parse kernel version string. Got: `{}`", release);
    }

    let maybe_major = parts[0].parse::<u32>();
    let maybe_minor = parts[1].parse::<u32>();
    if maybe_major.is_err() || maybe_minor.is_err() {
        fatal!("Could not parse kernel version string. Got: `{}`", release);
    }

    let (major, minor) = (maybe_major.unwrap(), maybe_minor.unwrap());
    if (major, minor) < (3, 4) {
        fatal!("Kernel doesn't support necessary ptrace functionality; need 3.4.0 or better.");
    }

    if use_syscall_buffer && (major, minor) < (3, 5) {
        fatal!("Your kernel does not support syscall filtering; please use the -n option while recording");
    }
}

fn main() -> io::Result<()> {
    raise_resource_limits();
    let options = RdOptions::from_args();

    init_pmu();
    match &options.cmd {
        RdSubCommand::BuildId => return BuildIdCommand::new().run(),
        RdSubCommand::Dump { .. } => {
            DumpCommand::new(&options).run()?;
        }
        RdSubCommand::ReRun { .. } => {
            ReRunCommand::new(&options).run()?;
        }
        RdSubCommand::TraceInfo { .. } => {
            TraceInfoCommand::new(&options).run()?;
        }
        RdSubCommand::Ps { .. } => {
            PsCommand::new(&options).run()?;
        }
        _ => (),
    }

    // write!(stderr(), "{:?}\n", options)?;
    Ok(())
}
