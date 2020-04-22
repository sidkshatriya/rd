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
use crate::commands::rd_options::{RdOptions, RdSubCommand};
use crate::commands::rerun_command::ReRunCommand;
use crate::commands::RdCommand;
use std::io;
use structopt::StructOpt;

fn main() -> io::Result<()> {
    let options = RdOptions::from_args();

    match &options.cmd {
        RdSubCommand::BuildId => return BuildIdCommand::new().run(),
        RdSubCommand::Dump { .. } => {
            DumpCommand::new(&options).run()?;
            println!("{:?}", options);
        }
        RdSubCommand::ReRun { .. } => {
            ReRunCommand::new(&options).run()?;
            println!("{:?}", options);
        }
        _ => {
            println!("{:?}", options);
        }
    }

    Ok(())
}
