#![feature(get_mut_unchecked)]
#![feature(map_first_last)]
#![feature(llvm_asm)]
#![feature(raw_ref_op)]
#![feature(termination_trait_lib)]
#![feature(associated_type_defaults)]
#![feature(slice_ptr_get)]
#![feature(array_methods)]
#![feature(arc_new_cyclic)]
#![feature(format_args_capture)]
// Can disallow some of these in the future
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::redundant_static_lifetimes)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::single_match)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::module_inception)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::let_and_return)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::needless_return)]
#![allow(clippy::or_fun_call)]
#![allow(clippy::needless_lifetimes)]
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
mod breakpoint_condition;
#[macro_use]
mod remote_ptr;
mod arch_structs;
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
mod extra_registers;
mod fast_forward;
mod fd_table;
mod file_monitor;
mod gdb_connection;
mod gdb_expression;
mod gdb_register;
mod kernel_supplement;
mod monitored_shared_memory;
mod monkey_patcher;
mod preload_interface;
mod preload_interface_arch;
mod priority_tup;
mod rd;
mod record_signal;
mod record_syscall;
mod remote_code_ptr;
mod replay_syscall;
mod replay_timeline;
mod return_address_list;
mod scheduler;
mod scoped_fd;
mod seccomp_bpf;
mod seccomp_filter_rewriter;
mod session;
mod sig;
mod taskish_uid;
mod thread_db;
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
use commands::{
    exit_result::ExitResult, record_command::RecordCommand, replay_command::ReplayCommand,
};
use nix::sys::{
    signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
    utsname::uname,
};
use rand::random;
use std::os::raw::c_uint;
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

fn main() -> ExitResult<()> {
    // In rust SIGPIPE is ignored. See https://github.com/rust-lang/rust/issues/62569
    // Undo this.
    let sa = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
    unsafe { sigaction(Signal::SIGPIPE, &sa) }.unwrap();

    // Seed the PRNG
    unsafe { libc::srand(random::<c_uint>()) };

    raise_resource_limits();
    let options = RdOptions::from_args();
    if options.output_options_chosen {
        eprintln!("{:?}", options);
    }

    init_pmu();
    match &options.cmd {
        RdSubCommand::BuildId => return BuildIdCommand::new().run(),
        RdSubCommand::Dump { .. } => {
            return DumpCommand::new(&options).run();
        }
        RdSubCommand::ReRun { .. } => {
            return ReRunCommand::new(&options).run();
        }
        RdSubCommand::Replay { .. } => {
            return ReplayCommand::new(&options).run();
        }
        RdSubCommand::TraceInfo { .. } => {
            return TraceInfoCommand::new(&options).run();
        }
        RdSubCommand::Ps { .. } => {
            return PsCommand::new(&options).run();
        }
        RdSubCommand::Record { .. } => {
            return RecordCommand::new(&options).run();
        }
        _ => (),
    }

    ExitResult::Ok(())
}
