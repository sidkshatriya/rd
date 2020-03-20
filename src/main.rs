#![feature(asm)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate raw_cpuid;
#[macro_use]
extern crate static_assertions;

use crate::address_space::kernel_map_iterator::KernelMapIterator;

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
mod property_table;
mod rd;
mod remote_code_ptr;
mod remote_ptr;
mod replay_syscall;
mod scoped_fd;
mod session;
mod task;
mod task_set;
mod taskish_uid;
mod thread_group;
mod ticks;
mod trace;
mod trace_capnp;
mod util;
mod wait_status;

fn main() {
    println!("Hello, world!");
    KernelMapIterator::test_output();
}
