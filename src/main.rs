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
mod arch;
#[macro_use]
mod kernel_abi;
mod flags;
mod kernel_metadata;
#[macro_use]
mod log;
mod bindings;
mod perf_counters;
#[macro_use]
mod registers;
mod address_space;
mod auto_remote_syscalls;
mod core;
mod diversion_session;
mod emu_fs;
mod event;
mod extra_registers;
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
mod scoped_fd;
mod session;
mod task;
mod task_set;
mod taskish_uid;
mod thread_group;
mod ticks;
mod trace_capnp;
mod trace_frame;
mod trace_stream;
mod trace_writer;
mod util;
mod wait_status;

fn main() {
    println!("Hello, world!");
}
