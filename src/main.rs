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
mod kernel_abi;
mod flags;
mod kernel_metadata;
#[macro_use]
mod log;
mod bindings;
mod perf_counters;
mod record_task;
#[macro_use]
mod registers;
mod address_space;
mod auto_remote_syscalls;
mod diversion_session;
mod emu_fs;
mod extra_registers;
mod fd_table;
mod gdb_register;
mod kernel_supplement;
mod monitored_shared_memory;
mod monkey_patcher;
mod property_table;
mod rd;
mod record_session;
mod remote_code_ptr;
mod remote_ptr;
mod replay_session;
mod replay_task;
mod scoped_fd;
mod session_interface;
mod task_interface;
mod task_set;
mod taskish_uid;
mod thread_group;
mod ticks;
mod trace_capnp;
mod trace_frame;
mod trace_stream;
mod util;
mod wait_status;

fn main() {
    println!("Hello, world!");
}
