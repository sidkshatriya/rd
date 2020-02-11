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
mod extra_registers;
mod gdb_register;
mod kernel_supplement;
mod remote_code_ptr;
mod remote_ptr;
mod replay_task;
mod scoped_fd;
mod task;
mod ticks;
mod trace_capnp;
mod util;
mod wait_status;

fn main() {
    println!("Hello, world!");
}
