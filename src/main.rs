#![allow(dead_code)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
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
mod remote_code_ptr;
mod remote_ptr;
mod scoped_fd;
mod task;
mod ticks;
mod trace_capnp;
mod util;
mod wait_status;

fn main() {
    println!("Hello, world!");
}
