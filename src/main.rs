#![allow(dead_code)]

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;

#[macro_use]
mod kernel_abi;
mod flags;
mod kernel_metadata;
#[macro_use]
mod log;
mod bindings;
mod perf_counters;
mod record_task;
mod scoped_fd;
mod task;
mod ticks;
mod util;
mod wait_status;
mod x64_arch;
mod x86_arch;

use log::LogLevel::*;

fn main() {
    println!("Hello, world!");
}
