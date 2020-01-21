#![allow(dead_code)]

#[macro_use]
extern crate bitflags;

#[macro_use]
mod kernel_abi;
mod flags;
mod kernel_metadata;
mod perf_counters;
mod perf_event;
mod ptrace;
mod record_task;
mod scoped_fd;
mod signal;
mod task;
mod ticks;
mod wait_status;
mod x64_arch;
mod x86_arch;

fn main() {
    println!("Hello, world!");
}
