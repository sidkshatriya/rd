#![allow(dead_code)]

#[macro_use]
mod kernel_abi;
mod flags;
mod kernel_metadata;
mod perf_counters;
mod ptrace;
mod record_task;
mod signal;
mod wait_status;
mod x64_arch;
mod x86_arch;

fn main() {
    println!("Hello, world!");
}
