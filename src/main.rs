#![allow(dead_code)]

#[macro_use]
mod kernel_abi;
mod flags;
mod kernel_metadata;
mod record_task;
mod wait_status;
mod x64_arch;
mod x86_arch;

fn main() {
    println!("Hello, world!");
}
