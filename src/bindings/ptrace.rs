#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/ptrace_bindings_generated.rs"));

#[cfg(target_arch = "x86")]
pub const PTRACE_ARCH_PRCTL: u32 = 30;
