#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
// Silence warning: "`extern` block uses type `u128`, which is not FFI-safe"
#![allow(improper_ctypes)]

include!(concat!(env!("OUT_DIR"), "/kernel_bindings_generated.rs"));
