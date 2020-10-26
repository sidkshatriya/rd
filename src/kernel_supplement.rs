#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

include!(concat!(
    env!("OUT_DIR"),
    "/kernel_supplement_bindings_generated.rs"
));

/// @TODO Manually specifying this as _NSIG does not give correct value
pub const NUM_SIGNALS: usize = 65;
