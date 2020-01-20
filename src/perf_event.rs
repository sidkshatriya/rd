#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

include!(concat!(
    env!("OUT_DIR"),
    "/perf_event_bindings_generated.rs"
));
