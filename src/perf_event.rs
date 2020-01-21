#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

include!(concat!(
    env!("OUT_DIR"),
    "/perf_event_bindings_generated.rs"
));

pub const PERF_EVENT_IOC_DISABLE: u64 = PERF_EVENT_IOC_DISABLE_;
pub const PERF_EVENT_IOC_ENABLE: u64 = PERF_EVENT_IOC_ENABLE_;
