#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use libc::c_ulong;

include!(concat!(
    env!("OUT_DIR"),
    "/perf_event_bindings_generated.rs"
));

pub const PERF_EVENT_IOC_DISABLE: c_ulong = PERF_EVENT_IOC_DISABLE_ as c_ulong;
pub const PERF_EVENT_IOC_ENABLE: c_ulong = PERF_EVENT_IOC_ENABLE_ as c_ulong;
pub const PERF_EVENT_IOC_PERIOD: c_ulong = PERF_EVENT_IOC_PERIOD_ as c_ulong;
pub const PERF_EVENT_IOC_RESET: c_ulong = PERF_EVENT_IOC_RESET_ as c_ulong;
