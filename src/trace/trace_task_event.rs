use crate::remote_ptr::{RemotePtr, Void};
use crate::wait_status::WaitStatus;
use libc::pid_t;
use std::ffi::OsString;

pub enum TraceTaskEventType {
    NONE,
    /// created by clone(2), fork(2), vfork(2) syscalls
    CLONE,
    EXEC,
    EXIT,
}

/// @TODO Should this be an enum?
pub struct TraceTaskEvent {
    type_: TraceTaskEventType,
    tid_: pid_t,
    // CLONE only
    parent_tid_: pid_t,
    // CLONE only
    own_ns_tid_: pid_t,
    // CLONE only
    clone_flags_: i32,
    // EXEC only
    file_name_: OsString,
    // EXEC only
    cmd_line_: Vec<OsString>,
    // EXEC only
    exe_base_: RemotePtr<Void>,
    // EXIT only
    exit_status_: WaitStatus,
}
