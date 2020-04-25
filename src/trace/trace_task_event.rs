use crate::remote_ptr::{RemotePtr, Void};
use crate::wait_status::WaitStatus;
use libc::pid_t;
use std::ffi::{OsStr, OsString};

#[derive(Clone)]
pub enum TraceTaskEventVariant {
    /// DIFF NOTE: We DONT have a `None` variant here, unlike rr.
    ///
    /// Created by clone(2), fork(2), vfork(2) syscalls
    Clone(TraceTaskEventClone),
    Exec(TraceTaskEventExec),
    Exit(TraceTaskEventExit),
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum TraceTaskEventType {
    Clone,
    Exec,
    Exit,
}

impl TraceTaskEvent {
    pub fn clone_variant(&self) -> &TraceTaskEventClone {
        match &self.variant {
            TraceTaskEventVariant::Clone(v) => v,
            _ => panic!("Not a TraceTaskEventTypeClone"),
        }
    }
    pub fn exec_variant(&self) -> &TraceTaskEventExec {
        match &self.variant {
            TraceTaskEventVariant::Exec(v) => v,
            _ => panic!("Not a TraceTaskEventTypeExec"),
        }
    }
    pub fn exit_variant(&self) -> &TraceTaskEventExit {
        match &self.variant {
            TraceTaskEventVariant::Exit(v) => v,
            _ => panic!("Not a TraceTaskEventTypeExit"),
        }
    }
}

#[derive(Clone)]
pub struct TraceTaskEventClone {
    pub(super) parent_tid_: pid_t,
    pub(super) own_ns_tid_: pid_t,
    pub(super) clone_flags_: i32,
}

impl TraceTaskEventClone {
    pub fn parent_tid(&self) -> pid_t {
        self.parent_tid_
    }
    pub fn own_ns_tid(&self) -> pid_t {
        self.own_ns_tid_
    }
    pub fn clone_flags(&self) -> i32 {
        self.clone_flags_
    }
}

#[derive(Clone)]
pub struct TraceTaskEventExec {
    pub(super) file_name_: OsString,
    pub(super) cmd_line_: Vec<OsString>,
    pub(super) exe_base_: RemotePtr<Void>,
}

impl TraceTaskEventExec {
    pub fn file_name(&self) -> &OsStr {
        &self.file_name_
    }
    pub fn cmd_line(&self) -> &[OsString] {
        &self.cmd_line_
    }
    pub fn exe_base(&self) -> RemotePtr<Void> {
        self.exe_base_
    }
}

#[derive(Clone)]
pub struct TraceTaskEventExit {
    pub(super) exit_status_: WaitStatus,
}

impl TraceTaskEventExit {
    pub fn exit_status(&self) -> WaitStatus {
        self.exit_status_
    }
}

pub struct TraceTaskEvent {
    pub(super) variant: TraceTaskEventVariant,
    pub(super) tid_: pid_t,
}

impl TraceTaskEvent {
    pub fn tid(&self) -> pid_t {
        self.tid_
    }
    pub fn event_variant(&self) -> &TraceTaskEventVariant {
        &self.variant
    }
    pub fn event_type(&self) -> TraceTaskEventType {
        match &self.variant {
            TraceTaskEventVariant::Clone(_) => TraceTaskEventType::Clone,
            TraceTaskEventVariant::Exit(_) => TraceTaskEventType::Exit,
            TraceTaskEventVariant::Exec(_) => TraceTaskEventType::Exec,
        }
    }
}
