use crate::address_space::WatchConfig;
use crate::task::task::Task;
use libc::siginfo_t;

pub struct Session {}

#[derive(Clone)]
pub struct BreakStatus {
    /// The triggering Task. This may be different from session->current_task()
    /// when replay switches to a new task when ReplaySession::replay_step() ends.
    task: *mut Task,
    /// List of watchpoints hit; any watchpoint hit causes a stop after the
    /// instruction that triggered the watchpoint has completed.
    watchpoints_hit: Vec<WatchConfig>,
    /// When non-null, we stopped because a signal was delivered to |task|.
    signal: Box<siginfo_t>,
    /// True when we stopped because we hit a software breakpoint at |task|'s
    /// current ip().
    breakpoint_hit: bool,
    /// True when we stopped because a singlestep completed in |task|.
    singlestep_complete: bool,
    /// True when we stopped because we got too close to the specified ticks
    /// target.
    approaching_ticks_target: bool,
    /// True when we stopped because |task| is about to exit.
    task_exit: bool,
}

/// In general, multiple break reasons can apply simultaneously.
impl BreakStatus {
    pub fn new() {
        unimplemented!()
    }

    /// True when we stopped because we hit a software or hardware breakpoint at
    /// |task|'s current ip().
    pub fn hardware_or_software_breakpoint_hit() -> bool {
        unimplemented!()
    }

    /// Returns just the data watchpoints hit.
    pub fn data_watchpoints_hit() -> Vec<WatchConfig> {
        unimplemented!()
    }

    pub fn any_break() -> bool {
        unimplemented!()
    }
}
