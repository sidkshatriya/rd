use crate::scoped_fd::ScopedFd;
use crate::ticks::Ticks;
use libc::pid_t;

enum TicksSemantics {
    TicksRetiredConditionalBranches,
    TicksTakenBranches,
}

use TicksSemantics::*;

struct PerfCounters {
    // Only valid while 'counting' is true
    counting_period: Ticks,
    tid: pid_t,
    // We use separate fds for counting ticks and for generating interrupts. The
    // former ignores ticks in aborted transactions, and does not support
    // sample_period; the latter does not ignore ticks in aborted transactions,
    // but does support sample_period.
    fd_ticks_measure: ScopedFd,
    fd_minus_ticks_measure: ScopedFd,
    fd_ticks_interrupt: ScopedFd,
    fd_ticks_in_transaction: ScopedFd,
    fd_useless_counter: ScopedFd,
    ticks_semantics_: ScopedFd,
    started: bool,
    counting: bool,
}

impl PerfCounters {}
