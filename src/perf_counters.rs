use crate::perf_event::perf_event_attr;
use crate::scoped_fd::ScopedFd;
use crate::task::Task;
use crate::ticks::Ticks;
use nix::unistd::Pid;
use std::os::unix::io::RawFd;

// @TODO Do we want these as global variables?
static attributes_initialized: bool = false;
// At some point we might support multiple kinds of ticks for the same CPU arch.
// At that point this will need to become more complicated.
/*
static ticks_attr: perf_event_attr = perf_event_attr {};
static minus_ticks_attr: perf_event_attr = perf_event_attr;
static cycles_attr: perf_event_attr = perf_event_attr;
static hw_interrupts_attr: perf_event_attr = perf_event_attr;
static pmu_flags: u32 = 0;
static skid_size: u32 = 0;
static has_ioc_period_bug: bool = false;
static has_kvm_in_txcp_bug: bool = false;
static has_xen_pmi_bug: bool = false;
static supports_txcp: bool = false;
static only_one_counter: bool = false;
static activate_useless_counter: bool = false;
*/

/// This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
/// hope that tracees don't either.
const TIME_SLICE_SIGNAL: i32 = libc::SIGSTKFLT;

#[derive(Copy, Clone)]
enum TicksSemantics {
    TicksRetiredConditionalBranches,
    TicksTakenBranches,
}

use TicksSemantics::*;

struct PerfCounters {
    // Only valid while 'counting' is true
    counting_period: Ticks,
    tid: Pid,
    // We use separate fds for counting ticks and for generating interrupts. The
    // former ignores ticks in aborted transactions, and does not support
    // sample_period; the latter does not ignore ticks in aborted transactions,
    // but does support sample_period.
    fd_ticks_measure: ScopedFd,
    fd_minus_ticks_measure: ScopedFd,
    fd_ticks_interrupt: ScopedFd,
    fd_ticks_in_transaction: ScopedFd,
    fd_useless_counter: ScopedFd,
    ticks_semantics_: TicksSemantics,
    started: bool,
    counting: bool,
}

impl PerfCounters {
    pub fn new(tid: Pid, ticks_semantics: TicksSemantics) -> Self {
        PerfCounters {
            tid,
            ticks_semantics_: ticks_semantics,
            started: false,
            counting: false,
            fd_ticks_measure: ScopedFd::new(),
            fd_minus_ticks_measure: ScopedFd::new(),
            fd_ticks_interrupt: ScopedFd::new(),
            fd_ticks_in_transaction: ScopedFd::new(),
            fd_useless_counter: ScopedFd::new(),
            counting_period: 0,
        }
    }

    pub fn set_tid(&mut self, tid: Pid) {
        self.stop();
        self.tid = tid;
    }

    /// Reset all counter values to 0 and program the counters to send
    /// TIME_SLICE_SIGNAL when 'ticks_period' tick events have elapsed. (In reality
    /// the hardware triggers its interrupt some time after that. We also allow
    /// the interrupt to fire early.)
    /// This must be called while the task is stopped, and it must be called
    /// before the task is allowed to run again.
    /// `ticks_period` of zero means don't interrupt at all.
    pub fn reset(ticks_period: Ticks) {}

    /// Close the perfcounter fds. They will be automatically reopened if/when
    /// reset is called again.
    pub fn stop(&mut self) {
        if !self.started {
            return;
        }

        self.fd_ticks_interrupt.close();
        self.fd_ticks_measure.close();
        self.fd_minus_ticks_measure.close();
        self.fd_useless_counter.close();
        self.fd_ticks_in_transaction.close();
    }

    /// Suspend counting until the next reset. This may or may not actually stop
    /// the performance counters, depending on whether or not this is required
    /// for correctness on this kernel version.
    pub fn stop_counting(&self) {
        // @TODO.
    }

    /// Return the number of ticks we need for an emulated branch.
    pub fn ticks_for_unconditional_indirect_branch(task: &Task) -> Ticks {
        // @TODO.
        5
    }

    /// Return the number of ticks we need for a direct call.
    pub fn ticks_for_direct_call(t: &Task) -> Ticks {
        // @TODO.
        5
    }

    /// Read the current value of the ticks counter.
    /// `t` is used for debugging purposes.
    pub fn read_ticks(t: &Task) -> Ticks {
        // @TODO.
        5
    }

    /// Returns what ticks mean for these counters.
    pub fn ticks_semantics(&self) -> TicksSemantics {
        self.ticks_semantics_
    }

    /// Return the fd we last used to generate the ticks-counter signal.
    pub fn ticks_interrupt_fd(&self) -> RawFd {
        self.fd_ticks_interrupt.get()
    }

    // @TODO
    // fn is_rr_ticks_attr(const perf_event_attr& attr) -> bool ;

    pub fn supports_ticks_semantics(ticks_semantics: TicksSemantics) -> bool {
        // @TODO.
        false
    }

    pub fn default_ticks_semantics() -> TicksSemantics {
        // @TODO.
        TicksRetiredConditionalBranches
    }

    /// When an interrupt is requested, at most this many ticks may elapse before
    /// the interrupt is delivered.
    pub fn skid_size() -> u32 {
        // @TODO.
        5
    }

    /// Use a separate skid_size for recording since we seem to see more skid
    /// in practice during recording, in particular during the
    /// async_signal_syscalls tests
    pub fn recording_skid_size() -> u32 {
        Self::skid_size() * 5
    }
}

impl Drop for PerfCounters {
    fn drop(&mut self) {
        self.stop()
    }
}
