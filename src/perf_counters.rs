use crate::perf_event::{PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE};
use crate::scoped_fd::ScopedFd;
use crate::task::Task;
use crate::ticks::Ticks;
use libc::ioctl;
use nix::unistd::Pid;
use std::os::unix::io::RawFd;

// @TODO Do we want these as global variables?
// At some point we might support multiple kinds of ticks for the same CPU arch.
// At that point this will need to become more complicated.
/*
static ticks_attr: perf_event_attr = perf_event_attr {};
static minus_ticks_attr: perf_event_attr = perf_event_attr;
static cycles_attr: perf_event_attr = perf_event_attr;
static hw_interrupts_attr: perf_event_attr = perf_event_attr;
static pmu_flags: u32 = 0;
static skid_size: u32 = 0;
static has_xen_pmi_bug: bool = false;
static supports_txcp: bool = false;
static only_one_counter: bool = false;
static activate_useless_counter: bool = false;
*/

static ATTRIBUTES_INITIALIZED: bool = false;
static HAS_IOC_PERIOD_BUG: bool = false;
static HAS_KVM_IN_TXCP_BUG: bool = false;

const NUM_BRANCHES: i32 = 500;
const RR_SKID_MAXL: i32 = 1000;
const PERF_COUNT_RR: i32 = 0x72727272;

/// This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
/// hope that tracees don't either.
const TIME_SLICE_SIGNAL: i32 = libc::SIGSTKFLT;

const IN_TX: u64 = 1 << 32;
const IN_TXCP: u64 = 1 << 33;

bitflags! {
    struct PmuFlags: u32 {
        const PMU_ZERO = 0;

        // Set if this CPU supports ticks counting retired conditional branches.
        const PMU_TICKS_RCB = 1<<0;

        // Some CPUs turn off the whole PMU when there are no remaining events
        // scheduled (perhaps as a power consumption optimization). This can be a
        // very expensive operation, and is thus best avoided. For cpus, where this
        // is a problem, we keep a cycles counter (which corresponds to one of the
        // fixed function counters, so we don't use up a programmable PMC) that we
        // don't otherwise use, but keeps the PMU active, greatly increasing
        // performance.
        const PMU_BENEFITS_FROM_USELESS_COUNTER = 1<<1;

        // Whether to skip the check for Intel CPU bugs
        const PMU_SKIP_INTEL_BUG_CHECK = 1<<2;

        // Set if this CPU supports ticks counting all taken branches
        // (excluding interrupts, far branches, and rets).
        const PMU_TICKS_TAKEN_BRANCHES = 1<<3;

        const PMU_TICKS_TAKEN_BRANCHES_WITH_SKIP_INTEL_BUG_CHECK =
            Self::PMU_TICKS_TAKEN_BRANCHES.bits | Self::PMU_SKIP_INTEL_BUG_CHECK.bits;
    }
}

#[derive(Copy, Clone)]
enum TicksSemantics {
    TicksRetiredConditionalBranches,
    TicksTakenBranches,
}

/// Find out the cpu model using the cpuid instruction.
/// Full list of CPUIDs at http://sandpile.org/x86/cpuid.htm
/// Another list at
/// http://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers
enum CpuMicroarch {
    UnknownCpu,
    IntelMerom,
    IntelPenryn,
    IntelNehalem,
    IntelWestmere,
    IntelSandyBridge,
    IntelIvyBridge,
    IntelHaswell,
    IntelBroadwell,
    IntelSkylake,
    IntelSilvermont,
    IntelGoldmont,
    IntelKabylake,
    IntelCometlake,
    AMDF15R30,
    AMDRyzen,
}

use CpuMicroarch::*;

/// XXX please only edit this if you really know what you're doing.
/// event = 0x5101c4:
/// - 51 = generic PMU
/// - 01 = umask for event BR_INST_RETIRED.CONDITIONAL
/// - c4 = eventsel for event BR_INST_RETIRED.CONDITIONAL
/// event = 0x5301cb:
/// - 51 = generic PMU
/// - 01 = umask for event HW_INTERRUPTS.RECEIVED
/// - cb = eventsel for event HW_INTERRUPTS.RECEIVED
/// See Intel 64 and IA32 Architectures Performance Monitoring Events.
/// See check_events from libpfm4.
const PMU_CONFIGS: [PmuConfig; 15] = [
    PmuConfig {
        uarch: IntelCometlake,
        name: "Intel Cometlake",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelKabylake,
        name: "Intel Kabylake",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelSilvermont,
        name: "Intel Silvermont",
        rcb_cntr_event: 0x517ec4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelGoldmont,
        name: "Intel Goldmont",
        rcb_cntr_event: 0x517ec4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelSkylake,
        name: "Intel Skylake",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelBroadwell,
        name: "Intel Broadwell",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelHaswell,
        name: "Intel Haswell",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelIvyBridge,
        name: "Intel Ivy Bridge",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelSandyBridge,
        name: "Intel Sandy Bridge",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x5301cb,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelNehalem,
        name: "Intel Nehalem",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x50011d,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelWestmere,
        name: "Intel Westmere",
        rcb_cntr_event: 0x5101c4,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0x50011d,
        skid_size: 100,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
    PmuConfig {
        uarch: IntelPenryn,
        name: "Intel Penryn",
        rcb_cntr_event: 0,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0,
        skid_size: 100,
        flags: PmuFlags::PMU_ZERO,
    },
    PmuConfig {
        uarch: IntelMerom,
        name: "Intel Merom",
        rcb_cntr_event: 0,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0,
        skid_size: 100,
        flags: PmuFlags::PMU_ZERO,
    },
    PmuConfig {
        uarch: AMDF15R30,
        name: "AMD Family 15h Revision 30h",
        rcb_cntr_event: 0xc4,
        minus_ticks_cntr_event: 0xc6,
        hw_intr_cntr_event: 0,
        skid_size: 250,
        flags: PmuFlags::PMU_TICKS_TAKEN_BRANCHES_WITH_SKIP_INTEL_BUG_CHECK,
    },
    PmuConfig {
        uarch: AMDRyzen,
        name: "AMD Ryzen",
        rcb_cntr_event: 0x5100d1,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0,
        skid_size: 1000,
        flags: PmuFlags::PMU_TICKS_RCB,
    },
];

use TicksSemantics::*;

struct PmuConfig {
    uarch: CpuMicroarch,
    name: &'static str,
    rcb_cntr_event: u32,
    minus_ticks_cntr_event: u32,
    hw_intr_cntr_event: u32,
    skid_size: u32,
    flags: PmuFlags,
}

fn always_recreate_counters() -> bool {
    // When we have the KVM IN_TXCP bug, reenabling the TXCP counter after
    // disabling it does not work.
    HAS_IOC_PERIOD_BUG || HAS_KVM_IN_TXCP_BUG
}

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
    pub fn reset(ticks_period: Ticks) {
        // @TODO.
    }

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
    pub fn stop_counting(&mut self) {
        if !self.counting {
            return;
        }

        self.counting = false;
        if always_recreate_counters() {
            self.stop()
        } else {
            unsafe {
                ioctl(*self.fd_ticks_interrupt, PERF_EVENT_IOC_DISABLE, 0);
            }
            if self.fd_minus_ticks_measure.is_open() {
                unsafe {
                    ioctl(*self.fd_minus_ticks_measure, PERF_EVENT_IOC_DISABLE, 0);
                }
            }
            if self.fd_ticks_measure.is_open() {
                unsafe {
                    ioctl(*self.fd_ticks_measure, PERF_EVENT_IOC_DISABLE, 0);
                }
            }
            if self.fd_ticks_in_transaction.is_open() {
                unsafe {
                    ioctl(*self.fd_ticks_in_transaction, PERF_EVENT_IOC_DISABLE, 0);
                }
            }
        }
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
