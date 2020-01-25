use crate::log::*;
use crate::perf_event::perf_event_attr;
use crate::perf_event::perf_type_id;
use crate::perf_event::{PERF_COUNT_HW_CPU_CYCLES, PERF_TYPE_HARDWARE, PERF_TYPE_RAW};
use crate::perf_event::{PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE};
use crate::scoped_fd::ScopedFd;
use crate::task::Task;
use crate::ticks::Ticks;
use crate::util::*;
use libc::ioctl;
use nix::unistd::Pid;
use raw_cpuid::CpuId;
use std::convert::TryInto;
use std::io::stderr;
use std::io::Write;
use std::mem::size_of_val;
use std::mem::zeroed;
use std::os::unix::io::RawFd;

// At some point we might support multiple kinds of ticks for the same CPU arch.
// At that point this will need to become more complicated.

// @TODO Pending possible globals
// static supports_txcp: bool = false;
// static only_one_counter: bool = false;
// end pending possible globals

lazy_static! {
    // @TODO need code to check for ioc period bug. Hardcoded for now.
    static ref HAS_IOC_PERIOD_BUG: bool = false;
    static ref PMU_ATTRIBUTES: PmuAttributes = get_init_attributes();
}

// @TODO for now we just hardcode this.
const HAS_KVM_IN_TXCP_BUG: bool = false;
const HAS_XEN_PMI_BUG: bool = false;
// end hardcode.

const NUM_BRANCHES: i32 = 500;
const RD_SKID_MAX: u32 = 1000;
const PERF_COUNT_RD: u32 = 0x72727272;

/// This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
/// hope that tracees don't either.
const TIME_SLICE_SIGNAL: i32 = libc::SIGSTKFLT;

const IN_TX: u64 = 1 << 32;
const IN_TXCP: u64 = 1 << 33;

bitflags! {
    struct PmuFlags: u32 {
        const PMU_ZERO = 0;

        /// Set if this CPU supports ticks counting retired conditional branches.
        const PMU_TICKS_RCB = 1<<0;

        /// Some CPUs turn off the whole PMU when there are no remaining events
        /// scheduled (perhaps as a power consumption optimization). This can be a
        /// very expensive operation, and is thus best avoided. For cpus, where this
        /// is a problem, we keep a cycles counter (which corresponds to one of the
        /// fixed function counters, so we don't use up a programmable PMC) that we
        /// don't otherwise use, but keeps the PMU active, greatly increasing
        /// performance.
        const PMU_BENEFITS_FROM_USELESS_COUNTER = 1<<1;

        /// Whether to skip the check for Intel CPU bugs
        const PMU_SKIP_INTEL_BUG_CHECK = 1<<2;

        /// Set if this CPU supports ticks counting all taken branches
        /// (excluding interrupts, far branches, and rets).
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
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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

/// Return the detected, known microarchitecture of this CPU, or don't
/// return; i.e. never return UnknownCpu.
fn get_cpu_microarch() -> CpuMicroarch {
    // @TODO forced micro arch from command line options.
    let cpuid = CpuId::new();
    let vendor_info_string = cpuid.get_vendor_info().unwrap().as_string().to_owned();

    if vendor_info_string != "GenuineIntel" && vendor_info_string != "AuthenticAMD" {
        clean_fatal!("Unknown CPU vendor '{}'", vendor_info_string);
    }

    let cpuid_data = cpuid.get_feature_info().unwrap();
    // let cpu_type : u32 = cpuid_data.eax & 0xF0FF0;
    let cpu_type: u32 = ((cpuid_data.model_id() as u32) << 4)
        + ((cpuid_data.family_id() as u32) << 8)
        + ((cpuid_data.extended_model_id() as u32) << 16);
    let ext_family: u8 = cpuid_data.extended_family_id();
    match cpu_type {
        0x006F0 | 0x10660 => return IntelMerom,
        0x10670 | 0x106D0 => return IntelPenryn,
        0x106A0 | 0x106E0 | 0x206E0 => return IntelNehalem,
        0x20650 | 0x206C0 | 0x206F0 => return IntelWestmere,
        0x206A0 | 0x206D0 | 0x306e0 => return IntelSandyBridge,
        0x306A0 => return IntelIvyBridge,
        0x306C0 | 0x306F0 | 0x40650 | 0x40660 => return IntelHaswell,
        0x306D0 | 0x40670 | 0x406F0 | 0x50660 => return IntelBroadwell,
        0x406e0 | 0x50650 | 0x506e0 => return IntelSkylake,
        0x30670 | 0x406c0 | 0x50670 => return IntelSilvermont,
        0x506f0 => return IntelGoldmont,
        0x806e0 | 0x906e0 => return IntelKabylake,
        0xa0660 => return IntelCometlake,
        0x30f00 => return AMDF15R30,
        0x00f10 => {
            if ext_family == 8 {
                // @TODO Supress environment warnings.
                write!(
                    stderr(),
                    "You have a Ryzen CPU. The Ryzen\n\
                     retired-conditional-branches hardware\n\
                     performance counter is not accurate enough; rr will\n\
                     be unreliable.\n\
                     See https://github.com/mozilla/rr/issues/2034.\n"
                )
                .unwrap();
                // }
                return AMDRyzen;
            }
        }
        _ => (),
    }

    if vendor_info_string == "AuthenticAMD" {
        clean_fatal!(
            "AMD CPUs not supported.\n\
             For Ryzen, see https://github.com/mozilla/rr/issues/2034.\n\
             For post-Ryzen CPUs, please file a Github issue."
        );
    } else {
        clean_fatal!("Intel CPU type {:#x} unknown", cpu_type);
    }

    UnknownCpu // not reached
}

/// @TODO.
fn check_for_bugs() {}

/// init_perf_event_attr() in rr.
fn new_perf_event_attr(type_id: perf_type_id, config: u64) -> perf_event_attr {
    let mut attr: perf_event_attr = unsafe { zeroed() };
    attr.type_ = type_id;
    attr.size = size_of_val(&attr) as u32;
    attr.config = config;
    // rr requires that its events count userspace tracee code
    // only.
    attr.set_exclude_kernel(1);
    attr.set_exclude_guest(1);
    attr
}

struct PmuAttributes {
    pmu_flags: PmuFlags,
    skid_size: u32,
    ticks_attr: perf_event_attr,
    hw_interrupts_attr: Option<perf_event_attr>,
    cycles_attr: Option<perf_event_attr>,
    minus_ticks_attr: Option<perf_event_attr>,
    activate_useless_counter: Option<bool>,
}

/// Gets the values for the lazy_static! global PMU_ATTRIBUTES.
fn get_init_attributes() -> PmuAttributes {
    let uarch = get_cpu_microarch();
    let mut maybe_pmu: Option<&PmuConfig> = None;
    for config in &PMU_CONFIGS {
        if uarch == config.uarch {
            maybe_pmu = Some(config);
            break;
        }
    }

    let pmu = maybe_pmu.unwrap();
    if !(pmu.flags & (PmuFlags::PMU_TICKS_RCB | PmuFlags::PMU_TICKS_TAKEN_BRANCHES)
        == (PmuFlags::PMU_TICKS_RCB | PmuFlags::PMU_TICKS_TAKEN_BRANCHES))
    {
        fatal!("Microarchitecture `{}' currently unsupported.", pmu.name);
    }

    let pmu_flags;
    let skid_size;
    let ticks_attr;
    let mut hw_interrupts_attr = None;
    let mut cycles_attr = None;
    let mut minus_ticks_attr = None;
    let mut activate_useless_counter = None;
    if running_under_rd() {
        ticks_attr = new_perf_event_attr(PERF_TYPE_HARDWARE, PERF_COUNT_RD as u64);
        skid_size = RD_SKID_MAX;
        pmu_flags = pmu.flags & (PmuFlags::PMU_TICKS_RCB | PmuFlags::PMU_TICKS_TAKEN_BRANCHES);
    } else {
        skid_size = pmu.skid_size;
        pmu_flags = pmu.flags;
        ticks_attr = new_perf_event_attr(PERF_TYPE_RAW, pmu.rcb_cntr_event as u64);
        if pmu.minus_ticks_cntr_event != 0 {
            minus_ticks_attr = Some(new_perf_event_attr(
                PERF_TYPE_RAW,
                pmu.minus_ticks_cntr_event as u64,
            ));
        }

        cycles_attr = Some(new_perf_event_attr(
            PERF_TYPE_HARDWARE,
            PERF_COUNT_HW_CPU_CYCLES as u64,
        ));
        let mut hw_interrupts_attr_bare =
            new_perf_event_attr(PERF_TYPE_RAW, pmu.hw_intr_cntr_event as u64);
        // libpfm encodes the event with this bit set, so we'll do the
        // same thing.  Unclear if necessary.
        hw_interrupts_attr_bare.set_exclude_hv(1);
        hw_interrupts_attr = Some(hw_interrupts_attr_bare);

        if !(pmu_flags & PmuFlags::PMU_SKIP_INTEL_BUG_CHECK == PmuFlags::PMU_SKIP_INTEL_BUG_CHECK) {
            check_for_bugs();
        }

        // For maintainability, and since it doesn't impact performance when not
        // needed, we always activate this. If it ever turns out to be a problem,
        // this can be set to pmu->flags & PMU_BENEFITS_FROM_USELESS_COUNTER,
        // instead.
        //
        // We also disable this counter when running under rr. Even though it's the
        // same event for the same task as the outer rr, the linux kernel does not
        // coalesce them and tries to schedule the new one on a general purpose PMC.
        // On CPUs with only 2 general PMCs (e.g. KNL), we'd run out.
        activate_useless_counter = Some(*HAS_IOC_PERIOD_BUG && !running_under_rd());
    }

    PmuAttributes {
        pmu_flags,
        skid_size,
        ticks_attr,
        hw_interrupts_attr,
        cycles_attr,
        minus_ticks_attr,
        activate_useless_counter,
    }
}

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
    *HAS_IOC_PERIOD_BUG || HAS_KVM_IN_TXCP_BUG
}

fn read_counter(fd: &ScopedFd) -> u64 {
    let mut val: u64 = 0;
    // @TODO what about checking for errno?
    let nread = unsafe {
        libc::read(
            **fd,
            &mut val as *mut u64 as *mut libc::c_void,
            size_of_val(&val),
        )
    };
    debug_assert!(nread == size_of_val(&val).try_into().unwrap());
    val
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
        if PMU_ATTRIBUTES.pmu_flags & PmuFlags::PMU_TICKS_TAKEN_BRANCHES
            == PmuFlags::PMU_TICKS_TAKEN_BRANCHES
        {
            1
        } else {
            0
        }
    }

    /// Return the number of ticks we need for a direct call.
    pub fn ticks_for_direct_call(t: &Task) -> Ticks {
        if PMU_ATTRIBUTES.pmu_flags & PmuFlags::PMU_TICKS_TAKEN_BRANCHES
            == PmuFlags::PMU_TICKS_TAKEN_BRANCHES
        {
            1
        } else {
            0
        }
    }

    /// Read the current value of the ticks counter.
    /// `t` is used for debugging purposes.
    pub fn read_ticks(&self, t: &Task) -> Ticks {
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
