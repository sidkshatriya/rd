use crate::{
    bindings::{
        fcntl::{f_owner_ex, F_OWNER_TID, F_SETOWN_EX, F_SETSIG},
        perf_event::{
            perf_event_attr,
            perf_type_id,
            PERF_COUNT_HW_CPU_CYCLES,
            PERF_EVENT_IOC_DISABLE,
            PERF_EVENT_IOC_ENABLE,
            PERF_EVENT_IOC_PERIOD,
            PERF_EVENT_IOC_RESET,
            PERF_TYPE_HARDWARE,
            PERF_TYPE_RAW,
        },
    },
    flags::Flags,
    kernel_metadata::signal_name,
    log::LogLevel::{LogDebug, LogInfo, LogWarn},
    scoped_fd::ScopedFd,
    session::task::task_inner::task_inner::TaskInner,
    ticks::Ticks,
    util::running_under_rd,
};
use libc::{c_ulong, fcntl, ioctl, pid_t, F_SETFL, O_ASYNC};
use nix::{
    errno::errno,
    poll::{poll, PollFd, PollFlags},
    unistd::read,
};
use raw_cpuid::CpuId;
use std::{
    io::{stderr, Write},
    mem::size_of,
    os::unix::io::RawFd,
    sync::Mutex,
};

lazy_static! {
    static ref PMU_BRANCHES_ACCUMULATOR: Mutex<u32> = Mutex::new(0);
    static ref PMU_BUGS_AND_EXTRA: PmuBugsAndExtra = check_for_bugs_and_extra();
    static ref PMU_ATTRIBUTES: PmuAttributes = get_init_attributes();
}

pub fn init_pmu() {
    // PMU_BUGS_AND_EXTRA/PMU_ATTRIBUTES are static ref and get initialized lazily
    // Here as a side effect they get initialized by storing in a boolean.
    // @TODO this needs to be set in a boolean explicitly. Otherwise there is a mutex locking issue
    let only_one_counter = PMU_BUGS_AND_EXTRA.only_one_counter;
    log!(
        LogDebug,
        "Initialized PMU Successfully (only_one_counter={}).",
        only_one_counter
    );
}

// @TODO for now we just hardcode this.
const HAS_XEN_PMI_BUG: bool = false;
// end hardcode.

const NUM_BRANCHES: u64 = 500;
const RD_SKID_MAX: Ticks = 1000;
const PERF_COUNT_RD: u32 = 0x72727272;

/// This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
/// hope that tracees don't either.
pub const TIME_SLICE_SIGNAL: i32 = libc::SIGSTKFLT;

const IN_TX: u64 = 1 << 32;
const IN_TXCP: u64 = 1 << 33;

bitflags! {
    struct PmuFlags: u32 {
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

#[derive(Copy, Clone, Debug)]
pub enum TicksSemantics {
    TicksRetiredConditionalBranches,
    TicksTakenBranches,
}

use TicksSemantics::*;

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
    let maybe_forced_uarch = Flags::get().forced_uarch.as_ref().map(|u| u.to_lowercase());
    match maybe_forced_uarch {
        Some(forced_uarch) => {
            for pmu in &PMU_CONFIGS {
                let name: String = pmu.name.to_lowercase();
                if let Some(_) = name.find(&forced_uarch) {
                    log!(LogInfo, "Using forced uarch {}", pmu.name);
                    return pmu.uarch;
                }
            }

            clean_fatal!(
                "Forced uarch {} isn't known",
                Flags::get().forced_uarch.as_ref().unwrap()
            );
        }
        None => (),
    }

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
                if !Flags::get().suppress_environment_warnings {
                    write!(
                        stderr(),
                        "You have a Ryzen CPU. The Ryzen\n\
                     retired-conditional-branches hardware\n\
                     performance counter is not accurate enough; rd will\n\
                     be unreliable.\n\
                     See https://github.com/mozilla/rr/issues/2034.\n"
                    )
                    .unwrap();
                }
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
}

struct PmuBugsAndExtra {
    has_ioc_period_bug: bool,
    supports_txcp: bool,
    has_kvm_in_txcp_bug: bool,
    activate_useless_counter: bool,
    only_one_counter: bool,
}

/// check_for_bugs() in rr.
fn check_for_bugs_and_extra() -> PmuBugsAndExtra {
    let has_ioc_period_bug;
    let supports_txcp;
    let has_kvm_in_txcp_bug;
    let only_one_counter;

    if PMU_ATTRIBUTES
        .pmu_flags
        .contains(PmuFlags::PMU_SKIP_INTEL_BUG_CHECK)
    {
        // Set some defaults since we're not checking the CPU.
        has_ioc_period_bug = false;
        supports_txcp = false;
        has_kvm_in_txcp_bug = false;
        // @TODO is this a reasonable default? Should this be true?
        // In rr, it seems that only_one_counter = false by default as it is a global static bool.
        only_one_counter = false;
    } else {
        has_ioc_period_bug = system_has_ioc_period_bug();
        let res = supports_txp_and_has_kvm_in_txcp_bug();
        supports_txcp = res.0;
        has_kvm_in_txcp_bug = res.1;
        only_one_counter = check_working_counters();
    }
    // For maintainability, and since it doesn't impact performance when not
    // needed, we always activate this. If it ever turns out to be a problem,
    // this can be set to pmu->flags & PMU_BENEFITS_FROM_USELESS_COUNTER,
    // instead.
    //
    // We also disable this counter when running under rd. Even though it's the
    // same event for the same task as the outer rd, the linux kernel does not
    // coalesce them and tries to schedule the new one on a general purpose PMC.
    // On CPUs with only 2 general PMCs (e.g. KNL), we'd run out.
    let activate_useless_counter = has_ioc_period_bug && !running_under_rd();
    PmuBugsAndExtra {
        has_ioc_period_bug,
        supports_txcp,
        has_kvm_in_txcp_bug,
        activate_useless_counter,
        only_one_counter,
    }
}

/// check_for_ioc_period_bug() in rr
fn system_has_ioc_period_bug() -> bool {
    // Start a cycles counter
    let mut attr: perf_event_attr = PMU_ATTRIBUTES.ticks_attr;
    attr.__bindgen_anon_1.sample_period = 0xffffffff;
    attr.set_exclude_kernel(1);
    let (bug_fd, _) = start_counter(0, -1, &mut attr);

    let new_period: u64 = 1;
    if perf_ioctl(&bug_fd, PERF_EVENT_IOC_PERIOD, &new_period as *const u64) != 0 {
        fatal!("ioctl(PERF_EVENT_IOC_PERIOD) failed");
    }

    let mut poll_bug_fd = [PollFd::new(bug_fd.as_raw(), PollFlags::POLLIN)];
    poll(&mut poll_bug_fd, 0).unwrap();

    let has_ioc_period_bug = poll_bug_fd[0].revents().is_none();
    log!(LogDebug, "has_ioc_period_bug={}", has_ioc_period_bug);
    has_ioc_period_bug
}

/// check_for_kvm_in_txcp_bug() in rr
fn supports_txp_and_has_kvm_in_txcp_bug() -> (bool, bool) {
    let mut count: u64 = 0;
    let mut attr: perf_event_attr = PMU_ATTRIBUTES.ticks_attr;
    attr.config = attr.config | IN_TXCP;
    attr.__bindgen_anon_1.sample_period = 0;
    let (fd, disabled_txcp) = start_counter(0, -1, &mut attr);
    if fd.is_open() && !disabled_txcp {
        perf_ioctl_null(&fd, PERF_EVENT_IOC_DISABLE);
        perf_ioctl_null(&fd, PERF_EVENT_IOC_ENABLE);
        do_branches();
        count = read_counter(&fd);
    }

    let supports_txcp = count > 0;
    let has_kvm_in_txcp_bug = supports_txcp && count < NUM_BRANCHES;
    log!(LogDebug, "supports txcp={}", supports_txcp);
    log!(
        LogDebug,
        "has_kvm_in_txcp_bug={} count={}",
        has_kvm_in_txcp_bug,
        count
    );
    (supports_txcp, has_kvm_in_txcp_bug)
}

/// init_perf_event_attr() in rr.
fn new_perf_event_attr(type_id: perf_type_id, config: u64) -> perf_event_attr {
    let mut attr: perf_event_attr = Default::default();
    attr.type_ = type_id;
    attr.size = std::mem::size_of::<perf_event_attr>() as u32;
    attr.config = config;
    // rd requires that its events count userspace tracee code
    // only.
    attr.set_exclude_kernel(1);
    attr.set_exclude_guest(1);
    attr
}

struct PmuAttributes {
    pmu_flags: PmuFlags,
    skid_size: Ticks,
    ticks_attr: perf_event_attr,
    hw_interrupts_attr: Option<perf_event_attr>,
    cycles_attr: Option<perf_event_attr>,
    minus_ticks_attr: Option<perf_event_attr>,
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
    if !(pmu.flags.contains(PmuFlags::PMU_TICKS_RCB)
        || pmu.flags.contains(PmuFlags::PMU_TICKS_TAKEN_BRANCHES))
    {
        fatal!("Microarchitecture `{}' currently unsupported.", pmu.name);
    }

    let pmu_flags;
    let skid_size;
    let ticks_attr;
    let mut hw_interrupts_attr = None;
    let mut cycles_attr = None;
    let mut minus_ticks_attr = None;
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
    }

    PmuAttributes {
        pmu_flags,
        skid_size,
        ticks_attr,
        hw_interrupts_attr,
        cycles_attr,
        minus_ticks_attr,
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
        flags: PmuFlags::empty(),
    },
    PmuConfig {
        uarch: IntelMerom,
        name: "Intel Merom",
        rcb_cntr_event: 0,
        minus_ticks_cntr_event: 0,
        hw_intr_cntr_event: 0,
        skid_size: 100,
        flags: PmuFlags::empty(),
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

struct PmuConfig {
    uarch: CpuMicroarch,
    name: &'static str,
    rcb_cntr_event: u32,
    minus_ticks_cntr_event: u32,
    hw_intr_cntr_event: u32,
    skid_size: Ticks,
    flags: PmuFlags,
}

fn always_recreate_counters() -> bool {
    // When we have the KVM IN_TXCP bug, reenabling the TXCP counter after
    // disabling it does not work.
    PMU_BUGS_AND_EXTRA.has_ioc_period_bug || PMU_BUGS_AND_EXTRA.has_kvm_in_txcp_bug
}

/// DIFF NOTE: Return type is an i64 on rr.
fn read_counter(fd: &ScopedFd) -> u64 {
    let mut buf = [0u8; size_of::<u64>()];
    let result = read(fd.as_raw(), &mut buf);
    match result {
        Ok(nread) if nread == size_of::<u64>() => u64::from_le_bytes(buf),
        // In rd we check the result for success unlike rr.
        _ => {
            fatal!("Could not read pert counter successfully");
            unreachable!()
        }
    }
}

fn start_counter(tid: pid_t, group_fd: i32, attr: &mut perf_event_attr) -> (ScopedFd, bool) {
    let mut disabled_txcp = false;

    attr.set_pinned(0);
    if group_fd == -1 {
        attr.set_pinned(1);
    }

    let mut fd: RawFd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr as *mut perf_event_attr,
            tid,
            -1,
            group_fd,
            0,
        ) as RawFd
    };
    if 0 >= fd
        && errno() == libc::EINVAL
        && attr.type_ == PERF_TYPE_RAW
        && (attr.config & IN_TXCP == IN_TXCP)
    {
        // The kernel might not support IN_TXCP, so try again without it.
        let mut tmp_attr: perf_event_attr = *attr;
        tmp_attr.config = tmp_attr.config & !IN_TXCP;
        fd = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                &mut tmp_attr,
                tid,
                -1,
                group_fd,
                0,
            ) as RawFd
        };
        if fd >= 0 {
            disabled_txcp = true;

            log!(LogWarn, "kernel does not support IN_TXCP");
            let cpuid = CpuId::new();
            if cpuid.get_extended_feature_info().unwrap().has_hle()
                && !Flags::get().suppress_environment_warnings
            {
                write!(
                    stderr(),
                    "Your CPU supports Hardware Lock Elision but your kernel does\n\
                     not support setting the IN_TXCP PMU flag. Record and replay\n\
                     of code that uses HLE will fail unless you update your\n\
                     kernel.\n"
                )
                .unwrap();
            }
        }
    }

    if 0 >= fd {
        if errno() == libc::EACCES {
            fatal!(
                "Permission denied to use 'perf_event_open'; are perf events \n\
                 enabled? Try 'perf record'."
            );
        }
        if errno() == libc::ENOENT {
            fatal!(
                "Unable to open performance counter with 'perf_event_open'; \n\
                 are perf events enabled? Try 'perf record'."
            );
        }
        fatal!("Failed to initialize counter");
    }

    (ScopedFd::from_raw(fd), disabled_txcp)
}

/// Wrapper for the libc ioctl call.
fn perf_ioctl(fd: &ScopedFd, param1: c_ulong, param2: *const u64) -> i32 {
    unsafe { ioctl(fd.as_raw(), param1, param2) }
}

/// Same as perf_ioctl() except third param is always 0.
fn perf_ioctl_null(fd: &ScopedFd, param1: c_ulong) -> i32 {
    unsafe { ioctl(fd.as_raw(), param1, 0) }
}

fn do_branches() {
    // Do NUM_BRANCHES conditional branches that can't be optimized out.
    // 'accumulator' is always odd and can't be zero
    let mut accumulator: u32 = (unsafe { libc::rand() } as u32)
        .overflowing_mul(2)
        .0
        .overflowing_add(1)
        .0;
    for _ in 0..NUM_BRANCHES {
        if accumulator == 0 {
            break;
        }
        accumulator = accumulator.overflowing_mul(7).0.overflowing_add(2).0 & 0xffffff;
    }

    let mut lock = PMU_BRANCHES_ACCUMULATOR.lock().unwrap();
    *lock = accumulator;
}

/// Returns true if there is only 1 working counter, false otherwise.
fn check_working_counters() -> bool {
    let mut attr = PMU_ATTRIBUTES.ticks_attr;
    attr.__bindgen_anon_1.sample_period = 0;

    let mut attr2 = PMU_ATTRIBUTES.cycles_attr.unwrap();
    // @TODO check
    attr2.__bindgen_anon_1.sample_period = 0;

    let (fd, _) = start_counter(0, -1, &mut attr);
    let (fd2, _) = start_counter(0, -1, &mut attr2);
    do_branches();
    let events = read_counter(&fd);
    let events2 = read_counter(&fd2);

    // @TODO the perf stat command does not seem to be correct.
    if events < NUM_BRANCHES {
        let config = PMU_ATTRIBUTES.ticks_attr.config;
        fatal!(
            "\nGot {} branch events, expected at least {}.\n\n\
             The hardware performance counter seems to not be working. Check\n\
             that hardware performance counters are working by running:\n\
             perf stat --event=r{:#x} true\n\
             in a linux shell and checking that it reports a nonzero number of events.\n\
             If performance counters seem to be working with 'perf', file an\n\
             rd issue, otherwise check your hardware/OS/VM configuration. Also\n\
             check that other software is not using performance counters on\n\
             this CPU.",
            events,
            NUM_BRANCHES,
            config
        );
    }

    let only_one_counter = events2 == 0;
    log!(LogWarn, "only_one_counter={}", only_one_counter);
    let cpuid = CpuId::new();

    if only_one_counter
        && cpuid.get_extended_feature_info().unwrap().has_hle()
        && !Flags::get().suppress_environment_warnings
    {
        write!(
            stderr(),
            "Your CPU supports Hardware Lock Elision but you only have one\n\
             hardware performance counter available. Record and replay\n\
             of code that uses HLE will fail unless you alter your\n\
             configuration to make more than one hardware performance counter\n\
             available.\n"
        )
        .unwrap();
    }
    only_one_counter
}

pub struct PerfCounters {
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
    ticks_semantics: TicksSemantics,
    started: bool,
    counting: bool,
}

fn make_counter_async(fd: &ScopedFd, signal: i32) {
    if unsafe {
        fcntl(fd.as_raw(), F_SETFL, O_ASYNC) != 0
            || fcntl(fd.as_raw(), F_SETSIG as i32, signal) != 0
    } {
        fatal!(
            "Failed to make ticks counter ASYNC with sig{}",
            signal_name(signal)
        );
    }
}

impl PerfCounters {
    pub fn new(tid: pid_t, ticks_semantics: TicksSemantics) -> Self {
        PerfCounters {
            tid,
            ticks_semantics,
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

    pub fn set_tid(&mut self, tid: pid_t) {
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
    pub fn reset(&mut self, param_ticks_period: Ticks) {
        let mut ticks_period: u64 = param_ticks_period;
        if ticks_period == 0 && !always_recreate_counters() {
            // We can't switch a counter between sampling and non-sampling via
            // PERF_EVENT_IOC_PERIOD so just turn 0 into a very big number.
            ticks_period = 1 << 60;
        }

        if !self.started {
            log!(
                LogDebug,
                "Recreating counters with period {} ({:#x})",
                ticks_period,
                ticks_period
            );

            let mut attr = PMU_ATTRIBUTES.ticks_attr;
            // Note that perf_event_attr struct implements the `Copy` trait.
            let maybe_minus_attr = PMU_ATTRIBUTES.minus_ticks_attr;
            attr.__bindgen_anon_1.sample_period = ticks_period;
            self.fd_ticks_interrupt = start_counter(self.tid, -1, &mut attr).0;
            match maybe_minus_attr {
                Some(mut minus_attr) => {
                    if minus_attr.config != 0 {
                        self.fd_minus_ticks_measure = start_counter(
                            self.tid,
                            self.fd_ticks_interrupt.as_raw(),
                            &mut minus_attr,
                        )
                        .0;
                    }
                }
                None => (),
            }

            if !PMU_BUGS_AND_EXTRA.only_one_counter && PMU_BUGS_AND_EXTRA.supports_txcp {
                if PMU_BUGS_AND_EXTRA.has_kvm_in_txcp_bug {
                    // IN_TXCP isn't going to work reliably. Assume that HLE/RTM are not
                    // used,
                    // and check that.
                    attr.__bindgen_anon_1.sample_period = 0;
                    attr.config = attr.config | IN_TX;
                    self.fd_ticks_in_transaction =
                        start_counter(self.tid, self.fd_ticks_interrupt.as_raw(), &mut attr).0;
                } else {
                    // Set up a separate counter for measuring ticks, which does not have
                    // a sample period and does not count events during aborted
                    // transactions.
                    // We have to use two separate counters here because the kernel does
                    // not support setting a sample_period with IN_TXCP, apparently for
                    // reasons related to this Intel note on IA32_PERFEVTSEL2:
                    // ``When IN_TXCP=1 & IN_TX=1 and in sampling, spurious PMI may
                    // occur and transactions may continuously abort near overflow
                    // conditions. Software should favor using IN_TXCP for counting over
                    // sampling. If sampling, software should use large “sample-after“
                    // value after clearing the counter configured to use IN_TXCP and
                    // also always reset the counter even when no overflow condition
                    // was reported.''
                    attr.__bindgen_anon_1.sample_period = 0;
                    attr.config = attr.config | IN_TXCP;
                    self.fd_ticks_measure =
                        start_counter(self.tid, self.fd_ticks_interrupt.as_raw(), &mut attr).0;
                }
            }

            // This creates a local copy.
            let mut cycles_attr = PMU_ATTRIBUTES.cycles_attr.unwrap();
            if PMU_BUGS_AND_EXTRA.activate_useless_counter && !self.fd_useless_counter.is_open() {
                // N.B.: This is deliberately not in the same group as the other counters
                // since we want to keep it scheduled at all times.
                self.fd_useless_counter = start_counter(self.tid, -1, &mut cycles_attr).0;
            }

            let own = f_owner_ex {
                type_: F_OWNER_TID,
                pid: self.tid,
            };
            if unsafe {
                fcntl(
                    self.fd_ticks_interrupt.as_raw(),
                    F_SETOWN_EX as i32,
                    &own as *const f_owner_ex,
                )
            } != 0
            {
                fatal!("Failed to SETOWN_EX ticks event fd");
            }
            make_counter_async(&self.fd_ticks_interrupt, TIME_SLICE_SIGNAL);
        } else {
            log!(
                LogDebug,
                "Resetting counters with period {} ({:#x})",
                ticks_period,
                ticks_period
            );

            if perf_ioctl_null(&self.fd_ticks_interrupt, PERF_EVENT_IOC_RESET) != 0 {
                fatal!("ioctl(PERF_EVENT_IOC_RESET) failed");
            }
            if perf_ioctl(
                &self.fd_ticks_interrupt,
                PERF_EVENT_IOC_PERIOD,
                &ticks_period,
            ) != 0
            {
                fatal!(
                    "ioctl(PERF_EVENT_IOC_PERIOD) failed with period {}",
                    ticks_period
                );
            }
            if perf_ioctl_null(&self.fd_ticks_interrupt, PERF_EVENT_IOC_ENABLE) != 0 {
                fatal!("ioctl(PERF_EVENT_IOC_ENABLE) failed");
            }
            if self.fd_minus_ticks_measure.is_open() {
                if perf_ioctl_null(&self.fd_minus_ticks_measure, PERF_EVENT_IOC_RESET) != 0 {
                    fatal!("ioctl(PERF_EVENT_IOC_RESET) failed");
                }
                if perf_ioctl_null(&self.fd_minus_ticks_measure, PERF_EVENT_IOC_ENABLE) != 0 {
                    fatal!("ioctl(PERF_EVENT_IOC_ENABLE) failed");
                }
            }
            if self.fd_ticks_measure.is_open() {
                if perf_ioctl_null(&self.fd_ticks_measure, PERF_EVENT_IOC_RESET) != 0 {
                    fatal!("ioctl(PERF_EVENT_IOC_RESET) failed");
                }
                if perf_ioctl_null(&self.fd_ticks_measure, PERF_EVENT_IOC_ENABLE) != 0 {
                    fatal!("ioctl(PERF_EVENT_IOC_ENABLE) failed");
                }
            }
            if self.fd_ticks_in_transaction.is_open() {
                if perf_ioctl_null(&self.fd_ticks_in_transaction, PERF_EVENT_IOC_RESET) != 0 {
                    fatal!("ioctl(PERF_EVENT_IOC_RESET) failed");
                }
                if perf_ioctl_null(&self.fd_ticks_in_transaction, PERF_EVENT_IOC_ENABLE) != 0 {
                    fatal!("ioctl(PERF_EVENT_IOC_ENABLE) failed");
                }
            }
        }

        self.started = true;
        self.counting = true;
        self.counting_period = ticks_period;
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
            // @TODO should we check if the ioctl calls succeded?
            perf_ioctl_null(&self.fd_ticks_interrupt, PERF_EVENT_IOC_DISABLE);
            if self.fd_minus_ticks_measure.is_open() {
                perf_ioctl_null(&self.fd_minus_ticks_measure, PERF_EVENT_IOC_DISABLE);
            }
            if self.fd_ticks_measure.is_open() {
                perf_ioctl_null(&self.fd_ticks_measure, PERF_EVENT_IOC_DISABLE);
            }
            if self.fd_ticks_in_transaction.is_open() {
                perf_ioctl_null(&self.fd_ticks_in_transaction, PERF_EVENT_IOC_DISABLE);
            }
        }
    }

    /// Return the number of ticks we need for an emulated branch.
    pub fn ticks_for_unconditional_indirect_branch(_task: &TaskInner) -> Ticks {
        if PMU_ATTRIBUTES
            .pmu_flags
            .contains(PmuFlags::PMU_TICKS_TAKEN_BRANCHES)
        {
            1
        } else {
            0
        }
    }

    /// Return the number of ticks we need for a direct call.
    pub fn ticks_for_direct_call(_task: &TaskInner) -> Ticks {
        if PMU_ATTRIBUTES
            .pmu_flags
            .contains(PmuFlags::PMU_TICKS_TAKEN_BRANCHES)
        {
            1
        } else {
            0
        }
    }

    /// Read the current value of the ticks counter.
    /// `t` is used for debugging purposes.
    pub fn read_ticks(&self, t: &TaskInner) -> Ticks {
        if !self.started || !self.counting {
            return 0;
        }

        if self.fd_ticks_in_transaction.is_open() {
            let transaction_ticks = read_counter(&self.fd_ticks_in_transaction);
            if transaction_ticks > 0 {
                log!(LogDebug, "{} IN_TX ticks detected", transaction_ticks);
                if !Flags::get().force_things {
                    ed_assert!(
                        t,
                        false,
                        "{} IN_TX ticks detected while HLE not supported due to KVM PMU\n\
                     virtualization bug. See \
                     http://marc.info/?l=linux-kernel&m=148582794808419&w=2\n\
                     Aborting. Retry with -F to override, but it will probably\n\
                     fail.",
                        transaction_ticks
                    );
                }
            }
        }

        let skid_size = if t.session().is_recording() {
            Self::recording_skid_size() as u64
        } else {
            Self::skid_size() as u64
        };

        let adjusted_counting_period = self.counting_period + skid_size;
        let mut interrupt_val = read_counter(&self.fd_ticks_interrupt);
        if !self.fd_ticks_measure.is_open() {
            if self.fd_minus_ticks_measure.is_open() {
                let minus_measure_val = read_counter(&self.fd_minus_ticks_measure);
                interrupt_val = interrupt_val - minus_measure_val;
            }
            ed_assert!(
                t,
                self.counting_period == 0 || interrupt_val <= adjusted_counting_period,
                "Detected {} ticks, expected no more than {}",
                interrupt_val,
                adjusted_counting_period
            );
            return interrupt_val;
        }

        let measure_val = read_counter(&self.fd_ticks_measure);
        if measure_val > interrupt_val {
            // There is some kind of kernel or hardware bug that means we sometimes
            // see more events with IN_TXCP set than without. These are clearly
            // spurious events :-(. For now, work around it by returning the
            // interrupt_val. That will work if HLE hasn't been used in this interval.
            // Note that interrupt_val > measure_val is valid behavior (when HLE is
            // being used).
            log!(
                LogDebug,
                "Measured too many ticks; measure={}, interrupt={}",
                measure_val,
                interrupt_val
            );
            ed_assert!(
                t,
                self.counting_period == 0 || interrupt_val <= adjusted_counting_period,
                "Detected {} ticks, expected no more than {}",
                interrupt_val,
                adjusted_counting_period
            );

            return interrupt_val;
        }
        ed_assert!(
            t,
            self.counting_period == 0 || interrupt_val <= adjusted_counting_period,
            "Detected {} ticks, expected no more than {}",
            interrupt_val,
            adjusted_counting_period
        );

        measure_val
    }

    /// Returns what ticks mean for these counters.
    pub fn ticks_semantics(&self) -> TicksSemantics {
        self.ticks_semantics
    }

    /// Return the fd we last used to generate the ticks-counter signal.
    pub fn ticks_interrupt_fd(&self) -> RawFd {
        self.fd_ticks_interrupt.as_raw()
    }

    pub fn is_rd_ticks_attr(attr: &perf_event_attr) -> bool {
        attr.type_ == PERF_TYPE_HARDWARE && attr.config == PERF_COUNT_RD as u64
    }

    pub fn supports_ticks_semantics(ticks_semantics: TicksSemantics) -> bool {
        match ticks_semantics {
            TicksRetiredConditionalBranches => {
                PMU_ATTRIBUTES.pmu_flags.contains(PmuFlags::PMU_TICKS_RCB)
            }
            TicksTakenBranches => PMU_ATTRIBUTES
                .pmu_flags
                .contains(PmuFlags::PMU_TICKS_TAKEN_BRANCHES),
        }
    }

    pub fn default_ticks_semantics() -> TicksSemantics {
        if PMU_ATTRIBUTES
            .pmu_flags
            .contains(PmuFlags::PMU_TICKS_TAKEN_BRANCHES)
        {
            return TicksTakenBranches;
        }
        if PMU_ATTRIBUTES.pmu_flags.contains(PmuFlags::PMU_TICKS_RCB) {
            return TicksRetiredConditionalBranches;
        }
        fatal!("Unsupported architecture");
        unreachable!()
    }

    /// When an interrupt is requested, at most this many ticks may elapse before
    /// the interrupt is delivered.
    pub fn skid_size() -> Ticks {
        PMU_ATTRIBUTES.skid_size
    }

    /// Use a separate skid_size for recording since we seem to see more skid
    /// in practice during recording, in particular during the
    /// async_signal_syscalls tests
    pub fn recording_skid_size() -> Ticks {
        Self::skid_size() * 5
    }
}

impl Drop for PerfCounters {
    fn drop(&mut self) {
        self.stop()
    }
}
