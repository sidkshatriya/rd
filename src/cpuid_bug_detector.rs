use crate::{
    flags::Flags,
    kernel_abi::{is_geteuid32_syscall, is_geteuid_syscall},
    perf_counters::PerfCounters,
    session::task::replay_task::ReplayTask,
};
use std::os::raw::c_int;

/// Helper to detect when the "CPUID can cause rcbs to be lost" bug is present.
/// See http://robert.ocallahan.org/2014/09/vmware-cpuid-conditional-branch.html
///
/// This bug is caused by VMM optimizations described in
/// https://www.usenix.org/system/files/conference/atc12/atc12-final158.pdf
/// that cause instruction sequences related to CPUID to be optimized,
/// eliminating the user-space execution of a conditional branch between two
/// CPUID instructions (in some circumstances).
#[derive(Default)]
pub struct CPUIDBugDetector {
    trace_rcb_count_at_last_geteuid: u64,
    actual_rcb_count_at_last_geteuid: u64,
    detected_cpuid_bug: bool,
}

extern "C" {
    fn cpuid_loop(iterations: c_int) -> c_int;
}

impl CPUIDBugDetector {
    /// Call this in the context of the first spawned process to run the
    /// code that triggers the bug.
    pub fn run_detection_code() {
        // Call cpuid_loop to generate trace data we can use to detect
        // the cpuid rcb undercount bug. This generates 4 geteuid
        // calls which should have 2 rcbs between each of the
        // 3 consecutive pairs.
        unsafe {
            cpuid_loop(4);
        }
    }

    /// Call this when task t enters a traced syscall during replay.
    pub fn notify_reached_syscall_during_replay(&mut self, t: &ReplayTask) {
        // We only care about events that happen before the first exec,
        // when our detection code runs.
        if t.session().done_initial_exec() {
            return;
        }
        let sys = t.current_trace_frame().event().syscall_event().number;
        if !is_geteuid32_syscall(sys, t.arch()) && !is_geteuid_syscall(sys, t.arch()) {
            return;
        }
        let trace_rcb_count = t.current_trace_frame().ticks();
        let actual_rcb_count = t.tick_count();
        if self.trace_rcb_count_at_last_geteuid > 0 && !self.detected_cpuid_bug {
            if !rcb_counts_ok(t, self.trace_rcb_count_at_last_geteuid, trace_rcb_count)
                || !rcb_counts_ok(t, self.actual_rcb_count_at_last_geteuid, actual_rcb_count)
            {
                self.detected_cpuid_bug = true;
            }
        }
        self.trace_rcb_count_at_last_geteuid = trace_rcb_count;
        self.actual_rcb_count_at_last_geteuid = actual_rcb_count;
    }
}

fn rcb_counts_ok(t: &ReplayTask, prev: u64, current: u64) -> bool {
    let expected_count = 2 + PerfCounters::ticks_for_direct_call(t);
    if current - prev == expected_count {
        return true;
    }
    if !Flags::get().suppress_environment_warnings {
        eprintln!(
            "\n\
         rd: Warning: You appear to be running in a VMWare guest with a bug\n\
             where a conditional branch instruction between two CPUID instructions\n\
             sometimes fails to be counted by the conditional branch performance\n\
             counter. Work around this problem by adding\n\
                 monitor_control.disable_hvsim_clusters = true\n\
             to your .vmx file.\n"
        );
    }
    false
}
