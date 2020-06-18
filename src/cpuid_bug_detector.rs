use crate::session::task::replay_task::ReplayTask;

/// Helper to detect when the "CPUID can cause rcbs to be lost" bug is present.
/// See http://robert.ocallahan.org/2014/09/vmware-cpuid-conditional-branch.html
///
/// This bug is caused by VMM optimizations described in
/// https://www.usenix.org/system/files/conference/atc12/atc12-final158.pdf
/// that cause instruction sequences related to CPUID to be optimized,
/// eliminating the user-space execution of a conditional branch between two
/// CPUID instructions (in some circumstances).
///
/// @TODO This is currently just an empty implementation as we assume that rcbs DONT get lost i.e.
/// user is not a running buggy VMWare guest.
pub struct CPUIDBugDetector;

impl Default for CPUIDBugDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CPUIDBugDetector {
    pub fn new() -> CPUIDBugDetector {
        CPUIDBugDetector
    }

    /// Call this in the context of the first spawned process to run the
    /// code that triggers the bug.
    pub fn run_detection_code() {
        // Do nothing currently
    }

    /// Call this when task t enters a traced syscall during replay.
    pub fn notify_reached_syscall_during_replay(_t: &ReplayTask) {
        // Do nothing currently
    }
}
