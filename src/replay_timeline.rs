#[derive(Copy, Clone, Eq, PartialEq)]
pub enum RunDirection {
    RunForward,
    RunBackward,
}

impl Default for RunDirection {
    fn default() -> Self {
        // Pick an arbitrary one
        RunDirection::RunForward
    }
}

/// This class manages a set of ReplaySessions corresponding to different points
/// in the same recording. It provides an API for explicitly managing
/// checkpoints along this timeline and navigating to specific events.
pub struct ReplayTimeline;
