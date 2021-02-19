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
