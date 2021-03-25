use crate::session::task::Task;

pub trait BreakpointCondition {
    fn evaluate(&self, t: &dyn Task);
}
