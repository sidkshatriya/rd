use crate::{
    extra_registers::ExtraRegisters,
    registers::Registers,
    return_address_list::ReturnAddressList,
    session::{
        replay_session::{ReplaySession, ReplayStepKey},
        task::Task,
        SessionSharedPtr,
    },
    ticks::Ticks,
    trace::trace_frame::FrameTime,
};
use std::{
    cell::{Ref, RefCell},
    rc::{Rc, Weak},
};

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

impl Default for ReplayTimeline {
    fn default() -> Self {
        unimplemented!()
    }
}

impl Drop for ReplayTimeline {
    fn drop(&mut self) {
        unimplemented!()
    }
}

impl ReplayTimeline {
    pub fn new(_session: SessionSharedPtr) -> ReplayTimeline {
        unimplemented!()
    }

    pub fn add_explicit_checkpoint(&self) -> Mark {
        unimplemented!()
    }

    pub fn mark(&self) -> Mark {
        unimplemented!()
    }

    fn session_mark_key(session: &ReplaySession) -> MarkKey {
        let maybe_t = session.current_task();
        let tick_count = match maybe_t {
            Some(t) => t.borrow().tick_count(),
            None => 0,
        };
        MarkKey::new(
            session.trace_reader().time(),
            tick_count,
            session.current_step_key(),
        )
    }
}

pub struct Mark {
    ptr: Rc<RefCell<InternalMark>>,
}

impl Mark {
    ///  Return the values of the general-purpose registers at this mark.
    pub fn regs(&self) -> Ref<Registers> {
        Ref::map(self.ptr.borrow(), |b| &b.proto.regs)
    }

    pub fn extra_regs(&self) -> Ref<ExtraRegisters> {
        Ref::map(self.ptr.borrow(), |b| &b.extra_regs)
    }

    pub fn time(&self) -> FrameTime {
        self.ptr.borrow().proto.key.trace_time
    }
}

/// Everything we know about the tracee state for a particular Mark.
/// This data alone does not allow us to determine the time ordering
/// of two Marks.
struct InternalMark {
    /// @TODO Is this what we want?
    owner: Weak<ReplayTimeline>,
    /// Reuse ProtoMark to contain the MarkKey + Registers + ReturnAddressList.
    proto: ProtoMark,
    extra_regs: ExtraRegisters,
    /// Optional checkpoint for this Mark.
    checkpoint: SessionSharedPtr,
    ticks_at_event_start: Ticks,
    /// Number of users of `checkpoint`.
    checkpoint_refcount: u32,
    /// The next InternalMark in the ReplayTimeline's Mark vector is the result
    /// of singlestepping from this mark *and* no signal is reported in the
    /// break_status when doing such a singlestep.
    singlestep_to_next_mark_no_signal: bool,
}

/// A MarkKey consists of FrameTime + Ticks + ReplayStepKey. These values
/// do not uniquely identify a program state, but they are intrinsically
/// totally ordered. The ReplayTimeline::marks database is an ordered
/// map from MarkKeys to a time-ordered list of Marks associated with each
/// MarkKey.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct MarkKey {
    pub trace_time: FrameTime,
    pub ticks: Ticks,
    pub step_key: ReplayStepKey,
}

impl MarkKey {
    fn new(trace_time: FrameTime, ticks: Ticks, step_key: ReplayStepKey) -> MarkKey {
        MarkKey {
            trace_time,
            ticks,
            step_key,
        }
    }
}

impl Default for Mark {
    fn default() -> Self {
        unimplemented!()
    }
}

/// All the information we'll need to construct a mark lazily.
/// Marks are expensive to create since we may have to restore
/// a previous session state so we can replay forward to find out
/// how the Mark should be ordered relative to other Marks with the same
/// MarkKey. So instead of creating a Mark for the current moment
/// whenever we *might* need to return to that moment, create a ProtoMark
/// instead. This contains a snapshot of enough state to create a full
/// Mark later.
/// MarkKey + Registers + ReturnAddressList are assumed to identify a unique
/// program state.
struct ProtoMark {
    pub key: MarkKey,
    pub regs: Registers,
    pub return_addresses: ReturnAddressList,
}

impl ProtoMark {
    pub fn new(key: MarkKey, t: &mut dyn Task) -> ProtoMark {
        ProtoMark {
            key,
            regs: t.regs_ref().clone(),
            return_addresses: ReturnAddressList::new(t),
        }
    }

    pub fn new_from_key(key: MarkKey) -> ProtoMark {
        ProtoMark {
            key,
            regs: Default::default(),
            return_addresses: Default::default(),
        }
    }

    pub fn equal_states(&self, session: &ReplaySession) -> bool {
        if ReplayTimeline::session_mark_key(session) != self.key {
            return false;
        }
        let t = session.current_task().unwrap();
        let mut tb = t.borrow_mut();
        equal_regs(&self.regs, tb.regs_ref())
            && self.return_addresses == ReturnAddressList::new(tb.as_mut())
    }
}

/// Different strategies for placing automatic checkpoints.
pub enum CheckpointStrategy {
    /// Use this when we want to bound the overhead of checkpointing to be
    /// insignificant relative to the cost of forward execution.
    LowOverhead,
    /// Use this when we expect reverse execution to happen soon, to a
    /// destination not far behind the current execution point. In this case
    /// it's worth increasing checkpoint density.
    /// We pass this when we have opportunities to make checkpoints during
    /// reverse_continue or reverse_singlestep, since it's common for short
    /// reverse-executions to follow other reverse-execution.
    ExpectShortReverseExecution,
}

/// An estimate of how much progress a session has made. This should roughly
/// correlate to the time required to replay from the start of a session
/// to the current point, in microseconds.
///
/// DIFF NOTE: This is a i64 in rr
pub type Progress = u64;

fn equal_regs(r1: &Registers, r2: &Registers) -> bool {
    // Compare ip()s first since they will usually fail to match, especially
    // when we're comparing InternalMarks with the same MarkKey
    r1.ip() == r2.ip() && r1.matches(r2)
}
