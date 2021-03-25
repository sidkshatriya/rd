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
    cell::RefCell,
    cmp::Ordering,
    collections::BTreeMap,
    fmt::Display,
    io::Write,
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

type InternalMarkSharedPtr = Rc<InternalMark>;

/// This class manages a set of ReplaySessions corresponding to different points
/// in the same recording. It provides an API for explicitly managing
/// checkpoints along this timeline and navigating to specific events.
pub struct ReplayTimeline {
    /// All known marks.
    ///
    /// An InternalMark appears in a ReplayTimeline 'marks' map if and only if
    /// that ReplayTimeline is the InternalMark's 'owner'. ReplayTimeline's
    /// destructor clears the 'owner' of all marks in the map.
    ///
    /// For each MarkKey, the InternalMarks are stored in execution order.
    ///
    /// The key problem we're dealing with here is that we don't have any state
    /// that we can use to compute a total time order on Marks. MarkKeys are
    /// totally ordered, but different program states can have the same MarkKey
    /// (i.e. same retired conditional branch count). The only way to determine
    /// the time ordering of two Marks m1 and m2 is to actually replay the
    /// execution until we see m1 and m2 and observe which one happened first.
    /// We record that ordering for all Marks by storing all the Marks for a given
    /// MarkKey in vector ordered by time.
    /// Determining this order is expensive so we avoid creating Marks unless we
    /// really need to! If we're at a specific point in time and we///may* need to
    /// create a Mark for this point later, create a ProtoMark instead to
    /// capture enough state so that a Mark can later be created if needed.
    ///
    /// We assume there will be a limited number of InternalMarks per MarkKey.
    /// This should be true because ReplayTask::tick_count() should increment
    /// frequently during execution. In some cases we see hundreds of elements
    /// but that's not too bad.
    marks: RefCell<BTreeMap<MarkKey, Vec<InternalMarkSharedPtr>>>,

    /// All mark keys with at least one checkpoint. The value is the number of
    /// checkpoints. There can be multiple checkpoints for a given MarkKey
    /// because a MarkKey may have multiple corresponding Marks.
    marks_with_checkpoints: RefCell<BTreeMap<MarkKey, u32>>,
}

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

    fn remove_mark_with_checkpoint(&self, key: MarkKey) {
        debug_assert!(self.marks_with_checkpoints.borrow()[&key] > 0);
        self.marks_with_checkpoints
            .borrow_mut()
            .insert(key, self.marks_with_checkpoints.borrow()[&key] - 1);
        if self.marks_with_checkpoints.borrow()[&key] == 0 {
            self.marks_with_checkpoints.borrow_mut().remove(&key);
        }
    }
}

/// DIFF NOTE: One important difference between rd and rr's Mark is that
/// rd's Mark always indicates a position in the replay unlike
/// in rr where `ptr` can be null
pub struct Mark {
    ptr: InternalMarkSharedPtr,
}

impl Eq for Mark {}

impl Ord for Mark {
    /// See ReplayTimeline::less_than() in rr
    /// @TODO Check this again
    fn cmp(&self, m2: &Self) -> Ordering {
        // DIFF NOTE: This is a DEBUG_ASSERT in rr
        assert!(self.ptr.owner.ptr_eq(&m2.ptr.owner));
        if self == m2 {
            Ordering::Equal
        } else {
            if self.ptr.proto.key < m2.ptr.proto.key {
                return Ordering::Less;
            }
            if m2.ptr.proto.key < self.ptr.proto.key {
                return Ordering::Greater;
            }
            // We now know that self & m2 have the same ptr.proto.key
            for m in &self.ptr.owner.upgrade().unwrap().marks.borrow()[&self.ptr.proto.key] {
                if Rc::eq(m, &m2.ptr) {
                    return Ordering::Greater;
                }
                if Rc::eq(m, &self.ptr) {
                    return Ordering::Less;
                }
            }
            assert!(false, "Marks missing from vector, invariants broken!");
            unreachable!()
        }
    }
}

impl PartialOrd for Mark {
    fn partial_cmp(&self, m2: &Self) -> Option<Ordering> {
        Some(Self::cmp(self, &m2))
    }
}

impl PartialEq for Mark {
    fn eq(&self, other: &Self) -> bool {
        Rc::eq(&self.ptr, &other.ptr)
    }
}

impl Mark {
    ///  Return the values of the general-purpose registers at this mark.
    pub fn regs(&self) -> &Registers {
        &self.ptr.proto.regs
    }

    pub fn extra_regs(&self) -> &ExtraRegisters {
        &self.ptr.extra_regs
    }

    pub fn time(&self) -> FrameTime {
        self.ptr.proto.key.trace_time
    }

    fn from_internal_mark(weak: InternalMarkSharedPtr) -> Mark {
        Mark { ptr: weak }
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
    checkpoint: Option<SessionSharedPtr>,
    /// Number of users of `checkpoint`
    checkpoint_refcount: u32,
    ticks_at_event_start: Ticks,
    /// The next InternalMark in the ReplayTimeline's Mark vector is the result
    /// of singlestepping from this mark *and* no signal is reported in the
    /// break_status when doing such a singlestep.
    singlestep_to_next_mark_no_signal: bool,
}

impl PartialOrd for InternalMark {
    fn partial_cmp(&self, _other: &Self) -> Option<Ordering> {
        unimplemented!()
    }
}

impl PartialEq for InternalMark {
    fn eq(&self, _other: &Self) -> bool {
        unimplemented!()
    }
}

impl Drop for InternalMark {
    fn drop(&mut self) {
        match self.owner.upgrade() {
            Some(owner) => match self.checkpoint.as_ref() {
                Some(_session) => {
                    owner.remove_mark_with_checkpoint(self.proto.key);
                }
                None => (),
            },
            None => (),
        }
    }
}

impl InternalMark {
    fn new(owner: Weak<ReplayTimeline>, session: &ReplaySession, key: MarkKey) -> InternalMark {
        let proto;
        let extra_regs;
        match session.current_task() {
            Some(t) => {
                proto = ProtoMark::new(key, t.borrow_mut().as_mut());
                extra_regs = t.borrow_mut().extra_regs_ref().clone();
            }
            None => {
                proto = ProtoMark::new_from_key(key);
                extra_regs = Default::default()
            }
        }

        InternalMark {
            owner,
            proto,
            extra_regs,
            checkpoint: None,
            checkpoint_refcount: 0,
            ticks_at_event_start: session.ticks_at_start_of_current_event(),
            singlestep_to_next_mark_no_signal: false,
        }
    }

    fn equal_states(&self, session: &ReplaySession) -> bool {
        self.proto.equal_states(session)
    }

    /// DIFF NOTE: Called full_print() in rr
    fn full_write(&self, out: &mut dyn Write) {
        write!(out, "{{{},regs:", self.proto.key).unwrap();
        self.proto.regs.write_register_file(out).unwrap();
        write!(out, ",return_addresses=[").unwrap();
        for i in 0..ReturnAddressList::COUNT {
            // @TODO: This is %p in rr
            write!(
                out,
                "{:08x}",
                self.proto.return_addresses.addresses[i].as_usize()
            )
            .unwrap();
            if i + 1 < ReturnAddressList::COUNT {
                write!(out, ",").unwrap();
            }
        }
        write!(out, "]}}").unwrap();
    }
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

impl Display for MarkKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "time:{},ticks:{},st:{}",
            self.trace_time,
            self.ticks,
            self.step_key.as_i32()
        )
    }
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
