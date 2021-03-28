use crate::{
    breakpoint_condition::BreakpointCondition,
    extra_registers::ExtraRegisters,
    log::LogDebug,
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    return_address_list::ReturnAddressList,
    session::{
        address_space::WatchType,
        replay_session::{
            ReplayResult,
            ReplaySession,
            ReplayStatus,
            ReplayStepKey,
            StepConstraints,
        },
        session_inner::RunCommand,
        task::{replay_task::ReplayTask, Task},
        SessionSharedPtr,
    },
    taskish_uid::{AddressSpaceUid, TaskUid},
    ticks::Ticks,
    trace::trace_frame::FrameTime,
};
use std::{
    cell::{Ref, RefCell},
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
    fmt::Display,
    io::Write,
    mem,
    ops::Bound::{Excluded, Included, Unbounded},
    rc::{Rc, Weak},
};

#[derive(Copy, Clone)]
enum ForceProgress {
    ForceProgress,
    DontForceProgress,
}

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

type InternalMarkSharedPtr = Rc<RefCell<InternalMark>>;
type ReplayTimelineSharedPtr = Rc<RefCell<ReplayTimeline>>;
type ReplayTimelineSharedWeakPtr = Weak<RefCell<ReplayTimeline>>;

#[derive(Copy, Clone, Default)]
struct ReplayStepToMarkStrategy {
    singlesteps_to_perform: u32,
}

impl ReplayStepToMarkStrategy {
    pub fn setup_step_constraints() -> StepConstraints {
        unimplemented!()
    }
}

/// This class manages a set of ReplaySessions corresponding to different points
/// in the same recording. It provides an API for explicitly managing
/// checkpoints along this timeline and navigating to specific events.
pub struct ReplayTimeline {
    weak_self: ReplayTimelineSharedWeakPtr,
    current: Option<SessionSharedPtr>,
    /// current is known to be at or after this mark
    current_at_or_after_mark: Option<InternalMarkSharedPtr>,

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
    marks: BTreeMap<MarkKey, Vec<InternalMarkSharedPtr>>,

    /// All mark keys with at least one checkpoint. The value is the number of
    /// checkpoints. There can be multiple checkpoints for a given MarkKey
    /// because a MarkKey may have multiple corresponding Marks.
    marks_with_checkpoints: BTreeMap<MarkKey, u32>,

    breakpoints: HashSet<(AddressSpaceUid, RemoteCodePtr, Box<dyn BreakpointCondition>)>,

    watchpoints: HashSet<(
        AddressSpaceUid,
        RemotePtr<Void>,
        usize,
        WatchType,
        Box<dyn BreakpointCondition>,
    )>,

    breakpoints_applied: bool,

    reverse_execution_barrier_event: FrameTime,

    /// Checkpoints used to accelerate reverse execution.
    reverse_exec_checkpoints: BTreeMap<Mark, Progress>,

    /// When these are non-None, then when singlestepping from
    /// no_watchpoints_interval_start to no_break_interval_end, none of the currently
    /// set watchpoints fire.
    no_watchpoints_hit_interval_start: Option<Mark>,
    no_watchpoints_hit_interval_end: Option<Mark>,

    /// A single checkpoint that's very close to the current point, used to
    /// accelerate a sequence of reverse singlestep operations.
    reverse_exec_short_checkpoint: Mark,
}

impl Default for ReplayTimeline {
    fn default() -> Self {
        unimplemented!()
    }
}

impl Drop for ReplayTimeline {
    fn drop(&mut self) {
        for (_k, v) in self.marks.iter() {
            for internal_mark in v {
                internal_mark.borrow_mut().owner = Weak::new();
                internal_mark.borrow_mut().checkpoint = None;
            }
        }
    }
}

type StopFilterFn = dyn Fn(&ReplayTask) -> bool;
type InterruptCheckFn = dyn Fn(&ReplayTask) -> bool;

impl ReplayTimeline {
    pub fn is_running(&self) -> bool {
        self.current.is_some()
    }

    /// The current state. The current state can be moved forward or backward
    /// using ReplaySession's APIs. Do not set breakpoints on its tasks directly.
    /// Use ReplayTimeline's breakpoint methods.
    pub fn current_session(&self) -> &ReplaySession {
        self.current.as_ref().unwrap().as_replay().unwrap()
    }

    pub fn weak_self_ptr(&self) -> ReplayTimelineSharedWeakPtr {
        self.weak_self.clone()
    }

    /// Return a mark for the current state. A checkpoint need not be retained,
    /// but this mark can be seeked to later.
    /// This can be expensive in some (perhaps unusual) situations since we
    /// may need to clone the current session and run it a bit, to figure out
    /// where we are relative to other Marks. So don't call this unless you
    /// need it.
    pub fn mark(&mut self) -> Mark {
        match self.current_mark() {
            Some(mark) => {
                return Mark::from_internal_mark(mark);
            }
            None => (),
        }

        let key = self.current_mark_key();
        let m = Rc::new(RefCell::new(InternalMark::new(
            self.weak_self_ptr(),
            self.current_session(),
            key,
        )));

        if !self.marks.contains_key(&key) {
            self.marks.insert(key, Vec::new());
        }

        let len = self.marks.get(&key).unwrap().len();
        if len == 0 {
            self.marks.get_mut(&key).unwrap().push(m.clone());
        } else if self.current_at_or_after_mark.is_some()
            && *self.current_at_or_after_mark.as_ref().unwrap().borrow()
                == *self.marks.get(&key).unwrap()[len - 1].borrow()
        {
            self.marks.get_mut(&key).unwrap().push(m.clone());
        } else {
            // Now the hard part: figuring out where to put it in the list of existing
            // marks.
            self.unapply_breakpoints_and_watchpoints();
            let tmp_session = self.current_session().clone_replay();
            let tmp_session_replay: &ReplaySession = tmp_session.as_replay().unwrap();

            // We could set breakpoints at the marks and then continue with an
            // interrupt set to fire when our tick-count increases. But that requires
            // new replay functionality (probably a new RunCommand), so for now, do the
            // simplest thing and just single-step until we find where to put the new
            // mark(s).
            log!(
                LogDebug,
                "mark() replaying to find mark location for {}",
                *m.borrow()
            );
            let mut new_marks = Vec::<InternalMarkSharedPtr>::new();
            new_marks.push(m.clone());

            // Allow coalescing of multiple repetitions of a single x86 string
            // instruction (as long as we don't reach one of our mark_vector states).
            let mut constraints = StepConstraints::new(RunCommand::RunSinglestepFastForward);
            for mv in self.marks.get(&key).unwrap().iter() {
                constraints
                    .stop_before_states
                    .push(mv.borrow().proto.regs.clone());
            }

            let mut mark_index = len;
            loop {
                let result = tmp_session_replay.replay_step_with_constraints(&constraints);
                if Self::session_mark_key(tmp_session_replay) != key
                    || result.status != ReplayStatus::ReplayContinue
                {
                    break;
                }
                if !result.break_status.singlestep_complete {
                    continue;
                }

                for (i, existing_mark) in self.marks.get_mut(&key).unwrap().iter().enumerate() {
                    if existing_mark.borrow().equal_states(tmp_session_replay) {
                        if !result.did_fast_forward && result.break_status.signal.is_none() {
                            new_marks[new_marks.len() - 1]
                                .borrow_mut()
                                .singlestep_to_next_mark_no_signal = true;
                        }
                        mark_index = i;
                        break;
                    }
                }

                if mark_index != len {
                    break;
                }

                // Some callers singlestep through N instructions, all with the same
                // MarkKey, requesting a Mark after each step. If there's a Mark at the
                // end of the N instructions, this could mean N(N+1)/2 singlestep
                // operations total. To avoid that, add all the intermediate states to
                // the mark map now, so the first mark() call will perform N singlesteps
                // and the rest will perform none.
                if !result.did_fast_forward && result.break_status.signal.is_none() {
                    new_marks[new_marks.len() - 1]
                        .borrow_mut()
                        .singlestep_to_next_mark_no_signal = true;
                }
                new_marks.push(Rc::new(RefCell::new(InternalMark::new(
                    self.weak_self_ptr(),
                    self.current_session(),
                    key,
                ))));
            }

            // mark_index is the current index of the next mark after 'current'. So
            // insert our new marks at mark_index.
            let mark_vector = self.marks.get_mut(&key).unwrap();
            let end_vec = mark_vector.split_off(mark_index);
            mark_vector.extend_from_slice(&new_marks);
            mark_vector.extend_from_slice(&end_vec);
        }
        self.current_at_or_after_mark = Some(m.clone());
        Mark::from_internal_mark(m)
    }

    /// Indicates that the current replay position is the result of
    /// singlestepping from 'from'.
    pub fn mark_after_singlestep(&self, _from: &Mark, _result: &ReplayResult) {
        unimplemented!()
    }

    /// Returns true if it's safe to add a checkpoint here.
    pub fn can_add_checkpoint(&self) -> bool {
        unimplemented!()
    }

    /// Ensure that the current session is explicitly checkpointed.
    /// Explicit checkpoints are reference counted.
    /// Only call this if can_add_checkpoint would return true.
    pub fn add_explicit_checkpoint(&mut self) -> Mark {
        debug_assert!(self.current_session().can_clone());

        let m = self.mark();
        if m.ptr.borrow().checkpoint.is_none() {
            self.unapply_breakpoints_and_watchpoints();
            m.ptr.borrow_mut().checkpoint = Some(self.current_session().clone_replay());
            let key = m.ptr.borrow().proto.key;
            let val = self.marks_with_checkpoints.get(&key).copied();
            match val {
                None => {
                    self.marks_with_checkpoints.insert(key, 1);
                }
                Some(v) => {
                    self.marks_with_checkpoints.insert(key, v + 1);
                }
            };
        }
        let cnt = m.ptr.borrow().checkpoint_refcount;
        m.ptr.borrow_mut().checkpoint_refcount = cnt + 1;
        m
    }

    /// Remove an explicit checkpoint reference count for this mark.
    pub fn remove_explicit_checkpoint(&mut self, mark: &Mark) {
        let cnt = mark.ptr.borrow().checkpoint_refcount;
        debug_assert!(cnt > 0);
        mark.ptr.borrow_mut().checkpoint_refcount = cnt - 1;
        if mark.ptr.borrow().checkpoint_refcount == 0 {
            mark.ptr.borrow_mut().checkpoint = None;
            self.remove_mark_with_checkpoint(mark.ptr.borrow().proto.key);
        }
    }

    /// Return true if we're currently at the given mark.
    pub fn at_mark(&self, _mark: &Mark) {
        unimplemented!()
    }

    /// Add/remove breakpoints and watchpoints. Use these APIs instead
    /// of operating on the task directly, so that ReplayTimeline can track
    /// breakpoints and automatically move them across sessions as necessary.
    /// Only one breakpoint for a given address space/addr combination can be set;
    /// setting another for the same address space/addr will replace the first.
    /// Likewise only one watchpoint for a given task/addr/num_bytes/type can be
    /// set. gdb expects that setting two breakpoints on the same address and then
    /// removing one removes both.
    pub fn add_breakpoint(
        &self,
        _t: &ReplayTask,
        _addr: RemoteCodePtr,
        _condition: Option<Box<dyn BreakpointCondition>>,
    ) -> bool {
        unimplemented!()
    }

    /// You can't remove a breakpoint with a specific condition, so don't
    /// place multiple breakpoints with conditions on the same location.
    pub fn remove_breakpoint(&self, _t: &ReplayTask, _addr: RemoteCodePtr) {
        unimplemented!()
    }

    pub fn add_watchpoint(
        &self,
        _t: &ReplayTask,
        _addr: RemotePtr<Void>,
        _num_bytes: usize,
        _type_: WatchType,
        _condition: Option<Box<dyn BreakpointCondition>>,
    ) -> bool {
        unimplemented!()
    }

    /// You can't remove a watchpoint with a specific condition, so don't
    /// place multiple breakpoints with conditions on the same location.
    pub fn remove_watchpoint(
        &self,
        _t: &ReplayTask,
        _addr: RemotePtr<Void>,
        _num_bytes: usize,
        _type_: WatchType,
    ) -> bool {
        unimplemented!()
    }

    pub fn remove_breakpoints_and_watchpoints(&self) -> bool {
        unimplemented!()
    }

    pub fn has_breakpoint_at_address(&self, _t: &ReplayTask, _addr: RemoteCodePtr) -> bool {
        unimplemented!()
    }

    pub fn has_watchpoint_at_address(
        &self,
        _t: &ReplayTask,
        _addr: RemotePtr<Void>,
        _num_bytes: usize,
        _type_: WatchType,
    ) -> bool {
        unimplemented!()
    }

    /// Ensure that reverse execution never proceeds into an event before
    /// |event|. Reverse execution will stop with a |task_exit| break status when
    /// at the beginning of this event.
    pub fn set_reverse_execution_barrier_event(&self, _event: FrameTime) {
        unimplemented!()
    }

    /// State-changing APIs. These may alter state associated with
    /// current_session().
    /// Reset the current session to the last available session before event
    /// 'time'. Useful if you want to run up to that event.
    pub fn seek_to_before_event(&self, _time: FrameTime) {
        unimplemented!()
    }

    /// Reset the current session to the last checkpointed session before (or at)
    /// the mark. Will return at the mark if this mark was explicitly checkpointed
    /// previously (and not deleted).
    pub fn seek_up_to_mark(&self, _mark: &Mark) {
        unimplemented!()
    }

    /// Sets current session to 'mark' by restoring the nearest useful checkpoint
    /// and executing forwards if necessary.
    pub fn seek_to_mark(&self, _mark: &Mark) {
        unimplemented!()
    }

    /// Replay 'current'.
    /// If there is a breakpoint at the current task's current ip(), then
    /// when running forward we will immediately break at the breakpoint. When
    /// running backward we will ignore the initial "hit" of the breakpoint ---
    /// this is the behavior gdb expects.
    /// Likewise, if there is a breakpoint at the current task's current ip(),
    /// then running forward will immediately break at the breakpoint, but
    /// running backward will ignore the initial "hit" of the breakpoint; this is
    /// what gdb expects.
    ///
    /// replay_step_forward only does one replay step. That means we'll only
    /// execute code in current_session().current_task().
    pub fn replay_step_forward(
        &self,
        _command: RunCommand,
        _stop_at_time: FrameTime,
    ) -> ReplayResult {
        unimplemented!()
    }

    pub fn reverse_continue(
        &self,
        _stop_filter: &StopFilterFn,
        _interrupt_check: &InterruptCheckFn,
    ) -> ReplayResult {
        unimplemented!()
    }

    pub fn reverse_singlestep(
        &self,
        _stop_filter: &StopFilterFn,
        _interrupt_check: &InterruptCheckFn,
    ) -> ReplayResult {
        unimplemented!()
    }

    /// Try to identify an existing Mark which is known to be one singlestep
    /// before 'from', and for which we know singlestepping to 'from' would
    /// trigger no break statuses other than "singlestep_complete".
    /// If we can't, return a None.
    /// Will only return a Mark for the same executing task as 'from', which
    /// must be 't'.
    pub fn lazy_reverse_singlestep(&self, from: &Mark, t: &ReplayTask) -> Option<Mark> {
        if self.no_watchpoints_hit_interval_start.is_none()
            || self.no_watchpoints_hit_interval_end.is_none()
        {
            return None;
        }
        let m = self.find_singlestep_before(from)?;
        if m >= *self.no_watchpoints_hit_interval_start.as_ref().unwrap()
            && m < *self.no_watchpoints_hit_interval_end.as_ref().unwrap()
            && !self.has_breakpoint_at_address(t, from.ptr.borrow().proto.regs.ip())
        {
            return Some(m);
        }

        None
    }

    pub fn new(_session: SessionSharedPtr) -> ReplayTimeline {
        unimplemented!()
    }

    /// We track the set of breakpoints/watchpoints requested by the client.
    /// When we switch to a new ReplaySession, these need to be reapplied before
    /// replaying that session, but we do this lazily.
    /// apply_breakpoints_and_watchpoints() forces the breakpoints/watchpoints
    /// to be applied to the current session.
    /// Our checkpoints never have breakpoints applied.
    pub fn apply_breakpoints_and_watchpoints(&self) {
        unimplemented!()
    }

    /// unapply_breakpoints_and_watchpoints() forces the breakpoints/watchpoints
    /// to not be applied to the current session. Use this when we need to
    /// clone the current session or replay the current session without
    /// triggering breakpoints.
    fn unapply_breakpoints_and_watchpoints(&self) {
        unimplemented!()
    }

    fn apply_breakpoints_internal(&self) {
        unimplemented!()
    }

    fn unapply_breakpoints_internal(&self) {
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

    fn current_mark_key(&self) -> MarkKey {
        Self::session_mark_key(self.current_session())
    }

    fn proto_mark(&self) -> ProtoMark {
        unimplemented!()
    }

    fn seek_to_proto_mark(&self, _pmark: &ProtoMark) {
        unimplemented!()
    }

    /// Returns a shared pointer to the mark if there is one for the current state.
    fn current_mark(&self) -> Option<InternalMarkSharedPtr> {
        let maybe_it = self.marks.get(&self.current_mark_key());
        // Avoid creating an entry in 'marks' if it doesn't already exist
        match maybe_it {
            Some(v) => {
                for m in v {
                    if m.borrow().equal_states(self.current_session()) {
                        return Some(m.clone());
                    }
                }
                None
            }
            None => None,
        }
    }

    /// Assumes key is already present in self.marks_with_checkpoints
    fn remove_mark_with_checkpoint(&mut self, key: MarkKey) {
        debug_assert!(self.marks_with_checkpoints.get(&key).is_some());
        debug_assert!(self.marks_with_checkpoints[&key] > 0);
        self.marks_with_checkpoints
            .insert(key, self.marks_with_checkpoints[&key] - 1);
        if self.marks_with_checkpoints[&key] == 0 {
            self.marks_with_checkpoints.remove(&key);
        }
    }

    fn seek_to_before_key(&mut self, key: MarkKey) {
        let mut it = self
            .marks_with_checkpoints
            .range((Included(key), Unbounded));
        // 'it' points to the first value equivalent to or greater than 'key'.
        let current_key = self.current_mark_key();
        let lb = it.next().map(|(&k, _)| k);
        let first = self
            .marks_with_checkpoints
            .first_key_value()
            .map(|(&k, _)| k);
        // @TODO Check scenario when self.marks_with_checkpoints is empty
        if lb == first {
            if current_key < key {
                // We can use the current session, so do nothing.
            } else {
                // nowhere earlier to go, so restart from beginning.
                let s = Some(ReplaySession::create(
                    Some(&self.current_session().trace_reader().dir()),
                    *self.current_session().flags(),
                ));
                self.current = s;
                self.breakpoints_applied = false;
                self.current_at_or_after_mark = None;
            }
        } else {
            let it = *self
                .marks_with_checkpoints
                .range((Unbounded, Excluded(key)))
                .next_back()
                .unwrap()
                .0;
            // 'it' is now at the last checkpoint before 'key'
            if it < current_key && current_key < key {
                // Current state is closer to the destination than any checkpoint we
                // have, so do nothing.
            } else {
                // Return one of the checkpoints at *it.
                self.current = None;
                for mark_it in &self.marks[&it] {
                    if mark_it.borrow().checkpoint.is_some() {
                        self.current = Some(
                            mark_it
                                .borrow()
                                .checkpoint
                                .as_ref()
                                .unwrap()
                                .as_replay()
                                .unwrap()
                                .clone_replay(),
                        );
                        // At this point, mark_it.checkpoint is fully initialized but current
                        // is not. Swap them so that mark_it.checkpoint is not fully
                        // initialized, to reduce resource usage.
                        mem::swap(
                            self.current.as_mut().unwrap(),
                            mark_it.borrow_mut().checkpoint.as_mut().unwrap(),
                        );
                        self.breakpoints_applied = false;
                        self.current_at_or_after_mark = Some(mark_it.clone());
                        break;
                    }
                }
                debug_assert!(self.current.is_some());
            }
        }
    }

    /// Run forward towards the midpoint of the current position and |end|.
    /// Must stop before we reach |end|.
    /// Returns false if we made no progress.
    fn run_forward_to_intermediate_point(&self, _end: &Mark, _force: ForceProgress) -> bool {
        unimplemented!()
    }

    fn update_strategy_and_fix_watchpoint_quirk(
        &self,
        _strategy: &ReplayStepToMarkStrategy,
        _constraints: &StepConstraints,
        _result: &ReplayResult,
        _before: &ProtoMark,
    ) {
        unimplemented!()
    }

    /// Take a single replay step towards |mark|. Stop before or at |mark|, and
    /// stop if any breakpoint/watchpoint/signal is hit.
    /// Maintain current strategy state in |strategy|. Passing the same
    /// |strategy| object to consecutive replay_step_to_mark invocations helps
    /// optimize performance.
    fn replay_step_to_mark(
        &self,
        _mark: &Mark,
        _strategy: &ReplayStepToMarkStrategy,
    ) -> ReplayResult {
        unimplemented!()
    }

    fn singlestep_with_breakpoints_disabled(&self) -> ReplayResult {
        unimplemented!()
    }

    fn fix_watchpoint_coalescing_quirk(&self, _result: &ReplayResult, _before: &ProtoMark) -> bool {
        unimplemented!()
    }

    fn find_singlestep_before(&self, mark: &Mark) -> Option<Mark> {
        let mark_vector = self.marks.get(&mark.ptr.borrow().proto.key)?;

        let mut i: isize = mark_vector.len() as isize - 1;
        while i >= 0 {
            if Rc::ptr_eq(&mark_vector[i as usize], &mark.ptr) {
                break;
            }
            i -= 1;
        }
        debug_assert!(i >= 0, "Mark not in vector???");

        if i == 0 {
            return None;
        }
        if !mark_vector[i as usize - 1]
            .borrow()
            .singlestep_to_next_mark_no_signal
        {
            return None;
        }
        Some(Mark::from_internal_mark(
            mark_vector[i as usize - 1].clone(),
        ))
    }

    fn is_start_of_reverse_execution_barrier_event(&self) -> bool {
        unimplemented!()
    }

    fn update_observable_break_status(_now: &Mark, _result: &ReplayResult) {
        unimplemented!()
    }

    /// Simply called reverse_singlestep() in rr
    fn reverse_singlestep2(
        &self,
        _origin: &Mark,
        _step_tuid: TaskUid,
        _step_ticks: Ticks,
        _stop_filter: &StopFilterFn,
        _interrupt_check: &InterruptCheckFn,
    ) -> ReplayResult {
        unimplemented!()
    }

    /// Reasonably fast since it just relies on checking the mark map.
    fn less_than(_m1: &Mark, _m2: &Mark) -> bool {
        unimplemented!()
    }

    fn estimate_progress(&self) -> Progress {
        unimplemented!()
    }

    /// Called when the current session has moved forward to a new execution
    /// point and we might want to make a checkpoint to support reverse-execution.
    /// If this adds a checkpoint, it will call
    /// discard_past_reverse_exec_checkpoints
    /// first.
    fn maybe_add_reverse_exec_checkpoint(&self, _strategy: CheckpointStrategy) {
        unimplemented!()
    }

    /// Discard some reverse-exec checkpoints in the past, if necessary. We do
    /// this to stop the number of checkpoints growing out of control.
    fn discard_past_reverse_exec_checkpoints(&self, _strategy: CheckpointStrategy) {
        unimplemented!()
    }

    /// Discard all reverse-exec checkpoints that are in the future (they're
    /// useless).
    fn discard_future_reverse_exec_checkpoints(&self) {
        unimplemented!()
    }

    fn set_short_checkpoint(&self) -> Mark {
        unimplemented!()
    }

    /// If result.break_status hit watchpoints or breakpoints, evaluate their
    /// conditions and clear the break_status flags if the conditions don't hold.
    fn evaluate_conditions(&self, _result: &ReplayResult) {
        unimplemented!()
    }
}

/// DIFF NOTE: One important difference between rd and rr's Mark is that
/// rd's Mark always indicates a position in the replay unlike
/// in rr where `ptr` can be null
pub struct Mark {
    ptr: InternalMarkSharedPtr,
}

impl Display for Mark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", *self.ptr.borrow())
    }
}

impl Eq for Mark {}

impl Ord for Mark {
    /// See ReplayTimeline::less_than() in rr
    /// @TODO Check this again
    fn cmp(&self, m2: &Self) -> Ordering {
        // DIFF NOTE: This is a DEBUG_ASSERT in rr
        assert!(self.ptr.borrow().owner.ptr_eq(&m2.ptr.borrow().owner));
        if self == m2 {
            Ordering::Equal
        } else {
            if self.ptr.borrow().proto.key < m2.ptr.borrow().proto.key {
                return Ordering::Less;
            }
            if m2.ptr.borrow().proto.key < self.ptr.borrow().proto.key {
                return Ordering::Greater;
            }
            // We now know that self & m2 have the same ptr.proto.key
            for m in &self.ptr.borrow().owner.upgrade().unwrap().borrow().marks
                [&self.ptr.borrow().proto.key]
            {
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
    pub fn regs(&self) -> Ref<Registers> {
        Ref::map(self.ptr.borrow(), |b| &b.proto.regs)
    }

    pub fn extra_regs(&self) -> Ref<ExtraRegisters> {
        Ref::map(self.ptr.borrow(), |b| &b.extra_regs)
    }

    pub fn time(&self) -> FrameTime {
        self.ptr.borrow().proto.key.trace_time
    }

    fn from_internal_mark(ptr: InternalMarkSharedPtr) -> Mark {
        Mark { ptr }
    }
}

/// Everything we know about the tracee state for a particular Mark.
/// This data alone does not allow us to determine the time ordering
/// of two Marks.
struct InternalMark {
    /// @TODO Is this what we want?
    owner: ReplayTimelineSharedWeakPtr,
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

impl Display for InternalMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.proto)
    }
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
                    owner
                        .borrow_mut()
                        .remove_mark_with_checkpoint(self.proto.key);
                }
                None => (),
            },
            None => (),
        }
    }
}

impl InternalMark {
    fn new(
        owner: ReplayTimelineSharedWeakPtr,
        session: &ReplaySession,
        key: MarkKey,
    ) -> InternalMark {
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
            // @TODO: Check this. This is %p in rr
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

impl Display for ProtoMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{{{},regs_ip:{}}}", self.key, self.regs.ip(),)
    }
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
