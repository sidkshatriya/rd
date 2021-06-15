use crate::{
    breakpoint_condition::BreakpointCondition,
    extra_registers::ExtraRegisters,
    fast_forward::maybe_at_or_after_x86_string_instruction,
    log::{LogDebug, LogError},
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    return_address_list::ReturnAddressList,
    session::{
        address_space::{BreakpointType, WatchType},
        replay_session::{
            ReplayResult, ReplaySession, ReplayStatus, ReplayStepKey, StepConstraints,
        },
        session_inner::{BreakStatus, RunCommand},
        task::{replay_task::ReplayTask, Task},
        Session, SessionSharedPtr,
    },
    taskish_uid::{AddressSpaceUid, TaskUid},
    ticks::Ticks,
    trace::trace_frame::FrameTime,
};
use nix::sys::mman::ProtFlags;
use std::{
    cell::{Ref, RefCell},
    cmp::Ordering,
    collections::BTreeMap,
    fmt::Display,
    io::{stderr, Write},
    mem,
    ops::Bound::{Excluded, Included, Unbounded},
    rc::{Rc, Weak},
};

#[derive(Ord, Eq, PartialEq, PartialOrd, Clone)]
struct TimelineBreakpoint {
    uid: AddressSpaceUid,
    addr: RemoteCodePtr,
}

#[derive(Ord, Eq, PartialEq, PartialOrd, Clone)]
struct TimelineWatchpoint {
    uid: AddressSpaceUid,
    addr: RemotePtr<Void>,
    size: usize,
    watch_type: WatchType,
}

#[derive(Copy, Clone, Eq, PartialEq)]
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
pub type ReplayTimelineSharedPtr = Rc<RefCell<ReplayTimeline>>;
pub type ReplayTimelineSharedWeakPtr = Weak<RefCell<ReplayTimeline>>;

#[derive(Copy, Clone, Default)]
struct ReplayStepToMarkStrategy {
    singlesteps_to_perform: u32,
}

impl ReplayStepToMarkStrategy {
    pub fn setup_step_constraints(&mut self) -> StepConstraints {
        let mut constraints = StepConstraints {
            command: RunCommand::Continue,
            stop_at_time: Default::default(),
            ticks_target: Default::default(),
            stop_before_states: Default::default(),
        };
        if self.singlesteps_to_perform > 0 {
            constraints.command = RunCommand::SinglestepFastForward;
            self.singlesteps_to_perform -= 1;
        }

        constraints
    }
}

/// This class manages a set of ReplaySessions corresponding to different points
/// in the same recording. It provides an API for explicitly managing
/// checkpoints along this timeline and navigating to specific events.
#[derive(Default)]
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
    /// really need to! If we're at a specific point in time and we *may* need to
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

    /// DIFF NOTE: rr uses a tuple in a set. We use a struct & Option in a map.
    breakpoints: BTreeMap<TimelineBreakpoint, Option<Box<dyn BreakpointCondition>>>,

    /// DIFF NOTE: rr uses a tuple in a set. We use a struct & Option in a map.
    watchpoints: BTreeMap<TimelineWatchpoint, Option<Box<dyn BreakpointCondition>>>,

    breakpoints_applied: bool,

    /// @TODO Lack of a barrier event is indicated with the value being 0
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
    reverse_exec_short_checkpoint: Option<Mark>,
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
type InterruptCheckFn = dyn Fn() -> bool;

impl ReplayTimeline {
    /// Checkpointing strategy:
    ///
    /// We define a series of intervals of increasing length, each one ending at
    /// the current replay position. In each interval N, we allow at most N
    /// checkpoints. We ensure that interval lengths grow exponentially (in the
    /// limit), so the maximum number of checkpoints for a given execution length
    /// L is O(log L).
    ///
    /// Interval N has length inter_checkpoint_interval to the
    /// power of checkpoint_interval_exponent.
    /// We allow at most N checkpoints in interval N.
    /// To discard excess checkpoints, first pick the smallest interval N with
    /// too many checkpoints, and discard the latest checkpoint in interval N
    /// that is not in interval N-1. Repeat until there are no excess checkpoints.
    /// All checkpoints after the current replay point are always discarded.
    /// The script checkpoint-visualizer.html simulates this algorithm and
    /// visualizes its results.
    /// The implementation here is quite naive, but that's OK because we will
    /// never have a large number of checkpoints.

    /// Try to space out our checkpoints by a minimum of this much in LOW_OVERHEAD
    /// mode.
    /// This is currently aiming for about 0.5s of replay time, so a reverse step or
    /// continue whose destination is within 0.5 should take at most a second.
    /// Also, based on a guesstimate that taking checkpoints of Firefox requires
    /// about 50ms, this would make checkpointing overhead about 10% of replay time,
    /// which sounds reasonable.
    const LOW_OVERHEAD_INTER_CHECKPOINT_INTERVAL: Progress = 500000;

    /// Space out checkpoints linearly by this much in
    /// EXPECT_SHORT_REVERSE_EXECUTION mode, until we reach
    /// low_overhead_inter_checkpoint_interval.
    const EXPECTING_REVERSE_EXEC_INTER_CHECKPOINT_INTERVAL: Progress = 100000;

    /// Don't allow more than this number of breakpoint/watchpoint stops
    /// in a given replay interval. If we hit more than this, try to split
    /// the interval in half and replay with watchpoints/breakpoints in the latter
    /// half.
    const STOP_COUNT_LIMIT: usize = 20;

    pub fn is_running(&self) -> bool {
        self.current.is_some()
    }

    /// The current state. The current state can be moved forward or backward
    /// using ReplaySession's APIs. Do not set breakpoints on its tasks directly.
    /// Use ReplayTimeline's breakpoint methods.
    pub fn current_session(&self) -> &ReplaySession {
        self.current.as_ref().unwrap().as_replay().unwrap()
    }

    pub fn current_session_shr_ptr(&self) -> SessionSharedPtr {
        self.current.as_ref().unwrap().clone()
    }

    pub fn weak_self_clone(&self) -> ReplayTimelineSharedWeakPtr {
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
            self.weak_self_clone(),
            self.current_session(),
            key,
        )));

        self.marks.entry(key).or_insert(Vec::new());
        let len = self.marks[&key].len();
        if len == 0
            || (self.current_at_or_after_mark.is_some()
                && Rc::ptr_eq(
                    self.current_at_or_after_mark.as_ref().unwrap(),
                    &self.marks[&key][len - 1],
                ))
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
            let mut new_marks: Vec<InternalMarkSharedPtr> = vec![m.clone()];

            // Allow coalescing of multiple repetitions of a single x86 string
            // instruction (as long as we don't reach one of our mark_vector states).
            let mut constraints = StepConstraints::new(RunCommand::SinglestepFastForward);
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
                    self.weak_self_clone(),
                    tmp_session_replay,
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
    pub fn mark_after_singlestep(&mut self, from: &Mark, result: &mut ReplayResult) {
        debug_assert!(result.break_status.singlestep_complete);
        let m = self.mark();
        let m_key = m.ptr.borrow().proto.key;
        if !result.did_fast_forward
            && m_key == from.ptr.borrow().proto.key
            && result.break_status.signal.is_none()
        {
            self.marks.entry(m_key).or_insert(Vec::new());
            let mark_vector = &self.marks[&m_key];
            for i in 0..mark_vector.len() {
                if Rc::ptr_eq(&mark_vector[i], &from.ptr) {
                    if i + 1 >= mark_vector.len() || !Rc::ptr_eq(&mark_vector[i + 1], &m.ptr) {
                        let mut m_prev: isize = -1;
                        for j in 0..mark_vector.len() {
                            log!(
                                LogDebug,
                                "  mark_vector[{}] = {}",
                                j,
                                *mark_vector[j].borrow()
                            );
                            if j > 0 && Rc::ptr_eq(&mark_vector[j], &m.ptr) {
                                m_prev = j as isize - 1;
                            }
                        }
                        if m_prev >= 0 {
                            log!(
                                LogError,
                                "Probable previous-to-duplicated-state at {}:",
                                m_prev,
                            );
                            mark_vector[m_prev as usize]
                                .borrow()
                                .full_write(&mut stderr());
                            log!(LogError, "Probable previous-to-duplicated-state at {}:", i);
                            from.ptr.borrow().full_write(&mut stderr());
                            log!(LogError, "Probable duplicated state at {}:", m_prev + 1);
                            m.ptr.borrow().full_write(&mut stderr());
                        }

                        let t = result.break_status.task.upgrade().unwrap();
                        ed_assert!(
                            &t,
                            false,
                            " Probable duplicated states leading to {} at index {}",
                            m,
                            i + 1
                        )
                    }
                    break;
                }
            }
            from.ptr.borrow_mut().singlestep_to_next_mark_no_signal = true;
        }
    }

    /// Returns true if it's safe to add a checkpoint here.
    pub fn can_add_checkpoint(&self) -> bool {
        self.current_session().can_clone()
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
    pub fn at_mark(&self, mark: &Mark) -> bool {
        self.current_mark()
            .as_ref()
            .map_or(false, |m| Rc::ptr_eq(m, &mark.ptr))
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
        &mut self,
        t: &ReplayTask,
        addr: RemoteCodePtr,
        condition: Option<Box<dyn BreakpointCondition>>,
    ) -> bool {
        if self.has_breakpoint_at_address(t, addr) {
            self.remove_breakpoint(t, addr);
        }
        // Apply breakpoints now; we need to actually try adding this breakpoint
        // to see if it works.
        self.apply_breakpoints_and_watchpoints();
        if !t.vm().add_breakpoint(addr, BreakpointType::User) {
            return false;
        }
        self.breakpoints.insert(
            TimelineBreakpoint {
                uid: t.vm().uid(),
                addr,
            },
            condition,
        );

        true
    }

    /// You can't remove a breakpoint with a specific condition, so don't
    /// place multiple breakpoints with conditions on the same location.
    pub fn remove_breakpoint(&mut self, t: &ReplayTask, addr: RemoteCodePtr) {
        if self.breakpoints_applied {
            t.vm().remove_breakpoint(addr, BreakpointType::User);
        }
        ed_assert!(t, self.has_breakpoint_at_address(t, addr));
        let tb = TimelineBreakpoint {
            uid: t.vm().uid(),
            addr,
        };
        assert!(self.breakpoints.remove(&tb).is_some());
    }

    pub fn add_watchpoint(
        &mut self,
        t: &ReplayTask,
        addr: RemotePtr<Void>,
        num_bytes: usize,
        type_: WatchType,
        condition: Option<Box<dyn BreakpointCondition>>,
    ) -> bool {
        if self.has_watchpoint_at_address(t, addr, num_bytes, type_) {
            self.remove_watchpoint(t, addr, num_bytes, type_);
        }
        // Apply breakpoints now; we need to actually try adding this breakpoint
        // to see if it works.
        self.apply_breakpoints_and_watchpoints();
        if !t.vm().add_watchpoint(addr, num_bytes, type_) {
            return false;
        }
        self.watchpoints.insert(
            TimelineWatchpoint {
                uid: t.vm().uid(),
                addr,
                size: num_bytes,
                watch_type: type_,
            },
            condition,
        );
        self.no_watchpoints_hit_interval_start = None;
        self.no_watchpoints_hit_interval_end = None;
        true
    }

    /// You can't remove a watchpoint with a specific condition, so don't
    /// place multiple breakpoints with conditions on the same location.
    pub fn remove_watchpoint(
        &mut self,
        t: &ReplayTask,
        addr: RemotePtr<Void>,
        num_bytes: usize,
        type_: WatchType,
    ) {
        if self.breakpoints_applied {
            t.vm().remove_watchpoint(addr, num_bytes, type_);
        }
        ed_assert!(t, self.has_watchpoint_at_address(t, addr, num_bytes, type_));
        let wt = TimelineWatchpoint {
            uid: t.vm().uid(),
            addr,
            size: num_bytes,
            watch_type: type_,
        };
        assert!(self.watchpoints.remove(&wt).is_some());
    }

    pub fn remove_breakpoints_and_watchpoints(&mut self) {
        self.unapply_breakpoints_and_watchpoints();
        self.breakpoints.clear();
        self.watchpoints.clear();
    }

    pub fn has_breakpoint_at_address(&self, t: &dyn Task, addr: RemoteCodePtr) -> bool {
        let tb = TimelineBreakpoint {
            uid: t.vm().uid(),
            addr,
        };

        self.breakpoints.contains_key(&tb)
    }

    pub fn has_watchpoint_at_address(
        &self,
        t: &ReplayTask,
        addr: RemotePtr<Void>,
        num_bytes: usize,
        type_: WatchType,
    ) -> bool {
        let tb = TimelineWatchpoint {
            uid: t.vm().uid(),
            addr,
            size: num_bytes,
            watch_type: type_,
        };

        self.watchpoints.contains_key(&tb)
    }

    /// Ensure that reverse execution never proceeds into an event before
    /// |event|. Reverse execution will stop with a |task_exit| break status when
    /// at the beginning of this event.
    pub fn set_reverse_execution_barrier_event(&mut self, event: FrameTime) {
        self.reverse_execution_barrier_event = event;
    }

    /// State-changing APIs. These may alter state associated with
    /// current_session().
    /// Reset the current session to the last available session before event
    /// 'time'. Useful if you want to run up to that event.
    pub fn seek_to_before_event(&mut self, time: FrameTime) {
        self.seek_to_before_key(MarkKey::new(time, 0, ReplayStepKey::default()));
    }

    /// Reset the current session to the last checkpointed session before (or at)
    /// the mark. Will return at the mark if this mark was explicitly checkpointed
    /// previously (and not deleted).
    pub fn seek_up_to_mark(&mut self, mark: &Mark) {
        let key = mark.ptr.borrow().proto.key;
        if self.current_mark_key() == key {
            let cm = self.mark();
            if cm <= *mark {
                // close enough, stay where we are
                return;
            }
        }

        self.marks.entry(key).or_insert(Vec::new());
        // Check if any of the marks with the same key as 'mark', but not after
        // 'mark', are usable.
        let mark_vector = &self.marks[&key];
        let mut at_or_before_mark = false;
        let mut i = mark_vector.len() as isize - 1;
        while i >= 0 {
            let m = &mark_vector[i as usize];
            if Rc::ptr_eq(m, &mark.ptr) {
                at_or_before_mark = true;
            }
            if at_or_before_mark && m.borrow().checkpoint.is_some() {
                self.current = Some(
                    m.borrow()
                        .checkpoint
                        .as_ref()
                        .unwrap()
                        .as_replay()
                        .unwrap()
                        .clone_replay(),
                );
                // At this point, m.checkpoint is fully initialized but current
                // is not. Swap them so that m.checkpoint is not fully
                // initialized, to reduce resource usage.
                mem::swap(
                    self.current.as_mut().unwrap(),
                    m.borrow_mut().checkpoint.as_mut().unwrap(),
                );
                self.breakpoints_applied = false;
                self.current_at_or_after_mark = Some(m.clone());
                return;
            }
            i -= 1;
        }

        self.seek_to_before_key(mark.ptr.borrow().proto.key)
    }

    /// Sets current session to 'mark' by restoring the nearest useful checkpoint
    /// and executing forwards if necessary.
    pub fn seek_to_mark(&mut self, mark: &Mark) {
        self.seek_up_to_mark(mark);
        // @TODO Check this. Make sure logic is correct.
        while self
            .current_mark()
            .as_ref()
            .map_or(true, |m| !Rc::ptr_eq(m, &mark.ptr))
        {
            self.unapply_breakpoints_and_watchpoints();
            let mut strategy: ReplayStepToMarkStrategy = Default::default();
            self.replay_step_to_mark(mark, &mut strategy);
        }
        self.current_at_or_after_mark = Some(mark.ptr.clone());
        // XXX handle cases where breakpoints can't yet be applied
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
        &mut self,
        command: RunCommand,
        stop_at_time: FrameTime,
    ) -> ReplayResult {
        debug_assert_ne!(command, RunCommand::SinglestepFastForward);

        let mut result: ReplayResult;
        self.apply_breakpoints_and_watchpoints();
        let before: ProtoMark = self.proto_mark();
        self.current_session().set_visible_execution(true);
        let mut constraints = StepConstraints::new(command);
        constraints.stop_at_time = stop_at_time;
        result = self
            .current_session()
            .replay_step_with_constraints(&constraints);
        self.current_session().set_visible_execution(false);
        if command == RunCommand::Continue {
            // Since it's easy for us to fix the coalescing quirk for forward
            // execution, we may as well do so. It's nice to have forward execution
            // behave consistently with reverse execution.
            self.fix_watchpoint_coalescing_quirk(&mut result, &before);
            // Hide any singlestepping we did
            result.break_status.singlestep_complete = false;
        }
        self.maybe_add_reverse_exec_checkpoint(CheckpointStrategy::LowOverhead);

        let did_hit_breakpoint: bool = result.break_status.hardware_or_software_breakpoint_hit();
        self.evaluate_conditions(&mut result);
        if did_hit_breakpoint && !result.break_status.any_break() {
            // Singlestep past the breakpoint
            self.current_session().set_visible_execution(true);
            result = self.singlestep_with_breakpoints_disabled();
            if command == RunCommand::Continue {
                result.break_status.singlestep_complete = false;
            }
            self.current_session().set_visible_execution(false);
        }
        result
    }

    pub fn reverse_continue(
        &mut self,
        stop_filter: &StopFilterFn,
        interrupt_check: &InterruptCheckFn,
    ) -> ReplayResult {
        let mut end: Mark = self.mark();
        log!(LogDebug, "ReplayTimeline::reverse_continue from {}", end);

        let mut last_stop_is_watch_or_signal: bool = false;
        let mut final_result: ReplayResult = Default::default();
        // @TODO In rr, no value is 0. This is tricky. Check this again.
        let mut final_tuid: Option<TaskUid> = None;
        // @TODO In rr, no value is 0. This is tricky. Check this again.
        let mut final_ticks: Option<Ticks> = None;
        let mut maybe_dest: Option<Mark> = None;
        let mut restart_points: Vec<Mark> = Vec::new();

        while maybe_dest.is_none() {
            let mut start: Mark = self.mark();
            let mut checkpoint_at_first_break: bool;
            if start >= end {
                checkpoint_at_first_break = true;
                if restart_points.is_empty() {
                    self.seek_to_before_key(end.ptr.borrow().proto.key);
                    start = self.mark();
                    if start >= end {
                        log!(LogDebug, "Couldn't seek to before {}, returning exit", end);
                        // Can't go backwards. Call this an exit.
                        final_result.status = ReplayStatus::ReplayExited;
                        final_result.break_status = BreakStatus::default();
                        return final_result;
                    }
                    log!(LogDebug, "Seeked backward from {} to {}", end, start);
                } else {
                    let seek: Mark = restart_points.pop().unwrap();
                    self.seek_to_mark(&seek);
                    log!(
                        LogDebug,
                        "Seeked directly backward from {} to {}",
                        start,
                        seek
                    );
                    start = seek;
                }
            } else {
                checkpoint_at_first_break = false;
            }
            self.maybe_add_reverse_exec_checkpoint(CheckpointStrategy::ExpectShortReverseExecution);

            log!(
                LogDebug,
                "reverse-continue continuing forward from {} up to {}",
                start,
                end
            );

            let mut at_breakpoint = false;
            let mut strategy = ReplayStepToMarkStrategy::default();
            let mut stop_count: usize = 0;
            let mut made_progress_between_stops = false;
            // A lack of value is indicated by 0
            let mut avoidable_stop_ip = RemoteCodePtr::default();
            let mut avoidable_stop_ticks: Ticks = 0;
            loop {
                self.apply_breakpoints_and_watchpoints();
                let mut result: ReplayResult;
                if at_breakpoint {
                    result = self.singlestep_with_breakpoints_disabled();
                } else {
                    result = self.replay_step_to_mark(&end, &mut strategy);
                    // This will remove all reverse-exec checkpoints ahead of the
                    // current time, and add new ones if necessary. This should be
                    // helpful if we have to reverse-continue far back in time, where
                    // the interval between 'start' and 'end' could be lengthy; we'll
                    // populate the interval with new checkpoints, speeding up
                    // the following seek and possibly future operations.
                }
                at_breakpoint = result.break_status.hardware_or_software_breakpoint_hit();
                let avoidable_stop = result.break_status.breakpoint_hit
                    || !result.break_status.watchpoints_hit.is_empty();
                if avoidable_stop {
                    let task = result.break_status.task.upgrade().unwrap();
                    made_progress_between_stops =
                        avoidable_stop_ip != task.ip() || avoidable_stop_ticks != task.tick_count();
                    avoidable_stop_ip = task.ip();
                    avoidable_stop_ticks = task.tick_count();
                }

                self.evaluate_conditions(&mut result);
                if result.break_status.any_break()
                    && !stop_filter(
                        result
                            .break_status
                            .task
                            .upgrade()
                            .unwrap()
                            .as_replay_task()
                            .unwrap(),
                    )
                {
                    result.break_status = BreakStatus::default();
                }

                self.maybe_add_reverse_exec_checkpoint(
                    CheckpointStrategy::ExpectShortReverseExecution,
                );
                if checkpoint_at_first_break
                    && maybe_dest != Some(start.clone())
                    && result.break_status.any_break()
                {
                    checkpoint_at_first_break = false;
                    self.set_short_checkpoint();
                }

                if !result.break_status.data_watchpoints_hit().is_empty()
                    || result.break_status.signal.is_some()
                {
                    maybe_dest = Some(self.mark());
                    if result.break_status.signal.is_some() {
                        log!(
                            LogDebug,
                            "Found signal break at {}",
                            maybe_dest.as_ref().unwrap()
                        );
                    } else {
                        log!(
                            LogDebug,
                            "Found watch break at {}, addr={}",
                            maybe_dest.as_ref().unwrap(),
                            result.break_status.data_watchpoints_hit()[0].addr
                        );
                    }
                    // @TODO Check this
                    final_result = result.clone();
                    final_tuid = if !result.break_status.task.ptr_eq(&Weak::new()) {
                        Some(result.break_status.task.upgrade().unwrap().tuid())
                    } else {
                        None
                    };
                    final_ticks = if !result.break_status.task.ptr_eq(&Weak::new()) {
                        Some(result.break_status.task.upgrade().unwrap().tick_count())
                    } else {
                        None
                    };
                    last_stop_is_watch_or_signal = true;
                }
                debug_assert_eq!(result.status, ReplayStatus::ReplayContinue);

                if self.is_start_of_reverse_execution_barrier_event() {
                    maybe_dest = Some(self.mark());
                    final_result = result.clone();
                    final_result.break_status.task =
                        Rc::downgrade(&self.current_session().current_task().unwrap());
                    final_result.break_status.task_exit = true;
                    final_tuid = Some(final_result.break_status.task.upgrade().unwrap().tuid());
                    final_ticks = Some(result.break_status.task.upgrade().unwrap().tick_count());
                    last_stop_is_watch_or_signal = false;
                }

                if self.at_mark(&end) {
                    // In the next iteration, retry from an earlier checkpoint.
                    end = start;
                    break;
                }

                // If there is a breakpoint at the current ip() where we start a
                // reverse-continue, gdb expects us to skip it.
                if result.break_status.hardware_or_software_breakpoint_hit() {
                    maybe_dest = Some(self.mark());
                    log!(
                        LogDebug,
                        "Found breakpoint break at {}",
                        maybe_dest.as_ref().unwrap()
                    );
                    final_result = result.clone();
                    final_tuid = if !result.break_status.task.ptr_eq(&Weak::new()) {
                        Some(result.break_status.task.upgrade().unwrap().tuid())
                    } else {
                        None
                    };
                    final_ticks = if !result.break_status.task.ptr_eq(&Weak::new()) {
                        Some(result.break_status.task.upgrade().unwrap().tick_count())
                    } else {
                        None
                    };
                    last_stop_is_watch_or_signal = false;
                }

                if interrupt_check() {
                    log!(LogDebug, "Interrupted at {}", end);
                    self.seek_to_mark(&end);
                    final_result = ReplayResult::default();
                    final_result.break_status.task =
                        Rc::downgrade(&self.current_session().current_task().unwrap());
                    return final_result;
                }

                if avoidable_stop {
                    stop_count += 1;
                    if stop_count > Self::STOP_COUNT_LIMIT {
                        let before_running: Mark = self.mark();
                        if self.run_forward_to_intermediate_point(
                            &end,
                            if made_progress_between_stops {
                                ForceProgress::DontForceProgress
                            } else {
                                ForceProgress::ForceProgress
                            },
                        ) {
                            debug_assert!(!self.at_mark(&end));
                            // We made some progress towards |end| with breakpoints/watchpoints
                            // disabled, without reaching |end|. Continuing running forward from
                            // here with breakpoints/watchpoints enabled. If we need to seek
                            // backwards again, try resuming from the point where we disabled
                            // breakpoints/watchpoints.
                            if maybe_dest.is_some() {
                                restart_points.push(start.clone());
                            }
                            restart_points.push(before_running.clone());
                            maybe_dest = None;
                            break;
                        }
                    }
                }
            }
        }

        if last_stop_is_watch_or_signal {
            log!(
                LogDebug,
                "Performing final reverse-singlestep to pass over watch/signal"
            );
            let tuid = final_tuid.unwrap();
            let stop_filter = move |t: &ReplayTask| t.tuid() == tuid;
            self.reverse_singlestep2(
                maybe_dest.as_ref().unwrap(),
                final_tuid.unwrap(),
                final_ticks.unwrap(),
                &stop_filter,
                interrupt_check,
            );
        } else {
            log!(
                LogDebug,
                "Seeking to final destination {}",
                maybe_dest.as_ref().unwrap()
            );
            self.seek_to_mark(maybe_dest.as_ref().unwrap());
        }
        // fix break_status.task since the actual ReplayTask* may have changed
        // since we saved final_result
        final_result.break_status.task = Rc::downgrade(
            &self
                .current_session()
                .find_task_from_task_uid(final_tuid.unwrap())
                .unwrap(),
        );
        // Hide any singlestepping we did, since a continue operation should
        // never return a singlestep status
        final_result.break_status.singlestep_complete = false;
        final_result
    }

    pub fn reverse_singlestep(
        &mut self,
        tuid: TaskUid,
        tuid_ticks: Ticks,
        stop_filter: &StopFilterFn,
        interrupt_check: &InterruptCheckFn,
    ) -> ReplayResult {
        let m = self.mark();
        self.reverse_singlestep2(&m, tuid, tuid_ticks, stop_filter, interrupt_check)
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

    #[allow(clippy::field_reassign_with_default)]
    pub fn new(session: SessionSharedPtr) -> Rc<RefCell<ReplayTimeline>> {
        // Using the ..Default::default() idiom gives a strange compile error
        // Just ignore the clippy
        let mut timeline = ReplayTimeline::default();
        timeline.current = Some(session);

        Rc::new_cyclic(move |w| {
            timeline.weak_self = w.clone();
            RefCell::new(timeline)
        })
    }

    /// We track the set of breakpoints/watchpoints requested by the client.
    /// When we switch to a new ReplaySession, these need to be reapplied before
    /// replaying that session, but we do this lazily.
    /// apply_breakpoints_and_watchpoints() forces the breakpoints/watchpoints
    /// to be applied to the current session.
    /// Our checkpoints never have breakpoints applied.
    pub fn apply_breakpoints_and_watchpoints(&mut self) {
        if self.breakpoints_applied {
            return;
        }
        self.breakpoints_applied = true;
        self.apply_breakpoints_internal();
        for wp in self.watchpoints.keys() {
            let maybe_vm = self.current_session().find_address_space(wp.uid);
            // XXX handle cases where we can't apply a watchpoint right now. Later
            // during replay the address space might be created (or new mappings might
            // be created) and we should reapply watchpoints then.
            // XXX we could make this more efficient by providing a method to set
            // several watchpoints at once on a given AddressSpace.
            match maybe_vm {
                Some(vm) if wp.watch_type != WatchType::Exec => {
                    vm.add_watchpoint(wp.addr, wp.size, wp.watch_type);
                }
                _ => (),
            }
        }
    }

    /// unapply_breakpoints_and_watchpoints() forces the breakpoints/watchpoints
    /// to not be applied to the current session. Use this when we need to
    /// clone the current session or replay the current session without
    /// triggering breakpoints.
    fn unapply_breakpoints_and_watchpoints(&mut self) {
        if !self.breakpoints_applied {
            return;
        }
        self.breakpoints_applied = false;
        self.unapply_breakpoints_internal();
        for wp in self.watchpoints.keys() {
            let maybe_vm = self.current_session().find_address_space(wp.uid);
            match maybe_vm {
                Some(vm) if wp.watch_type != WatchType::Exec => {
                    vm.remove_watchpoint(wp.addr, wp.size, wp.watch_type);
                }
                _ => (),
            }
        }
    }

    fn apply_breakpoints_internal(&self) {
        for bp in self.breakpoints.keys() {
            let maybe_vm = self.current_session().find_address_space(bp.uid);
            // XXX handle cases where we can't apply a breakpoint right now. Later
            // during replay the address space might be created (or new mappings might
            // be created) and we should reapply breakpoints then.
            match maybe_vm {
                Some(vm) => {
                    vm.add_breakpoint(bp.addr, BreakpointType::User);
                }
                _ => (),
            }
        }
        for wp in self.watchpoints.keys() {
            let maybe_vm = self.current_session().find_address_space(wp.uid);
            match maybe_vm {
                Some(vm) if wp.watch_type == WatchType::Exec => {
                    vm.add_watchpoint(wp.addr, wp.size, wp.watch_type);
                }
                _ => (),
            }
        }
    }

    fn unapply_breakpoints_internal(&self) {
        for bp in self.breakpoints.keys() {
            let maybe_vm = self.current_session().find_address_space(bp.uid);
            match maybe_vm {
                Some(vm) => vm.remove_breakpoint(bp.addr, BreakpointType::User),
                None => (),
            }
            for wp in self.watchpoints.keys() {
                let maybe_vm = self.current_session().find_address_space(wp.uid);
                match maybe_vm {
                    Some(vm) if wp.watch_type == WatchType::Exec => {
                        vm.remove_watchpoint(wp.addr, wp.size, wp.watch_type);
                    }
                    _ => (),
                }
            }
        }
    }

    fn session_mark_key(session: &ReplaySession) -> MarkKey {
        let maybe_t = session.current_task();
        let tick_count = match maybe_t {
            Some(t) => t.tick_count(),
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
        match self.current_session().current_task() {
            Some(rc_t) => ProtoMark::new(self.current_mark_key(), &**rc_t),
            None => ProtoMark::new_from_key(self.current_mark_key()),
        }
    }

    fn seek_to_proto_mark(&mut self, pmark: &ProtoMark) {
        self.seek_to_before_key(pmark.key);
        self.unapply_breakpoints_and_watchpoints();
        while !pmark.equal_states(self.current_session()) {
            if self.current_session().trace_reader().time() < pmark.key.trace_time {
                let mut constraints = StepConstraints::new(RunCommand::Continue);
                constraints.stop_at_time = pmark.key.trace_time;
                self.current_session()
                    .replay_step_with_constraints(&constraints);
            } else {
                let t = self.current_session().current_task().unwrap();
                let mark_addr: RemoteCodePtr = pmark.regs.ip();
                if t.regs_ref().ip() == mark_addr
                    && self.current_session().current_step_key().in_execution()
                {
                    // At required IP, but not in the correct state. Singlestep over
                    // this IP.
                    let mut constraints = StepConstraints::new(RunCommand::SinglestepFastForward);
                    constraints.stop_before_states.push(pmark.regs.clone());
                    self.current_session()
                        .replay_step_with_constraints(&constraints);
                } else {
                    // Get a shared reference to t.vm() in case t dies during replay_step
                    let vm = t.vm();
                    vm.add_breakpoint(mark_addr, BreakpointType::User);
                    self.current_session().replay_step(RunCommand::Continue);
                    vm.remove_breakpoint(mark_addr, BreakpointType::User);
                }
            }
        }
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
                    Some(&self.current_session().trace_reader().trace_stream().dir()),
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
                self.marks.entry(it).or_insert(Vec::new());
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
    fn run_forward_to_intermediate_point(&mut self, end: &Mark, force: ForceProgress) -> bool {
        self.unapply_breakpoints_and_watchpoints();

        log!(
            LogDebug,
            "Trying to find intermediate point between {} and {} {}",
            self.current_mark_key(),
            end,
            if force == ForceProgress::ForceProgress {
                " (forced)"
            } else {
                ""
            }
        );

        let now: FrameTime = self.current_session().trace_reader().time();
        let mid: FrameTime = (now + end.ptr.borrow().proto.key.trace_time) / 2;
        if now < mid && mid < end.ptr.borrow().proto.key.trace_time {
            let mut constraints = StepConstraints::new(RunCommand::Continue);
            constraints.stop_at_time = mid;
            while self.current_session().trace_reader().time() < mid {
                self.current_session()
                    .replay_step_with_constraints(&constraints);
            }
            debug_assert_eq!(self.current_session().trace_reader().time(), mid);

            log!(
                LogDebug,
                "Ran forward to mid event {}",
                self.current_mark_key()
            );
            return true;
        }

        if self.current_session().trace_reader().time() < end.ptr.borrow().proto.key.trace_time
            && end.ptr.borrow().ticks_at_event_start < end.ptr.borrow().proto.key.ticks
        {
            let mut constraints = StepConstraints::new(RunCommand::Continue);
            constraints.stop_at_time = end.ptr.borrow().proto.key.trace_time;
            while self.current_session().trace_reader().time()
                < end.ptr.borrow().proto.key.trace_time
            {
                self.current_session()
                    .replay_step_with_constraints(&constraints);
            }
            debug_assert_eq!(
                self.current_session().trace_reader().time(),
                end.ptr.borrow().proto.key.trace_time
            );
            log!(LogDebug, "Ran forward to event {}", self.current_mark_key());
            return true;
        }

        let t = match self.current_session().current_task() {
            Some(t) => t,
            None => {
                log!(LogDebug, "Made no progress");
                return false;
            }
        };
        let start_ticks: Ticks = t.tick_count();
        let mut end_ticks: Ticks = self.current_session().current_trace_frame().ticks();
        if end.ptr.borrow().proto.key.trace_time == self.current_session().trace_reader().time() {
            end_ticks = u64::min(end_ticks, end.ptr.borrow().proto.key.ticks);
        }
        ed_assert!(&t, start_ticks <= end_ticks);
        let target: Ticks = u64::min(end_ticks, (start_ticks + end_ticks) / 2);
        let m: ProtoMark = self.proto_mark();
        if target != end_ticks {
            // We can only try stepping if we won't end up at `end`
            let mut constraints = StepConstraints::new(RunCommand::Continue);
            constraints.ticks_target = target;
            let mut result: ReplayResult = self
                .current_session()
                .replay_step_with_constraints(&constraints);
            if !m.equal_states(self.current_session()) {
                while t.tick_count() < target && !result.break_status.approaching_ticks_target {
                    result = self
                        .current_session()
                        .replay_step_with_constraints(&constraints);
                }
                log!(LogDebug, "Ran forward to {}", self.current_mark_key());
                return true;
            }
            debug_assert!(result.break_status.approaching_ticks_target);
            debug_assert_eq!(t.tick_count(), start_ticks);
        }

        // We didn't make any progress that way.
        // Normally we should just give up now and let reverse_continue keep
        // running and hitting breakpoints etc since we're pretty close to the
        // target already and the overhead of what we have to do here otherwise
        // can be high. But there's a pathological case where reverse_continue
        // is hitting a breakpoint on each iteration of a string instruction.
        // If that's happening then we will be told to force progress.
        if force == ForceProgress::ForceProgress {
            // Let's try a fast-forward singlestep to jump over an x86 string
            // instruction that may be triggering a lot of breakpoint hits. Make
            // sure
            // we stop before |end|.
            let mut maybe_tmp_session: Option<SessionSharedPtr> = None;
            if start_ticks + 1 >= end_ticks {
                // This singlestep operation might leave us at |end|, which is not
                // allowed. So make a backup of the current state.
                maybe_tmp_session = Some(self.current_session().clone_replay());
                log!(LogDebug, "Created backup tmp_session");
            }
            let mut constraints = StepConstraints::new(RunCommand::SinglestepFastForward);
            constraints
                .stop_before_states
                .push(end.ptr.borrow().proto.regs.clone());
            let _result: ReplayResult = self
                .current_session()
                .replay_step_with_constraints(&constraints);
            if self.at_mark(end) {
                debug_assert!(maybe_tmp_session.is_some());
                self.current = maybe_tmp_session;
                log!(
                    LogDebug,
                    "Singlestepping arrived at |end|, restoring session"
                );
            } else if !m.equal_states(self.current_session()) {
                log!(
                    LogDebug,
                    "Did fast-singlestep forward to {}",
                    self.current_mark_key()
                );
                return true;
            }
        }

        log!(LogDebug, "Made no progress");
        false
    }

    fn update_strategy_and_fix_watchpoint_quirk(
        &mut self,
        strategy: &mut ReplayStepToMarkStrategy,
        constraints: &StepConstraints,
        result: &mut ReplayResult,
        before: &ProtoMark,
    ) {
        if constraints.command == RunCommand::Continue
            && self.fix_watchpoint_coalescing_quirk(result, before)
        {
            // It's quite common for x86 string instructions to trigger the same
            // watchpoint several times in consecutive instructions, e.g. if we're
            // doing a "rep movsb" over an 8-byte watchpoint. 8 invocations of
            // fix_watchpoint_coalescing_quirk could require 8 replays from some
            // previous checkpoint. To avoid that, after
            // fix_watchpoint_coalescing_quirk has fired once, singlestep the
            // next 7 times.
            strategy.singlesteps_to_perform = 7;
        }
    }

    /// Take a single replay step towards |mark|. Stop before or at |mark|, and
    /// stop if any breakpoint/watchpoint/signal is hit.
    /// Maintain current strategy state in |strategy|. Passing the same
    /// |strategy| object to consecutive replay_step_to_mark invocations helps
    /// optimize performance.
    fn replay_step_to_mark(
        &mut self,
        mark: &Mark,
        strategy: &mut ReplayStepToMarkStrategy,
    ) -> ReplayResult {
        let t = self.current_session().current_task().unwrap();
        let before: ProtoMark = self.proto_mark();
        ed_assert!(
            &t,
            before.key <= mark.ptr.borrow().proto.key,
            "Current mark {} is already after target {}",
            before,
            mark
        );
        let mut result: ReplayResult;
        if self.current_session().trace_reader().time() < mark.ptr.borrow().proto.key.trace_time {
            // Easy case: each RunCommand::RunContinue can only advance by at most one
            // trace event, so do one. But do a singlestep if our strategy suggests
            // we should.
            let mut constraints: StepConstraints = strategy.setup_step_constraints();
            constraints.stop_at_time = mark.ptr.borrow().proto.key.trace_time;
            result = self
                .current_session()
                .replay_step_with_constraints(&constraints);
            self.update_strategy_and_fix_watchpoint_quirk(
                strategy,
                &constraints,
                &mut result,
                &before,
            );
            return result;
        }

        ed_assert_eq!(
            &t,
            self.current_session().trace_reader().time(),
            mark.ptr.borrow().proto.key.trace_time
        );
        // t must remain valid through here since t can only die when we complete
        // an event, and we're not going to complete another event before
        // reaching the mark ... apart from where we call
        // fix_watchpoint_coalescing_quirk.

        if t.tick_count() < mark.ptr.borrow().proto.key.ticks {
            // Try to make progress by just continuing with a ticks constraint
            // set to stop us before the mark. This is efficient in the worst case,
            // when we must execute lots of instructions to reach the mark.
            let mut constraints: StepConstraints = strategy.setup_step_constraints();
            constraints.ticks_target = mark.ptr.borrow().proto.key.ticks - 1;
            if constraints.ticks_target > 0 {
                result = self
                    .current_session()
                    .replay_step_with_constraints(&constraints);
                let approaching_ticks_target: bool = result.break_status.approaching_ticks_target;
                result.break_status.approaching_ticks_target = false;
                // We can't be at the mark yet.
                ed_assert!(&t, t.tick_count() < mark.ptr.borrow().proto.key.ticks);
                // If there's a break indicated, we should return that to the
                // caller without doing any more work
                if !approaching_ticks_target || result.break_status.any_break() {
                    self.update_strategy_and_fix_watchpoint_quirk(
                        strategy,
                        &constraints,
                        &mut result,
                        &before,
                    );
                    return result;
                }
            }
            // We may not have made any progress so we'll need to try another strategy
        }

        let mark_addr_code: RemoteCodePtr = mark.ptr.borrow().proto.regs.ip();
        let mark_addr: RemotePtr<Void> = mark_addr_code.to_data_ptr();

        // Try adding a breakpoint at the required IP and running to it.
        // We can't do this if we're currently at the IP, since we'd make no progress.
        // However, we need to be careful, since there are two related situations when
        // the instruction at the mark ip is never actually executed. The first
        // happens if the IP is invalid entirely, the second if it is valid, but
        // not executable. In either case we need to fall back to the (slower, but
        // more generic) code below.
        if t.regs_ref().ip() != mark_addr_code
            && (t
                .vm()
                .mapping_of(mark_addr)
                .map_or(false, |m| m.map.prot().contains(ProtFlags::PROT_EXEC)))
        {
            let succeeded: bool = t.vm().add_breakpoint(mark_addr_code, BreakpointType::User);
            ed_assert!(&t, succeeded);
            let constraints: StepConstraints = strategy.setup_step_constraints();
            result = self
                .current_session()
                .replay_step_with_constraints(&constraints);
            t.vm()
                .remove_breakpoint(mark_addr_code, BreakpointType::User);
            // If we hit our breakpoint and there is no client breakpoint there,
            // pretend we didn't hit it.
            if result.break_status.breakpoint_hit && !self.has_breakpoint_at_address(&**t, t.ip()) {
                result.break_status.breakpoint_hit = false;
            }
            self.update_strategy_and_fix_watchpoint_quirk(
                strategy,
                &constraints,
                &mut result,
                &before,
            );
            return result;
        }

        // At required IP, but not in the correct state. Singlestep over this IP.
        // We need the FAST_FORWARD option in case the mark state occurs after
        // many iterations of a string instruction at this address.
        let mut constraints = StepConstraints::new(RunCommand::SinglestepFastForward);
        // We don't want to fast-forward past the mark state, so give the mark
        // state as a state we should stop before. FAST_FORWARD always does at
        // least one singlestep so one call to replay_step_to_mark will fast-forward
        // to the state before the mark and return, then the next call to
        // replay_step_to_mark will singlestep into the mark state.
        constraints
            .stop_before_states
            .push(mark.ptr.borrow().proto.regs.clone());
        result = self
            .current_session()
            .replay_step_with_constraints(&constraints);
        // Hide internal singlestep but preserve other break statuses
        result.break_status.singlestep_complete = false;
        result
    }

    fn singlestep_with_breakpoints_disabled(&mut self) -> ReplayResult {
        self.apply_breakpoints_and_watchpoints();
        self.unapply_breakpoints_internal();
        let result = self.current_session().replay_step(RunCommand::Singlestep);
        self.apply_breakpoints_internal();
        result
    }

    /// Intel CPUs (and maybe others) coalesce iterations of REP-prefixed string
    /// instructions so that a watchpoint on a byte at location L can fire after
    /// the iteration that writes byte L+63 (or possibly more?).
    /// This causes problems for us since this coalescing doesn't happen when we
    /// single-step.
    /// This function is called after doing a ReplaySession::replay_step with
    /// command == RUN_CONTINUE. RUN_SINGLESTEP and RUN_SINGLESTEP_FAST_FORWARD
    /// disable this coalescing (the latter, because it's aware of watchpoints
    /// and single-steps when it gets too close to them).
    /// |before| is the state before we did the replay_step.
    /// If a watchpoint fired, and it looks like it could have fired during a
    /// string instruction, we'll backup to |before| and replay forward, stopping
    /// before the breakpoint could fire and single-stepping to make sure the
    /// coalescing quirk doesn't happen.
    /// Returns true if we might have fixed something.
    fn fix_watchpoint_coalescing_quirk(
        &mut self,
        result: &mut ReplayResult,
        before: &ProtoMark,
    ) -> bool {
        if result.status == ReplayStatus::ReplayExited
            || result.break_status.data_watchpoints_hit().is_empty()
        {
            // no watchpoint hit. Nothing to fix.
            return false;
        }
        let break_status_task = result.break_status.task.upgrade().unwrap();
        if !maybe_at_or_after_x86_string_instruction(break_status_task.as_replay_task().unwrap()) {
            return false;
        }

        let after_tuid: TaskUid = break_status_task.tuid();
        let after_ticks: Ticks = break_status_task.tick_count();
        log!(
            LogDebug,
            "Fixing x86-string coalescing quirk from {} to {} (final cx {})",
            before,
            self.proto_mark(),
            break_status_task.regs_ref().cx()
        );

        self.seek_to_proto_mark(before);

        // Keep going until the watchpoint fires. It will either fire early, or at
        // the same time as some other break.
        self.apply_breakpoints_and_watchpoints();
        let mut approaching_ticks_target = false;
        loop {
            let t = self.current_session().current_task().unwrap();
            if t.tuid() == after_tuid {
                if approaching_ticks_target {
                    // We don't need to set any stop_before_states here.
                    // RunCommand::RunSinglestepFastForward always avoids the coalescing quirk, so
                    // if a watchpoint is triggered by the string instruction at
                    // string_instruction_ip, it will have the correct timing.
                    *result = self
                        .current_session()
                        .replay_step(RunCommand::SinglestepFastForward);
                    if !result.break_status.data_watchpoints_hit().is_empty() {
                        let break_status_task = result.break_status.task.upgrade().unwrap();
                        log!(
                            LogDebug,
                            "Fixed x86-string coalescing quirk; now at {} (new cx {})",
                            self.current_mark_key(),
                            break_status_task.regs_ref().cx()
                        );
                        break;
                    }
                } else {
                    let mut constraints = StepConstraints::new(RunCommand::Continue);
                    constraints.ticks_target = after_ticks - 1;
                    *result = self
                        .current_session()
                        .replay_step_with_constraints(&constraints);
                    approaching_ticks_target = result.break_status.approaching_ticks_target;
                }
                ed_assert!(&t, t.tick_count() <= after_ticks, "We went too far!");
            } else {
                self.current_session().replay_step(RunCommand::Continue);
            }
        }
        true
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

    fn is_start_of_reverse_execution_barrier_event(&mut self) -> bool {
        if self.current_session().trace_reader().time() != self.reverse_execution_barrier_event
            || self.current_session().current_step_key().in_execution()
        {
            return false;
        }
        log!(
            LogDebug,
            "Found reverse execution barrier at {}",
            self.mark()
        );
        true
    }

    /// DIFF NOTE: The rr method is void but here we return a Mark (i.e. now)
    fn update_observable_break_status(&mut self, result: &ReplayResult) -> Mark {
        let now = self.mark();
        if self.no_watchpoints_hit_interval_start.is_none()
            || !result.break_status.watchpoints_hit.is_empty()
        {
            self.no_watchpoints_hit_interval_start = Some(now.clone());
        }
        now
    }

    /// DIFF NOTE: Simply called reverse_singlestep() in rr
    fn reverse_singlestep2(
        &mut self,
        origin: &Mark,
        step_tuid: TaskUid,
        step_ticks: Ticks,
        stop_filter: &StopFilterFn,
        interrupt_check: &InterruptCheckFn,
    ) -> ReplayResult {
        log!(
            LogDebug,
            "ReplayTimeline::reverse_singlestep from {}",
            origin
        );

        let mut outer: Mark = origin.clone();
        // DIFF NOTE: @TODO In rr ticks_target is signed so this would become -1
        // IMPORTANT: Need to figure out if there are any edge case issues here
        let ticks_target: Ticks = if step_ticks == 0 { 0 } else { step_ticks - 1 };

        loop {
            let mut end: Mark = outer;
            let mut start: Mark;
            // DIFF NOTE: No initialization in rr
            let mut seen_barrier = false;

            loop {
                let mut current_key: MarkKey = end.ptr.borrow().proto.key;

                loop {
                    if end.ptr.borrow().proto.key.trace_time != current_key.trace_time
                        || end.ptr.borrow().proto.key.ticks != current_key.ticks
                    {
                        break;
                    }
                    self.seek_to_before_key(current_key);
                    self.maybe_add_reverse_exec_checkpoint(
                        CheckpointStrategy::ExpectShortReverseExecution,
                    );
                    if self.current_mark_key() == current_key {
                        // Can't go further back. Treat this as an exit.
                        log!(LogDebug, "Couldn't seek to before {}, returning exit", end);
                        let result: ReplayResult = ReplayResult::new(ReplayStatus::ReplayExited);
                        return result;
                    }
                    log!(
                        LogDebug,
                        "Seeked backward from {} to {}",
                        current_key,
                        self.current_mark_key()
                    );
                    current_key = self.current_mark_key();
                }

                start = self.mark();
                log!(LogDebug, "Running forward from {}", start);
                // Now run forward until we're reasonably close to the correct tick value.
                let mut constraints = StepConstraints::new(RunCommand::Continue);
                let mut approaching_ticks_target: bool = false;
                let mut seen_other_task_break: bool = false;
                while !self.at_mark(&end) {
                    let t = self.current_session().current_task().unwrap();
                    if stop_filter(t.as_replay_task().unwrap())
                        && self.current_session().done_initial_exec()
                    {
                        if t.tuid() == step_tuid {
                            if t.tick_count() >= ticks_target {
                                // Don't step any further.
                                log!(LogDebug, "Approaching ticks target");
                                approaching_ticks_target = true;
                                break;
                            }
                            self.unapply_breakpoints_and_watchpoints();
                            constraints.ticks_target =
                                if constraints.command == RunCommand::Continue {
                                    ticks_target
                                } else {
                                    0
                                };
                            let result: ReplayResult = self
                                .current_session()
                                .replay_step_with_constraints(&constraints);
                            if result.break_status.approaching_ticks_target {
                                log!(
                                    LogDebug,
                                    "   approached ticks target at {}",
                                    self.current_mark_key()
                                );
                                constraints =
                                    StepConstraints::new(RunCommand::SinglestepFastForward);
                            }
                        } else {
                            if seen_other_task_break {
                                self.unapply_breakpoints_and_watchpoints();
                            } else {
                                self.apply_breakpoints_and_watchpoints();
                            }
                            constraints.ticks_target = 0;
                            let result: ReplayResult =
                                self.current_session().replay_step(RunCommand::Continue);
                            if result.break_status.any_break() {
                                seen_other_task_break = true;
                            }
                        }
                    } else {
                        self.unapply_breakpoints_and_watchpoints();
                        constraints.ticks_target = 0;
                        self.current_session().replay_step(RunCommand::Continue);
                    }
                    if self.is_start_of_reverse_execution_barrier_event() {
                        seen_barrier = true;
                    }
                    self.maybe_add_reverse_exec_checkpoint(
                        CheckpointStrategy::ExpectShortReverseExecution,
                    );
                }

                if approaching_ticks_target || seen_barrier {
                    break;
                }
                if seen_other_task_break {
                    // We saw a break in another task that the debugger cares about, but
                    // that's not the stepping task. At this point reverse-singlestep
                    // will move back past that break, so We'll need to report that break
                    // instead of the singlestep.
                    return self.reverse_continue(stop_filter, interrupt_check);
                }
                end = start;
            }
            debug_assert!(
                stop_filter(
                    self.current_session()
                        .current_task()
                        .unwrap()
                        .as_replay_task()
                        .unwrap()
                ) || seen_barrier
            );

            let mut destination_candidate: Option<Mark> = None;
            let mut step_start: Mark = self.set_short_checkpoint();
            // @TODO Check this again
            let mut destination_candidate_result = ReplayResult::default();
            let mut destination_candidate_tuid: Option<TaskUid> = None;
            // True when the singlestep starting at the destination candidate saw
            // another task break.
            let mut destination_candidate_saw_other_task_break: bool = false;

            if self.is_start_of_reverse_execution_barrier_event() {
                destination_candidate = Some(self.mark());
                destination_candidate_result.break_status.task_exit = true;
                destination_candidate_tuid =
                    Some(self.current_session().current_task().unwrap().tuid());
            }

            self.no_watchpoints_hit_interval_start = None;
            let mut seen_other_task_break: bool = false;
            loop {
                let mut now: Mark;
                let mut result: ReplayResult;
                if stop_filter(
                    self.current_session()
                        .current_task()
                        .unwrap()
                        .as_replay_task()
                        .unwrap(),
                ) {
                    self.apply_breakpoints_and_watchpoints();
                    if self.current_session().current_task().unwrap().tuid() == step_tuid {
                        let before_step: Mark = self.mark();
                        let mut constraints =
                            StepConstraints::new(RunCommand::SinglestepFastForward);
                        constraints
                            .stop_before_states
                            .push(end.ptr.borrow().proto.regs.clone());
                        result = self
                            .current_session()
                            .replay_step_with_constraints(&constraints);
                        now = self.update_observable_break_status(&result);
                        if result.break_status.hardware_or_software_breakpoint_hit() {
                            // If we hit a breakpoint while singlestepping, we didn't
                            // make any progress.
                            self.unapply_breakpoints_and_watchpoints();
                            result = self
                                .current_session()
                                .replay_step_with_constraints(&constraints);
                            now = self.update_observable_break_status(&result);
                        }
                        if result.break_status.singlestep_complete {
                            self.mark_after_singlestep(&before_step, &mut result);
                            if now > end {
                                // This last step is not usable.
                                log!(LogDebug, "   not usable, stopping now");
                                break;
                            }
                            destination_candidate = Some(step_start);
                            log!(
                                LogDebug,
                                "Setting candidate after step: {}",
                                destination_candidate.as_ref().unwrap()
                            );
                            destination_candidate_result = result.clone();
                            destination_candidate_tuid =
                                Some(result.break_status.task.upgrade().unwrap().tuid());
                            destination_candidate_saw_other_task_break = seen_other_task_break;
                            seen_other_task_break = false;
                            step_start = now.clone();
                        }
                    } else {
                        result = self.current_session().replay_step(RunCommand::Continue);
                        now = self.update_observable_break_status(&result);
                        if result.break_status.any_break() {
                            seen_other_task_break = true;
                        }
                        if result.break_status.hardware_or_software_breakpoint_hit() {
                            self.unapply_breakpoints_and_watchpoints();
                            result = self
                                .current_session()
                                .replay_step(RunCommand::SinglestepFastForward);
                            now = self.update_observable_break_status(&result);
                            if result.break_status.any_break() {
                                seen_other_task_break = true;
                            }
                        }
                    }
                } else {
                    self.unapply_breakpoints_and_watchpoints();
                    result = self.current_session().replay_step(RunCommand::Continue);
                    self.no_watchpoints_hit_interval_start = None;
                    now = self.mark();
                }

                if self.is_start_of_reverse_execution_barrier_event() {
                    destination_candidate = Some(self.mark());
                    log!(
                        LogDebug,
                        "Setting candidate to barrier {}",
                        destination_candidate.as_ref().unwrap()
                    );
                    destination_candidate_result = result;
                    destination_candidate_result.break_status.task_exit = true;
                    destination_candidate_tuid =
                        Some(self.current_session().current_task().unwrap().tuid());
                    destination_candidate_saw_other_task_break = false;
                    seen_other_task_break = false;
                }

                if now >= end {
                    log!(LogDebug, "Stepped to {} (>= {}) stopping", now, end);
                    break;
                }
                self.maybe_add_reverse_exec_checkpoint(
                    CheckpointStrategy::ExpectShortReverseExecution,
                );
            }
            self.no_watchpoints_hit_interval_end =
                if self.no_watchpoints_hit_interval_start.is_some() {
                    Some(end)
                } else {
                    None
                };

            if seen_other_task_break || destination_candidate_saw_other_task_break {
                // We saw a break in another task that the debugger cares about, but
                // that's not the stepping task. Report that break instead of the
                // singlestep.
                return self.reverse_continue(stop_filter, interrupt_check);
            }

            if destination_candidate.is_some() {
                log!(
                    LogDebug,
                    "Found destination {}",
                    destination_candidate.as_ref().unwrap()
                );
                self.seek_to_mark(destination_candidate.as_ref().unwrap());
                destination_candidate_result.break_status.task = self
                    .current_session()
                    .find_task_from_task_uid(destination_candidate_tuid.unwrap())
                    .map_or(Weak::new(), |rc_t| Rc::downgrade(&rc_t));
                debug_assert!(!destination_candidate_result
                    .break_status
                    .task
                    .ptr_eq(&Weak::new()));
                self.evaluate_conditions(&mut destination_candidate_result);
                return destination_candidate_result;
            }

            // No destination candidate found. Search further backward.
            outer = start;
        }
    }

    /// Reasonably fast since it just relies on checking the mark map.
    fn less_than(m1: &Mark, m2: &Mark) -> bool {
        *m1 < *m2
    }

    fn estimate_progress(&self) -> Progress {
        let stats = self.current_session().statistics();
        // The following parameters were estimated by running Firefox startup
        // and shutdown in an opt build on a Lenovo W530 laptop, replaying with
        // DUMP_STATS_PERIOD set to 100 (twice, and using only values from the
        // second run, to ensure caches are warm), and then minimizing least-squares
        // error.
        const MICROSECONDS_PER_TICK: f64 = 0.0020503143;
        const MICROSECONDS_PER_SYSCALL: f64 = 39.6793587609;
        const MICROSECONDS_PER_BYTE_WRITTEN: f64 = 0.001833611;
        const MICROSECONDS_CONSTANT: f64 = 997.8257239043;
        let progress = MICROSECONDS_PER_TICK * stats.ticks_processed as f64
            + MICROSECONDS_PER_SYSCALL * stats.syscalls_performed as f64
            + MICROSECONDS_PER_BYTE_WRITTEN * stats.bytes_written as f64
            + MICROSECONDS_CONSTANT;

        progress as i64
    }

    /// Called when the current session has moved forward to a new execution
    /// point and we might want to make a checkpoint to support reverse-execution.
    /// If this adds a checkpoint, it will call
    /// discard_past_reverse_exec_checkpoints
    /// first.
    fn maybe_add_reverse_exec_checkpoint(&mut self, strategy: CheckpointStrategy) {
        self.discard_future_reverse_exec_checkpoints();

        let now: Progress = self.estimate_progress();
        let it = self
            .reverse_exec_checkpoints
            .iter()
            .next_back()
            .map(|(_, v)| *v);
        if let Some(v) = it {
            if v >= now - Self::inter_checkpoint_interval(strategy) {
                // Latest checkpoint is close enough; we don't need to do anything.
                return;
            }
        }

        if !self.current_session().can_clone() {
            // We can't create a checkpoint right now.
            return;
        }

        // We always discard checkpoints before adding the new one to reduce the
        // maximum checkpoint count by one.
        self.discard_past_reverse_exec_checkpoints(strategy);

        let m: Mark = self.add_explicit_checkpoint();
        log!(LogDebug, "Creating reverse-exec checkpoint at {}", m);
        self.reverse_exec_checkpoints.insert(m, now);
    }

    fn inter_checkpoint_interval(strategy: CheckpointStrategy) -> Progress {
        if strategy == CheckpointStrategy::LowOverhead {
            Self::LOW_OVERHEAD_INTER_CHECKPOINT_INTERVAL
        } else {
            Self::EXPECTING_REVERSE_EXEC_INTER_CHECKPOINT_INTERVAL
        }
    }

    const CHECKPOINT_INTERVAL_EXPONENT: Progress = 2;

    fn next_interval_length(len: Progress) -> Progress {
        if len >= Self::LOW_OVERHEAD_INTER_CHECKPOINT_INTERVAL {
            return Self::CHECKPOINT_INTERVAL_EXPONENT * len;
        }
        len + Self::EXPECTING_REVERSE_EXEC_INTER_CHECKPOINT_INTERVAL
    }

    /// Discard some reverse-exec checkpoints in the past, if necessary. We do
    /// this to stop the number of checkpoints growing out of control.
    fn discard_past_reverse_exec_checkpoints(&mut self, strategy: CheckpointStrategy) {
        let now: Progress = self.estimate_progress();
        // No checkpoints are allowed in the first interval, since we're about to
        // add one there.
        let mut checkpoints_to_delete: Vec<Mark> = Vec::new();
        {
            let mut checkpoints_allowed: usize = 0;
            let mut checkpoints_in_range: usize = 0;
            let mut it = self.reverse_exec_checkpoints.iter().peekable();
            let mut len = Self::inter_checkpoint_interval(strategy);
            // @TODO: This needs to be checked again
            loop {
                let start: Progress = now - len;
                // Count checkpoints >= start, starting at 'it', and leave the first
                // checkpoint entry < start in 'tmp_it'.
                let mut tmp_it = it.clone();
                let mut curr_tmp = tmp_it.next_back();
                while curr_tmp.is_some() && *curr_tmp.unwrap().1 >= start {
                    checkpoints_in_range += 1;
                    curr_tmp = tmp_it.next_back();
                }
                // Delete excess checkpoints starting with 'it'.
                let mut curr = it.next_back();
                while checkpoints_in_range > checkpoints_allowed {
                    checkpoints_to_delete.push(curr.unwrap().0.clone());
                    checkpoints_in_range -= 1;
                    curr = it.next_back();
                }
                checkpoints_allowed += 1;
                it = tmp_it;
                // Even though peek() looks ahead, if the iteration is over this
                // should return None
                if it.peek().is_none() {
                    break;
                }
                len = Self::next_interval_length(len);
            }
        }

        for m in &checkpoints_to_delete {
            log!(LogDebug, "Discarding reverse-exec checkpoint at {}", m);
            self.remove_explicit_checkpoint(m);
            self.reverse_exec_checkpoints.remove(m);
        }
    }

    /// Discard all reverse-exec checkpoints that are in the future (they're
    /// useless).
    fn discard_future_reverse_exec_checkpoints(&mut self) {
        let now: Progress = self.estimate_progress();
        loop {
            let res = self
                .reverse_exec_checkpoints
                .iter()
                .map(|(a, &b)| (a.clone(), b))
                .next_back();

            match res {
                Some((k, v)) => {
                    if v <= now {
                        break;
                    }
                    log!(
                        LogDebug,
                        "Discarding reverse-exec future checkpoint at {}",
                        k.ptr.borrow()
                    );
                    self.remove_explicit_checkpoint(&k);
                    self.reverse_exec_checkpoints.remove(&k);
                }
                None => {
                    break;
                }
            }
        }
    }

    fn set_short_checkpoint(&mut self) -> Mark {
        if !self.can_add_checkpoint() {
            return self.mark();
        }

        // Add checkpoint before removing one in case m ==
        // reverse_exec_short_checkpoint
        let m: Mark = self.add_explicit_checkpoint();
        log!(LogDebug, "Creating short-checkpoint at {}", m);
        if self.reverse_exec_short_checkpoint.is_some() {
            let chkp = self.reverse_exec_short_checkpoint.take().unwrap();
            log!(LogDebug, "Discarding old short-checkpoint at {}", chkp);
            self.remove_explicit_checkpoint(&chkp);
        }
        m
    }

    /// If result.break_status hit watchpoints or breakpoints, evaluate their
    /// conditions and clear the break_status flags if the conditions don't hold.
    fn evaluate_conditions(&self, result: &mut ReplayResult) {
        let maybe_t = result.break_status.task.upgrade();
        if maybe_t.is_none() {
            return;
        }
        let t = maybe_t.unwrap();
        let auid = t.vm().uid();

        if result.break_status.breakpoint_hit {
            let addr = t.ip();
            let key = TimelineBreakpoint { uid: auid, addr };
            let it = self.breakpoints.get(&key);
            let mut hit = false;
            // DIFF NOTE: @TODO Check this. This is while loop in rr we shouldn't need a while loop here
            if let Some(conditions) = it {
                if conditions.is_none() || conditions.as_ref().unwrap().evaluate(&**t) {
                    hit = true;
                }
            }
            if !hit {
                result.break_status.breakpoint_hit = false;
            }
        }

        let mut to_remove = Vec::new();
        for (i, w) in result.break_status.watchpoints_hit.iter().enumerate() {
            let key = TimelineWatchpoint {
                uid: auid,
                addr: w.addr,
                size: w.num_bytes,
                watch_type: w.type_,
            };
            let it = self.watchpoints.get(&key);
            let mut hit = false;
            // DIFF NOTE: @TODO Check this. This is while loop in rr we shouldn't need a while loop here
            if let Some(conditions) = it {
                if conditions.is_none() || conditions.as_ref().unwrap().evaluate(&**t) {
                    hit = true;
                }
            }
            if !hit {
                to_remove.push(i);
            }
        }

        for &i in &to_remove {
            result.break_status.watchpoints_hit.remove(i);
        }
    }
}

/// DIFF NOTE: One important difference between rd and rr's Mark is that
/// rd's Mark always indicates a position in the replay unlike
/// in rr where `ptr` can be null
#[derive(Clone)]
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
        debug_assert!(self.ptr.borrow().owner.ptr_eq(&m2.ptr.borrow().owner));
        if Rc::ptr_eq(&self.ptr, &m2.ptr) {
            Ordering::Equal
        } else {
            let self_key = self.ptr.borrow().proto.key;
            let m2_key = m2.ptr.borrow().proto.key;
            if self_key < m2_key {
                return Ordering::Less;
            }
            if m2_key < self_key {
                return Ordering::Greater;
            }
            // We now know that self & m2 have the same ptr.proto.key and same owner
            let owner = self.ptr.borrow().owner.upgrade().unwrap();
            // Need to do this unsafely as owner may already be borrowed mutably
            // @TODO: Do this more cleanly??
            let marks = unsafe { &(*(owner.as_ptr())).marks };
            for m in marks.get(&self_key).unwrap_or(&vec![]) {
                if Rc::ptr_eq(m, &m2.ptr) {
                    return Ordering::Greater;
                }
                if Rc::ptr_eq(m, &self.ptr) {
                    return Ordering::Less;
                }
            }

            panic!("Marks missing from vector, invariants broken!");
        }
    }
}

impl PartialOrd for Mark {
    fn partial_cmp(&self, m2: &Self) -> Option<Ordering> {
        Some(Self::cmp(self, m2))
    }
}

impl PartialEq for Mark {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.ptr, &other.ptr)
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
                proto = ProtoMark::new(key, &**t);
                extra_regs = t.extra_regs_ref().clone();
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
        writeln!(out, "]}}").unwrap();
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
    pub fn new(key: MarkKey, t: &dyn Task) -> ProtoMark {
        let regs = t.regs_ref().clone();
        ProtoMark {
            key,
            regs,
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
        let equal_regs = equal_regs(&self.regs, &t.regs_ref());
        equal_regs && self.return_addresses == ReturnAddressList::new(&**t)
    }
}

/// Different strategies for placing automatic checkpoints.
#[derive(Copy, Clone, Eq, PartialEq)]
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
pub type Progress = i64;

fn equal_regs(r1: &Registers, r2: &Registers) -> bool {
    // Compare ip()s first since they will usually fail to match, especially
    // when we're comparing InternalMarks with the same MarkKey
    r1.ip() == r2.ip() && r1.matches(r2)
}
