//! Overview of rd scheduling:
//!
//! rd honours priorities set by setpriority(2) --- even in situations where the
//! kernel doesn't, e.g. when a non-privileged task tries to increase its
//! priority. Normally rd honors priorities strictly by scheduling the highest
//! priority runnable task; tasks with equal priorities are scheduled in
//! round-robin fashion. Strict priority scheduling helps find bugs due to
//! starvation.
//!
//! When a task calls sched_yield we temporarily switch to a completely
//! fair scheduler that ignores priorities. All tasks are placed on a queue
//! and while the queue is non-empty we take the next task from the queue and
//! run it for a quantum if it's runnable. We do this because tasks calling
//! sched_yield are often expecting some kind of fair scheduling and may deadlock
//! (e.g. trying to acquire a spinlock) if some other tasks don't get a chance
//! to run.
//!
//! The scheduler only runs during recording. During replay we're just replaying
//! the recorded scheduling decisions.
//!
//! The main interface to the scheduler is `get_next_thread`. This gets called
//! after every rd event to decide which task to run next.
//!
//! The scheduler gives the current task a 'timeslice', a ticks deadline after
//! which we will try to switch to another task. So `get_next_thread` first
//! checks whether the currently running task has exceeded that deadline. If
//! not, and the current task is runnable, we schedule it again. If it's blocked
//! or has exceeded its deadline, we search for another task to run:
//! taking tasks from the round-robin queue until we find one that's runnable,
//! and then if the round-robin queue is empty, choosing the highest-priority
//! task that's runnable. If the highest-priority runnable task has the same
//! priority as the current task, choose the next runnable task after the
//! current task (so equal priority tasks run in round-robin order).
//!
//! The main parameter to the scheduler is `max_ticks`, which controls the
//! length of each timeslice.
use crate::{
    bindings::{
        kernel::{itimerval, setitimer, ITIMER_REAL},
        ptrace::{PTRACE_EVENT_EXEC, PTRACE_EVENT_EXIT},
    },
    event::{EventType, Switchable, SyscallState},
    kernel_abi::{is_exit_group_syscall, is_exit_syscall, is_sched_yield_syscall, SupportedArch},
    log::{LogDebug, LogWarn},
    priority_tup::PriorityTup,
    session::{
        record_session::RecordSession,
        task::{
            record_task::{EmulatedStopType, RecordTask},
            task_inner::{ResumeRequest, TicksRequest, WaitRequest},
            Task,
            TaskSharedPtr,
            TaskSharedWeakPtr,
        },
        SessionSharedPtr,
        SessionSharedWeakPtr,
    },
    sig,
    ticks::Ticks,
    util::monotonic_now_sec,
    wait_status::WaitStatus,
};
use libc::{nanosleep, pid_t, sysconf, timespec, EINTR, WUNTRACED, _SC_NPROCESSORS_CONF, __WALL};
use nix::{
    errno::errno,
    sched::{sched_getaffinity, CpuSet},
    unistd::Pid,
};
use owning_ref::OwningHandle;
use rand::{random, seq::SliceRandom, thread_rng};
use std::{
    cell::{Cell, RefCell},
    cmp::min,
    collections::{BTreeSet, VecDeque},
    mem,
    ptr,
    rc::{Rc, Weak},
};

/// Probability of making a thread low priority. Keep this reasonably low
/// because the goal is to victimize some specific threads
const LOW_PRIORITY_PROBABILITY: f64 = 0.1;
/// Give main threads a higher probability of being low priority because
/// many tests are basically main-thread-only
const MAIN_THREAD_LOW_PRIORITY_PROBABILITY: f64 = 0.3;
const VERY_SHORT_TIMESLICE_PROBABILITY: f64 = 0.1;
const VERY_SHORT_TIMESLICE_MAX_DURATION: Ticks = 100;
const SHORT_TIMESLICE_PROBABILITY: f64 = 0.1;
const SHORT_TIMESLICE_MAX_DURATION: Ticks = 10000;
/// Time between priority refreshes is uniformly distributed from 0 to 20s
const PRIORITIES_REFRESH_MAX_INTERVAL: Ticks = 20;

/// High-Priority-Only Intervals
///
/// We assume that for a test failure we want to reproduce, we will reproduce a
/// failure if we completely avoid scheduling a certain thread for a period of
/// D seconds, where the start of that period must fall between S and S+T
/// seconds since the start of the test. All these constants are unknown to
/// rr, but we assume 1ms <= D <= 2s.
///
/// Since we only need to reproduce any particular bug once, it would be best
/// to have roughly similar probabilities for reproducing each bug given its
/// unknown parameters. It's unclear what is the optimal approach here, but
/// here's ours:
///
/// First we have to pick the right thread to treat as low priority --- without
/// making many other threads low priority, since they might need to run while
/// our victim thread is being starved. So we give each thread a 0.1 probability
/// of being low priority, except for the main thread which we make 0.3, since
/// starving the main thread is often very interesting.
/// Then we guess a value D' for D. We uniformly choose between 1ms, 2ms, 4ms,
/// 8ms, ..., 1s, 2s. Out of these 12 possibilities, one is between D and 2xD.
/// We adopt the goal of high-priority-only intervals consume at most 20% of
/// running time. Then to maximise the probability of triggering the test
/// failure, we start high-priority-only intervals as often as possible,
/// i.e. one for D' seconds starting every 5xD' seconds.
/// The start time of the first interval is chosen uniformly randomly to be
/// between 0 and 4xD'.
/// Then, if we guessed D' and the low-priority thread correctly, the
/// probability of triggering the test failure is 1 if T >= 4xD', T/4xD'
/// otherwise, i.e. >= T/8xD. (Higher values of D' than optimal can also trigger
/// failures, but at reduced probabilities since we can schedule them less
/// often.)
const MIN_HIGH_PRIORITY_ONLY_DURATION: f64 = 0.001;
const HIGH_PRIORITY_ONLY_DURATION_STEPS: i32 = 12;
const HIGH_PRIORITY_ONLY_DURATION_STEP_FACTOR: f64 = 2.0;
/// Allow this much of overall runtime to be in the "high priority only" interval
const HIGH_PRIORITY_ONLY_FRACTION: f64 = 0.2;

/// Tasks sorted by priority.
type TaskPrioritySet = BTreeSet<PriorityTup>;
type TaskQueue = VecDeque<TaskSharedWeakPtr>;

/// DIFF NOTE: In rr we deal with *RecordTasks. Here we are dealing with the
/// "superclass" Task (see the various TaskSharedWeakPtr-s). This will mean
/// that we need to do as_record_task() in various locations. An extra step...
pub struct Scheduler {
    session: RefCell<SessionSharedWeakPtr>,
    /// Every task of this session is either in task_priority_set
    /// (when in_round_robin_queue is false), or in task_round_robin_queue
    /// (when in_round_robin_queue is true).
    ///
    /// task_priority_set is a set of pairs of (task->priority, task). This
    /// lets us efficiently iterate over the tasks with a given priority, or
    /// all tasks in priority order.
    task_priority_set: RefCell<TaskPrioritySet>,
    task_round_robin_queue: RefCell<TaskQueue>,

    /// The currently scheduled task. This may be `None` if the last scheduled
    /// task has been destroyed.
    current_: RefCell<Option<TaskSharedWeakPtr>>,
    current_timeslice_end_: Cell<Ticks>,

    /// At this time (or later) we should refresh these values.
    high_priority_only_intervals_refresh_time: Cell<f64>,
    high_priority_only_intervals_start: Cell<f64>,
    high_priority_only_intervals_duration: Cell<f64>,
    high_priority_only_intervals_period: Cell<f64>,
    /// At this time (or later) we should rerandomize RecordTask priorities.
    priorities_refresh_time: Cell<f64>,

    max_ticks_: Cell<Ticks>,

    must_run_task: RefCell<Option<TaskSharedWeakPtr>>,

    pretend_affinity_mask_: Cell<CpuSet>,

    /// @TODO Is this what we want?
    pretend_num_cores_: Cell<u32>,

    /// When true, context switch at every possible point.
    always_switch: Cell<bool>,
    /// When true, make random scheduling decisions to try to increase the
    /// probability of finding buggy schedules.
    enable_chaos: Cell<bool>,

    enable_poll: Cell<bool>,
    last_reschedule_in_high_priority_only_interval: Cell<bool>,
}

#[repr(u64)]
pub enum TicksHowMany {
    /// Like most task schedulers, there are conflicting goals to balance. Lower
    /// max-ticks generally makes the application more "interactive", generally
    /// speaking lower latency. (And wrt catching bugs, this setting generally
    /// creates more opportunity for bugs to arise in multi-threaded/process
    /// applications.) This comes at the cost of more overhead from scheduling and
    /// context switching. Context switches during recording are expensive because
    /// we must context switch to the rd process and then to the next tracee task.
    /// Increasing max-ticks generally gives the application higher throughput.
    ///
    /// Using ticks (retired conditional branches) to compute timeslices is quite
    /// crude, since they don't correspond to any unit of time in general.
    /// Hopefully that can be improved, but empirical data from Firefox
    /// demonstrate, surprisingly consistently, a distribution of insns/rcb massed
    /// around 10. Somewhat arbitrarily guessing ~4cycles/insn on average
    /// (fair amount of pointer chasing), that implies for a nominal 2GHz CPU
    /// 50,000 ticks per millisecond. We choose the default max ticks to give us
    /// 10ms timeslices, i.e. 500,000 ticks.
    DefaultMaxTicks = 500_000,

    /// Don't allow max_ticks to get above this value.
    MaxMaxTicks = 1000_000_000,
}

/// Schedule a new runnable task (which may be the same as current()).
///
/// The new current() task is guaranteed to either have already been
/// runnable, or have been made runnable by a waitpid status change (in
/// which case, result.by_waitpid will be true.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct Rescheduled {
    pub interrupted_by_signal: bool,
    pub by_waitpid: bool,
    pub started_new_timeslice: bool,
}

impl Scheduler {
    /// DIFF This constructor does NOT call regenerate_affinity_mask() like in rr.
    pub fn new(max_ticks: Ticks, always_switch: bool) -> Scheduler {
        Scheduler {
            session: RefCell::new(Weak::new()),
            task_priority_set: Default::default(),
            task_round_robin_queue: Default::default(),
            current_: Default::default(),
            current_timeslice_end_: Default::default(),
            high_priority_only_intervals_refresh_time: Default::default(),
            high_priority_only_intervals_start: Default::default(),
            high_priority_only_intervals_duration: Default::default(),
            high_priority_only_intervals_period: Default::default(),
            priorities_refresh_time: Default::default(),
            max_ticks_: Cell::new(max_ticks),
            must_run_task: Default::default(),
            pretend_affinity_mask_: Cell::new(CpuSet::new()),
            pretend_num_cores_: Cell::new(1),
            always_switch: Cell::new(always_switch),
            enable_chaos: Default::default(),
            enable_poll: Default::default(),
            last_reschedule_in_high_priority_only_interval: Default::default(),
        }
    }

    pub fn set_session_weak_ptr(&self, weak_ptr: SessionSharedWeakPtr) {
        *self.session.borrow_mut() = weak_ptr;
    }

    fn session(&self) -> SessionSharedPtr {
        self.session.borrow().upgrade().unwrap()
    }

    pub fn record_session(&self) -> OwningHandle<SessionSharedPtr, &RecordSession> {
        let sess = self.session();
        let owning_handle =
            OwningHandle::new_with_fn(sess, |o| unsafe { (*o).as_record() }.unwrap());

        owning_handle
    }

    pub fn set_max_ticks(&self, max_ticks: Ticks) {
        debug_assert!(max_ticks <= TicksHowMany::MaxMaxTicks as u64);
        self.max_ticks_.set(max_ticks);
    }

    pub fn max_ticks(&self) -> Ticks {
        self.max_ticks_.get()
    }

    pub fn set_always_switch(&self, always_switch: bool) {
        self.always_switch.set(always_switch);
    }

    pub fn set_enable_chaos(&self, enable_chaos: bool) {
        self.enable_chaos.set(enable_chaos);
    }

    pub fn set_num_cores(&self, num_cores: u32) {
        self.pretend_num_cores_.set(num_cores);
    }

    /// Schedule a new runnable task (which may be the same as current()).
    ///
    /// The new current() task is guaranteed to either have already been
    /// runnable, or have been made runnable by a waitpid status change (in
    /// which case, result.by_waitpid will be true.
    pub fn reschedule(&self, switchable: Switchable) -> Rescheduled {
        let mut result = Rescheduled::default();
        result.interrupted_by_signal = false;
        result.by_waitpid = false;
        result.started_new_timeslice = false;

        log!(LogDebug, "Scheduling next task");

        *self.must_run_task.borrow_mut() = None;
        self.enable_poll.set(false);

        let mut now = monotonic_now_sec();

        self.maybe_reset_priorities(now);

        match self.current() {
            Some(curr) if switchable == Switchable::PreventSwitch => {
                log!(
                    LogDebug,
                    "  ({} is un-switchable at {})",
                    curr.borrow().tid,
                    curr.borrow().as_record_task().unwrap().ev()
                );

                if curr.borrow().is_running() {
                    log!(LogDebug, "  and running; waiting for state change");
                    // |current| is un-switchable, but already running. Wait for it to change
                    // state before "scheduling it", so avoid busy-waiting with our client. */
                    curr.borrow_mut()
                        .wait(Some(self.interrupt_after_elapsed_time()));
                    // @TODO Monitor unswitchable waits stuff
                    result.by_waitpid = true;
                    log!(LogDebug, "  new status is {}", curr.borrow().status());
                }

                self.validate_scheduled_task();
                return result;
            }
            _ => (),
        }

        let mut maybe_next: Option<TaskSharedPtr>;
        loop {
            self.maybe_reset_high_priority_only_intervals(now);
            self.last_reschedule_in_high_priority_only_interval
                .set(self.in_high_priority_only_interval(now));

            match self.current() {
                Some(curr) => {
                    // Determine if we should run current_ again
                    let round_robin_task = self.get_round_robin_task();
                    if round_robin_task.is_none() {
                        maybe_next = self.find_next_runnable_task(
                            Some(&curr),
                            &mut result.by_waitpid,
                            curr.borrow().as_record_task().unwrap().priority - 1,
                        );

                        if maybe_next.is_some() {
                            // There is a runnable higher-priority task (different from current btw). Run it.
                            break;
                        }
                    }
                    // To run current_ again:
                    // -- its timeslice must not have expired
                    // -- it must be high priority if we're in a high-priority-only interval
                    // -- it must be the head of the round-robin queue or the queue is empty
                    // (this might not hold if it was at the head of the queue but we
                    // rejected current_ and popped it in a previous iteration of this loop)
                    // -- it must be runnable, and not in an unstable exit.
                    let tick_count = curr.borrow().tick_count();
                    let is_unstable = curr.borrow().unstable.get();
                    if !is_unstable
                        && !self.always_switch.get()
                        && (round_robin_task.is_none()
                            || Rc::ptr_eq(round_robin_task.as_ref().unwrap(), &curr))
                        && (self.treat_as_high_priority(&curr)
                            || !self.last_reschedule_in_high_priority_only_interval.get())
                        && tick_count < self.current_timeslice_end()
                        && self.is_task_runnable(
                            curr.borrow_mut().as_record_task_mut().unwrap(),
                            &mut result.by_waitpid,
                        )
                    {
                        log!(LogDebug, "  Carrying on with task {}", curr.borrow().tid);
                        self.validate_scheduled_task();
                        return result;
                    }
                    // Having rejected current_, be prepared to run the next task in the
                    // round-robin queue.
                    self.maybe_pop_round_robin_task(curr.borrow_mut().as_rec_mut_unwrap());
                }
                None => (),
            }

            log!(LogDebug, "  need to reschedule");

            maybe_next = self.get_round_robin_task();
            match maybe_next.as_ref() {
                Some(nt) => {
                    log!(LogDebug, "Trying task {} from yield queue", nt.borrow().tid);
                    if self.is_task_runnable(
                        nt.borrow_mut().as_record_task_mut().unwrap(),
                        &mut result.by_waitpid,
                    ) {
                        break;
                    }
                    self.maybe_pop_round_robin_task(nt.borrow_mut().as_rec_mut_unwrap());

                    continue;
                }
                None => {
                    let maybe_t = self.current();
                    maybe_next = self.find_next_runnable_task(
                        maybe_t.as_ref(),
                        &mut result.by_waitpid,
                        i32::MAX,
                    );
                }
            }

            // When there's only one thread, treat it as low priority for the
            // purposes of high-priority-only-intervals. Otherwise single-threaded
            // workloads mostly don't get any chaos mode effects.
            match maybe_next.as_ref() {
                Some(nt)
                    if !self.treat_as_high_priority(nt)
                        && self.last_reschedule_in_high_priority_only_interval.get() =>
                {
                    if result.by_waitpid {
                        log!(
                            LogDebug,
                            "Waking up low-priority task with by_waitpid; not sleeping"
                        );

                    // We must run this low-priority task. Fortunately it's just waking
                    // up from a blocking syscall; we'll record the syscall event and then
                    // (unless it was an interrupted syscall) we'll return to
                    // get_next_thread, which will either run a higher priority thread
                    // or (more likely) reach here again but in the !*by_waitpid case.
                    } else {
                        log!(
                            LogDebug,
                            "Waking up low-priority task without by_waitpid; sleeping"
                        );
                        sleep_time(0.001);
                        now = monotonic_now_sec();

                        continue;
                    }
                }
                _ => (),
            }

            break;
        }

        match maybe_next.as_ref() {
            Some(nt) if !nt.borrow().unstable.get() => {
                log!(LogDebug, "  selecting task {}", nt.borrow().tid)
            }
            _ => {
                // All the tasks are blocked (or we found an unstable-exit task).
                // Wait for the next one to change state.

                // Clear the round-robin queue since we will no longer be able to service
                // those tasks in-order.
                while let Some(t) = self.get_round_robin_task() {
                    self.maybe_pop_round_robin_task(t.borrow_mut().as_rec_mut_unwrap());
                }

                log!(
                    LogDebug,
                    "  all tasks blocked or some unstable, waiting for runnable ({} total)",
                    self.task_priority_set.borrow().len()
                );

                let mut status: WaitStatus;
                loop {
                    let mut raw_status: i32 = 0;
                    if self.enable_poll.get() {
                        let mut timer: itimerval = Default::default();
                        timer.it_value.tv_sec = 1;
                        if unsafe { setitimer(ITIMER_REAL, &timer, ptr::null_mut()) } < 0 {
                            fatal!("Failed to set itimer");
                        }

                        log!(LogDebug, "  Arming one-second timer for polling");
                    }

                    let tid: pid_t =
                        unsafe { libc::waitpid(-1, &mut raw_status, __WALL | WUNTRACED) };

                    if self.enable_poll.get() {
                        let timer: itimerval = Default::default();
                        if unsafe { setitimer(ITIMER_REAL, &timer, ptr::null_mut()) } < 0 {
                            fatal!("Failed to set itimer");
                        }

                        log!(LogDebug, "  Disarming one-second timer for polling");
                    }

                    status = WaitStatus::new(raw_status);
                    now = -1.0; // invalid, don't use

                    if -1 == tid {
                        if EINTR == errno() {
                            log!(LogDebug, "  waitpid(-1) interrupted");
                            let curr = self.current().unwrap();
                            // @TODO If we were interruped then self.current_ must be Some()
                            // Is that a fair assumption??
                            ed_assert!(&curr.borrow(), self.must_run_task.borrow().is_none());

                            result.interrupted_by_signal = true;

                            return result;
                        }

                        fatal!("Failed to waitpid()");
                    }

                    log!(LogDebug, "{} changed status to {}", tid, status);

                    maybe_next = self.session().find_task_from_rec_tid(tid);

                    if status.maybe_ptrace_event() == PTRACE_EVENT_EXEC {
                        match maybe_next.as_ref() {
                            // Other threads may have unexpectedly died, in which case this
                            // will be marked as unstable even though it's actually not. There's
                            // no way to know until we see the EXEC event that we weren't really
                            // in an unstable exit.
                            Some(nt) => nt.borrow_mut().unstable.set(false),
                            None => {
                                // The thread-group-leader died and now the exec'ing thread has
                                // changed its thread ID to be thread-group leader.
                                maybe_next = Some(self.record_session().revive_task_for_exec(tid));
                            }
                        }
                    }

                    match maybe_next.as_ref() {
                        None => log!(LogDebug, "    ... but it's dead"),
                        Some(_) => break,
                    }
                }

                let nt = maybe_next.as_ref().unwrap();
                ed_assert!(
                    &nt.borrow(),
                    nt.borrow().unstable.get()
                        // Note the call to did_waitpid() below
                        || nt.borrow().as_record_task().unwrap().may_be_blocked()
                        || status.maybe_ptrace_event() == PTRACE_EVENT_EXIT,
                    "Scheduled task should have been blocked or unstable"
                );

                nt.borrow_mut().did_waitpid(status);
                result.by_waitpid = true;
                *self.must_run_task.borrow_mut() = Some(Rc::downgrade(nt));
            }
        }

        let nt = maybe_next.unwrap();
        match self.current() {
            Some(curr) if !Rc::ptr_eq(&curr, &nt) => log!(
                LogDebug,
                "Switching from {} ({:?}) to {} ({:?}) (priority {} to {}) at {}",
                curr.borrow().tid,
                curr.borrow().name(),
                nt.borrow().tid,
                nt.borrow().name(),
                curr.borrow().as_record_task().unwrap().priority,
                nt.borrow().as_record_task().unwrap().priority,
                curr.borrow()
                    .as_record_task()
                    .unwrap()
                    .trace_writer()
                    .time()
            ),
            _ => (),
        }

        self.maybe_reset_high_priority_only_intervals(now);
        *self.current_.borrow_mut() = Some(Rc::downgrade(&nt));
        self.validate_scheduled_task();
        self.setup_new_timeslice();
        result.started_new_timeslice = true;

        result
    }

    /// Set the priority of `t` to `value` and update related state.
    pub fn update_task_priority(&self, t: &mut RecordTask, value: i32) {
        if !self.enable_chaos.get() {
            self.update_task_priority_internal(t, value);
        }
    }

    /// Do one round of round-robin scheduling if we're not already doing one.
    /// If we start round-robin scheduling now, make last_task the last
    /// task to be scheduled.
    /// If the task_round_robin_queue is empty this moves all tasks into it,
    /// putting last_task last.
    pub fn schedule_one_round_robin(&self, t: &mut RecordTask) {
        log!(LogDebug, "Scheduling round-robin because of task {}", t.tid);

        let rc_t = t.weak_self_ptr().upgrade().unwrap();
        ed_assert!(t, Rc::ptr_eq(&self.current().unwrap(), &rc_t));
        self.maybe_pop_round_robin_task(t);
        ed_assert!(t, !t.in_round_robin_queue);
        for PriorityTup(_, _, w) in self.task_priority_set.borrow().iter() {
            let tt = w.upgrade().unwrap();
            if !Rc::ptr_eq(&rc_t, &tt)
                && !tt.borrow().as_record_task().unwrap().in_round_robin_queue
            {
                self.task_round_robin_queue
                    .borrow_mut()
                    .push_back(w.clone());
                tt.borrow_mut()
                    .as_record_task_mut()
                    .unwrap()
                    .in_round_robin_queue = true;
            }
        }

        self.task_priority_set.borrow_mut().clear();
        self.task_round_robin_queue
            .borrow_mut()
            .push_back(t.weak_self_ptr());
        t.in_round_robin_queue = true;
        self.expire_timeslice();
    }

    pub fn on_create_task(&self, t: TaskSharedPtr) {
        debug_assert!(!t.borrow().as_record_task().unwrap().in_round_robin_queue);
        if self.enable_chaos.get() {
            // new tasks get a random priority
            t.borrow_mut().as_record_task_mut().unwrap().priority = self.choose_random_priority(&t);
        }

        self.task_priority_set.borrow_mut().insert(PriorityTup(
            t.borrow().as_record_task().unwrap().priority,
            t.borrow().tuid().serial(),
            Rc::downgrade(&t),
        ));
    }

    ///  De-register a thread. This function should be called when a thread exits.
    pub fn on_destroy_task(&self, t: &mut RecordTask) {
        let weak = t.weak_self_ptr();
        let maybe_curr = self.current_.borrow().clone();
        match maybe_curr {
            Some(curr) if curr.ptr_eq(&weak) => *self.current_.borrow_mut() = None,
            _ => (),
        }

        let in_rrq = t.in_round_robin_queue;
        if in_rrq {
            for (i, it) in self.task_round_robin_queue.borrow().iter().enumerate() {
                if it.ptr_eq(&weak) {
                    self.task_round_robin_queue.borrow_mut().remove(i);
                    break;
                }
            }
        } else {
            self.task_priority_set.borrow_mut().remove(&PriorityTup(
                t.priority,
                t.tuid().serial(),
                weak,
            ));
        }
    }

    pub fn current(&self) -> Option<TaskSharedPtr> {
        self.current_
            .borrow()
            .as_ref()
            .map(|p| p.upgrade().unwrap())
    }

    pub fn set_current(&self, maybe_t: Option<TaskSharedWeakPtr>) {
        *self.current_.borrow_mut() = maybe_t;
    }

    pub fn current_timeslice_end(&self) -> Ticks {
        self.current_timeslice_end_.get()
    }

    pub fn expire_timeslice(&self) {
        self.current_timeslice_end_.set(0);
    }

    pub fn interrupt_after_elapsed_time(&self) -> f64 {
        // Where does the 3 seconds come from?  No especially
        // good reason.  We want this to be pretty high,
        // because it's a last-ditch recovery mechanism, not a
        // primary thread scheduler.  Though in theory the
        // PTRACE_INTERRUPT's shouldn't interfere with other
        // events, that's hard to test thoroughly so try to
        // aVoid it.
        let mut delay: f64 = 3.0;
        if self.enable_chaos.get() {
            let now = monotonic_now_sec();
            if self.high_priority_only_intervals_start.get() != 0.0 {
                let next_interval_start: f64 = (((now
                    - self.high_priority_only_intervals_start.get())
                    / self.high_priority_only_intervals_period.get())
                .floor()
                    + 1.0)
                    * self.high_priority_only_intervals_period.get()
                    + self.high_priority_only_intervals_start.get();
                delay = delay.min(next_interval_start - now);
            }

            if self.high_priority_only_intervals_refresh_time.get() != 0.0 {
                delay = delay.min(self.high_priority_only_intervals_refresh_time.get() - now);
            }

            if self.priorities_refresh_time.get() != 0.0 {
                delay = delay.min(self.priorities_refresh_time.get() - now);
            }
        }

        0.001_f64.max(delay)
    }

    /// Return the number of cores we should report to applications.
    pub fn pretend_num_cores(&self) -> u32 {
        self.pretend_num_cores_.get()
    }

    /// Return the processor affinity masks we should report to applications.
    pub fn pretend_affinity_mask(&self) -> CpuSet {
        self.pretend_affinity_mask_.get()
    }

    pub fn in_stable_exit(&self, t: &mut RecordTask) {
        self.update_task_priority_internal(t, t.priority);
    }

    /// Pull a task from the round-robin queue if available. Otherwise,
    /// find the highest-priority task that is runnable. If the highest-priority
    /// runnable task has the same priority as 't', return 't' or
    /// the next runnable task after 't' in round-robin order.
    /// Sets 'by_waitpid' to true if we determined the task was runnable by
    /// calling waitpid on it and observing a state change. This task *must*
    /// be returned by get_next_thread, and is_runnable_task must not be called
    /// on it again until it has run.
    /// Considers only tasks with priority <= priority_threshold.
    fn find_next_runnable_task(
        &self,
        maybe_t: Option<&TaskSharedPtr>,
        by_waitpid: &mut bool,
        priority_threshold: i32,
    ) -> Option<TaskSharedPtr> {
        *by_waitpid = false;
        let task_priority_setb = self.task_priority_set.borrow();
        let mut range = task_priority_setb.range(..);
        loop {
            if let Some(PriorityTup(priority_ref, _, _)) = range.next() {
                let priority = *priority_ref;
                if priority > priority_threshold {
                    return None;
                }

                let start = PriorityTup(priority, 0, Weak::new());
                let end = PriorityTup(priority + 1, 0, Weak::new());
                let same_priority_range = task_priority_setb.range(start..end);

                if !self.enable_chaos.get() {
                    let same_priority_vec = match maybe_t {
                        Some(t)
                            if t.borrow().as_record_task().unwrap().priority == priority
                                && task_priority_setb.contains(&PriorityTup(
                                    priority,
                                    t.borrow().tuid().serial(),
                                    t.borrow().weak_self_ptr(),
                                )) =>
                        {
                            let (lte, gt): (Vec<&PriorityTup>, Vec<&PriorityTup>) =
                                same_priority_range.partition(|p| {
                                    // Its not important to exactly specify the weak ptr as its
                                    // ignored anyways in the cmp
                                    **p <= PriorityTup(
                                        priority,
                                        t.borrow().tuid().serial(),
                                        Weak::new(),
                                    )
                                });

                            gt.iter().chain(lte.iter()).cloned().cloned().collect()
                        }
                        _ => same_priority_range.cloned().collect::<Vec<PriorityTup>>(),
                    };

                    for PriorityTup(_, _, task_weak) in same_priority_vec {
                        if self.is_task_runnable(
                            task_weak
                                .upgrade()
                                .unwrap()
                                .borrow_mut()
                                .as_record_task_mut()
                                .unwrap(),
                            by_waitpid,
                        ) {
                            return Some(task_weak.upgrade().unwrap());
                        }
                    }
                } else {
                    let mut rg = thread_rng();
                    let mut same_priority_shuffled =
                        same_priority_range.cloned().collect::<Vec<PriorityTup>>();
                    same_priority_shuffled.shuffle(&mut rg);

                    for PriorityTup(_, _, task_weak) in same_priority_shuffled {
                        if self.is_task_runnable(
                            task_weak
                                .upgrade()
                                .unwrap()
                                .borrow_mut()
                                .as_record_task_mut()
                                .unwrap(),
                            by_waitpid,
                        ) {
                            return Some(task_weak.upgrade().unwrap());
                        }
                    }
                }

                let range_start = PriorityTup(priority + 1, 0, Weak::new());
                range = task_priority_setb.range(range_start..);
            } else {
                return None;
            }
        }
    }

    /// Returns the first task in the round-robin queue or null if it's empty,
    /// removing it from the round-robin queue.
    fn get_round_robin_task(&self) -> Option<TaskSharedPtr> {
        self.task_round_robin_queue
            .borrow_mut()
            .pop_front()
            .map(|w| w.upgrade().unwrap())
    }

    fn maybe_pop_round_robin_task(&self, t: &mut RecordTask) {
        if self.task_round_robin_queue.borrow().is_empty() {
            return;
        }

        if self
            .task_round_robin_queue
            .borrow()
            .front()
            .unwrap()
            .ptr_eq(&t.weak_self_ptr())
        {
            self.task_round_robin_queue.borrow_mut().pop_front();
            t.in_round_robin_queue = false;
            self.task_priority_set.borrow_mut().insert(PriorityTup(
                t.priority,
                t.tuid().serial(),
                t.weak_self_ptr(),
            ));
        }
    }

    fn setup_new_timeslice(&self) {
        let mut max_timeslice_duration = self.max_ticks_.get();

        if self.enable_chaos.get() {
            // Hypothesis: some bugs require short timeslices to expose. But we don't
            // want the average timeslice to be too small. So make 10% of timeslices
            // very short, 10% short-ish, and the rest uniformly distributed between 0
            // and |max_ticks_|.
            let timeslice_kind_frac = random_frac();
            if timeslice_kind_frac < VERY_SHORT_TIMESLICE_PROBABILITY {
                max_timeslice_duration = VERY_SHORT_TIMESLICE_MAX_DURATION;
            } else if timeslice_kind_frac
                < VERY_SHORT_TIMESLICE_PROBABILITY + SHORT_TIMESLICE_PROBABILITY
            {
                max_timeslice_duration = SHORT_TIMESLICE_MAX_DURATION;
            } else {
                max_timeslice_duration = self.max_ticks_.get();
            }
        }

        let tick_count = self.current().unwrap().borrow().tick_count();
        self.current_timeslice_end_.set(
            tick_count + (random::<Ticks>() % min(self.max_ticks_.get(), max_timeslice_duration)),
        );
    }

    fn maybe_reset_priorities(&self, now: f64) {
        if !self.enable_chaos.get() || self.priorities_refresh_time.get() > now {
            return;
        }

        // Reset task priorities again at some point in the future.
        self.priorities_refresh_time
            .set(now + random_frac() * PRIORITIES_REFRESH_MAX_INTERVAL as f64);
        let mut tasks = Vec::new();
        for p in self.task_priority_set.borrow().iter() {
            tasks.push(p.2.clone());
        }

        for p in self.task_round_robin_queue.borrow().iter() {
            tasks.push(p.clone());
        }

        for t in tasks {
            let tt = t.upgrade().unwrap();
            let priority = self.choose_random_priority(&tt);
            self.update_task_priority_internal(
                tt.borrow_mut().as_record_task_mut().unwrap(),
                priority,
            );
        }
    }

    fn choose_random_priority(&self, t: &TaskSharedPtr) -> i32 {
        let prob = if t.borrow().tgid() == t.borrow().tid {
            MAIN_THREAD_LOW_PRIORITY_PROBABILITY
        } else {
            LOW_PRIORITY_PROBABILITY
        };

        if random_frac() < prob {
            1
        } else {
            0
        }
    }

    fn update_task_priority_internal(&self, t: &mut RecordTask, mut value: i32) {
        if t.stable_exit && !self.enable_chaos.get() {
            // Tasks in a stable exit have the highest priority. We should force them
            // to complete exiting ASAP to clean up resources. They may not be runnable
            // due to waiting for PTRACE_EVENT_EXIT to complete.
            value = -9999;
        }

        if t.priority == value {
            return;
        }

        if t.in_round_robin_queue {
            t.priority = value;
            return;
        }

        self.task_priority_set.borrow_mut().remove(&PriorityTup(
            t.priority,
            t.tuid().serial(),
            t.weak_self_ptr(),
        ));
        t.priority = value;
        self.task_priority_set.borrow_mut().insert(PriorityTup(
            t.priority,
            t.tuid().serial(),
            t.weak_self_ptr(),
        ));
    }

    fn maybe_reset_high_priority_only_intervals(&self, now: f64) {
        if !self.enable_chaos.get() || self.high_priority_only_intervals_refresh_time.get() > now {
            return;
        }
        let duration_step = random::<u16>() as i32 % HIGH_PRIORITY_ONLY_DURATION_STEPS;
        self.high_priority_only_intervals_duration.set(
            MIN_HIGH_PRIORITY_ONLY_DURATION
                * HIGH_PRIORITY_ONLY_DURATION_STEP_FACTOR.powi(duration_step),
        );
        self.high_priority_only_intervals_period
            .set(self.high_priority_only_intervals_duration.get() / HIGH_PRIORITY_ONLY_FRACTION);
        self.high_priority_only_intervals_start.set(
            now + random_frac()
                * (self.high_priority_only_intervals_period.get()
                    - self.high_priority_only_intervals_duration.get()),
        );
        self.high_priority_only_intervals_refresh_time.set(
            now + MIN_HIGH_PRIORITY_ONLY_DURATION
                * HIGH_PRIORITY_ONLY_DURATION_STEP_FACTOR
                    .powi(HIGH_PRIORITY_ONLY_DURATION_STEPS - 1)
                / HIGH_PRIORITY_ONLY_FRACTION,
        );
    }

    fn in_high_priority_only_interval(&self, now: f64) -> bool {
        if now < self.high_priority_only_intervals_start.get() {
            return false;
        }

        // @TODO make sure this is what we want
        let mod_: f64 = (now - self.high_priority_only_intervals_start.get())
            % self.high_priority_only_intervals_period.get();

        mod_ < self.high_priority_only_intervals_duration.get()
    }

    fn treat_as_high_priority(&self, t: &TaskSharedPtr) -> bool {
        self.task_priority_set.borrow().len() > 1
            && t.borrow_mut().as_record_task_mut().unwrap().priority == 0
    }

    /// Returns true if we should return t as the runnable task. Otherwise we
    /// should check the next task. Note that if this returns true get_next_thread
    /// |must| return t as the runnable task, otherwise we will lose an event and
    ///  probably deadlock!!!
    fn is_task_runnable(&self, t: &mut RecordTask, by_waitpid: &mut bool) -> bool {
        ed_assert!(
            t,
            self.must_run_task.borrow().is_none(),
            "is_task_runnable called again after it returned a task that must run!"
        );

        if t.unstable.get() {
            log!(LogDebug, "  {} is unstable", t.tid);
            return true;
        }

        if !t.may_be_blocked() {
            log!(LogDebug, "  {} isn't blocked", t.tid);
            return true;
        }

        if t.emulated_stop_type != EmulatedStopType::NotStopped {
            if t.is_signal_pending(sig::SIGCONT) {
                // We have to do this here. RecordTask::signal_delivered can't always
                // do it because if we don't PTRACE_CONT the task, we'll never see the
                // SIGCONT.
                t.emulate_sigcont();
                // We shouldn't run any user code since there is at least one signal
                // pending.
                t.resume_execution(
                    ResumeRequest::ResumeSyscall,
                    WaitRequest::ResumeWait,
                    TicksRequest::ResumeNoTicks,
                    None,
                );
                *by_waitpid = true;
                *self.must_run_task.borrow_mut() = Some(t.weak_self_ptr());
                log!(
                    LogDebug,
                    "  Got {} out of emulated stop due to pending SIGCONT",
                    t.tid
                );

                return true;
            } else {
                log!(LogDebug, "  {} is stopped by ptrace or signal", t.tid);
                // We have no way to detect a SIGCONT coming from outside the tracees.
                // We just have to poll SigPnd in /proc/<pid>/status.
                self.enable_poll.set(true);
                // We also need to check if the task got killed.
                t.try_wait();
                // N.B.: If we supported ptrace exit notifications for killed tracee's
                // that would need handling here, but we don't at the moment.
                return t.is_dying();
            }
        }

        if EventType::EvSyscall == t.ev().event_type()
            && SyscallState::ProcessingSyscall == t.ev().syscall_event().state
            && treat_syscall_as_nonblocking(t.ev().syscall_event().number, t.arch())
        {
            // These syscalls never really block but the kernel may report that
            // the task is not stopped yet if we pass WNOHANG. To make them
            // behave predictably, do a blocking wait.
            t.wait(None);
            *by_waitpid = true;
            *self.must_run_task.borrow_mut() = Some(t.weak_self_ptr());
            log!(LogDebug, "  sched_yield ready with status {}", t.status());
            return true;
        }

        log!(
            LogDebug,
            "  {} is blocked on {}; checking status ...",
            t.tid,
            t.ev()
        );

        let did_wait_for_t: bool = t.try_wait();
        if did_wait_for_t {
            *by_waitpid = true;
            *self.must_run_task.borrow_mut() = Some(t.weak_self_ptr());
            log!(LogDebug, "  ready with status {}", t.status());
            return true;
        }
        log!(LogDebug, "  still blocked");
        // Try next task
        false
    }

    fn validate_scheduled_task(&self) {
        let curr = self.current().unwrap();
        ed_assert!(
            &curr.borrow(),
            self.must_run_task.borrow().is_none()
                || Rc::ptr_eq(
                    &self
                        .must_run_task
                        .borrow()
                        .as_ref()
                        .unwrap()
                        .upgrade()
                        .unwrap(),
                    &curr
                )
        );
        ed_assert!(
            &curr.borrow(),
            self.task_round_robin_queue.borrow().is_empty()
                || Rc::ptr_eq(
                    &curr,
                    &self
                        .task_round_robin_queue
                        .borrow()
                        .front()
                        .unwrap()
                        .upgrade()
                        .unwrap()
                )
        );
    }

    /// Compute an affinity mask to report via sched_getaffinity.
    /// This mask should include whatever CPU number the task is
    /// actually running on, otherwise we may confuse applications.
    /// The mask should also match the number of CPUs we're pretending
    /// to have.
    ///
    /// DIFF NOTE: This is a private method in rr.
    /// In rd this need to be pub because of the way things are being constructed.
    pub fn regenerate_affinity_mask(&self) {
        let ret = sched_getaffinity(Pid::from_raw(0));
        match ret {
            Err(e) => fatal!("Failed sched_getaffinity {:?}", e),
            Ok(aff) => self.pretend_affinity_mask_.set(aff),
        }

        let maybe_cpu: Option<u32> = self.record_session().trace_writer().bound_to_cpu();
        let cpu = match maybe_cpu {
            None => {
                // We only run one thread at a time but we're not limiting
                // where that thread can run, so report all available CPUs
                // in the affinity mask even though that doesn't match
                // pretend_num_cores. We only run unbound during tests or
                // when explicitly requested by the user.
                return;
            }
            Some(cpu) => {
                match self.pretend_affinity_mask_.get().is_set(cpu as usize) {
                    Err(e) => {
                        log!(LogWarn, "Bound CPU {} not in affinity mask: {:?}", cpu, e);
                        // Use the original affinity mask since something strange is
                        // going on.
                        return;
                    }
                    Ok(false) => {
                        log!(LogWarn, "Bound CPU {} not in affinity mask", cpu);
                        // Use the original affinity mask since something strange is
                        // going on.
                        return;
                    }
                    Ok(true) => cpu,
                }
            }
        };
        // Try to limit the CPU numbers we generate to the ones that
        // actually exist on this system, but generate fake ones if there
        // aren't enough.
        let np = unsafe { sysconf(_SC_NPROCESSORS_CONF) };
        if np < 0 {
            fatal!("Error while obtaining the number of CPUs");
        }

        let mut faked_num_cpus: u32 = np as u32;
        if faked_num_cpus < self.pretend_num_cores_.get() {
            faked_num_cpus = self.pretend_num_cores_.get();
        }

        let mut pretend_affinity_mask = CpuSet::new();
        // DIFF NOTE: rr swallows any error. We don't for now.
        pretend_affinity_mask.set(cpu as usize).unwrap();
        if self.pretend_num_cores_.get() > 1 {
            // generate random CPU numbers that fit into the CPU mask
            let mut other_cpus = Vec::<u32>::new();
            for i in 0..faked_num_cpus {
                if i != cpu {
                    other_cpus.push(i);
                }
            }
            let mut rg = thread_rng();
            other_cpus.shuffle(&mut rg);
            for i in 0..self.pretend_num_cores_.get() as usize - 1 {
                // DIFF NOTE: rr swallows any error. We don't for now.
                pretend_affinity_mask.set(other_cpus[i] as usize).unwrap();
            }
        }

        self.pretend_affinity_mask_.set(pretend_affinity_mask);
    }
}

fn sleep_time(t: f64) {
    let mut ts: timespec = unsafe { mem::zeroed() };
    ts.tv_sec = t.floor() as i64;
    ts.tv_nsec = ((t - t.floor()) * 1e9) as i64;
    unsafe { nanosleep(&ts, ptr::null_mut()) };
}

fn random_frac() -> f64 {
    random::<u32>() as f64 / u32::MAX as f64
}

fn treat_syscall_as_nonblocking(syscallno: i32, arch: SupportedArch) -> bool {
    is_sched_yield_syscall(syscallno, arch)
        || is_exit_syscall(syscallno, arch)
        || is_exit_group_syscall(syscallno, arch)
}
