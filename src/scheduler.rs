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
    event::{EventType, Switchable, SyscallState},
    kernel_abi::{is_exit_group_syscall, is_exit_syscall, is_sched_yield_syscall, SupportedArch},
    log::{LogDebug, LogWarn},
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
};
use libc::{sysconf, _SC_NPROCESSORS_CONF};
use nix::{
    sched::{sched_getaffinity, CpuSet},
    unistd::Pid,
};
use rand::{seq::SliceRandom, thread_rng};
use std::{
    collections::{BTreeMap, VecDeque},
    mem,
    rc::Weak,
};

// Tasks sorted by priority.
type TaskPrioritySet = BTreeMap<i32, TaskSharedWeakPtr>;
type TaskQueue = VecDeque<TaskSharedWeakPtr>;

/// DIFF NOTE: In rr we deal with *RecordTasks. Here we are dealing with the
/// "superclass" Task (see the various TaskSharedWeakPtr-s). This will mean
/// that we need to do as_record_task() in various locations. An extra step...
pub struct Scheduler {
    /// @TODO Is this what we want?
    session: SessionSharedWeakPtr,
    /// Every task of this session is either in task_priority_set
    /// (when in_round_robin_queue is false), or in task_round_robin_queue
    /// (when in_round_robin_queue is true).
    ///
    /// task_priority_set is a set of pairs of (task->priority, task). This
    /// lets us efficiently iterate over the tasks with a given priority, or
    /// all tasks in priority order.
    task_priority_set: TaskPrioritySet,
    task_round_robin_queue: TaskQueue,

    /// The currently scheduled task. This may be `None` if the last scheduled
    /// task has been destroyed.
    current_: Option<TaskSharedWeakPtr>,
    current_timeslice_end_: Ticks,

    /// At this time (or later) we should refresh these values.
    high_priority_only_intervals_refresh_time: f64,
    high_priority_only_intervals_start: f64,
    high_priority_only_intervals_duration: f64,
    high_priority_only_intervals_period: f64,
    /// At this time (or later) we should rerandomize RecordTask priorities.
    priorities_refresh_time: f64,

    max_ticks_: Ticks,

    must_run_task: Option<TaskSharedWeakPtr>,

    pretend_affinity_mask_: CpuSet,

    /// @TODO Is this what we want?
    pretend_num_cores_: u32,

    /// When true, context switch at every possible point.
    always_switch: bool,
    /// When true, make random scheduling decisions to try to increase the
    /// probability of finding buggy schedules.
    enable_chaos: bool,

    enable_poll: bool,
    last_reschedule_in_high_priority_only_interval: bool,
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
    DefaultMaxTicks = 500000,

    /// Don't allow max_ticks to get above this value.
    MaxMaxTicks = 1000000000,
}

/// Schedule a new runnable task (which may be the same as current()).
///
/// The new current() task is guaranteed to either have already been
/// runnable, or have been made runnable by a waitpid status change (in
/// which case, result.by_waitpid will be true.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Rescheduled {
    interrupted_by_signal: bool,
    by_waitpid: bool,
    started_new_timeslice: bool,
}

impl Scheduler {
    /// DIFF This constructor does NOT call regenerate_affinity_mask() like in rr.
    pub fn new(max_ticks: Ticks, always_switch: bool) -> Scheduler {
        Scheduler {
            session: Weak::new(),
            task_priority_set: Default::default(),
            task_round_robin_queue: Default::default(),
            current_: Default::default(),
            current_timeslice_end_: Default::default(),
            high_priority_only_intervals_refresh_time: Default::default(),
            high_priority_only_intervals_start: Default::default(),
            high_priority_only_intervals_duration: Default::default(),
            high_priority_only_intervals_period: Default::default(),
            priorities_refresh_time: Default::default(),
            max_ticks_: max_ticks,
            must_run_task: Default::default(),
            pretend_affinity_mask_: unsafe { mem::zeroed() },
            pretend_num_cores_: 1,
            always_switch,
            enable_chaos: Default::default(),
            enable_poll: Default::default(),
            last_reschedule_in_high_priority_only_interval: Default::default(),
        }
    }

    pub fn set_session_weak_ptr(&mut self, weak_ptr: SessionSharedWeakPtr) {
        self.session = weak_ptr;
    }

    fn session_shr_ptr(&self) -> SessionSharedPtr {
        self.session.upgrade().unwrap()
    }

    pub fn record_session(&self) -> &RecordSession {
        unimplemented!()
    }

    pub fn set_max_ticks(&mut self, max_ticks: Ticks) {
        debug_assert!(max_ticks <= TicksHowMany::MaxMaxTicks as u64);
        self.max_ticks_ = max_ticks;
    }

    pub fn max_ticks(&self) -> Ticks {
        self.max_ticks_
    }

    pub fn set_always_switch(&mut self, always_switch: bool) {
        self.always_switch = always_switch;
    }

    pub fn set_enable_chaos(&mut self, _enable_chaos: bool) {
        unimplemented!()
    }

    pub fn set_num_cores(&mut self, _num_cores: u32) {
        unimplemented!()
    }

    /// Schedule a new runnable task (which may be the same as current()).
    ///
    /// The new current() task is guaranteed to either have already been
    /// runnable, or have been made runnable by a waitpid status change (in
    /// which case, result.by_waitpid will be true.
    pub fn reschedule(&mut self, _switchable: Switchable) -> Rescheduled {
        unimplemented!()
    }

    /// Set the priority of `t` to `value` and update related state.
    pub fn update_task_priority(&mut self, _t: &RecordTask, _value: i32) {
        unimplemented!()
    }

    /// Do one round of round-robin scheduling if we're not already doing one.
    /// If we start round-robin scheduling now, make last_task the last
    /// task to be scheduled.
    /// If the task_round_robin_queue is empty this moves all tasks into it,
    /// putting last_task last.
    pub fn schedule_one_round_robin(&mut self, _last_task: &RecordTask) {
        unimplemented!()
    }

    pub fn on_create_task(&mut self, _t: TaskSharedPtr) {
        unimplemented!()
    }

    ///  De-register a thread. This function should be called when a thread exits.
    pub fn on_destroy_task(&mut self, _t: TaskSharedPtr) {
        unimplemented!()
    }

    pub fn current(&self) -> &RecordTask {
        unimplemented!()
    }

    pub fn set_current(&mut self, _t: &RecordTask) {
        unimplemented!()
    }

    pub fn current_timeslice_end(&self) -> Ticks {
        self.current_timeslice_end_
    }

    pub fn expire_timeslice(&mut self) {
        self.current_timeslice_end_ = 0;
    }

    pub fn interrupt_after_elapsed_time() -> f64 {
        unimplemented!()
    }

    /// Return the number of cores we should report to applications.
    pub fn pretend_num_cores(&self) -> u32 {
        unimplemented!()
    }

    /// Return the processor affinity masks we should report to applications.
    pub fn pretend_affinity_mask(&self) -> CpuSet {
        self.pretend_affinity_mask_
    }

    pub fn in_stable_exit(&self, _t: &RecordTask) {
        unimplemented!()
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
    fn find_next_runnable_task(_t: &RecordTask, _by_waitpid: &bool, _priority_threshold: i32) {
        unimplemented!()
    }

    /// Returns the first task in the round-robin queue or null if it's empty,
    /// removing it from the round-robin queue.
    fn get_round_robin_task(&self) -> &RecordTask {
        unimplemented!()
    }

    fn maybe_pop_round_robin_task(_t: &RecordTask) {
        unimplemented!()
    }

    fn get_next_task_with_same_priority(&self, _t: &RecordTask) {
        unimplemented!()
    }

    fn setup_new_timeslice() {
        unimplemented!()
    }

    fn maybe_reset_priorities(&self, _now: f64) {
        unimplemented!()
    }

    fn choose_random_priority(self, _t: &RecordTask) {
        unimplemented!()
    }
    fn update_task_priority_internal(_t: &RecordTask, _value: i32) {
        unimplemented!()
    }

    fn maybe_reset_high_priority_only_intervals(&self, _now: f64) {
        unimplemented!()
    }

    fn in_high_priority_only_interval(self, _now: f64) {
        unimplemented!()
    }

    fn treat_as_high_priority(&self, _t: &RecordTask) {
        unimplemented!()
    }

    /// Returns true if we should return t as the runnable task. Otherwise we
    /// should check the next task. Note that if this returns true get_next_thread
    /// |must| return t as the runnable task, otherwise we will lose an event and
    ///  probably deadlock!!!
    fn is_task_runnable(&mut self, t: &mut RecordTask, by_waitpid: &mut bool) -> bool {
        ed_assert!(
            t,
            self.must_run_task.is_none(),
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
                self.must_run_task = Some(t.weak_self_ptr());
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
                self.enable_poll = true;
                // We also need to check if the task got killed.
                t.try_wait();
                // N.B.: If we supported ptrace exit notifications for killed tracee's
                // that would need handling here, but we don't at the moment.
                return t.is_dying();
            }
        }

        if EventType::EvSyscall == t.ev().event_type()
            && SyscallState::ProcessingSyscall == t.ev().syscall().state
            && treat_syscall_as_nonblocking(t.ev().syscall().number, t.arch())
        {
            // These syscalls never really block but the kernel may report that
            // the task is not stopped yet if we pass WNOHANG. To make them
            // behave predictably, do a blocking wait.
            t.wait(None);
            *by_waitpid = true;
            self.must_run_task = Some(t.weak_self_ptr());
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
            self.must_run_task = Some(t.weak_self_ptr());
            log!(LogDebug, "  ready with status {}", t.status());
            return true;
        }
        log!(LogDebug, "  still blocked");
        // Try next task
        false
    }

    fn validate_scheduled_task(&self) {
        unimplemented!()
    }

    /// Compute an affinity mask to report via sched_getaffinity.
    /// This mask should include whatever CPU number the task is
    /// actually running on, otherwise we may confuse applications.
    /// The mask should also match the number of CPUs we're pretending
    /// to have.
    ///
    /// DIFF NOTE: This is a private method in rr.
    /// In rd this need to be pub because of the way things are being constructed.
    pub fn regenerate_affinity_mask(&mut self) {
        let ret = sched_getaffinity(Pid::from_raw(0));
        match ret {
            Err(e) => fatal!("Failed sched_getaffinity {:?}", e),
            Ok(aff) => self.pretend_affinity_mask_ = aff,
        }

        let maybe_cpu: Option<u32> = self
            .session_shr_ptr()
            .as_record()
            .unwrap()
            .trace_writer()
            .bound_to_cpu();
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
                match self.pretend_affinity_mask_.is_set(cpu as usize) {
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
        if faked_num_cpus < self.pretend_num_cores_ {
            faked_num_cpus = self.pretend_num_cores_;
        }
        let mut pretend_affinity_mask = CpuSet::new();
        // DIFF NOTE: rr swallows any error. We don't for now.
        pretend_affinity_mask.set(cpu as usize).unwrap();
        if self.pretend_num_cores_ > 1 {
            // generate random CPU numbers that fit into the CPU mask
            let mut other_cpus = Vec::<u32>::new();
            for i in 0..faked_num_cpus {
                if i != cpu {
                    other_cpus.push(i);
                }
            }
            let mut rg = thread_rng();
            other_cpus.shuffle(&mut rg);
            for i in 0..self.pretend_num_cores_ as usize - 1 {
                // DIFF NOTE: rr swallows any error. We don't for now.
                pretend_affinity_mask.set(other_cpus[i] as usize).unwrap();
            }
        }
        self.pretend_affinity_mask_ = pretend_affinity_mask;
    }
}

fn treat_syscall_as_nonblocking(syscallno: i32, arch: SupportedArch) -> bool {
    is_sched_yield_syscall(syscallno, arch)
        || is_exit_syscall(syscallno, arch)
        || is_exit_group_syscall(syscallno, arch)
}
