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
//! The main interface to the scheduler is |get_next_thread|. This gets called
//! after every rd event to decide which task to run next.
//!
//! The scheduler gives the current task a 'timeslice', a ticks deadline after
//! which we will try to switch to another task. So |get_next_thread| first
//! checks whether the currently running task has exceeded that deadline. If
//! not, and the current task is runnable, we schedule it again. If it's blocked
//! or has exceeded its deadline, we search for another task to run:
//! taking tasks from the round-robin queue until we find one that's runnable,
//! and then if the round-robin queue is empty, choosing the highest-priority
//! task that's runnable. If the highest-priority runnable task has the same
//! priority as the current task, choose the next runnable task after the
//! current task (so equal priority tasks run in round-robin order).
//!
//! The main parameter to the scheduler is |max_ticks|, which controls the
//! length of each timeslice.

use crate::task::record_task::record_task::RecordTask;
use crate::ticks::Ticks;
use libc::cpu_set_t;
use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::rc::{Rc, Weak};

// Tasks sorted by priority.
type TaskPrioritySet = BTreeSet<(i32, Weak<RefCell<RecordTask>>)>;
type TaskQueue = VecDeque<Weak<RefCell<RecordTask>>>;

pub struct Scheduler {
    // @TODO figure this out. Currently Session owns a scheduler
    // session: RecordSession,
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
    current_: Option<Rc<RefCell<RecordTask>>>,
    current_timeslice_end_: Ticks,

    /// At this time (or later) we should refresh these values.
    high_priority_only_intervals_refresh_time: f64,
    high_priority_only_intervals_start: f64,
    high_priority_only_intervals_duration: f64,
    high_priority_only_intervals_period: f64,
    /// At this time (or later) we should rerandomize RecordTask priorities.
    priorities_refresh_time: f64,

    max_ticks_: Ticks,

    must_run_task: RecordTask,

    pretend_affinity_mask_: cpu_set_t,
    pretend_num_cores_: u32,

    /// When true, context switch at every possible point.
    always_switch: bool,
    /// When true, make random scheduling decisions to try to increase the
    /// probability of finding buggy schedules.
    enable_chaos: bool,

    enable_poll: bool,
    last_reschedule_in_high_priority_only_interval: bool,
}

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
enum TickHowMany {
    DefaultMaxTicks = 500000,
}
