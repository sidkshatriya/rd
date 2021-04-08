use crate::{
    log::LogLevel::LogDebug,
    session::{
        task::{Task, WeakTaskPtrSet},
        SessionSharedPtr,
        SessionSharedWeakPtr,
    },
    taskish_uid::ThreadGroupUid,
    wait_status::WaitStatus,
    weak_ptr_set::WeakPtrSet,
};
use libc::pid_t;
use std::{
    cell::RefCell,
    rc::{Rc, Weak},
};

pub type ThreadGroupSharedPtr = Rc<RefCell<ThreadGroup>>;
pub type ThreadGroupSharedWeakPtr = Weak<RefCell<ThreadGroup>>;

/// Tracks a group of tasks with an associated ID, set from the
/// original "thread group leader", the child of `fork()` which became
/// the ancestor of all other threads in the group.  Each constituent
/// task must own a reference to this.
///
/// Note: We DONT want to derive Clone.
pub struct ThreadGroup {
    /// These are the various tasks (dyn Task) that are part of the
    /// thread group.
    tasks: WeakTaskPtrSet,
    pub tgid: pid_t,
    pub real_tgid: pid_t,
    pub real_tgid_own_namespace: pid_t,

    pub exit_status: WaitStatus,

    /// We don't allow tasks to make themselves undumpable. If they try,
    /// record that here and lie about it if necessary.
    pub dumpable: bool,

    /// Whether this thread group has execed
    pub execed: bool,

    /// True when a task in the task-group received a SIGSEGV because we
    /// couldn't push a signal handler frame. Only used during recording.
    pub received_sigframe_sigsegv: bool,

    /// private fields
    /// In rr, nullptr is used to indicate no session.
    /// However, in rd we always assume there is a session.
    /// The only place where session is removed is the forget_session() method in rr
    /// which we don't use.
    session_: SessionSharedWeakPtr,
    /// Parent ThreadGroup, or None if it's not a tracee (rd or init).
    /// DIFF NOTE: Different from rr where nullptr is used.
    parent_: Option<ThreadGroupSharedWeakPtr>,

    children_: WeakPtrSet<RefCell<ThreadGroup>>,

    serial: u32,
    weak_self: ThreadGroupSharedWeakPtr,
}

impl Drop for ThreadGroup {
    fn drop(&mut self) {
        for tg in self.children() {
            tg.borrow_mut().parent_ = None;
        }
        match &self.parent_ {
            Some(parent) => {
                parent
                    .upgrade()
                    .unwrap()
                    .borrow_mut()
                    .children_mut()
                    .erase(self.weak_self_ptr());
            }
            None => (),
        }
        // DIFF NOTE: @TODO This assert is not present in rr.
        // Is there any scenario where this assert may not hold but
        // but the program is still correct?
        assert_eq!(self.task_set().len(), 0);
        self.try_session()
            .map(|sess| sess.on_destroy_tg(self.tguid()));
    }
}

/// Tracks a group of tasks with an associated ID, set from the
/// original "thread group leader", the child of `fork()` which became
/// the ancestor of all other threads in the group.  Each constituent
/// task must own a reference to this.
impl ThreadGroup {
    pub fn task_set(&self) -> &WeakTaskPtrSet {
        &self.tasks
    }

    pub fn task_set_mut(&mut self) -> &mut WeakTaskPtrSet {
        &mut self.tasks
    }

    pub fn new(
        session: SessionSharedWeakPtr,
        maybe_parent: Option<ThreadGroupSharedWeakPtr>,
        tgid: pid_t,
        real_tgid: pid_t,
        real_tgid_own_namespace: pid_t,
        serial: u32,
    ) -> ThreadGroupSharedPtr {
        let tg = ThreadGroup {
            tgid,
            real_tgid,
            real_tgid_own_namespace,
            dumpable: true,
            execed: false,
            received_sigframe_sigsegv: false,
            session_: session.clone(),
            parent_: maybe_parent,
            serial,
            tasks: Default::default(),
            exit_status: Default::default(),
            children_: Default::default(),
            weak_self: Weak::new(),
        };
        log!(
            LogDebug,
            "creating new thread group {} (real tgid:{})",
            tgid,
            real_tgid
        );

        let tg_shared = Rc::new(RefCell::new(tg));
        let tg_weak = Rc::downgrade(&tg_shared);
        tg_shared.borrow_mut().weak_self = tg_weak.clone();

        if let Some(ref parent) = tg_shared.borrow().parent_ {
            parent
                .upgrade()
                .unwrap()
                .borrow_mut()
                .children_
                .insert(tg_weak);
        }
        session.upgrade().unwrap().on_create_tg(&tg_shared);
        tg_shared
    }

    /// Mark the members of this thread group as "unstable",
    /// meaning that even though a task may look runnable, it
    /// actually might not be.  (And so `waitpid(-1)` should be
    /// used to schedule the next task.)
    ///
    /// This is needed to handle the peculiarities of mass Task
    /// death at exit_group() and upon receiving core-dumping
    /// signals.  The reason it's needed is easier to understand if
    /// you keep in mind that the "main loop" of ptrace tracers is
    /// /supposed/ to look like
    ///
    ///   while (true) {
    ///     int tid = waitpid(-1, ...);
    ///     // do something with tid
    ///     ptrace(tid, PTRACE_SYSCALL, ...);
    ///   }
    ///
    /// That is, the tracer is supposed to let the kernel schedule
    /// threads and then respond to notifications generated by the
    /// kernel.
    ///
    /// Obviously this isn't how rd's recorder loop looks, because,
    /// among other things, rd has to serialize thread execution.
    /// Normally this isn't much of a problem.  However, mass task
    /// death is an exception.  What happens at a mass task death
    /// is a sequence of events like the following
    ///
    ///  1. A task calls exit_group() or is sent a core-dumping
    ///     signal.
    ///  2. rd receives a PTRACE_EVENT_EXIT notification for the
    ///     task.
    ///  3. rd detaches from the dying/dead task.
    ///  4. Successive calls to waitpid(-1) generate additional
    ///     PTRACE_EVENT_EXIT notifications for each also-dead task
    ///     in the original task's thread group.  Repeat (2) / (3)
    ///     for each notified task.
    ///
    /// So why destabilization?  After (2), rd can't block on the
    /// task shutting down (`waitpid(tid)`), because the kernel
    /// harvests the LWPs (Light weight processes) of the dying thread group in an unknown
    /// order (which we shouldn't assume, even if we could guess
    /// it).  If rd blocks on the task harvest, it will (usually)
    /// deadlock.
    ///
    /// And because rd doesn't know the order of tasks that will be
    /// reaped, it doesn't know which of the dying tasks to
    /// "schedule".  If it guesses and blocks on another task in
    /// the group's status-change, it will (usually) deadlock.
    ///
    /// So destabilizing a thread group, from rd's perspective, means
    /// handing scheduling control back to the kernel and not
    /// trying to harvest tasks before detaching from them.
    ///
    /// NB: an invariant of rd scheduling is that all process
    /// status changes happen as a result of rd resuming the
    /// execution of a task.  This is required to keep tracees in
    /// known states, preventing events from happening "behind rd's
    /// back".  However, destabilizing a thread group means that
    /// these kinds of changes are possible, in theory.
    ///
    /// Currently, instability is a one-way street; it's only used
    /// needed for death signals and exit_group().
    pub fn destabilize(&self, active_task: &dyn Task) {
        log!(LogDebug, "destabilizing thread group {}", self.tgid);
        active_task.unstable.set(true);
        for t in self.task_set().iter_except(active_task.weak_self_ptr()) {
            t.borrow().unstable.set(true);
            log!(LogDebug, "  destabilized task {}", t.borrow().tid());
        }
    }

    #[inline]
    pub fn session(&self) -> SessionSharedPtr {
        self.session_.upgrade().unwrap()
    }

    /// In some scenarios the session may not be available e.g.
    /// Session Rc may be getting drop()-ed. In that case use this
    /// method instead of session() e.g. in the ThreadGroup drop().
    pub fn try_session(&self) -> Option<SessionSharedPtr> {
        self.session_.upgrade()
    }

    pub fn session_weak_ptr(&self) -> &SessionSharedWeakPtr {
        &self.session_
    }

    pub fn parent(&self) -> Option<ThreadGroupSharedPtr> {
        self.parent_.as_ref().map(|wp| wp.upgrade().unwrap())
    }

    pub fn parent_weak_ptr(&self) -> Option<ThreadGroupSharedWeakPtr> {
        self.parent_.clone()
    }

    pub fn children(&self) -> &WeakPtrSet<RefCell<ThreadGroup>> {
        &self.children_
    }

    pub fn children_mut(&mut self) -> &mut WeakPtrSet<RefCell<ThreadGroup>> {
        &mut self.children_
    }

    pub fn tguid(&self) -> ThreadGroupUid {
        ThreadGroupUid::new_with(self.tgid, self.serial)
    }

    pub fn weak_self_ptr(&self) -> ThreadGroupSharedWeakPtr {
        self.weak_self.clone()
    }
}
