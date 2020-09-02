use super::{on_create_task_common, session_common::kill_all_tasks, task::TaskSharedPtr};
use crate::{
    emu_fs::{EmuFs, EmuFsSharedPtr},
    session::{
        session_inner::{session_inner::SessionInner, BreakStatus, RunCommand},
        task::Task,
        Session,
    },
};
use std::{
    cell::{Ref, RefCell, RefMut},
    ops::{Deref, DerefMut},
    rc::Rc,
};

/// A DiversionSession lets you run task(s) forward without replay.
/// Clone a ReplaySession to a DiversionSession to execute some arbitrary
/// code for its side effects.
///
/// Diversion allows tracees to execute freely, as in "recorder"
/// mode, but doesn't attempt to record any data.  Diverter
/// emulates the syscalls it's able to (such as writes to stdio fds),
/// and essentially ignores the syscalls it doesn't know how to
/// implement.  Tracees can easily get into inconsistent states within
/// diversion mode, and no attempt is made to detect or rectify that.
///
/// Diverter mode is designed to support short-lived diversions from
/// "replayer" sessions, as required to support gdb's `call foo()`
/// feature.  A diversion is created for the call frame, then discarded
/// when the call finishes (loosely speaking).
pub struct DiversionSession {
    session_inner: SessionInner,
    emu_fs: EmuFsSharedPtr,
}

impl Drop for DiversionSession {
    fn drop(&mut self) {
        unimplemented!()
    }
}

pub enum DiversionStatus {
    /// Some execution was done. diversion_step() can be called again.
    DiversionContinue,
    /// All tracees are dead. diversion_step() should not be called again.
    DiversionExited,
}

pub struct DiversionResult {
    pub status: DiversionStatus,
    pub break_status: BreakStatus,
}

pub type DiversionSessionSharedPtr = Rc<RefCell<DiversionSession>>;

impl DiversionSession {
    pub fn emufs(&self) -> Ref<'_, EmuFs> {
        self.emu_fs.borrow()
    }
    pub fn emufs_mut(&self) -> RefMut<'_, EmuFs> {
        self.emu_fs.borrow_mut()
    }
    pub fn new() -> DiversionSession {
        unimplemented!()
    }
    /// Try make progress in this diversion session. Run task t if possible.
    pub fn diversion_step(
        &self,
        _t: &mut dyn Task,
        _command: Option<RunCommand>,
        _signal_to_deliver: Option<i32>,
    ) -> DiversionResult {
        unimplemented!()
    }
}

impl Deref for DiversionSession {
    type Target = SessionInner;

    fn deref(&self) -> &Self::Target {
        &self.session_inner
    }
}

impl DerefMut for DiversionSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.session_inner
    }
}

impl Session for DiversionSession {
    // Forwarded method
    fn kill_all_tasks(&self) {
        kill_all_tasks(self)
    }

    fn as_session_inner(&self) -> &SessionInner {
        &self.session_inner
    }

    fn as_session_inner_mut(&mut self) -> &mut SessionInner {
        &mut self.session_inner
    }

    fn as_diversion(&self) -> Option<&DiversionSession> {
        Some(self)
    }

    fn on_create_task(&self, t: TaskSharedPtr) {
        on_create_task_common(self, t);
    }
}
