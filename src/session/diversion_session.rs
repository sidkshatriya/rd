use crate::emu_fs::{EmuFs, EmuFsSharedPtr};
use crate::kernel_abi::SupportedArch;
use crate::session::session_inner::session_inner::SessionInner;
use crate::session::session_inner::{BreakStatus, RunCommand};
use crate::session::Session;
use crate::task::Task;
use std::cell::{Ref, RefCell, RefMut};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

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
/// "replayer" sessions, as required to support gdb's |call foo()|
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

pub type DiversionSessionSharedPtr = Arc<RefCell<DiversionSession>>;

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
    fn as_session_inner(&self) -> &SessionInner {
        &self.session_inner
    }

    fn as_session_inner_mut(&mut self) -> &mut SessionInner {
        &mut self.session_inner
    }

    fn on_destroy(&self, t: &dyn Task) {
        unimplemented!()
    }

    fn as_diversion(&self) -> Option<&DiversionSession> {
        Some(self)
    }

    fn new_task(&self, tid: i32, rec_tid: i32, serial: u32, a: SupportedArch) {
        unimplemented!()
    }

    fn on_create(&self, t: &dyn Task) {
        unimplemented!()
    }
}
