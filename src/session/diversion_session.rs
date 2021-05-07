use super::{
    on_create_task_common,
    session_common::kill_all_tasks,
    task::{replay_task::ReplayTask, TaskSharedPtr, TaskSharedWeakPtr},
};
use crate::{
    arch::Architecture,
    auto_remote_syscalls::AutoRemoteSyscalls,
    bindings::ptrace::PTRACE_EVENT_EXIT,
    emu_fs::{EmuFs, EmuFsSharedPtr},
    kernel_abi::SupportedArch,
    kernel_metadata::syscall_name,
    log::LogDebug,
    preload_interface::preload_globals,
    session::{
        session_inner::{BreakStatus, RunCommand, SessionInner},
        task::{
            task_common::write_val_mem,
            task_inner::{ResumeRequest, TicksRequest, WaitRequest},
            Task,
        },
        Session,
    },
    sig::Sig,
};
use libc::pid_t;
use std::{
    cell::{Ref, RefMut},
    ops::{Deref, DerefMut},
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
        // We won't permanently leak any OS resources by not ensuring
        // we've cleaned up here, but sessions can be created and
        // destroyed many times, and we don't want to temporarily hog
        // resources.
        self.kill_all_tasks();
        debug_assert!(self.task_map.borrow().is_empty());
        debug_assert!(self.vm_map.borrow().is_empty());
        debug_assert_eq!(self.emufs().size(), 0);
        log!(
            LogDebug,
            "DiversionSession having session id: {} dropped",
            self.session_inner.unique_id
        );
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum DiversionStatus {
    /// Some execution was done. diversion_step() can be called again.
    DiversionContinue,
    /// All tracees are dead. diversion_step() should not be called again.
    DiversionExited,
}

impl Default for DiversionStatus {
    fn default() -> Self {
        // Arbitrary
        Self::DiversionContinue
    }
}

#[derive(Default)]
pub struct DiversionResult {
    pub status: DiversionStatus,
    pub break_status: BreakStatus,
}

impl Default for DiversionSession {
    fn default() -> Self {
        DiversionSession {
            session_inner: SessionInner::new(),
            emu_fs: EmuFs::create(),
        }
    }
}

impl DiversionSession {
    pub fn emufs(&self) -> Ref<'_, EmuFs> {
        self.emu_fs.borrow()
    }

    pub fn emufs_mut(&self) -> RefMut<'_, EmuFs> {
        self.emu_fs.borrow_mut()
    }

    /// Try make progress in this diversion session. Run task t if possible.
    pub fn diversion_step(
        &self,
        t: &dyn Task,
        command: RunCommand,
        signal_to_deliver: Option<Sig>,
    ) -> DiversionResult {
        debug_assert_ne!(command, RunCommand::RunSinglestepFastForward);
        self.assert_fully_initialized();

        let mut result: DiversionResult = Default::default();

        // An exit might have occurred while processing a previous syscall.
        if t.maybe_ptrace_event() == PTRACE_EVENT_EXIT {
            result.status = DiversionStatus::DiversionExited;
            return result;
        }

        // Disable syscall buffering during diversions
        if !t.preload_globals.get().is_null() {
            let child_addr =
                remote_ptr_field!(t.preload_globals.get(), preload_globals, in_diversion);
            write_val_mem(t, child_addr, &1, None);
        }
        t.set_syscallbuf_locked(true);

        match command {
            RunCommand::RunContinue => {
                log!(LogDebug, "Continuing to next syscall");
                t.resume_execution(
                    ResumeRequest::ResumeSysemu,
                    WaitRequest::ResumeWait,
                    TicksRequest::ResumeUnlimitedTicks,
                    signal_to_deliver,
                );
            }
            RunCommand::RunSinglestep => {
                log!(LogDebug, "Stepping to next insn/syscall");
                t.resume_execution(
                    ResumeRequest::ResumeSysemuSinglestep,
                    WaitRequest::ResumeWait,
                    TicksRequest::ResumeUnlimitedTicks,
                    signal_to_deliver,
                );
            }
            _ => {
                fatal!("Illegal run command {:?}", command);
            }
        }

        if t.maybe_ptrace_event() == PTRACE_EVENT_EXIT {
            result.status = DiversionStatus::DiversionExited;
            return result;
        }

        result.status = DiversionStatus::DiversionContinue;
        if t.maybe_stop_sig().is_sig() {
            log!(LogDebug, "Pending signal: {}", t.get_siginfo());
            result.break_status = self.diagnose_debugger_trap(t, command);
            log!(
                LogDebug,
                "Diversion break at ip={}; break={}, watch={}, singlestep={}",
                t.ip(),
                result.break_status.breakpoint_hit,
                !result.break_status.watchpoints_hit.is_empty(),
                result.break_status.singlestep_complete
            );
            ed_assert!(
                t,
                !result.break_status.singlestep_complete || command == RunCommand::RunSinglestep
            );
            return result;
        }

        let sys_no = t.regs_ref().original_syscallno() as i32;
        process_syscall(t, sys_no);
        self.check_for_watchpoint_changes(t, &mut result.break_status);
        result
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
    fn new_task(
        &self,
        tid: pid_t,
        rec_tid: Option<pid_t>,
        serial: u32,
        a: SupportedArch,
        weak_self: TaskSharedWeakPtr,
    ) -> Box<dyn Task> {
        let t = ReplayTask::new(self, tid, rec_tid, serial, a, weak_self);
        Box::new(t)
    }

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

fn process_syscall(t: &dyn Task, syscallno: i32) {
    let arch = t.arch();
    rd_arch_function_selfless!(process_syscall_arch, arch, t, syscallno)
}

fn process_syscall_arch<Arch: Architecture>(t: &dyn Task, syscallno: i32) {
    log!(
        LogDebug,
        "Processing {}",
        syscall_name(syscallno, Arch::arch())
    );

    if syscallno == Arch::IOCTL && t.is_desched_event_syscall() {
        // The arm/disarm-desched ioctls are emulated as no-ops.
        // However, because the rr preload library expects these
        // syscalls to succeed and aborts if they don't, we fudge a
        // "0" return value.
        finish_emulated_syscall_with_ret(t, 0);
        return;
    }

    // We blacklist these syscalls because the params include
    // namespaced identifiers that are different in replay than
    // recording, and during replay they may refer to different,
    // live resources.  For example, if a recorded tracees kills
    // one of its threads, then during replay that killed pid
    // might refer to a live process outside the tracee tree.  We
    // don't want diversion tracees randomly shooting down other
    // processes!
    //
    // We optimistically assume that filesystem operations were
    // intended by the user.
    //
    // There's a potential problem with "fd confusion": in the
    // diversion tasks, fds returned from open() during replay are
    // emulated.  But those fds may accidentally refer to live fds
    // in the task fd table.  So write()s etc may not be writing
    // to the file the tracee expects.  However, the only real fds
    // that leak into tracees are the stdio fds, and there's not
    // much harm that can be caused by accidental writes to them.
    if syscallno == Arch::IPC
        || syscallno == Arch::KILL
        || syscallno == Arch::RT_SIGQUEUEINFO
        || syscallno == Arch::RT_TGSIGQUEUEINFO
        || syscallno == Arch::TGKILL
        || syscallno == Arch::TKILL
    {
        log!(
            LogDebug,
            "Suppressing syscall {}",
            syscall_name(syscallno, t.arch())
        );

        return;
    }

    log!(
        LogDebug,
        "Executing syscall {}",
        syscall_name(syscallno, t.arch())
    );
    execute_syscall(t)
}

fn finish_emulated_syscall_with_ret(t: &dyn Task, ret: isize) {
    t.finish_emulated_syscall();
    let mut r = t.regs_ref().clone();
    r.set_syscall_result_signed(ret);
    t.set_regs(&r);
}

/// Execute the syscall contained in |t|'s current register set.  The
/// return value of the syscall is set for |t|'s registers, to be
/// returned to the tracee task.
fn execute_syscall(t: &dyn Task) {
    t.finish_emulated_syscall();

    let mut remote = AutoRemoteSyscalls::new(t);
    remote.syscall(
        remote.initial_regs_ref().original_syscallno() as i32,
        &[
            remote.initial_regs_ref().arg1(),
            remote.initial_regs_ref().arg2(),
            remote.initial_regs_ref().arg3(),
            remote.initial_regs_ref().arg4(),
            remote.initial_regs_ref().arg5(),
            remote.initial_regs_ref().arg6(),
        ],
    );
    remote
        .initial_regs_mut()
        .set_syscall_result(t.regs_ref().syscall_result());
}
