use crate::{
    bindings::{
        kernel::{itimerval, setitimer, ITIMER_REAL},
        ptrace::{PTRACE_EVENT_EXIT, PTRACE_INTERRUPT},
    },
    kernel_abi::{common::preload_interface::syscallbuf_record, SupportedArch},
    log::LogLevel::{LogDebug, LogWarn},
    registers::Registers,
    remote_ptr::{RemotePtr, Void},
    session::{
        task::{
            record_task::record_task::RecordTask,
            replay_task::ReplayTask,
            task_inner::{
                task_inner::{CloneReason, PtraceData, TaskInner, WriteFlags},
                CloneFlags,
                ResumeRequest,
                TicksRequest,
                WaitRequest,
            },
        },
        Session,
    },
    util::{is_zombie_process, to_timeval},
    wait_status::{MaybeStopSignal, WaitStatus},
};
use libc::{pid_t, waitpid, SIGSTOP, SIGTRAP};
use nix::errno::errno;
use std::{
    cell::RefCell,
    ffi::CString,
    io::Write,
    ops::DerefMut,
    ptr,
    rc::{Rc, Weak},
};

pub mod common;
pub mod record_task;
pub mod replay_task;
pub mod task_inner;

pub type TaskSharedPtr = Rc<RefCell<Box<dyn Task>>>;
pub type TaskSharedWeakPtr = Weak<RefCell<Box<dyn Task>>>;

pub trait Task: DerefMut<Target = TaskInner> {
    fn resume_execution(
        &mut self,
        how: ResumeRequest,
        wait_how: WaitRequest,
        tick_period: TicksRequest,
        maybe_sig: Option<i32>,
    );

    fn stored_record_size(&mut self, record: RemotePtr<syscallbuf_record>) -> u32;

    fn did_waitpid(&mut self, status: WaitStatus);

    fn next_syscallbuf_record(&mut self) -> RemotePtr<syscallbuf_record>;

    fn as_task_inner(&self) -> &TaskInner;
    fn as_task_inner_mut(&mut self) -> &mut TaskInner;

    fn as_record_task(&self) -> Option<&RecordTask> {
        None
    }
    fn as_record_task_mut(&mut self) -> Option<&mut RecordTask> {
        None
    }

    fn as_replay_task(&self) -> Option<&ReplayTask> {
        None
    }
    fn as_replay_task_mut(&mut self) -> Option<&mut ReplayTask> {
        None
    }

    /// Dump all pending events to the RecordTask INFO log.
    fn log_pending_events(&self) {}

    /// Call this hook just before exiting a syscall.  Often Task
    /// attributes need to be updated based on the finishing syscall.
    /// Use 'regs' instead of this->regs() because some registers may not be
    /// set properly in the task yet.
    fn on_syscall_exit(&self, syscallno: i32, arch: SupportedArch, regs: &Registers);

    /// Hook called by `resume_execution`.
    fn will_resume_execution(
        &self,
        _resume_req: ResumeRequest,
        _wait_req: WaitRequest,
        _ticks_req: TicksRequest,
        _sig: Option<i32>,
    ) {
    }

    /// Hook called by `did_waitpid`.
    fn did_wait(&mut self) {
        // Do nothing. However, for example, RecordTask::did_wait() overrides this.
    }

    /// Return the pid of the task in its own pid namespace.
    /// Only RecordTasks actually change pid namespaces.
    fn own_namespace_tid(&self) -> pid_t {
        self.tid
    }

    /// Called when SYS_rrcall_init_preload has happened.
    fn at_preload_init(&self);

    /// (Note: Methods following this are protected in the rr implementation)
    /// Return a new Task cloned from `p`.  `flags` are a set of
    /// CloneFlags (see above) that determine which resources are
    /// shared or copied to the new child.  `new_tid` is the tid
    /// assigned to the new task by the kernel.  `new_rec_tid` is
    /// only relevant to replay, and is the pid that was assigned
    /// to the task during recording.
    /// NOTE: Called simply Task::clone() in rr.
    fn clone_task(
        &self,
        reason: CloneReason,
        flags: CloneFlags,
        stack: Option<RemotePtr<Void>>,
        tls: Option<RemotePtr<Void>>,
        cleartid_addr: Option<RemotePtr<i32>>,
        new_tid: pid_t,
        new_rec_tid: pid_t,
        new_serial: u32,
        other_session: Option<&dyn Session>,
    ) -> &TaskInner;

    /// Internal method called after the first wait() during a clone().
    fn post_wait_clone(&self, _t: &TaskInner, _flags: i32) {}

    /// Internal method called after the clone to fix up the new address space.
    fn post_vm_clone(&self, _reason: CloneReason, _flags: i32, _origin: &TaskInner) -> bool {
        unimplemented!()
    }

    /// Dump attributes of this process, including pending events,
    /// to `out`, which defaults to LOG_FILE.
    fn dump(&self, _out: Option<&dyn Write>) {
        unimplemented!()
    }

    /// We're currently in user-space with registers set up to perform a system
    /// call. Continue into the kernel and stop where we can modify the syscall
    /// state.
    fn enter_syscall(&self) {
        unimplemented!()
    }

    /// We have observed entry to a syscall (either by PTRACE_EVENT_SECCOMP or
    /// a syscall, depending on the value of Session::syscall_seccomp_ordering()).
    /// Continue into the kernel to perform the syscall and stop at the
    /// PTRACE_SYSCALL syscall-exit trap. Returns false if we see the process exit
    /// before that.
    fn exit_syscall(&self) -> bool {
        unimplemented!()
    }

    /// This must be in an emulated syscall, entered through
    /// `cont_sysemu()` or `cont_sysemu_singlestep()`, but that's
    /// not checked.  If so, step over the system call instruction
    /// to "exit" the emulated syscall.
    fn finish_emulated_syscall(&self) {
        unimplemented!()
    }

    /// Assuming we've just entered a syscall, exit that syscall and reset
    /// state to reenter the syscall just as it was called the first time.
    /// Returns false if we see the process exit instead.
    fn exit_syscall_and_prepare_restart(&self) -> bool {
        unimplemented!()
    }

    /// Return true if the status of this has changed, but don't
    /// block.
    fn try_wait(&self) -> bool {
        unimplemented!()
    }

    /// Block until the status of this changes. wait() expects the wait to end
    /// with the process in a stopped() state. If interrupt_after_elapsed > 0,
    /// interrupt the task after that many seconds have elapsed.
    fn wait(&mut self, maybe_interrupt_after_elapsed: Option<f64>) {
        let interrupt_after_elapsed = maybe_interrupt_after_elapsed.unwrap_or(0.0);
        debug_assert!(interrupt_after_elapsed >= 0.0);
        log!(LogDebug, "going into blocking waitpid({}) ...", self.tid);
        ed_assert!(self, !self.unstable.get(), "Don't wait for unstable tasks");
        ed_assert!(
            self,
            self.session().is_recording() || interrupt_after_elapsed == 0.0
        );

        if self.wait_unexpected_exit() {
            return;
        }

        let mut status: WaitStatus;
        let mut sent_wait_interrupt = false;
        let mut ret: pid_t;
        loop {
            if interrupt_after_elapsed > 0.0 {
                let mut timer: itimerval = Default::default();
                timer.it_value = to_timeval(interrupt_after_elapsed);
                unsafe {
                    setitimer(ITIMER_REAL as u32, &timer, ptr::null_mut());
                }
            }
            let mut raw_status: i32 = 0;
            ret = unsafe { waitpid(self.tid, &mut raw_status, libc::__WALL) };
            status = WaitStatus::new(raw_status);
            if interrupt_after_elapsed > 0.0 {
                let timer: itimerval = Default::default();
                unsafe { setitimer(ITIMER_REAL as u32, &timer, ptr::null_mut()) };
            }
            if ret >= 0 || errno() != libc::EINTR {
                // waitpid was not interrupted by the alarm.
                break;
            }

            if is_zombie_process(self.real_tgid()) {
                // The process is dead. We must stop waiting on it now
                // or we might never make progress.
                // XXX it's not clear why the waitpid() syscall
                // doesn't return immediately in this case, but in
                // some cases it doesn't return normally at all!

                // Fake a PTRACE_EVENT_EXIT for this task.
                log!(
                    LogWarn,
                    "Synthesizing PTRACE_EVENT_EXIT for zombie process {}",
                    self.tid
                );
                status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
                ret = self.tid;
                // XXX could this leave unreaped zombies lying around?
                break;
            }

            if !sent_wait_interrupt && (interrupt_after_elapsed > 0.0) {
                self.ptrace_if_alive(PTRACE_INTERRUPT, RemotePtr::null(), PtraceData::None);
                sent_wait_interrupt = true;
                self.expecting_ptrace_interrupt_stop = 2;
            }
        }

        if ret >= 0 && status.exit_code().is_some() {
            // Unexpected non-stopping exit code returned in wait_status.
            // This shouldn't happen; a PTRACE_EXIT_EVENT for this task
            // should be observed first, and then we would kill the task
            // before wait()ing again, so we'd only see the exit
            // code in detach_and_reap. But somehow we see it here in
            // grandchild_threads and async_kill_with_threads tests (and
            // maybe others), when a PTRACE_EXIT_EVENT has not been sent.
            // Verify that we have not actually seen a PTRACE_EXIT_EVENT.
            ed_assert!(
                self,
                !self.seen_ptrace_exit_event,
                "A PTRACE_EXIT_EVENT was observed for this task, but somehow forgotten"
            );

            // Turn this into a PTRACE_EXIT_EVENT.
            log!(
                LogWarn,
                "Synthesizing PTRACE_EVENT_EXIT for process {} exited with {}",
                self.tid,
                status.exit_code().unwrap()
            );
            status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
        }

        log!(
            LogDebug,
            "  waitpid({}) returns {}; status {}",
            self.tid,
            ret,
            status
        );
        ed_assert!(
            self,
            self.tid == ret,
            "waitpid({}) failed with {}",
            self.tid,
            ret
        );

        if sent_wait_interrupt {
            log!(LogWarn, "Forced to PTRACE_INTERRUPT tracee");
            if !is_signal_triggered_by_ptrace_interrupt(status.maybe_group_stop_sig()) {
                log!(
                    LogWarn,
                    "  PTRACE_INTERRUPT raced with another event {:?}",
                    status
                );
            }
        }
        self.did_waitpid(status);
    }

    /// Return true if an unexpected exit was already detected for this task and
    /// it is ready to be reported.
    fn wait_unexpected_exit(&self) -> bool {
        unimplemented!()
    }

    /// Forwarded method signature
    fn open_mem_fd(&mut self) -> bool;

    /// Forwarded method signature
    fn read_bytes_fallible(&mut self, addr: RemotePtr<Void>, buf: &mut [u8]) -> Result<usize, ()>;

    /// Forwarded method signature
    fn read_bytes_helper(&mut self, addr: RemotePtr<Void>, buf: &mut [u8], ok: Option<&mut bool>);

    /// Forwarded method signature
    fn read_c_str(&mut self, child_addr: RemotePtr<u8>) -> CString;

    /// Forwarded method signature
    fn write_bytes_helper(
        &mut self,
        addr: RemotePtr<Void>,
        buf: &[u8],
        ok: Option<&mut bool>,
        flags: WriteFlags,
    );

    /// Forwarded method signature
    fn syscallbuf_data_size(&mut self) -> usize;

    /// Forwarded method signature
    fn write_bytes(&mut self, child_addr: RemotePtr<Void>, buf: &[u8]);
}

fn is_signal_triggered_by_ptrace_interrupt(group_stop_sig: MaybeStopSignal) -> bool {
    // We sometimes see SIGSTOP at interrupts, though the
    // docs don't mention that.
    group_stop_sig == SIGTRAP || group_stop_sig == SIGSTOP
}

fn is_singlestep_resume(request: ResumeRequest) -> bool {
    request == ResumeRequest::ResumeSinglestep || request == ResumeRequest::ResumeSysemuSinglestep
}
