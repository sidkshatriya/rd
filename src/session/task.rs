use crate::{
    bindings::{
        kernel::{itimerval, setitimer, user_desc, ITIMER_REAL},
        ptrace::{PTRACE_EVENT_EXIT, PTRACE_INTERRUPT},
    },
    kernel_abi::{syscall_instruction_length, syscall_number_for_gettid, SupportedArch},
    kernel_metadata::syscall_name,
    log::LogLevel::{LogDebug, LogWarn},
    preload_interface::{syscallbuf_record, PRELOAD_THREAD_LOCALS_SIZE},
    registers::Registers,
    remote_ptr::{RemotePtr, Void},
    session::{
        replay_session::ReplaySession,
        session_inner::PtraceSyscallSeccompOrdering,
        task::{
            record_task::RecordTask,
            replay_task::ReplayTask,
            task_inner::{
                CloneFlags,
                CloneReason,
                PtraceData,
                ResumeRequest,
                TaskInner,
                TicksRequest,
                WaitRequest,
                WriteFlags,
            },
        },
    },
    sig::Sig,
    util::{is_zombie_process, to_timeval},
    wait_status::{MaybeStopSignal, WaitStatus},
};
use libc::{pid_t, waitpid, EINTR, ENOSYS, SIGSTOP, SIGTRAP, WNOHANG, __WALL};
use nix::errno::errno;
use std::{

    ffi::{CString, OsStr, OsString},
    fmt::{self, Debug, Formatter},
    io::{stderr, Write},
    ops::DerefMut,
    os::unix::ffi::OsStringExt,
    ptr,
    rc::{Rc, Weak},
};
use task_inner::TrapReasons;

use super::SessionSharedPtr;
use crate::weak_ptr_set::WeakPtrSet;

pub mod record_task;
pub mod replay_task;
pub mod task_common;
pub mod task_inner;

pub type TaskSharedPtr = Rc<Box<dyn Task>>;
pub type TaskSharedWeakPtr = Weak<Box<dyn Task>>;
pub type WeakTaskPtrSet = WeakPtrSet<Box<dyn Task>>;

impl Debug for &dyn Task {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&format!(
            "Task(tid: {} rec_tid:{}, serial:{})",
            self.tid,
            self.rec_tid,
            self.tuid().serial()
        ))
    }
}

pub trait Task: DerefMut<Target = TaskInner> {
    /// Return a new Task cloned from `clone_this`. `flags` are a set of
    /// CloneFlags (see above) that determine which resources are
    /// shared or copied to the new child.  `new_tid` is the tid
    /// assigned to the new task by the kernel.  `new_rec_tid` is
    /// only relevant to replay, and is the pid that was assigned
    /// to the task during recording.
    ///
    /// NOTE: - Called simply Task::clone() in rr
    ///       - Sets the weak_self pointer for the task
    fn clone_task(
        &mut self,
        reason: CloneReason,
        flags: CloneFlags,
        stack: RemotePtr<Void>,
        tls: RemotePtr<Void>,
        _cleartid_addr: RemotePtr<i32>,
        new_tid: pid_t,
        new_rec_tid: Option<pid_t>,
        new_serial: u32,
        maybe_other_session: Option<SessionSharedPtr>,
    ) -> TaskSharedPtr;

    /// Lock or unlock the syscallbuf to prevent the preload library from using it.
    /// Only has an effect if the syscallbuf has been initialized.
    fn set_syscallbuf_locked(&mut self, locked: bool);

    /// Call this to reset syscallbuf_hdr->num_rec_bytes and zero out the data
    /// recorded in the syscall buffer. This makes for more deterministic behavior
    /// especially during replay, where during checkpointing we only save and
    /// restore the recorded data area.
    fn reset_syscallbuf(&mut self);

    fn detect_syscall_arch(&mut self) -> SupportedArch;

    /// DIFF NOTE: Unlike rr, it is NOT compulsory to always call this method
    /// to cleanup a task. Call this method when you need to explicitly remove
    /// the entry the task_map in SessionInner.
    /// If this method is NOT called then simply do what this method is doing
    /// which is to remove the corresponding TaskSharedPtr entry from the
    /// task_map. See kill_all_tasks() for an example where the task map
    /// is being pop-ed from.
    fn destroy(&mut self, maybe_detach: Option<bool>);

    /// Destroy in the tracee task the scratch buffer and syscallbuf (if
    /// syscallbuf_child is non-null).
    /// This task must already be at a state in which remote syscalls can be
    /// executed; if it's not, results are undefined.
    ///
    /// Must be idempotent
    fn destroy_buffers(&mut self);

    /// Calls open_mem_fd if this task's AddressSpace doesn't already have one.
    fn open_mem_fd_if_needed(&mut self) {
        if !self.vm().mem_fd().is_open() {
            self.open_mem_fd();
        }
    }

    /// DIFF NOTE: @TODO method is protected in rr
    ///
    /// Internal method called after the first wait() during a clone().
    fn post_wait_clone(&mut self, clone_from: &dyn Task, flags: CloneFlags);

    /// DIFF NOTE: @TODO method is protected in rr
    ///
    /// Internal method called after the clone to fix up the new address space.
    fn post_vm_clone(
        &mut self,
        reason: CloneReason,
        flags: CloneFlags,
        origin: &mut dyn Task,
    ) -> bool;

    fn post_exec_syscall(&mut self);

    fn post_exec_for_exe(&mut self, exe_file: &OsStr);

    fn resume_execution(
        &mut self,
        how: ResumeRequest,
        wait_how: WaitRequest,
        tick_period: TicksRequest,
        maybe_sig: Option<Sig>,
    );

    fn stored_record_size(&mut self, record: RemotePtr<syscallbuf_record>) -> usize;

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

    fn as_rec_unwrap(&self) -> &RecordTask {
        panic!("Not a RecordTask!")
    }

    fn as_rec_mut_unwrap(&mut self) -> &mut RecordTask {
        panic!("Not a RecordTask!")
    }

    fn as_replay_task(&self) -> Option<&ReplayTask> {
        None
    }

    fn as_replay_task_mut(&mut self) -> Option<&mut ReplayTask> {
        None
    }

    /// Dump all pending events to the RecordTask INFO log.
    fn log_pending_events(&self) {
        // Do nothing by default. Trait impl-s can override.
    }

    /// Call this hook just before exiting a syscall.  Often Task
    /// attributes need to be updated based on the finishing syscall.
    /// Use 'regs' instead of this->regs() because some registers may not be
    /// set properly in the task yet.
    fn on_syscall_exit(&mut self, syscallno: i32, arch: SupportedArch, regs: &Registers);

    /// Hook called by `resume_execution`.
    fn will_resume_execution(
        &mut self,
        _resume_req: ResumeRequest,
        _wait_req: WaitRequest,
        _ticks_req: TicksRequest,
        _sig: Option<Sig>,
    ) {
        // Do nothing by default.
        // Trait impl-s can override. See for example RecordTask::will_resume_execution()
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

    /// Called when SYS_rdcall_init_preload has happened.
    fn at_preload_init(&mut self);

    /// Dump attributes of this process, including pending events,
    /// to `out`, which defaults to LOG_FILE.
    fn dump(&self, maybe_out: Option<&mut dyn Write>) {
        let err = &mut stderr();
        let out = maybe_out.unwrap_or(err);
        write!(
            out,
            "  {:?}(tid:{} rec_tid:{} status:{}{})<{:?}>\n",
            self.prname,
            self.tid,
            self.rec_tid,
            self.wait_status,
            if self.unstable.get() { " UNSTABLE" } else { "" },
            self as *const _
        )
        .unwrap();

        if self.session().is_recording() {
            // TODO pending events are currently only meaningful
            // during recording.  We should change that
            // eventually, to have more informative output.
            self.log_pending_events();
        }
    }

    /// We're currently in user-space with registers set up to perform a system
    /// call. Continue into the kernel and stop where we can modify the syscall
    /// state.
    fn enter_syscall(&mut self) {
        let mut need_ptrace_syscall_event = !self.seccomp_bpf_enabled
            || self.session().syscall_seccomp_ordering()
                == PtraceSyscallSeccompOrdering::SeccompBeforeSyscall;
        let mut need_seccomp_event = self.seccomp_bpf_enabled;
        while need_ptrace_syscall_event || need_seccomp_event {
            let resume_how = if need_ptrace_syscall_event {
                ResumeRequest::ResumeSyscall
            } else {
                ResumeRequest::ResumeCont
            };

            self.resume_execution(
                resume_how,
                WaitRequest::ResumeWait,
                TicksRequest::ResumeNoTicks,
                None,
            );
            if self.is_ptrace_seccomp_event() {
                ed_assert!(self, need_seccomp_event);
                need_seccomp_event = false;
                continue;
            }
            ed_assert!(self, !self.maybe_ptrace_event().is_ptrace_event());
            if self.session().is_recording() && self.maybe_group_stop_sig().is_sig() {
                self.as_record_task_mut().unwrap().stash_group_stop();
                continue;
            }

            if self.maybe_stop_sig().is_not_sig() {
                ed_assert!(self, need_ptrace_syscall_event);
                need_ptrace_syscall_event = false;
                continue;
            }
            if ReplaySession::is_ignored_signal(Some(self.maybe_stop_sig().unwrap_sig()))
                && self.session().is_replaying()
            {
                continue;
            }
            ed_assert!(
                self,
                self.session().is_recording(),
                " got unexpected signal {}",
                self.maybe_stop_sig(),
            );
            if self.maybe_stop_sig() == self.session().as_record().unwrap().syscallbuf_desched_sig()
            {
                continue;
            }
            self.as_record_task_mut().unwrap().stash_sig();
        }
    }

    /// We have observed entry to a syscall (either by PTRACE_EVENT_SECCOMP or
    /// a syscall, depending on the value of Session::syscall_seccomp_ordering()).
    /// Continue into the kernel to perform the syscall and stop at the
    /// PTRACE_SYSCALL syscall-exit trap. Returns false if we see the process exit
    /// before that.
    fn exit_syscall(&mut self) -> bool {
        // If PTRACE_SYSCALL_BEFORE_SECCOMP, we are inconsistent about
        // whether we process the syscall on the syscall entry trap or
        // on the seccomp trap. Detect if we are on the former and
        // just bring us forward to the seccomp trap.
        let mut will_see_seccomp: bool = self.seccomp_bpf_enabled
            && (self.session().syscall_seccomp_ordering()
                == PtraceSyscallSeccompOrdering::SyscallBeforeSeccomp)
            && !self.is_ptrace_seccomp_event();
        loop {
            self.resume_execution(
                ResumeRequest::ResumeSyscall,
                WaitRequest::ResumeWait,
                TicksRequest::ResumeNoTicks,
                None,
            );
            if will_see_seccomp && self.is_ptrace_seccomp_event() {
                will_see_seccomp = false;
                continue;
            }
            if self.maybe_ptrace_event() == PTRACE_EVENT_EXIT {
                return false;
            }
            ed_assert!(self, !self.maybe_ptrace_event().is_ptrace_event());
            if self.maybe_stop_sig().is_not_sig() {
                let arch = self.arch();
                self.canonicalize_regs(arch);
                break;
            }
            if ReplaySession::is_ignored_signal(self.maybe_stop_sig().get_raw_repr())
                && self.session().is_replaying()
            {
                continue;
            }
            ed_assert!(self, self.session().is_recording());
            self.as_record_task_mut().unwrap().stash_sig();
        }

        true
    }

    /// This must be in an emulated syscall, entered through
    /// `cont_sysemu()` or `cont_sysemu_singlestep()`, but that's
    /// not checked.  If so, step over the system call instruction
    /// to "exit" the emulated syscall.
    fn finish_emulated_syscall(&mut self) {
        // XXX verify that this can't be interrupted by a breakpoint trap
        let r = self.regs_ref().clone();

        // Passing `TicksRequest::ResumeNoTicks` here is not only a small performance optimization,
        // but also avoids counting an event if the instruction immediately following
        // a syscall instruction is a conditional branch.
        self.resume_execution(
            ResumeRequest::ResumeSyscall,
            WaitRequest::ResumeWait,
            TicksRequest::ResumeNoTicks,
            None,
        );

        self.set_regs(&r);
        self.wait_status = Default::default();
    }

    /// Assuming we've just entered a syscall, exit that syscall and reset
    /// state to reenter the syscall just as it was called the first time.
    /// Returns false if we see the process exit instead.
    fn exit_syscall_and_prepare_restart(&mut self) -> bool {
        let mut r: Registers = self.regs_ref().clone();
        let syscallno: i32 = r.original_syscallno() as i32;
        log!(
            LogDebug,
            "exit_syscall_and_prepare_restart from syscall {}",
            syscall_name(syscallno, r.arch())
        );
        r.set_original_syscallno(syscall_number_for_gettid(r.arch()) as isize);
        self.set_regs(&r);
        // This exits the hijacked SYS_gettid.  Now the tracee is
        // ready to do our bidding.
        if !self.exit_syscall() {
            // The tracee suddenly exited. To get this to replay correctly, we need to
            // make it look like we really entered the syscall. Then
            // handle_ptrace_exit_event will record something appropriate.
            r.set_original_syscallno(syscallno as isize);
            r.set_syscall_result_signed(-ENOSYS as isize);
            self.set_regs(&r);
            return false;
        }
        log!(LogDebug, "exit_syscall_and_prepare_restart done");

        // Restore these regs to what they would have been just before
        // the tracee trapped at the syscall.
        r.set_original_syscallno(-1);
        r.set_syscallno(syscallno as isize);
        r.set_ip(r.ip() - syscall_instruction_length(r.arch()));
        self.set_regs(&r);

        true
    }

    /// Return true if the status of this has changed, but don't
    /// block.
    fn try_wait(&mut self) -> bool {
        if self.wait_unexpected_exit() {
            return true;
        }

        let mut raw_status: i32 = 0;
        let ret = unsafe { waitpid(self.tid, &mut raw_status, WNOHANG | __WALL) } as i32;
        ed_assert!(
            self,
            0 <= ret,
            "waitpid({}, NOHANG) failed with {}",
            self.tid,
            ret
        );
        log!(
            LogDebug,
            "waitpid({}, NOHANG) returns {}, status {}",
            self.tid,
            ret,
            WaitStatus::new(raw_status)
        );

        if ret == self.tid {
            self.did_waitpid(WaitStatus::new(raw_status));
            return true;
        }

        false
    }

    /// Block until the status of self changes. wait() expects the wait to end
    /// with the process in a stopped state. If interrupt_after_elapsed > 0,
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
            if ret >= 0 || errno() != EINTR {
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
                self.ptrace_if_alive(PTRACE_INTERRUPT, RemotePtr::null(), &mut PtraceData::None);
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
    fn wait_unexpected_exit(&mut self) -> bool {
        if self.detected_unexpected_exit {
            log!(
                LogDebug,
                "Unexpected (SIGKILL) exit was detected; reporting it now"
            );
            self.did_waitpid(WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT));
            self.detected_unexpected_exit = false;
            return true;
        }
        false
    }

    fn open_mem_fd(&mut self) -> bool;

    fn read_bytes_fallible(&mut self, addr: RemotePtr<Void>, buf: &mut [u8]) -> Result<usize, ()>;

    fn read_bytes_helper(&mut self, addr: RemotePtr<Void>, buf: &mut [u8], ok: Option<&mut bool>);

    /// Read bytes from `child_addr` into `buf`, or don't
    /// return.
    fn read_bytes(&mut self, child_addr: RemotePtr<Void>, buf: &mut [u8]);

    fn read_c_str(&mut self, child_addr: RemotePtr<u8>) -> CString;

    fn write_bytes_helper(
        &mut self,
        addr: RemotePtr<Void>,
        buf: &[u8],
        ok: Option<&mut bool>,
        flags: WriteFlags,
    );

    fn syscallbuf_data_size(&mut self) -> usize;

    fn write_bytes(&mut self, child_addr: RemotePtr<Void>, buf: &[u8]);

    /// Call this after the tracee successfully makes a
    /// `prctl(PR_SET_NAME)` call to change the task name to the
    /// string pointed at in the tracee's address space by
    /// `child_addr`.
    fn update_prname(&mut self, child_addr: RemotePtr<Void>) {
        let mut buf = vec![0u8; 16];
        let res = self.read_bytes_fallible(child_addr, &mut buf);
        ed_assert!(self, res.is_ok());
        let bytes_read = res.unwrap();
        ed_assert!(self, bytes_read > 0);
        self.prname = OsString::from_vec(buf);
    }

    fn compute_trap_reasons(&mut self) -> TrapReasons;

    fn set_thread_area(&mut self, tls: RemotePtr<user_desc>);
}

fn is_signal_triggered_by_ptrace_interrupt(group_stop_sig: MaybeStopSignal) -> bool {
    // We sometimes see SIGSTOP at interrupts, though the
    // docs don't mention that.
    group_stop_sig == SIGTRAP || group_stop_sig == SIGSTOP
}

fn is_singlestep_resume(request: ResumeRequest) -> bool {
    request == ResumeRequest::ResumeSinglestep || request == ResumeRequest::ResumeSysemuSinglestep
}
