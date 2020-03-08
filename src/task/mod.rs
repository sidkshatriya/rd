use crate::kernel_abi::SupportedArch;
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::session::Session;
use crate::task::record_task::record_task::RecordTask;
use crate::task::replay_task::ReplayTask;
use crate::task::task_inner::task_inner::TaskInner;
use crate::task::task_inner::task_inner::{CloneReason, WriteFlags};
use crate::task::task_inner::{ResumeRequest, TicksRequest, WaitRequest};
use crate::wait_status::WaitStatus;
use libc::pid_t;
use std::cell::RefCell;
use std::ffi::CString;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::ops::Deref;
use std::ops::DerefMut;
use std::rc::{Rc, Weak};

pub mod common;
pub mod record_task;
pub mod replay_task;
pub mod task_inner;

pub type TaskSharedPtr = Rc<RefCell<Box<dyn Task>>>;
pub type TaskSharedWeakPtr = Weak<RefCell<Box<dyn Task>>>;

#[derive(Clone)]
pub struct TaskPtr(pub TaskSharedWeakPtr);

impl PartialEq for TaskPtr {
    fn eq(&self, other: &Self) -> bool {
        // If the addresses of the dyn Task ptrs are same then they are the same task.
        self.0.upgrade().unwrap().as_ptr() as *const u8 as usize
            == other.0.upgrade().unwrap().as_ptr() as *const u8 as usize
    }
}

impl Eq for TaskPtr {}

impl Hash for TaskPtr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let addr = self.0.upgrade().unwrap().as_ptr() as *const u8 as usize;
        // The hash is the hash of the address of the task (dyn Task).
        addr.hash(state);
    }
}

impl Deref for TaskPtr {
    type Target = TaskSharedWeakPtr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait Task: DerefMut<Target = TaskInner> {
    fn as_task_inner(&self) -> &TaskInner;
    fn as_task_inner_mut(&mut self) -> &mut TaskInner;

    fn as_record_task(&self) -> Option<&RecordTask>;
    fn as_record_task_mut(&mut self) -> Option<&mut RecordTask>;

    fn as_replay_task(&self) -> Option<&ReplayTask>;
    fn as_replay_task_mut(&mut self) -> Option<&mut ReplayTask>;

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
        resume_req: ResumeRequest,
        wait_req: WaitRequest,
        ticks_req: TicksRequest,
        sig: i32,
    ) {
    }

    /// Hook called by `did_waitpid`.
    fn did_wait(&self) {}

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
        flags: i32,
        stack: RemotePtr<Void>,
        tls: RemotePtr<Void>,
        cleartid_addr: RemotePtr<i32>,
        new_tid: pid_t,
        new_rec_tid: pid_t,
        new_serial: u32,
        other_session: Option<&dyn Session>,
    ) -> &TaskInner;

    /// Internal method called after the first wait() during a clone().
    fn post_wait_clone(&self, t: &TaskInner, flags: i32) {}

    /// Internal method called after the clone to fix up the new address space.
    fn post_vm_clone(&self, reason: CloneReason, flags: i32, origin: &TaskInner) -> bool {
        unimplemented!()
    }

    /// Dump attributes of this process, including pending events,
    /// to `out`, which defaults to LOG_FILE.
    fn dump(&self, out: Option<&dyn Write>) {
        unimplemented!()
    }

    /// Resume execution `how`, deliverying `sig` if nonzero.
    /// After resuming, `wait_how`. In replay, reset hpcs and
    /// request a tick period of tick_period. The default value
    /// of tick_period is 0, which means effectively infinite.
    /// If interrupt_after_elapsed is nonzero, we interrupt the task
    /// after that many seconds have elapsed.
    ///
    /// All tracee execution goes through here.
    fn resume_execution(
        &self,
        how: ResumeRequest,
        wait_how: WaitRequest,
        tick_period: TicksRequest,
        sig: Option<i32>,
    ) {
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

    /// Force the wait status of this to `status`, as if
    /// `wait()/try_wait()` had returned it. Call this whenever a waitpid
    /// returned activity for this past.
    fn did_waitpid(&self, status: WaitStatus) {
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
    fn wait(&self, interrupt_after_elapsed: Option<f64>) {
        unimplemented!()
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
