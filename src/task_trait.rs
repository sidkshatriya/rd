use crate::kernel_abi::SupportedArch;
use crate::registers::Registers;
use crate::remote_ptr::RemotePtr;
use crate::session::session::Session;
use crate::task::task::CloneReason;
use crate::task::task::Task;
use crate::task::{ResumeRequest, TicksRequest, WaitRequest};
use libc::pid_t;
use std::hash::{Hash, Hasher};

/// @TODO should we store *const dyn TaskTrait?
#[derive(Copy, Clone)]
pub struct TaskTraitRawPtr(pub *mut dyn TaskTrait);

impl PartialEq for TaskTraitRawPtr {
    fn eq(&self, other: &Self) -> bool {
        // If the addresses of the dyn TaskTrait ptrs are same then they are the same task.
        self.0 as *const u8 as usize == other.0 as *const u8 as usize
    }
}

impl Eq for TaskTraitRawPtr {}

impl Hash for TaskTraitRawPtr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let addr = self.0 as *const u8 as usize;
        // The hash is the hash of the address of the task (dyn TaskTrait).
        addr.hash(state);
    }
}

pub trait TaskTrait {
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
        unimplemented!()
    }

    /// Called when SYS_rrcall_init_preload has happened.
    fn at_preload_init(&self);

    /// (Note: Methods following this are protected in the rr implementation)
    /// Return a new Task cloned from |p|.  |flags| are a set of
    /// CloneFlags (see above) that determine which resources are
    /// shared or copied to the new child.  |new_tid| is the tid
    /// assigned to the new task by the kernel.  |new_rec_tid| is
    /// only relevant to replay, and is the pid that was assigned
    /// to the task during recording.
    fn clone(
        &self,
        reason: CloneReason,
        flags: i32,
        stack: RemotePtr<u8>,
        tls: RemotePtr<u8>,
        cleartid_addr: RemotePtr<i32>,
        new_tid: pid_t,
        new_rec_tid: pid_t,
        new_serial: u32,
        other_session: Option<&Session>,
    ) -> &Task;

    /// Internal method called after the first wait() during a clone().
    fn post_wait_clone(&self, t: &Task, flags: i32) {}

    /// Internal method called after the clone to fix up the new address space.
    fn post_vm_clone(&self, reason: CloneReason, flags: i32, origin: &Task) -> bool {
        unimplemented!()
    }
}
