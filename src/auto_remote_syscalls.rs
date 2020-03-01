use crate::registers::Registers;
use crate::remote_code_ptr::RemoteCodePtr;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::task_interface::task::task::Task;
use crate::wait_status::WaitStatus;
use libc::pid_t;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MemParamsEnabled {
    EnableMemoryParams,
    DisableMemoryParams,
}

pub struct AutoRestoreMem {}

impl AutoRestoreMem {
    /// Convenience constructor for pushing a C string |str|, including
    /// the trailing '\0' byte.
    pub fn push_cstr(remote: &AutoRemoteSyscalls, s: &str) -> AutoRestoreMem {
        unimplemented!()
    }
    /// Get a pointer to the reserved memory.
    /// Returns None if we failed.
    pub fn get(&self) -> Option<RemotePtr<Void>> {
        unimplemented!()
    }
}

/// RAII helper to prepare a Task for remote syscalls and undo any
/// preparation upon going out of scope. Note that this restores register
/// values when going out of scope, so *all* changes to Task's register
/// state are lost.
///
/// Note: We do NOT want Copy or Clone.
pub struct AutoRemoteSyscalls<'a> {
    task: &'a Task,
    initial_regs: Registers,
    initial_ip: RemoteCodePtr,
    initial_sp: RemotePtr<Void>,
    /// This is different from rr where null is used.
    fixed_sp: Option<RemotePtr<Void>>,
    replaced_bytes: Vec<u8>,
    restore_wait_status: WaitStatus,

    /// This is different from rr where -1 is used for not set value.
    new_tid_: Option<pid_t>,
    /// Whether we had to mmap a scratch region because none was found
    scratch_mem_was_mapped: bool,
    use_singlestep_path: bool,

    enable_mem_params_: MemParamsEnabled,
}

impl<'a> AutoRemoteSyscalls<'a> {
    /// Prepare |t| for a series of remote syscalls.
    ///
    /// NBBB!  Before preparing for a series of remote syscalls,
    /// the caller *must* ensure the callee will not receive any
    /// signals.  This code does not attempt to deal with signals.
    pub fn new_with_mem_params(
        t: &Task,
        enable_mem_params: MemParamsEnabled,
    ) -> AutoRemoteSyscalls {
        AutoRemoteSyscalls {
            task: t,
            initial_regs: t.regs().clone(),
            initial_ip: t.ip(),
            initial_sp: t.regs().sp(),
            fixed_sp: None,
            replaced_bytes: vec![],
            restore_wait_status: t.status(),
            new_tid_: None,
            scratch_mem_was_mapped: false,
            use_singlestep_path: false,
            enable_mem_params_: enable_mem_params,
        }
    }

    /// You mostly want to use this convenience method.
    pub fn new(t: &Task) -> AutoRemoteSyscalls {
        Self::new_with_mem_params(t, MemParamsEnabled::EnableMemoryParams)
    }

    ///  If t's stack pointer doesn't look valid, temporarily adjust it to
    ///  the top of *some* stack area.
    pub fn maybe_fix_stack_pointer() {
        unimplemented!()
    }

    ///  "Initial" registers saved from the target task.
    pub fn regs(&self) -> &Registers {
        &self.initial_regs
    }
    /// In case changed registers need to be restored
    pub fn regs_mut(&mut self) -> &Registers {
        &mut self.initial_regs
    }

    ///  Undo any preparations to make remote syscalls in the context of |t|.
    ///
    ///  This is usually called automatically by the destructor;
    ///  don't call it directly unless you really know what you'd
    ///  doing.  *ESPECIALLY* don't call this on a |t| other than
    ///  the one passed to the contructor, unless you really know
    ///  what you're doing.
    pub fn restore_state_to(&self, t: &Task) {
        unimplemented!()
    }

    /// Make |syscallno| with variadic |args| (limited to 6 on
    /// x86).  Return the raw kernel return value.
    /// Returns -ESRCH if the process dies or has died.
    pub fn syscall1(&self, syscallno: i32, arg1: usize) -> isize {
        unimplemented!()
    }
    pub fn syscall2(&self, syscallno: i32, arg1: usize, arg2: usize) -> isize {
        unimplemented!()
    }

    pub fn syscall3(&self, syscallno: i32, arg1: usize, arg2: usize, arg3: usize) -> isize {
        unimplemented!()
    }

    pub fn syscall4(
        &self,
        syscallno: i32,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
    ) -> isize {
        unimplemented!()
    }

    pub fn syscall5(
        &self,
        syscallno: i32,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) -> isize {
        unimplemented!()
    }
    pub fn syscall6(
        &self,
        syscallno: i32,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) -> isize {
        unimplemented!()
    }

    /// Arranges for 'fd' to be transmitted to this process and returns
    /// our opened version of it.
    /// Returns a closed fd if the process dies or has died.
    pub fn retrieve_fd(&self, fd: i32) -> ScopedFd {
        unimplemented!()
    }
}

impl<'a> Drop for AutoRemoteSyscalls<'a> {
    fn drop(&mut self) {
        self.restore_state_to(self.task)
    }
}
