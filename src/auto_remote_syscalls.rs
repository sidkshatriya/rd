use crate::address_space::kernel_mapping::KernelMapping;
use crate::address_space::memory_range::MemoryRange;
use crate::auto_remote_syscalls::MemParamsEnabled::DisableMemoryParams;
use crate::kernel_abi::SupportedArch;
use crate::kernel_abi::{
    has_mmap2_syscall, is_clone_syscall, is_rt_sigaction_syscall, is_sigaction_syscall,
    is_signal_syscall, syscall_number_for_mmap, syscall_number_for_mmap2,
    syscall_number_for_munmap,
};
use crate::kernel_metadata::syscall_name;
use crate::log::LogLevel::LogDebug;
use crate::registers::Registers;
use crate::remote_code_ptr::RemoteCodePtr;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::task_interface::task::task::Task;
use crate::task_interface::task::ResumeRequest::{ResumeSinglestep, ResumeSyscall};
use crate::task_interface::task::TicksRequest::ResumeNoTicks;
use crate::task_interface::task::WaitRequest::ResumeWait;
use crate::task_interface::TaskInterface;
use crate::util::{is_kernel_trap, page_size};
use crate::wait_status::WaitStatus;
use libc::{
    pid_t, ESRCH, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, PROT_READ, PROT_WRITE, PTRACE_EVENT_EXIT,
    SIGTRAP,
};
use std::convert::TryInto;
use std::ops::{Deref, DerefMut};

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
    t: &'a mut dyn TaskInterface,
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
        t: &mut dyn TaskInterface,
        enable_mem_params: MemParamsEnabled,
    ) -> AutoRemoteSyscalls {
        AutoRemoteSyscalls {
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
            t,
        }
    }

    /// You mostly want to use this convenience method.
    pub fn new(t: &mut dyn TaskInterface) -> AutoRemoteSyscalls {
        Self::new_with_mem_params(t, MemParamsEnabled::EnableMemoryParams)
    }

    ///  If t's stack pointer doesn't look valid, temporarily adjust it to
    ///  the top of *some* stack area.
    pub fn maybe_fix_stack_pointer(&mut self) {
        if !self.t.session_interface().done_initial_exec() {
            return;
        }

        let last_stack_byte: RemotePtr<Void> = self.t.regs().sp() - 1usize;
        match self.t.vm().borrow().mapping_of(last_stack_byte) {
            Some(m) => {
                if is_usable_area(&m.map) && m.map.start() + 2048usize <= self.t.regs().sp() {
                    // 'sp' is in a stack region and there's plenty of space there. No need
                    // to fix anything.
                    return;
                }
            }
            None => (),
        }

        let mut found_stack: Option<MemoryRange> = None;
        for (_, m) in self.t.vm().borrow().maps() {
            if is_usable_area(&m.map) {
                // m.map Deref-s into a MemoryRange
                found_stack = Some(*m.map);
                break;
            }
        }

        if found_stack.is_none() {
            let remote = Self::new_with_mem_params(self.t, DisableMemoryParams);
            found_stack = Some(MemoryRange::new_range(
                remote.infallible_mmap_syscall(
                    RemotePtr::<Void>::new(),
                    4096,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0,
                ),
                4096,
            ));
            self.scratch_mem_was_mapped = true;
        }

        self.fixed_sp = Some(found_stack.unwrap().end());
        self.initial_regs.set_sp(self.fixed_sp.unwrap());
    }

    ///  "Initial" registers saved from the target task.
    pub fn initial_regs_ref(&self) -> &Registers {
        &self.initial_regs
    }
    /// In case changed registers need to be restored
    pub fn initial_regs_mut(&mut self) -> &mut Registers {
        &mut self.initial_regs
    }

    ///  Undo any preparations to make remote syscalls in the context of |t|.
    ///
    ///  This is usually called automatically by the destructor;
    ///  don't call it directly unless you really know what you'd
    ///  doing.  *ESPECIALLY* don't call this on a |t| other than
    ///  the one passed to the constructor, unless you really know
    ///  what you're doing.
    pub fn restore_state_to(&mut self, maybe_other_task: Option<&'a mut dyn TaskInterface>) {
        let some_t = maybe_other_task.unwrap_or(self.t);
        // Unmap our scratch region if required
        if self.scratch_mem_was_mapped {
            let remote = AutoRemoteSyscalls::new(some_t);
            remote.infallible_syscall(
                syscall_number_for_munmap(remote.arch()),
                vec![self.fixed_sp.unwrap().as_usize() - 4096, 4096],
            );
        }
        if !self.replaced_bytes.is_empty() {
            // XXX how to clean up if the task died and the address space is shared with live task?
            some_t.write_mem(
                self.initial_regs.ip().to_data_ptr(),
                &self.replaced_bytes,
                None,
            );
        }

        // Make a copy
        let mut regs = self.initial_regs;
        regs.set_ip(self.initial_ip);
        regs.set_sp(self.initial_sp);
        // Restore stomped registers.
        some_t.set_regs(&regs);
        some_t.set_status(self.restore_wait_status);
    }

    /// Make |syscallno| with variadic |args| (limited to 6 on
    /// x86).  Return the raw kernel return value.
    /// Returns -ESRCH if the process dies or has died.
    pub fn syscall(&mut self, syscallno: i32, args: Vec<usize>) -> isize {
        // Make a copy
        let mut callregs = self.initial_regs;
        debug_assert!(args.len() <= 6);
        for (i, arg) in args.iter().enumerate() {
            callregs.set_arg(i, *arg);
        }
        self.syscall_base(syscallno, &mut callregs)
    }

    pub fn infallible_syscall(&self, syscallno: i32, args: Vec<usize>) -> isize {
        unimplemented!()
    }

    pub fn infallible_syscall_ptr(&self, syscallno: i32, args: Vec<usize>) -> RemotePtr<Void> {
        unimplemented!()
    }

    /// Remote mmap syscalls are common and non-trivial due to the need to
    /// select either mmap2 or mmap.
    pub fn infallible_mmap_syscall(
        &self,
        addr: RemotePtr<Void>,
        length: usize,
        prot: i32,
        flags: i32,
        child_fd: i32,
        offset_pages: u64,
    ) -> RemotePtr<Void> {
        // The first syscall argument is called "arg 1", so
        // our syscall-arg-index template parameter starts
        // with "1".
        let ret: RemotePtr<Void> = if has_mmap2_syscall(self.arch()) {
            self.infallible_syscall_ptr(
                syscall_number_for_mmap2(self.arch()),
                vec![
                    addr.as_usize(),
                    length,
                    prot as _,
                    flags as _,
                    child_fd as isize as _,
                    offset_pages.try_into().unwrap(),
                ],
            )
        } else {
            self.infallible_syscall_ptr(
                syscall_number_for_mmap(self.arch()),
                vec![
                    addr.as_usize(),
                    length,
                    prot as _,
                    flags as _,
                    child_fd as isize as usize,
                    (offset_pages * page_size() as u64).try_into().unwrap(),
                ],
            )
        };

        if flags & MAP_FIXED == MAP_FIXED {
            ed_assert!(self.t, addr == ret, "MAP_FIXED at {} but got {}", addr, ret);
        }

        ret
    }

    /// @TODO Note: offset is signed.
    pub fn infallible_lseek_syscall(&self, fd: i32, offset: i64, whence: i32) -> i64 {
        unimplemented!()
    }

    /// The Task in the context of which we're making syscalls.
    pub fn task(&self) -> &Task {
        self.t
    }

    /// A small helper to get at the Task's arch.
    pub fn arch(&self) -> SupportedArch {
        self.t.arch()
    }

    /// Arranges for 'fd' to be transmitted to this process and returns
    /// our opened version of it.
    /// Returns a closed fd if the process dies or has died.
    pub fn retrieve_fd(&self, fd: i32) -> ScopedFd {
        unimplemented!()
    }

    /// Remotely invoke in |t| the specified syscall with the given
    /// arguments.  The arguments must of course be valid in |t|,
    /// and no checking of that is done by this function.
    ///
    /// The syscall is finished in |t| and the result is returned.
    pub fn syscall_base(&mut self, syscallno: i32, callregs: &mut Registers) -> isize {
        log!(LogDebug, "syscall {}", syscall_name(syscallno, self.arch()));

        if callregs.arg1_signed() == SIGTRAP as isize
            && self.use_singlestep_path
            && (is_sigaction_syscall(syscallno, self.arch())
                || is_rt_sigaction_syscall(syscallno, self.arch())
                || is_signal_syscall(syscallno, self.arch()))
        {
            // Don't use the fast path if we're about to set up a signal handler
            // for SIGTRAP!
            log!(
                LogDebug,
                "Disabling singlestep path due to SIGTRAP sigaction"
            );
            self.setup_path(false);
            callregs.set_ip(self.initial_regs.ip());
        }

        callregs.set_syscallno(syscallno as isize);
        self.t.set_regs(callregs);

        if self.use_singlestep_path {
            loop {
                self.t
                    .resume_execution(ResumeSinglestep, ResumeWait, ResumeNoTicks, None);
                log!(LogDebug, "Used singlestep path; status={}", self.t.status());
                // When a PTRACE_EVENT_EXIT is returned we don't update registers
                if self.t.ip() != callregs.ip() {
                    // We entered the syscall, so stop now
                    break;
                }
                if ignore_signal(self.t) {
                    // We were interrupted by a signal before we even entered the syscall
                    continue;
                }
                ed_assert!(self.t, false, "Unexpected status {}", self.t.status());
            }
        } else {
            self.t.enter_syscall();
            log!(LogDebug, "Used enter_syscall; status={}", self.t.status());
            // proceed to syscall exit
            self.t
                .resume_execution(ResumeSyscall, ResumeWait, ResumeNoTicks, None);
            log!(LogDebug, "syscall exit status={}", self.t.status());
        }
        loop {
            // If the syscall caused the task to exit, just stop now with that status.
            if self.t.ptrace_event() == Some(PTRACE_EVENT_EXIT) {
                self.restore_wait_status = self.t.status();
                break;
            }
            if self.t.status().is_syscall()
                || (self.t.stop_sig() == Some(SIGTRAP)
                    && is_kernel_trap(self.t.get_siginfo().si_code))
            {
                // If we got a SIGTRAP then we assume that's our singlestep and we're
                // done.
                break;
            }
            let mut new_tid: Option<pid_t> = None;
            if is_clone_syscall(syscallno, self.arch())
                && self.t.clone_syscall_is_complete(&mut new_tid, self.arch())
            {
                debug_assert!(new_tid.is_some());
                self.new_tid_ = new_tid;
                self.t
                    .resume_execution(ResumeSyscall, ResumeWait, ResumeNoTicks, None);
                log!(LogDebug, "got clone event; new status={}", self.t.status());
                continue;
            }
            if ignore_signal(self.t) {
                if self.t.regs().syscall_may_restart() {
                    self.t.enter_syscall();
                    log!(
                        LogDebug,
                        "signal ignored; restarting syscall, status={}",
                        self.t.status()
                    );
                    self.t
                        .resume_execution(ResumeSyscall, ResumeWait, ResumeNoTicks, None);
                    log!(LogDebug, "syscall exit status={}", self.t.status());
                    continue;
                }
                log!(LogDebug, "signal ignored");
                // We have been notified of a signal after a non-interruptible syscall
                // completed. Don't continue, we're done here.
                break;
            }
            ed_assert!(self.t, false, "Unexpected status {}", self.t.status());
            break;
        }

        if self.t.is_dying() {
            log!(LogDebug, "Task is dying, no status result");
            return -ESRCH as isize;
        } else {
            log!(LogDebug, "done, result={}", self.t.regs().syscall_result());
            return self.t.regs().syscall_result_signed();
        }
    }

    pub fn enable_mem_params(&self) -> MemParamsEnabled {
        self.enable_mem_params_
    }

    /// When the syscall is 'clone', this will be recovered from the
    /// PTRACE_EVENT_FORK/VFORK/CLONE.
    pub fn new_tid(&self) -> Option<pid_t> {
        self.new_tid_
    }

    /// Private methods start
    fn setup_path(&self, enable_singlestep_path: bool) {
        unimplemented!()
    }

    fn check_syscall_result(&self, ret: isize, syscallno: i32) {
        unimplemented!()
    }

    fn retrieve_fd_arch(&self, fd: i32) -> ScopedFd {
        unimplemented!()
    }
}

impl<'a> Drop for AutoRemoteSyscalls<'a> {
    fn drop(&mut self) {
        self.restore_state_to(None)
    }
}

fn is_usable_area(km: &KernelMapping) -> bool {
    (km.prot() & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE)
        && (km.flags() & MAP_PRIVATE == MAP_PRIVATE)
}

impl<'a> Deref for AutoRemoteSyscalls<'a> {
    type Target = Task;

    fn deref(&self) -> &Self::Target {
        self.t
    }
}

impl<'a> DerefMut for AutoRemoteSyscalls<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.t
    }
}

fn ignore_signal(t: &Task) -> bool {
    unimplemented!()
}
