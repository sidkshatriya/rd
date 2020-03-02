use crate::address_space::address_space::AddressSpace;
use crate::address_space::kernel_mapping::KernelMapping;
use crate::address_space::memory_range::MemoryRange;
use crate::address_space::{Enabled, Privileged, Traced};
use crate::auto_remote_syscalls::MemParamsEnabled::{DisableMemoryParams, EnableMemoryParams};
use crate::kernel_abi::{
    has_mmap2_syscall, is_clone_syscall, is_open_syscall, is_openat_syscall,
    is_rt_sigaction_syscall, is_sigaction_syscall, is_signal_syscall, syscall_number_for__llseek,
    syscall_number_for_lseek, syscall_number_for_mmap, syscall_number_for_mmap2,
    syscall_number_for_munmap,
};
use crate::kernel_abi::{syscall_instruction, SupportedArch};
use crate::kernel_metadata::{errno_name, signal_name, syscall_name};
use crate::log::LogLevel::LogDebug;
use crate::registers::Registers;
use crate::remote_code_ptr::RemoteCodePtr;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::session_interface::replay_session::ReplaySession;
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
use std::mem::size_of;
use std::ops::{Deref, DerefMut};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MemParamsEnabled {
    EnableMemoryParams,
    DisableMemoryParams,
}

/// Do NOT want Copy or Clone for this struct
pub struct AutoRestoreMem<'a, 'b> {
    remote: &'a mut AutoRemoteSyscalls<'b>,
    /// Address of tmp mem.
    addr: Option<RemotePtr<Void>>,
    /// Saved data
    data: Vec<u8>,
    /// (We keep this around for error checking.)
    saved_sp: RemotePtr<Void>,
    /// Length of tmp mem
    len: usize,
}

impl<'a, 'b> Deref for AutoRestoreMem<'a, 'b> {
    type Target = AutoRemoteSyscalls<'b>;

    fn deref(&self) -> &Self::Target {
        self.remote
    }
}

impl<'a, 'b> DerefMut for AutoRestoreMem<'a, 'b> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.remote
    }
}

impl<'a, 'b> Drop for AutoRestoreMem<'a, 'b> {
    fn drop(&mut self) {
        let new_sp = self.regs_ref().sp() + self.len;
        ed_assert!(self.remote.task_ref(), self.saved_sp == new_sp);

        if self.addr.is_some() {
            // XXX what should we do if this task was sigkilled but the address
            // space is used by other live tasks?
            self.remote
                .task_mut()
                .write_bytes_helper(self.addr.unwrap(), &self.data, None, None);
        }
        self.remote.regs_mut().set_sp(new_sp);
        // Make a copy
        let new_regs = *self.remote.regs_ref();
        self.remote.task_mut().set_regs(&new_regs);
    }
}

impl<'a, 'b> AutoRestoreMem<'a, 'b> {
    /// Write |mem| into address space of the Task prepared for
    /// remote syscalls in |remote|, in such a way that the write
    /// will be undone.  The address of the reserved mem space is
    /// available via |get|.
    /// If |mem| is None, data is not written, only the space is reserved.
    /// You must provide |len| whether or not you are passing in mem. The |len|
    /// needs to be consistent if mem is provided. i.e. mem.unwrap().len() == len
    pub fn new(
        remote: &'a mut AutoRemoteSyscalls<'b>,
        mem: Option<&[u8]>,
        len: usize,
    ) -> AutoRestoreMem<'a, 'b> {
        let mut v = Vec::with_capacity(len);
        v.resize(len, 0);
        let mut result = AutoRestoreMem {
            remote,
            addr: None,
            data: v,
            saved_sp: 0.into(),
            len,
        };
        mem.map(|s| debug_assert_eq!(len, s.len()));
        result.init(mem);
        result
    }

    /// Convenience constructor for pushing a C string |str|, including
    /// the trailing '\0' byte.
    pub fn push_cstr(remote: &'a mut AutoRemoteSyscalls<'b>, s: &str) -> AutoRestoreMem<'a, 'b> {
        unimplemented!()
    }
    /// Get a pointer to the reserved memory.
    /// Returns None if we failed.
    pub fn get(&self) -> Option<RemotePtr<Void>> {
        self.addr
    }

    fn init(&mut self, mem: Option<&[u8]>) {
        ed_assert!(
            self.remote.task_ref(),
            self.remote.enable_mem_params() == EnableMemoryParams,
            "Memory parameters were disabled"
        );

        self.saved_sp = self.remote.regs_ref().sp();

        let new_sp = self.remote.regs_ref().sp() - self.len;
        self.remote.initial_regs_mut().set_sp(new_sp);

        // Copy regs
        let remote_regs = *self.remote.regs_ref();
        self.remote.task_mut().set_regs(&remote_regs);
        self.addr = Some(remote_regs.sp());

        let mut ok = true;
        self.remote
            .task_ref()
            .read_bytes_helper(self.addr.unwrap(), &mut self.data, Some(&mut ok));
        // @TODO what do we do if ok is false due to read_bytes_helper call above?
        if mem.is_some() {
            self.remote.task_ref().write_bytes_helper(
                self.addr.unwrap(),
                mem.unwrap(),
                Some(&mut ok),
                None,
            );
        }
        if !ok {
            self.addr = None;
        }
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
            initial_regs: t.regs_ref().clone(),
            initial_ip: t.ip(),
            initial_sp: t.regs_ref().sp(),
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

        let last_stack_byte: RemotePtr<Void> = self.t.regs_ref().sp() - 1usize;
        match self.t.vm().borrow().mapping_of(last_stack_byte) {
            Some(m) => {
                if is_usable_area(&m.map) && m.map.start() + 2048usize <= self.t.regs_ref().sp() {
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
            let mut remote = Self::new_with_mem_params(self.t, DisableMemoryParams);
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
    /// Called regs() in rr
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
            let mut remote = AutoRemoteSyscalls::new(some_t);
            remote.infallible_syscall(
                syscall_number_for_munmap(remote.arch()),
                &vec![self.fixed_sp.unwrap().as_usize() - 4096, 4096],
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
    pub fn syscall(&mut self, syscallno: i32, args: &[usize]) -> isize {
        // Make a copy
        let mut callregs = self.initial_regs;
        debug_assert!(args.len() <= 6);
        for (i, arg) in args.iter().enumerate() {
            callregs.set_arg(i, *arg);
        }
        self.syscall_base(syscallno, &mut callregs)
    }

    pub fn infallible_syscall(&mut self, syscallno: i32, args: &[usize]) -> isize {
        let ret = self.syscall(syscallno, args);
        self.check_syscall_result(ret, syscallno);
        ret
    }

    pub fn infallible_syscall_ptr(&mut self, syscallno: i32, args: &[usize]) -> RemotePtr<Void> {
        (self.infallible_syscall(syscallno, args) as usize).into()
    }

    /// Remote mmap syscalls are common and non-trivial due to the need to
    /// select either mmap2 or mmap.
    pub fn infallible_mmap_syscall(
        &mut self,
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
                &vec![
                    addr.as_usize(),
                    length,
                    prot as _,
                    flags as _,
                    child_fd as _,
                    offset_pages.try_into().unwrap(),
                ],
            )
        } else {
            self.infallible_syscall_ptr(
                syscall_number_for_mmap(self.arch()),
                &vec![
                    addr.as_usize(),
                    length,
                    prot as _,
                    flags as _,
                    child_fd as _,
                    (offset_pages * page_size() as u64).try_into().unwrap(),
                ],
            )
        };

        if flags & MAP_FIXED == MAP_FIXED {
            ed_assert!(self.t, addr == ret, "MAP_FIXED at {} but got {}", addr, ret);
        }

        ret
    }

    /// Note: offset is signed.
    pub fn infallible_lseek_syscall(&mut self, fd: i32, offset: i64, whence: i32) -> isize {
        match self.arch() {
            SupportedArch::X86 => {
                let mut mem =
                    AutoRestoreMem::new(self, Some(&offset.to_le_bytes()), size_of::<i64>());
                let arch = mem.arch();
                let addr = mem.get().unwrap();
                // AutoRestoreMem DerefMut-s to AutoRemoteSyscalls
                mem.infallible_syscall(
                    syscall_number_for__llseek(arch),
                    &vec![
                        fd as usize,
                        (offset >> 32) as usize,
                        offset.try_into().unwrap(),
                        addr.as_usize(),
                        whence as usize,
                    ],
                );
                mem.t.read_val_mem::<isize>(RemotePtr::cast(addr), None)
            }
            SupportedArch::X64 => self.infallible_syscall(
                syscall_number_for_lseek(self.arch()),
                &vec![fd as usize, offset as usize, whence as usize],
            ),
        }
    }

    /// The Task in the context of which we're making syscalls.
    pub fn task_ref(&self) -> &dyn TaskInterface {
        self.t
    }

    pub fn task_mut(&mut self) -> &mut dyn TaskInterface {
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
                if self.t.regs_ref().syscall_may_restart() {
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
            -ESRCH as isize
        } else {
            log!(
                LogDebug,
                "done, result={}",
                self.t.regs_ref().syscall_result()
            );
            self.t.regs_ref().syscall_result_signed()
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
    fn setup_path(&mut self, enable_singlestep_path: bool) {
        if !self.replaced_bytes.is_empty() {
            // XXX what to do here to clean up if the task died unexpectedly?
            self.t.write_mem(
                self.initial_regs.ip().to_data_ptr::<u8>(),
                &self.replaced_bytes,
                None,
            );
        }

        let syscall_ip: RemoteCodePtr;
        self.use_singlestep_path = enable_singlestep_path;
        if self.use_singlestep_path {
            syscall_ip = AddressSpace::rd_page_syscall_entry_point(
                Traced::Untraced,
                Privileged::Privileged,
                Enabled::RecordingAndReplay,
                self.t.arch(),
            );
        } else {
            syscall_ip = self.t.vm().borrow().traced_syscall_ip();
        }
        self.initial_regs.set_ip(syscall_ip);

        // We need to make sure to clear any breakpoints or other alterations of
        // the syscall instruction we're using. Note that the tracee may have set its
        // own breakpoints or otherwise modified the instruction, so suspending our
        // own breakpoint is insufficient.
        let syscall = syscall_instruction(self.t.arch());
        let mut ok = true;
        self.replaced_bytes = self.t.read_mem(
            self.initial_regs.ip().to_data_ptr::<u8>(),
            syscall.len(),
            Some(&mut ok),
        );

        if !ok {
            // The task died
            return;
        }

        if self.replaced_bytes == syscall {
            self.replaced_bytes.clear();
        } else {
            self.t.write_mem(
                self.initial_regs.ip().to_data_ptr::<u8>(),
                syscall,
                Some(&mut ok),
            );
        }
    }

    fn check_syscall_result(&self, ret: isize, syscallno: i32) {
        if -4096 < ret && ret < 0 {
            let mut extra_msg: String = String::new();
            if is_open_syscall(syscallno, self.arch()) {
                extra_msg = format!(
                    "{} opening ",
                    self.t
                        .read_c_str(self.t.regs_ref().arg1().into())
                        .to_string_lossy()
                );
            } else if is_openat_syscall(syscallno, self.arch()) {
                extra_msg = format!(
                    "{} opening ",
                    self.t
                        .read_c_str(self.t.regs_ref().arg2().into())
                        .to_string_lossy()
                );
            }
            ed_assert!(
                self.t,
                false,
                "Syscall {} failed with errno {} {}",
                syscall_name(syscallno, self.arch()),
                errno_name(-ret as i32),
                extra_msg
            );
        }
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

fn ignore_signal(t: &dyn TaskInterface) -> bool {
    let sig = t.stop_sig();
    if sig.is_none() {
        return false;
    }

    if t.session_interface().is_replaying() {
        if ReplaySession::is_ignored_signal(sig.unwrap()) {
            return true;
        }
    } else if t.session_interface().is_recording() {
        let rt = t.as_record_task().unwrap();
        if sig.unwrap()
            != rt
                .session_interface()
                .as_record()
                .unwrap()
                .syscallbuf_desched_sig()
        {
            rt.stash_sig();
        }
        return true;
    }
    ed_assert!(t, false, "Unexpected signal {}", signal_name(sig.unwrap()));
    return false;
}
