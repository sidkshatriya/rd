use crate::address_space::address_space::{AddressSpace, Mapping};
use crate::address_space::kernel_mapping::KernelMapping;
use crate::address_space::memory_range::MemoryRange;
use crate::address_space::{Enabled, Privileged, Traced};
use crate::arch::Architecture;
use crate::auto_remote_syscalls::MemParamsEnabled::{DisableMemoryParams, EnableMemoryParams};
use crate::kernel_abi::RD_NATIVE_ARCH;
use crate::kernel_abi::{
    has_mmap2_syscall, has_socketcall_syscall, is_clone_syscall, is_open_syscall,
    is_openat_syscall, is_rt_sigaction_syscall, is_sigaction_syscall, is_signal_syscall,
    syscall_number_for__llseek, syscall_number_for_close, syscall_number_for_lseek,
    syscall_number_for_mmap, syscall_number_for_mmap2, syscall_number_for_munmap,
    syscall_number_for_openat, syscall_number_for_sendmsg, syscall_number_for_socketcall,
};
use crate::kernel_abi::{syscall_instruction, SupportedArch};
use crate::kernel_metadata::{errno_name, signal_name, syscall_name};
use crate::log::LogLevel::LogDebug;
use crate::monitored_shared_memory::MonitoredSharedMemorySharedPtr;
use crate::rd::RD_RESERVED_ROOT_DIR_FD;
use crate::registers::Registers;
use crate::remote_code_ptr::RemoteCodePtr;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::session::replay_session::ReplaySession;
use crate::session::session_inner::session_inner::SessionInner;
use crate::task::task_inner::task_inner::TaskInner;
use crate::task::task_inner::ResumeRequest::{ResumeSinglestep, ResumeSyscall};
use crate::task::task_inner::TicksRequest::ResumeNoTicks;
use crate::task::task_inner::WaitRequest::ResumeWait;
use crate::task::Task;
use crate::util::{is_kernel_trap, page_size, resize_shmem_segment, tmp_dir};
use crate::wait_status::WaitStatus;
use core::ffi::c_void;
use libc::{
    pid_t, SYS_sendmsg, ESRCH, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, MAP_SHARED, O_CLOEXEC,
    O_CREAT, O_EXCL, O_RDWR, PROT_READ, PROT_WRITE, PTRACE_EVENT_EXIT, SCM_RIGHTS, SIGTRAP,
    SOL_SOCKET,
};
use nix::sys::stat::fstat;
use nix::unistd::unlink;
use nix::NixPath;
use std::cmp::max;
use std::convert::TryInto;
use std::mem::{size_of, size_of_val, transmute_copy, zeroed};
use std::ops::{Deref, DerefMut};
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum MemParamsEnabled {
    EnableMemoryParams,
    DisableMemoryParams,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum PreserveContents {
    PreserveContents,
    DiscardContents,
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
        ed_assert!(self.remote.task(), self.saved_sp == new_sp);

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
    /// Write `mem` into address space of the Task prepared for
    /// remote syscalls in `remote`, in such a way that the write
    /// will be undone.  The address of the reserved mem space is
    /// available via `get`.
    /// If `mem` is None, data is not written, only the space is reserved.
    /// You must provide `len` whether or not you are passing in mem. The `len`
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
            // We don't need an Option here because init will always add a value.
            saved_sp: 0.into(),
            len,
        };
        mem.map(|s| debug_assert_eq!(len, s.len()));
        result.init(mem);
        result
    }

    /// Convenience constructor for pushing a C string `str`, including
    /// the trailing '\0' byte.
    pub fn push_cstr<P: ?Sized + NixPath>(
        remote: &'a mut AutoRemoteSyscalls<'b>,
        s: &P,
    ) -> AutoRestoreMem<'a, 'b> {
        // rr assumes the construction always succeeds. We don't for now.
        s.with_nix_path(move |c| Self::new(remote, Some(c.to_bytes_with_nul()), c.len()))
            .unwrap()
    }

    /// Get a pointer to the reserved memory.
    /// Returns None if we failed.
    pub fn get(&self) -> Option<RemotePtr<Void>> {
        self.addr
    }

    fn init(&mut self, mem: Option<&[u8]>) {
        ed_assert!(
            self.remote.task(),
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
            .task_mut()
            .read_bytes_helper(self.addr.unwrap(), &mut self.data, Some(&mut ok));
        // @TODO what do we do if ok is false due to read_bytes_helper call above?
        if mem.is_some() {
            self.remote.task().write_bytes_helper(
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

    /// Return size of reserved memory buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// RAII helper to prepare a Task for remote syscalls and undo any
/// preparation upon going out of scope. Note that this restores register
/// values when going out of scope, so *all* changes to Task's register
/// state are lost.
///
/// Note: We do NOT want Copy or Clone.
pub struct AutoRemoteSyscalls<'a> {
    t: &'a mut dyn Task,
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
    /// Prepare `t` for a series of remote syscalls.
    ///
    /// NBBB!  Before preparing for a series of remote syscalls,
    /// the caller *must* ensure the callee will not receive any
    /// signals.  This code does not attempt to deal with signals.
    ///
    /// Note: In case you're wondering why this takes &mut dyn Task
    /// instead of &mut TaskInner, that is because of the call to
    /// resume_execution() (in AutoRemoteSyscalls::syscall_base()) calls will_resume_execution()
    /// which is a "virtual" method -- effectively in our rust implementation
    /// that means that will_resume_execution() must live in a Task trait impl
    /// And since struct TaskInner does NOT (deliberately) impl the Task trait
    /// AutoRemoteSyscalls needs to take a &mut dyn Task instead of &mut TaskInner.
    pub fn new_with_mem_params(
        t: &mut dyn Task,
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
    pub fn new(t: &mut dyn Task) -> AutoRemoteSyscalls {
        Self::new_with_mem_params(t, MemParamsEnabled::EnableMemoryParams)
    }

    ///  If t's stack pointer doesn't look valid, temporarily adjust it to
    ///  the top of *some* stack area.
    pub fn maybe_fix_stack_pointer(&mut self) {
        if !self.t.session().borrow().done_initial_exec() {
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

    ///  Undo any preparations to make remote syscalls in the context of `t`.
    ///
    ///  This is usually called automatically by the destructor;
    ///  don't call it directly unless you really know what you'd
    ///  doing.  *ESPECIALLY* don't call this on a `t` other than
    ///  the one passed to the constructor, unless you really know
    ///  what you're doing.
    pub fn restore_state_to(&mut self, maybe_other_task: Option<&'a mut dyn Task>) {
        let some_t = maybe_other_task.unwrap_or(self.t);
        // Unmap our scratch region if required
        if self.scratch_mem_was_mapped {
            let mut remote = AutoRemoteSyscalls::new(some_t);
            remote.infallible_syscall(
                syscall_number_for_munmap(remote.arch()),
                &[self.fixed_sp.unwrap().as_usize() - 4096, 4096],
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

    /// Make `syscallno` with variadic `args` (limited to 6 on
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
                &[
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
                &[
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
                    &[
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
                &[fd as usize, offset as usize, whence as usize],
            ),
        }
    }

    /// The Task in the context of which we're making syscalls.
    pub fn task(&self) -> &dyn Task {
        self.t
    }

    pub fn task_mut(&mut self) -> &mut dyn Task {
        self.t
    }

    /// A small helper to get at the Task's arch.
    pub fn arch(&self) -> SupportedArch {
        self.t.arch()
    }

    /// Arranges for 'fd' to be transmitted to this process and returns
    /// our opened version of it.
    /// Returns a closed fd if the process dies or has died.
    pub fn retrieve_fd_arch<Arch: Architecture>(&mut self, fd: i32) -> ScopedFd {
        let mut data_length: usize = max(
            reserve::<Arch::sockaddr_un>(),
            reserve::<Arch::msghdr>()
                // This is the aligned space. Don't need to align again.
                + rd_kernel_abi_arch_function!(cmsg_space, Arch::arch(), size_of_val(&fd))
                + reserve::<Arch::iovec>(),
        );
        if has_socketcall_syscall(Arch::arch()) {
            data_length += reserve::<SocketcallArgs<Arch>>();
        }
        let mut remote_buf = AutoRestoreMem::new(self, None, data_length);
        if remote_buf.get().is_none() {
            // Task must be dead
            return ScopedFd::new();
        }

        let mut sc_args_end: RemotePtr<Void> = remote_buf.get().unwrap();
        let mut maybe_sc_args: Option<RemotePtr<SocketcallArgs<Arch>>> = None;
        if has_socketcall_syscall(Arch::arch()) {
            maybe_sc_args = Some(allocate::<SocketcallArgs<Arch>>(
                &mut sc_args_end,
                &remote_buf,
            ));
        }

        let child_sock = remote_buf.task().session().borrow().tracee_fd_number();
        let child_syscall_result: isize =
            child_sendmsg(&mut remote_buf, maybe_sc_args, sc_args_end, child_sock, fd);
        if child_syscall_result == -ESRCH as isize {
            return ScopedFd::new();
        }

        ed_assert!(
            remote_buf.task(),
            child_syscall_result > 0,
            "Failed to sendmsg() in tracee; err={}",
            errno_name((-child_syscall_result).try_into().unwrap())
        );

        let our_fd: i32 = recvmsg_socket(
            &remote_buf
                .task()
                .session()
                .borrow()
                .tracee_socket_fd()
                .borrow(),
        );
        ScopedFd::from_raw(our_fd)
    }

    /// Remotely invoke in `t` the specified syscall with the given
    /// arguments.  The arguments must of course be valid in `t`,
    /// and no checking of that is done by this function.
    ///
    /// The syscall is finished in `t` and the result is returned.
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

    fn check_syscall_result(&mut self, ret: isize, syscallno: i32) {
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

    pub fn retrieve_fd(&mut self, fd: i32) -> ScopedFd {
        rd_arch_function!(self, retrieve_fd_arch, self.arch(), fd)
    }

    /// If None is provided for |tracee_prot`, PROT_READ ` PROT_WRITE is assumed.
    /// If None is provided for `tracee_flags`, 0 is assumed
    /// If None is provided for `monitored` it is assumed that there is no memory monitor.
    /// If None is provided for `map_hint` it is assumed that we DONT use MAP_FIXED
    pub fn create_shared_mmap(
        &mut self,
        size: usize,
        map_hint: Option<RemotePtr<Void>>,
        name: &str,
        maybe_tracee_prot: Option<i32>,
        maybe_tracee_flags: Option<i32>,
        monitored: Option<MonitoredSharedMemorySharedPtr>,
    ) -> KernelMapping {
        static NONCE: AtomicUsize = AtomicUsize::new(0);
        let tracee_prot = maybe_tracee_prot.unwrap_or(PROT_READ | PROT_WRITE);
        let tracee_flags = maybe_tracee_flags.unwrap_or(0);

        // Create the segment we'll share with the tracee.
        let path: String = format!(
            "{}{}{}-{}-{}",
            tmp_dir(),
            SessionInner::rd_mapping_prefix(),
            name,
            self.task().real_tgid(),
            NONCE.fetch_add(1, Ordering::SeqCst)
        );

        // Let the child create the shmem block and then send the fd back to us.
        // This lets us avoid having to make the file world-writeable so that
        // the child can read it when it's in a different user namespace (which
        // would be a security hole, letting other users abuse rr users).
        let child_shmem_fd: i32;
        {
            let arch = self.arch();
            let mut child_path = AutoRestoreMem::push_cstr(self, path.as_str());
            let path_addr_val = (child_path.get().unwrap() + 1usize).as_usize();
            // skip leading '/' since we want the path to be relative to the root fd
            child_shmem_fd = child_path
                .infallible_syscall(
                    syscall_number_for_openat(arch),
                    &[
                        RD_RESERVED_ROOT_DIR_FD as _,
                        path_addr_val,
                        (O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC) as usize,
                        0o600,
                    ],
                )
                .try_into()
                .unwrap();
        }

        // Remove the fs name so that we don't have to worry about cleaning
        // up this segment in error conditions.
        //
        // rr swallows any potential error but we don't for now.
        unlink(path.as_str()).unwrap();

        let mut shmem_fd: ScopedFd = self.retrieve_fd(child_shmem_fd);
        resize_shmem_segment(&shmem_fd, size);
        log!(LogDebug, "created shmem segment {}", path);

        // Map the segment in ours and the tracee's address spaces.
        let mut flags = MAP_SHARED;
        let map_addr = unsafe {
            libc::mmap(
                0 as *mut c_void,
                size,
                PROT_READ | PROT_WRITE,
                flags,
                shmem_fd.as_raw(),
                0,
            )
        };
        if map_addr as isize == -1 {
            fatal!("Failed to mmap shmem region");
        }
        if map_hint.is_some() {
            flags |= MAP_FIXED;
        }
        let child_map_addr = self.infallible_mmap_syscall(
            map_hint.unwrap(),
            size,
            tracee_prot,
            flags,
            child_shmem_fd,
            0,
        );

        let maybe_st = fstat(shmem_fd.as_raw());
        ed_assert!(self.task(), maybe_st.is_ok());
        let st = maybe_st.unwrap();
        let km: KernelMapping = self.task().vm().borrow_mut().map(
            self.task(),
            child_map_addr,
            size,
            tracee_prot,
            flags | tracee_flags,
            0,
            &path,
            st.st_dev,
            st.st_ino,
            None,
            None,
            None,
            map_addr,
            monitored,
        );

        shmem_fd.close();
        self.infallible_syscall(
            syscall_number_for_close(self.arch()),
            &[child_shmem_fd as _],
        );
        km
    }

    /// As this stands, it looks to be a move as far as m is concerned.
    pub fn make_private_shared(&self, m: Mapping) -> bool {
        unimplemented!()
    }

    /// Recreate an mmap region that is shared between rr and the tracee. The
    /// caller
    /// is responsible for recreating the data in the new mmap, if `preserve` is
    /// DiscardContents.
    /// OK to call this while 'm' references one of the mappings in remote's
    /// AddressSpace
    /// If None is provided for `preserve` then DiscardContents is assumed
    /// If None is provided for `monitored` it is assumed that there is no memory monitor.
    pub fn recreate_shared_mmap(
        &self,
        m: &Mapping,
        option_preserve: Option<PreserveContents>,
        monitored: Option<MonitoredSharedMemorySharedPtr>,
    ) -> &'a Mapping {
        unimplemented!()
    }

    /// Takes a mapping and replaces it by one that is shared between rr and
    /// the tracee. The caller is responsible for filling the contents of the
    /// new mapping.
    /// If None is provided for `monitored` it is assumed that there is no memory monitor.
    pub fn steal_mapping(
        &self,
        m: &Mapping,
        monitored: Option<MonitoredSharedMemorySharedPtr>,
    ) -> &'a Mapping {
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
    type Target = TaskInner;

    fn deref(&self) -> &Self::Target {
        self.t
    }
}

impl<'a> DerefMut for AutoRemoteSyscalls<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.t
    }
}

fn ignore_signal(t: &dyn Task) -> bool {
    let sig = t.stop_sig();
    if sig.is_none() {
        return false;
    }

    if t.session().borrow().is_replaying() {
        if ReplaySession::is_ignored_signal(sig.unwrap()) {
            return true;
        }
    } else if t.session().borrow().is_recording() {
        let rt = t.as_record_task().unwrap();
        if sig.unwrap()
            != rt
                .session()
                .borrow()
                .as_record()
                .unwrap()
                .syscallbuf_desched_sig()
        {
            rt.stash_sig();
        }
        return true;
    }
    ed_assert!(t, false, "Unexpected signal {}", signal_name(sig.unwrap()));
    false
}

/// The ABI of the socketcall syscall is a nightmare; the first arg to
/// the kernel is the sub-operation, and the second argument is a
/// pointer to the args.  The args depend on the sub-op.
#[repr(C, packed)]
struct SocketcallArgs<Arch: Architecture> {
    args: [Arch::signed_long; 3],
}

/// We derive Copy and Clone manually as the struct is marked packed.
impl<Arch: Architecture> Clone for SocketcallArgs<Arch> {
    fn clone(&self) -> Self {
        SocketcallArgs {
            // Wrapped in unsafe because of:
            // warning: borrow of packed field is unsafe and requires unsafe function or block (error E0133)
            args: unsafe { self.args.clone() },
        }
    }
}

impl<Arch: Architecture> Copy for SocketcallArgs<Arch> {}

/// The rr version takes a `bool ok` argument
/// This version simple returns a bool for success/failure
fn write_socketcall_args<Arch: Architecture>(
    t: &dyn Task,
    remote_mem: RemotePtr<SocketcallArgs<Arch>>,
    arg1: Arch::signed_long,
    arg2: Arch::signed_long,
    arg3: Arch::signed_long,
) -> bool {
    let mut ok: bool = false;
    let sc_args = [arg1, arg2, arg3];
    t.write_mem(RemotePtr::cast(remote_mem), &sc_args, Some(&mut ok));
    ok
}

const fn align_size(size: usize) -> usize {
    let align_amount = size_of::<usize>();
    (size + align_amount - 1) & !(align_amount - 1)
}

/// Called allocate() in rr
fn allocate_bytes(
    buf_end: &mut RemotePtr<Void>,
    remote_buf: &AutoRestoreMem,
    size: usize,
) -> RemotePtr<Void> {
    let r = *buf_end;
    // Note the mutation of buf_end here. A sort of bump pointer.
    *buf_end = *buf_end + align_size(size);
    if (*buf_end - remote_buf.get().unwrap()) > remote_buf.len() {
        fatal!("overflow");
    }
    // The data can be placed at r
    r
}

fn allocate<T>(buf_end: &mut RemotePtr<Void>, remote_buf: &AutoRestoreMem) -> RemotePtr<T> {
    RemotePtr::cast(allocate_bytes(buf_end, remote_buf, size_of::<T>()))
}

/// We don't need an AutoRemoteSyscall like rr does.
/// AutoRestoreMem Deref-s/DerefMut-s to AutoRemoteSyscalls
fn child_sendmsg<Arch: Architecture>(
    remote_buf: &mut AutoRestoreMem,
    sc_args: Option<RemotePtr<SocketcallArgs<Arch>>>,
    mut buf_end: RemotePtr<Void>,
    child_sock: i32,
    fd: i32,
) -> isize {
    let cmsgbuf_size = rd_kernel_abi_arch_function!(cmsg_space, Arch::arch(), size_of_val(&fd));
    let mut cmsgbuf = vec![0u8; cmsgbuf_size];

    // Pull the puppet strings to have the child send its fd
    // to us.  Similarly to above, we DONT_WAIT on the
    // call to finish, since it's likely not defined whether the
    // sendmsg() may block on our recvmsg()ing what the tracee
    // sent us (in which case we would deadlock with the tracee).
    // We call sendmsg on child socket, but first we have to prepare a lot of
    // data.
    let remote_msg = allocate::<Arch::msghdr>(&mut buf_end, remote_buf);
    let remote_msgdata = allocate::<Arch::iovec>(&mut buf_end, remote_buf);
    let remote_cmsgbuf = allocate_bytes(&mut buf_end, remote_buf, cmsgbuf_size);

    let mut ok = true;
    let mut msg = Arch::msghdr::default();
    Arch::set_msghdr(&mut msg, remote_cmsgbuf, cmsgbuf_size, remote_msgdata, 1);
    remote_buf.t.write_val_mem(remote_msg, &msg, Some(&mut ok));

    let cmsg_data_off = rd_kernel_abi_arch_function!(cmsg_data_offset, Arch::arch());
    let mut cmsghdr = Arch::cmsghdr::default();
    Arch::set_csmsghdr(
        &mut cmsghdr,
        rd_kernel_abi_arch_function!(cmsg_len, Arch::arch(), size_of_val(&fd)),
        SOL_SOCKET,
        SCM_RIGHTS,
    );
    // Copy the cmsghdr into the cmsgbuf
    unsafe {
        copy_nonoverlapping(
            &cmsghdr as *const _ as *const u8,
            cmsgbuf.as_mut_ptr(),
            size_of::<Arch::cmsghdr>(),
        );
    }
    // Copy the fd into the cmsgbuf
    cmsgbuf
        .get_mut(cmsg_data_off..cmsg_data_off + size_of_val(&fd))
        .unwrap()
        .copy_from_slice(&fd.to_le_bytes());

    remote_buf
        .task()
        .write_mem(remote_cmsgbuf, &cmsgbuf, Some(&mut ok));

    if !ok {
        return -ESRCH as isize;
    }

    let arch = remote_buf.arch();
    if sc_args.is_none() {
        return remote_buf.syscall(
            syscall_number_for_sendmsg(arch),
            &[child_sock as usize, remote_msg.as_usize(), 0],
        );
    }

    let success = write_socketcall_args::<Arch>(
        remote_buf.task(),
        sc_args.unwrap(),
        child_sock.into(),
        Arch::to_signed_long(remote_msg.as_usize()),
        0i32.into(),
    );

    if !success {
        return -ESRCH as isize;
    }

    remote_buf.syscall(
        syscall_number_for_socketcall(arch),
        &[SYS_sendmsg as _, sc_args.unwrap().as_usize()],
    )
}

fn recvmsg_socket(sock: &ScopedFd) -> i32 {
    let mut received_data: u8 = 0;
    let mut msgdata: libc::iovec = unsafe { zeroed() };
    msgdata.iov_base = &mut received_data as *mut u8 as *mut c_void;
    msgdata.iov_len = 1;

    // The i32 is our fd
    let cmsgbuf_size = rd_kernel_abi_arch_function!(cmsg_space, RD_NATIVE_ARCH, size_of::<i32>());
    let mut cmsgbuf = vec![0u8; cmsgbuf_size];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_control = cmsgbuf.as_mut_ptr() as *mut u8 as *mut c_void;
    msg.msg_controllen = cmsgbuf_size;
    msg.msg_iov = &mut msgdata as *mut libc::iovec;
    msg.msg_iovlen = 1;

    if 0 > unsafe { libc::recvmsg(sock.as_raw(), &mut msg, 0) } {
        fatal!("Failed to receive fd");
    }

    let cmsg_data_off = rd_kernel_abi_arch_function!(cmsg_data_offset, RD_NATIVE_ARCH);
    // @TODO review this transmute_copy
    let cmsghdr: libc::cmsghdr = unsafe { transmute_copy(&cmsgbuf) };
    debug_assert!(cmsghdr.cmsg_level == SOL_SOCKET && cmsghdr.cmsg_type == SCM_RIGHTS);
    let idata = cmsgbuf
        .get(cmsg_data_off..cmsg_data_off + size_of::<i32>())
        .unwrap();
    let our_fd: i32 = i32::from_le_bytes(idata.try_into().unwrap());
    debug_assert!(our_fd >= 0);
    our_fd
}

const fn reserve<T>() -> usize {
    align_size(size_of::<T>())
}
