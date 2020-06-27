use crate::{
    arch::Architecture,
    auto_remote_syscalls::MemParamsEnabled::{DisableMemoryParams, EnableMemoryParams},
    bindings::ptrace::PTRACE_EVENT_EXIT,
    kernel_abi::{
        has_mmap2_syscall,
        has_socketcall_syscall,
        is_clone_syscall,
        is_open_syscall,
        is_openat_syscall,
        is_rt_sigaction_syscall,
        is_sigaction_syscall,
        is_signal_syscall,
        syscall_instruction,
        syscall_number_for__llseek,
        syscall_number_for_close,
        syscall_number_for_lseek,
        syscall_number_for_mmap,
        syscall_number_for_mmap2,
        syscall_number_for_mremap,
        syscall_number_for_munmap,
        syscall_number_for_openat,
        syscall_number_for_sendmsg,
        syscall_number_for_socketcall,
        SupportedArch,
    },
    kernel_metadata::{errno_name, signal_name, syscall_name},
    log::LogLevel::LogDebug,
    monitored_shared_memory::MonitoredSharedMemorySharedPtr,
    rd::RD_RESERVED_ROOT_DIR_FD,
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::{
            address_space::{AddressSpace, AddressSpaceRef, AddressSpaceRefMut, Mapping},
            kernel_mapping::KernelMapping,
            memory_range::{MemoryRange, MemoryRangeKey},
            Enabled,
            Privileged,
            Traced,
        },
        replay_session::ReplaySession,
        session_inner::session_inner::SessionInner,
        task::{
            common::{read_mem, read_val_mem, write_mem, write_val_mem},
            record_task::SignalDisposition,
            task_inner::{
                task_inner::WriteFlags,
                ResumeRequest::{ResumeSinglestep, ResumeSyscall},
                TicksRequest::ResumeNoTicks,
                WaitRequest::ResumeWait,
            },
            Task,
        },
    },
    util::{find, is_kernel_trap, page_size, resize_shmem_segment, running_under_rd, tmp_dir},
    wait_status::{MaybeStopSignal, WaitStatus},
};
use core::ffi::c_void;
use libc::{
    pid_t,
    SYS_sendmsg,
    ESRCH,
    MREMAP_FIXED,
    MREMAP_MAYMOVE,
    O_CLOEXEC,
    O_CREAT,
    O_EXCL,
    O_RDWR,
    SCM_RIGHTS,
    SIGTRAP,
    SOL_SOCKET,
};
use nix::{
    sys::{
        mman::{munmap, MapFlags, ProtFlags},
        stat::fstat,
    },
    unistd::{unlink, PathconfVar::PATH_MAX},
    NixPath,
};
use std::{
    cmp::{max, min},
    convert::TryInto,
    ffi::OsStr,
    io::Write,
    mem::{size_of, size_of_val, zeroed},
    ops::{Deref, DerefMut},
    os::unix::ffi::OsStrExt,
    ptr::copy_nonoverlapping,
    slice,
    sync::atomic::{AtomicUsize, Ordering},
};

macro_rules! rd_syscall {
    ($slf:expr, $syscallno:expr) => {
        $slf.syscall($syscallno, &[])
    };
    ($slf:expr, $syscallno:expr, $a0:expr) => {
        $slf.syscall($syscallno, &[$a0 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr) => {
        $slf.syscall($syscallno, &[$a0 as usize, $a1 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr) => {
        $slf.syscall($syscallno, &[$a0 as usize, $a1 as usize, $a2 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {
        $slf.syscall(
            $syscallno,
            &[$a0 as usize, $a1 as usize, $a2 as usize, $a3 as usize],
        )
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $slf.syscall(
            $syscallno,
            &[
                $a0 as usize,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
            ],
        )
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        $slf.syscall(
            $syscallno,
            &[
                $a0 as usize,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
                $a5 as usize,
            ],
        )
    };
}

macro_rules! rd_infallible_syscall {
    ($slf:expr, $syscallno:expr) => {
        $slf.infallible_syscall($syscallno, &[])
    };
    ($slf:expr, $syscallno:expr, $a0:expr) => {
        $slf.infallible_syscall($syscallno, &[$a0 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr) => {
        $slf.infallible_syscall($syscallno, &[$a0 as usize, $a1 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr) => {
        $slf.infallible_syscall($syscallno, &[$a0 as usize, $a1 as usize, $a2 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {
        $slf.infallible_syscall(
            $syscallno,
            &[$a0 as usize, $a1 as usize, $a2 as usize, $a3 as usize],
        )
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $slf.infallible_syscall(
            $syscallno,
            &[
                $a0 as usize,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
            ],
        )
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        $slf.infallible_syscall(
            $syscallno,
            &[
                $a0 as usize,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
                $a5 as usize,
            ],
        )
    };
}

macro_rules! rd_infallible_syscall_ptr {
    ($slf:expr, $syscallno:expr) => {
        $slf.infallible_syscall_ptr($syscallno, &[])
    };
    ($slf:expr, $syscallno:expr, $a0:expr) => {
        $slf.infallible_syscall_ptr($syscallno, &[$a0 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr) => {
        $slf.infallible_syscall_ptr($syscallno, &[$a0 as usize, $a1 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr) => {
        $slf.infallible_syscall_ptr($syscallno, &[$a0 as usize, $a1 as usize, $a2 as usize])
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {
        $slf.infallible_syscall_ptr(
            $syscallno,
            &[$a0 as usize, $a1 as usize, $a2 as usize, $a3 as usize],
        )
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        $slf.infallible_syscall_ptr(
            $syscallno,
            &[
                $a0 as usize,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
            ],
        )
    };
    ($slf:expr, $syscallno:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {
        $slf.infallible_syscall_ptr(
            $syscallno,
            &[
                $a0 as usize,
                $a1 as usize,
                $a2 as usize,
                $a3 as usize,
                $a4 as usize,
                $a5 as usize,
            ],
        )
    };
}

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
        let new_sp = self.task().regs_ref().sp() + self.len;
        ed_assert!(self.remote.task(), self.saved_sp == new_sp);

        if self.addr.is_some() {
            // XXX what should we do if this task was sigkilled but the address
            // space is used by other live tasks?
            self.remote.task_mut().write_bytes_helper(
                self.addr.unwrap(),
                &self.data,
                None,
                WriteFlags::empty(),
            );
        }
        self.remote.initial_regs_mut().set_sp(new_sp);
        let initial_regs = self.remote.initial_regs_ref().clone();
        self.remote.task_mut().set_regs(&initial_regs);
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
            saved_sp: 0usize.into(),
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
        // rr assumes the AutoRestoreMem construction always succeeds. We don't.
        // This could happen if a CStr could not be extracted successfully.
        s.with_nix_path(move |c| {
            Self::new(
                remote,
                Some(c.to_bytes_with_nul()),
                c.to_bytes_with_nul().len(),
            )
        })
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

        self.saved_sp = self.remote.task().regs_ref().sp();

        let new_sp = self.remote.task().regs_ref().sp() - self.len;
        self.remote.initial_regs_mut().set_sp(new_sp);

        let initial_regs = self.remote.initial_regs_ref().clone();
        self.remote.task_mut().set_regs(&initial_regs);
        self.addr = Some(self.remote.initial_regs_ref().sp());

        let mut ok = true;
        self.remote
            .task_mut()
            .read_bytes_helper(self.addr.unwrap(), &mut self.data, Some(&mut ok));
        // @TODO what do we do if ok is false due to read_bytes_helper call above?
        // Adding a debug_assert!() for now.
        debug_assert!(ok);
        if mem.is_some() {
            self.remote.task_mut().write_bytes_helper(
                self.addr.unwrap(),
                mem.unwrap(),
                Some(&mut ok),
                WriteFlags::empty(),
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
        let mut remote = AutoRemoteSyscalls {
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
        };
        // We support two paths for syscalls:
        // -- a fast path using a privileged untraced syscall and PTRACE_SINGLESTEP.
        // This only requires a single task-wait.
        // -- a slower path using a privileged traced syscall and PTRACE_SYSCALL/
        // PTRACE_CONT via Task::enter_syscall(). This requires 2 or 3 task-waits
        // depending on whether the seccomp event fires before the syscall-entry
        // event.
        // Use the slow path when running under rr, because the rr recording us
        // needs to see and trace these tracee syscalls, and if they're untraced by
        // us they're also untraced by the outer rr.
        // Use the slow path if SIGTRAP is blocked or ignored because otherwise
        // the PTRACE_SINGLESTEP will cause the kernel to unblock it.
        let is_sigtrap_default_and_unblocked = is_sigtrap_default_and_unblocked(remote.task_mut());
        let enable_singlestep_path =
            remote.vm().has_rd_page() && !running_under_rd() && is_sigtrap_default_and_unblocked;
        remote.setup_path(enable_singlestep_path);
        if enable_mem_params == MemParamsEnabled::EnableMemoryParams {
            remote.maybe_fix_stack_pointer();
        };
        remote
    }

    /// You mostly want to use this convenience method.
    pub fn new(t: &mut dyn Task) -> AutoRemoteSyscalls {
        Self::new_with_mem_params(t, MemParamsEnabled::EnableMemoryParams)
    }

    ///  If t's stack pointer doesn't look valid, temporarily adjust it to
    ///  the top of *some* stack area.
    pub fn maybe_fix_stack_pointer(&mut self) {
        if !self.t.session().done_initial_exec() {
            return;
        }

        let last_stack_byte: RemotePtr<Void> = self.t.regs_ref().sp() - 1usize;
        match self.t.vm().mapping_of(last_stack_byte) {
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
        for (_, m) in self.t.vm().maps() {
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
                    None,
                    4096,
                    ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
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
            rd_infallible_syscall!(
                remote,
                syscall_number_for_munmap(remote.arch()),
                self.fixed_sp.unwrap().as_usize() - 4096,
                4096
            );
        }
        if !self.replaced_bytes.is_empty() {
            // XXX how to clean up if the task died and the address space is shared with live task?
            write_mem(
                some_t,
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

    /// @TODO Can get a bit more performance by specializing this method. Leave as is for now.
    ///
    /// Make `syscallno` with `args` (limited to 6 on
    /// x86).  Return the raw kernel return value.
    /// Returns -ESRCH if the process dies or has died.
    pub fn syscall(&mut self, syscallno: i32, args: &[usize]) -> isize {
        // Make a copy
        let mut callregs = self.initial_regs;
        debug_assert!(args.len() <= 6);
        for (i, arg) in args.iter().enumerate() {
            // Syscall argument are indexed from 1 onwards and not 0.
            // e.g. arg 1, arg 2, arg 3 etc.
            callregs.set_arg(i + 1, *arg);
        }
        self.syscall_base(syscallno, &mut callregs)
    }

    /// @TODO Can get a bit more performance by specializing this method. Leave as is for now.
    pub fn infallible_syscall(&mut self, syscallno: i32, args: &[usize]) -> isize {
        let ret = self.syscall(syscallno, args);
        self.check_syscall_result(ret, syscallno);
        ret
    }

    /// @TODO Can get a bit more performance by specializing this method. Leave as is for now.
    pub fn infallible_syscall_ptr(&mut self, syscallno: i32, args: &[usize]) -> RemotePtr<Void> {
        (self.infallible_syscall(syscallno, args) as usize).into()
    }

    /// Remote mmap syscalls are common and non-trivial due to the need to
    /// select either mmap2 or mmap.
    pub fn infallible_mmap_syscall(
        &mut self,
        maybe_addr_hint: Option<RemotePtr<Void>>,
        length: usize,
        prot: ProtFlags,
        flags: MapFlags,
        child_fd: i32,
        offset_pages: u64,
    ) -> RemotePtr<Void> {
        let addr_hint = maybe_addr_hint.unwrap_or(RemotePtr::null());
        // The first syscall argument is called "arg 1", so
        // our syscall-arg-index template parameter starts
        // with "1".
        let ret: RemotePtr<Void> = if has_mmap2_syscall(self.arch()) {
            let offset_pages_usize: usize = offset_pages.try_into().unwrap();
            rd_infallible_syscall_ptr!(
                self,
                syscall_number_for_mmap2(self.arch()),
                addr_hint.as_usize(),
                length,
                prot.bits(),
                flags.bits(),
                child_fd,
                offset_pages_usize
            )
        } else {
            let offset_usize: usize = (offset_pages * page_size() as u64).try_into().unwrap();
            rd_infallible_syscall_ptr!(
                self,
                syscall_number_for_mmap(self.arch()),
                addr_hint.as_usize(),
                length,
                prot.bits(),
                flags.bits(),
                child_fd,
                offset_usize
            )
        };

        if flags.contains(MapFlags::MAP_FIXED) {
            ed_assert!(
                self.t,
                addr_hint == ret,
                "MAP_FIXED at {} but got {}",
                addr_hint,
                ret
            );
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
                rd_infallible_syscall!(
                    mem,
                    syscall_number_for__llseek(arch),
                    fd,
                    (offset >> 32),
                    offset,
                    addr.as_usize(),
                    whence
                );
                read_val_mem::<isize>(mem.remote.t, RemotePtr::cast(addr), None)
            }
            SupportedArch::X64 => rd_infallible_syscall!(
                self,
                syscall_number_for_lseek(self.arch()),
                fd,
                offset,
                whence
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

    pub fn vm(&self) -> AddressSpaceRef {
        self.t.vm()
    }

    pub fn vm_mut(&self) -> AddressSpaceRefMut {
        self.t.vm_mut()
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

        let child_sock = remote_buf.task().session().tracee_fd_number();
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

        let our_fd: i32 = recvmsg_socket(&remote_buf.task().session().tracee_socket_fd().borrow());
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
            if self.t.maybe_ptrace_event() == PTRACE_EVENT_EXIT {
                self.restore_wait_status = self.t.status();
                break;
            }
            if self.t.status().is_syscall()
                || (self.t.maybe_stop_sig() == SIGTRAP
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
                self.t.regs_ref().syscall_result_signed()
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
            write_mem(
                self.t,
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
            syscall_ip = self.t.vm().traced_syscall_ip();
        }
        self.initial_regs.set_ip(syscall_ip);

        // We need to make sure to clear any breakpoints or other alterations of
        // the syscall instruction we're using. Note that the tracee may have set its
        // own breakpoints or otherwise modified the instruction, so suspending our
        // own breakpoint is insufficient.
        let syscall = syscall_instruction(self.t.arch());
        let mut ok = true;
        self.replaced_bytes = read_mem(
            self.t,
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
            write_mem(
                self.t,
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
        maybe_map_hint: Option<RemotePtr<Void>>,
        name: &OsStr,
        maybe_tracee_prot: Option<ProtFlags>,
        maybe_tracee_flags: Option<MapFlags>,
        monitored: Option<MonitoredSharedMemorySharedPtr>,
    ) -> KernelMapping {
        static NONCE: AtomicUsize = AtomicUsize::new(0);
        let tracee_prot: ProtFlags =
            maybe_tracee_prot.unwrap_or(ProtFlags::PROT_READ | ProtFlags::PROT_WRITE);
        let tracee_flags = maybe_tracee_flags.unwrap_or(MapFlags::empty());

        // Create the segment we'll share with the tracee.
        let mut path: Vec<u8> = Vec::new();
        path.extend_from_slice(tmp_dir().as_bytes());
        path.extend_from_slice(SessionInner::rd_mapping_prefix().as_bytes());
        path.extend_from_slice(name.as_bytes());
        write!(
            path,
            "-{}-{}",
            self.task().real_tgid(),
            NONCE.fetch_add(1, Ordering::SeqCst)
        )
        .unwrap();
        path.truncate(PATH_MAX as usize);

        // Let the child create the shmem block and then send the fd back to us.
        // This lets us avoid having to make the file world-writeable so that
        // the child can read it when it's in a different user namespace (which
        // would be a security hole, letting other users abuse rd users).
        let child_shmem_fd: i32;
        {
            let arch = self.arch();
            let mut child_path = AutoRestoreMem::push_cstr(self, path.as_slice());
            // skip leading '/' since we want the path to be relative to the root fd
            let path_addr_val = (child_path.get().unwrap() + 1usize).as_usize();
            child_shmem_fd = rd_infallible_syscall!(
                child_path,
                syscall_number_for_openat(arch),
                RD_RESERVED_ROOT_DIR_FD,
                path_addr_val,
                (O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC),
                0o600
            )
            .try_into()
            .unwrap();
        }

        // Remove the fs name so that we don't have to worry about cleaning
        // up this segment in error conditions.
        //
        // rr swallows any potential error but we don't for now.
        unlink(path.as_slice()).unwrap();

        let mut shmem_fd: ScopedFd = self.retrieve_fd(child_shmem_fd);
        resize_shmem_segment(&shmem_fd, size);
        log!(LogDebug, "created shmem segment {:?}", path);

        // Map the segment in ours and the tracee's address spaces.
        let mut flags = MapFlags::MAP_SHARED;
        // Here we map the shared memory segment into ours.
        let map_addr = unsafe {
            libc::mmap(
                0 as *mut c_void,
                size,
                (ProtFlags::PROT_READ | ProtFlags::PROT_WRITE).bits() as _,
                flags.bits(),
                shmem_fd.as_raw(),
                0,
            )
        };
        if map_addr as isize == -1 {
            fatal!("Failed to mmap shmem region");
        }
        if maybe_map_hint.is_some() {
            flags |= MapFlags::MAP_FIXED;
        }
        // Here we map the shared memory segment into the tracee.
        let child_map_addr = self.infallible_mmap_syscall(
            maybe_map_hint,
            size,
            tracee_prot,
            flags,
            child_shmem_fd,
            0,
        );

        let maybe_st = fstat(shmem_fd.as_raw());
        ed_assert!(self.task(), maybe_st.is_ok());
        let st = maybe_st.unwrap();
        let km: KernelMapping = self.task().vm_mut().map(
            self.task(),
            child_map_addr,
            size,
            tracee_prot,
            flags | tracee_flags,
            0,
            OsStr::from_bytes(&path),
            st.st_dev,
            st.st_ino,
            None,
            None,
            None,
            Some(map_addr),
            monitored,
        );

        shmem_fd.close();
        rd_infallible_syscall!(self, syscall_number_for_close(self.arch()), child_shmem_fd);
        km
    }

    /// Replace a MAP_PRIVATE segment by one that is shared between rr and the
    /// tracee. Returns true on success
    pub fn make_private_shared(&mut self, m: &Mapping) -> bool {
        if !(m.map.flags().contains(MapFlags::MAP_PRIVATE)) {
            return false;
        }

        // Find a place to map the current segment to temporarily
        let start = m.map.start();
        let sz = m.map.size();
        let free_mem = self.task().vm().find_free_memory(sz, None);
        let arch = self.arch();
        rd_infallible_syscall!(
            self,
            syscall_number_for_mremap(arch),
            start.as_usize(),
            sz,
            sz,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            free_mem.as_usize()
        );
        self.task()
            .vm_mut()
            .remap(self.task(), start, sz, free_mem, sz);

        // AutoRemoteSyscalls may have gotten unlucky and picked the old stack
        // segment as it's scratch space, reevaluate that choice
        let mut remote2 = AutoRemoteSyscalls::new(self.task_mut());

        let new_m = remote2.steal_mapping(m, None);

        // And copy over the contents. Since we can't just call memcpy in the
        // inferior, just copy directly from the remote private into the local
        // reference of the shared mapping. We use the fallible read method to
        // handle the case where the mapping is larger than the backing file, which
        // would otherwise cause a short read.
        let buf = unsafe { slice::from_raw_parts_mut(new_m.local_addr.unwrap() as *mut u8, sz) };

        // DIFF NOTE: Added a fatal!() here to deal with Err case.
        // rr does not do this, however, it makes sense to do this because short reads (and zero
        // length reads in some instances) DONT result in an error.
        // So if an error was reported, its probably a good idea to fatal!() here.
        let result = remote2.task_mut().read_bytes_fallible(free_mem, buf);
        if result.is_err() {
            fatal!("Error while reading fallibly");
        }

        // Finally unmap the original segment
        rd_infallible_syscall!(
            remote2,
            syscall_number_for_munmap(arch),
            free_mem.as_usize(),
            sz
        );
        remote2.task().vm_mut().unmap(remote2.task(), free_mem, sz);
        return true;
    }

    /// Recreate an mmap region that is shared between rd and the tracee. The caller
    /// is responsible for recreating the data in the new mmap, *if* `preserve` is
    /// DiscardContents.
    /// OK to call this while 'm' references one of the mappings in remote's
    /// AddressSpace
    /// If None is provided for `preserve` then DiscardContents is assumed
    /// If None is provided for `monitored` it is assumed that there is no memory monitor.
    /// DIFF NOTE: Returns the start addr to the new created mmap instead of reference to Mapping
    /// Note that this is not necessarily the same as `k.start()` as mappings could have
    /// been coalesced.
    pub fn recreate_shared_mmap(
        &mut self,
        k: MemoryRangeKey,
        option_preserve: Option<PreserveContents>,
        monitored: Option<MonitoredSharedMemorySharedPtr>,
    ) -> RemotePtr<Void> {
        let (map, flags, local_addr) = self
            .vm()
            .mapping_of(k.start())
            .map(|mapping| (mapping.map.clone(), mapping.flags, mapping.local_addr))
            .unwrap();
        ed_assert!(self.task(), map.fsname().len() <= PATH_MAX as usize);
        let flags = flags;
        let size = map.size();
        let name = map.fsname();
        let maybe_preserved_data = if option_preserve.is_some()
            && option_preserve.unwrap() == PreserveContents::PreserveContents
            && local_addr.is_some()
        {
            Some(local_addr.unwrap())
        } else {
            None
        };

        let km = self.create_shared_mmap(
            size,
            Some(map.start()),
            extract_name(name).unwrap(),
            Some(map.prot()),
            None,
            monitored,
        );

        let new_addr = km.start();
        *self.vm_mut().mapping_flags_of_mut(new_addr) = flags;
        // DIFF NOTE: Logic slightly different from rr. We are only returning start of recreated
        // mapping.
        let new_map_local_addr = self.vm().mapping_of(new_addr).unwrap().local_addr;
        if maybe_preserved_data.is_some() {
            let preserved_data = maybe_preserved_data.unwrap();
            let new_map_local = new_map_local_addr.unwrap();
            unsafe {
                // @TODO This should be non-overlapping but think about this more to be sure.
                copy_nonoverlapping(preserved_data, new_map_local, size);
                munmap(preserved_data, size).unwrap();
            }
        }
        new_addr
    }

    /// Takes a mapping and replaces it by one that is shared between rr and
    /// the tracee. The caller is responsible for filling the contents of the
    /// new mapping.
    /// If None is provided for `monitored` it is assumed that there is no memory monitor.
    pub fn steal_mapping(
        &mut self,
        m: &Mapping,
        monitored: Option<MonitoredSharedMemorySharedPtr>,
    ) -> Mapping {
        // We will include the name of the full path of the original mapping in the
        // name of the shared mapping, replacing slashes by dashes.
        let name_raw = m.map.fsname().as_bytes();

        // Truncate the string and replace all '/' with '-'
        // No sure why rr has deducted 40 from PATH_MAX, we do the same here too for now.
        let mut name = Vec::from(&name_raw[0..min(PATH_MAX as usize - 40, name_raw.len())]);
        name.iter_mut()
            .map(|c| {
                if *c == b'/' {
                    *c = b'-'
                }
            })
            .for_each(drop);

        // Now create the new mapping in its place
        let start = m.map.start();
        let sz = m.map.size();
        let km = self.create_shared_mmap(
            sz,
            Some(start),
            OsStr::from_bytes(&name),
            Some(m.map.prot()),
            Some(m.map.flags() & (MapFlags::MAP_GROWSDOWN | MapFlags::MAP_STACK)),
            monitored.clone(),
        );

        self.vm().mapping_of(km.start()).unwrap().clone()
    }
}

impl<'a> Drop for AutoRemoteSyscalls<'a> {
    fn drop(&mut self) {
        self.restore_state_to(None)
    }
}

fn is_usable_area(km: &KernelMapping) -> bool {
    (km.prot()
        .contains(ProtFlags::PROT_READ | ProtFlags::PROT_WRITE))
        && (km.flags().contains(MapFlags::MAP_PRIVATE))
}

fn ignore_signal(t: &dyn Task) -> bool {
    let maybe_sig: MaybeStopSignal = t.maybe_stop_sig();
    if !maybe_sig.is_sig() {
        return false;
    }

    if t.session().is_replaying() {
        if ReplaySession::is_ignored_signal(maybe_sig.unwrap_sig()) {
            return true;
        }
    } else if t.session().is_recording() {
        let rt = t.as_record_task().unwrap();
        // Better to use unwrap_sig() here as we've already made sure that maybe_sig.is_sig() above.
        if maybe_sig.unwrap_sig()
            != rt.session().as_record().unwrap().syscallbuf_desched_sig() as i32
        {
            rt.stash_sig();
        }
        return true;
    }
    ed_assert!(
        t,
        false,
        "Unexpected signal {}",
        signal_name(maybe_sig.unwrap_sig())
    );
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
    t: &mut dyn Task,
    remote_mem: RemotePtr<SocketcallArgs<Arch>>,
    arg1: Arch::signed_long,
    arg2: Arch::signed_long,
    arg3: Arch::signed_long,
) -> bool {
    let mut ok: bool = false;
    let sc_args = [arg1, arg2, arg3];
    write_mem(t, RemotePtr::cast(remote_mem), &sc_args, Some(&mut ok));
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
    write_val_mem(remote_buf.task_mut(), remote_msg, &msg, Some(&mut ok));

    let mut msgdata = Arch::iovec::default();
    // iov_base: doesn't matter much, we ignore the data
    Arch::set_iovec(&mut msgdata, RemotePtr::cast(remote_msg), 1);
    write_val_mem(remote_buf.task_mut(), remote_msgdata, &msgdata, Some(&mut ok));

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
            &raw const cmsghdr as *const u8,
            cmsgbuf.as_mut_ptr(),
            size_of::<Arch::cmsghdr>(),
        );
    }
    // Copy the fd into the cmsgbuf
    cmsgbuf[cmsg_data_off..cmsg_data_off + size_of_val(&fd)].copy_from_slice(&fd.to_le_bytes());

    write_mem(
        remote_buf.task_mut(),
        remote_cmsgbuf,
        &cmsgbuf,
        Some(&mut ok),
    );

    if !ok {
        return -ESRCH as isize;
    }

    let arch = remote_buf.arch();
    if sc_args.is_none() {
        return rd_syscall!(
            remote_buf,
            syscall_number_for_sendmsg(arch),
            child_sock,
            remote_msg.as_usize(),
            0
        );
    }

    let success = write_socketcall_args::<Arch>(
        remote_buf.task_mut(),
        sc_args.unwrap(),
        child_sock.into(),
        remote_msg.as_usize().try_into().unwrap(),
        0i32.into(),
    );

    if !success {
        return -ESRCH as isize;
    }

    rd_syscall!(
        remote_buf,
        syscall_number_for_socketcall(arch),
        SYS_sendmsg,
        sc_args.unwrap().as_usize()
    )
}

fn recvmsg_socket(sock: &ScopedFd) -> i32 {
    let mut received_data: u8 = 0;
    let mut msgdata: libc::iovec = unsafe { zeroed() };
    msgdata.iov_base = &raw mut received_data as *mut c_void;
    msgdata.iov_len = 1;

    // The i32 is our fd
    let cmsgbuf_size = unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize;
    let mut cmsgbuf = vec![0u8; cmsgbuf_size];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_control = cmsgbuf.as_mut_ptr().cast();
    msg.msg_controllen = cmsgbuf_size;
    msg.msg_iov = &raw mut msgdata;
    msg.msg_iovlen = 1;

    if 0 > unsafe { libc::recvmsg(sock.as_raw(), &raw mut msg, 0) } {
        fatal!("Failed to receive fd");
    }

    let cmsg: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    debug_assert!(unsafe {
        !cmsg.is_null() && (*cmsg).cmsg_level == SOL_SOCKET && (*cmsg).cmsg_type == SCM_RIGHTS
    });
    let our_fd: i32 = unsafe { *(libc::CMSG_DATA(cmsg) as *const i32) };
    debug_assert!(our_fd >= 0);
    our_fd
}

const fn reserve<T>() -> usize {
    align_size(size_of::<T>())
}

/// Recover the name that was originally chosen by finding the part of the
/// name between rd_mapping_prefix and the -%d-%d at the end.
fn extract_name(name: &OsStr) -> Option<&OsStr> {
    let mut name_it = name.as_bytes().iter().enumerate();

    let mut hyphens_seen: usize = 0;
    let mut pos_end: usize = 0;
    while let Some((pos, c)) = name_it.next_back() {
        if *c == b'-' {
            hyphens_seen += 1;
        } else if *c == b'/' {
            debug_assert!(
                false,
                "Passed something to create_shared_mmap that\n\
                                  wasn't a mapping shared between rd and the tracee?"
            );
        }

        if hyphens_seen == 2 {
            pos_end = pos;
            break;
        }
    }

    debug_assert_eq!(hyphens_seen, 2);
    let needle = SessionInner::rd_mapping_prefix().as_bytes();
    let prefix = find(name.as_bytes(), needle);
    match prefix {
        None => debug_assert!(
            false,
            "Passed something to create_shared_mmap that\n\
                                  wasn't a mapping shared between rd and the tracee?"
        ),
        Some(loc) => {
            let pos_start = loc + needle.len();
            // The extracted name needs to be at least 1 u8 long!
            if pos_start < pos_end {
                return Some(OsStr::from_bytes(&name.as_bytes()[pos_start..pos_end]));
            }
        }
    }

    None
}

fn is_sigtrap_default_and_unblocked(t: &dyn Task) -> bool {
    if !t.session().is_recording() {
        return true;
    }
    let rt = t.as_record_task().unwrap();
    rt.sig_disposition(SIGTRAP) == SignalDisposition::SignalDefault && !rt.is_sig_blocked(SIGTRAP)
}
