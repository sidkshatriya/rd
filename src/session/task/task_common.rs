//! This file contains all methods that are:
//! (a) Common between ReplayTask and Record tasks. These methods are called from forwarding stubs
//!     in the trait impls. These stubs are needed because default methods in the trait
//!     implementation have an implicit ?Sized constraint. By calling the stubs that call the
//!     methods in this file we get Sized for "free" because both ReplayTask and RecordTask are
//!     Sized.
//! (b) Some utility methods which because of their template parameters cannot be added to the
//!     Task trait. This makes calling them a tad bit more inconvenient as we _cannot_ invoke using
//!     the self.func_name() style. They are included in this file because they take &dyn Task or
//!     &dyn Task as their first parameter. It would have been confusing to include them
//!     in task_inner.rs
//! (c) Some misc methods that did not fit elsewhere...

use crate::{
    arch::Architecture,
    arch_structs::iovec,
    auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem, MemParamsEnabled},
    bindings::{
        kernel::{
            user_desc, user_regs_struct as native_user_regs_struct, NT_FPREGSET, NT_PRSTATUS,
            NT_X86_XSTATE, SHMDT,
        },
        prctl::{ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_FS, ARCH_SET_GS},
        ptrace::{
            PTRACE_ARCH_PRCTL, PTRACE_DETACH, PTRACE_EVENT_EXIT, PTRACE_GETREGS, PTRACE_GETSIGINFO,
            PTRACE_POKEUSER, PTRACE_SETFPREGS, PTRACE_SETFPXREGS, PTRACE_SETREGS, PTRACE_SETREGSET,
        },
        signal::{siginfo_t, POLL_IN},
    },
    core::type_has_no_holes,
    extra_registers::{ExtraRegisters, Format},
    fast_forward::at_x86_string_instruction,
    file_monitor,
    kernel_abi::{
        get_syscall_instruction_arch, is_at_syscall_instruction, is_mprotect_syscall,
        syscall_instruction_length, syscall_number_for_arch_prctl, syscall_number_for_close,
        syscall_number_for_mprotect, syscall_number_for_munmap, syscall_number_for_openat,
        syscall_number_for_prctl, syscall_number_for_set_thread_area, x64, x86,
        CloneParameterOrdering, CloneTLSType, FcntlOperation, SupportedArch,
    },
    kernel_metadata::{errno_name, ptrace_req_name},
    kernel_supplement::ARCH_SET_CPUID,
    log::LogLevel::{LogDebug, LogInfo, LogWarn},
    perf_counters::TIME_SLICE_SIGNAL,
    preload_interface::{
        self, preload_globals, syscallbuf_hdr, syscallbuf_locked_why, syscallbuf_record,
    },
    preload_interface_arch::rdcall_init_preload_params,
    registers::{with_converted_registers, Registers, X86_TF_FLAG},
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    seccomp_filter_rewriter::SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO,
    session::{
        address_space::{
            kernel_mapping::KernelMapping, memory_range::MemoryRangeKey, AddressSpace,
            BreakpointType, DebugStatus,
        },
        session_inner::SessionInner,
        task::{
            is_signal_triggered_by_ptrace_interrupt, is_singlestep_resume,
            task_inner::{
                CapturedState, CloneFlags, CloneReason, PtraceData, ResumeRequest, TicksRequest,
                TrapReasons, WaitRequest, WriteFlags, MAX_TICKS_REQUEST,
            },
            Task, TaskSharedPtr, PRELOAD_THREAD_LOCALS_SIZE,
        },
        Session, SessionSharedPtr,
    },
    sig,
    ticks::Ticks,
    util::{
        ceil_page_size, clone_flags_to_task_flags, cpuid, floor_page_size, is_kernel_trap,
        pwrite_all_fallible, trapped_instruction_at, trapped_instruction_len, u8_slice_mut,
        xsave_layout_from_trace, xsave_native_layout, TrappedInstruction, XSaveLayout,
        CPUID_GETFEATURES,
    },
    wait_status::WaitStatus,
};
use file_monitor::LazyOffset;
use libc::{
    pid_t, pread64, waitpid, CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_SYSVSEM, CLONE_THREAD,
    CLONE_VM, EAGAIN, ECHILD, EPERM, ESRCH, PR_SET_NAME, PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
    SEEK_SET, SIGCHLD, SIGTRAP, WNOHANG, __WALL,
};
use nix::{
    errno::{errno, Errno},
    fcntl::OFlag,
    sys::mman::{MapFlags, ProtFlags},
};
use sig::Sig;
use std::{
    cmp::{max, min},
    convert::TryInto,
    ffi::{c_void, CString, OsStr},
    mem::{size_of, size_of_val, zeroed},
    os::unix::ffi::OsStrExt,
    ptr,
    rc::Rc,
    slice,
};

/// Forwarded method definition
///
/// Open /proc/{tid}/mem fd for our AddressSpace, closing the old one
/// first. If necessary we force the tracee to open the file
/// itself and smuggle the fd back to us.
///
/// Returns false if the process no longer exists.
pub(super) fn open_mem_fd_common<T: Task>(task: &T) -> bool {
    // Use ptrace to read/write during open_mem_fd
    task.vm().set_mem_fd(ScopedFd::new());

    if !task.is_stopped.get() {
        log!(
            LogWarn,
            "Can't retrieve mem fd for {}; process not stopped, racing with exec?",
            task.tid()
        );
        return false;
    }

    // We're expecting that either we or the child can read the mem fd.
    // It's possible for both to not be the case (us on certain kernel
    // configurations, the child after it did a setuid).
    let pid_path = format!("/proc/{}", task.tid());
    let dir_fd = ScopedFd::open_path(pid_path.as_str(), OFlag::O_PATH);
    let mut fd: ScopedFd = ScopedFd::openat(&dir_fd, "mem", OFlag::O_RDWR);

    if !fd.is_open() {
        log!(LogDebug, "Falling back to the remote fd dance");
        let mut remote = AutoRemoteSyscalls::new(task);
        let remote_mem_dir_fd: i32 = remote.send_fd(&dir_fd) as i32;

        // If the remote dies, any of these can fail. That's ok, we'll just
        // find that the fd wasn't successfully opened.
        let mut remote_path = AutoRestoreMem::push_cstr(&mut remote, "mem");
        let arch = remote_path.arch();
        let addr = remote_path.get().unwrap() + 1usize;
        let remote_mem_fd = rd_syscall!(
            remote_path,
            syscall_number_for_openat(arch),
            remote_mem_dir_fd,
            addr.as_usize(),
            libc::O_RDWR
        ) as i32;

        fd = remote_path.retrieve_fd(remote_mem_fd);
        rd_syscall!(remote_path, syscall_number_for_close(arch), remote_mem_fd);
        rd_syscall!(
            remote_path,
            syscall_number_for_close(arch),
            remote_mem_dir_fd
        );
    }

    if !fd.is_open() {
        log!(
            LogInfo,
            "Can't retrieve mem fd for {}; process no longer exists?",
            task.tid()
        );

        return false;
    }

    task.vm().set_mem_fd(fd);

    true
}

/// Forwarded method definition
///
/// Read/write the number of bytes.
/// Number of bytes read can be less than desired
/// - Returns Err(()) if No bytes could be read at all AND there was an error
/// - Returns Ok(usize) if 0 or more bytes could be read. All bytes requested may not have been
/// read.
pub(super) fn read_bytes_fallible_common<T: Task>(
    task: &T,
    addr: RemotePtr<Void>,
    buf: &mut [u8],
) -> Result<usize, ()> {
    if buf.is_empty() {
        return Ok(0);
    }

    if let Some(found) = task.vm().local_mapping(addr, buf.len()) {
        buf.copy_from_slice(&found[0..buf.len()]);
        return Ok(buf.len());
    }

    if !task.vm().mem_fd().is_open() {
        return Ok(task.read_bytes_ptrace(addr, buf));
    }

    let mut all_read = 0;
    while all_read < buf.len() {
        Errno::clear();
        let nread: isize = unsafe {
            pread64(
                task.vm().mem_fd().as_raw(),
                buf.get_mut(all_read..)
                    .unwrap()
                    .as_mut_ptr()
                    .cast::<c_void>(),
                // How much more left to read
                buf.len() - all_read,
                // Where you're reading from in the tracee
                // This is of type off_t which is a i32 in x86 and i64 on x64
                (addr.as_usize() + all_read) as isize as _,
            )
        };
        // We open the mem_fd just after being notified of
        // exec(), when the Task is created.  Trying to read from that
        // fd seems to return 0 with errno 0.  Reopening the mem fd
        // allows the pwrite to succeed.  It seems that the first mem
        // fd we open, very early in exec, refers to the address space
        // before the exec and the second mem fd refers to the address
        // space after exec.
        if 0 == nread && 0 == all_read && 0 == errno() {
            // If we couldn't open the mem fd, then report 0 bytes read
            if !task.open_mem_fd() {
                // Hmmm.. given that errno is 0 it seems logical.
                return Ok(0);
            }
            // Try again
            continue;
        }
        if nread <= 0 {
            if all_read > 0 {
                // We did successfully read _some_ data, so return success and ignore
                // any error.
                Errno::clear();
                return Ok(all_read);
            }
            return Err(());
        }
        // We read some data. We should try again in case we get short reads.
        all_read += nread as usize;
    }

    Ok(all_read)
}

/// Forwarded method definition
///
/// If the data can't all be read, then if `maybe_ok` is None, asserts otherwise
/// sets the inner mutable bool to false.
pub(super) fn read_bytes_helper_common<T: Task>(
    task: &T,
    addr: RemotePtr<Void>,
    buf: &mut [u8],
    maybe_ok: Option<&mut bool>,
) {
    // pread64 etc can't handle addresses that appear to be negative ...
    // like [vsyscall].
    let result_nread = task.read_bytes_fallible(addr, buf);
    match result_nread {
        Ok(nread) if nread == buf.len() => (),
        _ => {
            let nread = result_nread.unwrap_or(0);
            match maybe_ok {
                Some(ok) => *ok = false,
                None => {
                    ed_assert!(
                        task,
                        false,
                        "Should have read {} bytes from {}, but only read {}",
                        buf.len(),
                        addr,
                        nread
                    );
                }
            }
        }
    }
}

/// NOT a Forwarded method due to extra template parameter
///
/// If the data can't all be read, then if `ok` is non-null, sets *ok to
/// false, otherwise asserts.
pub fn read_bytes_helper_for<T: Task, D>(
    task: &dyn Task,
    addr: RemotePtr<D>,
    data: &mut D,
    ok: Option<&mut bool>,
) {
    let buf = unsafe { std::slice::from_raw_parts_mut(data as *mut D as *mut u8, size_of::<D>()) };
    task.read_bytes_helper(RemotePtr::cast(addr), buf, ok);
}

/// Forwarded method definition
///
/// Read and return the C string located at `child_addr` in
/// this address space.
pub(super) fn read_c_str_common<T: Task>(task: &T, child_addr: RemotePtr<u8>) -> CString {
    // XXX handle invalid C strings
    // e.g. c-strings that don't end even when an unmapped region of memory
    // is reached.
    let mut p = child_addr;
    let mut s: Vec<u8> = Vec::new();
    loop {
        // We're only guaranteed that [child_addr, end_of_page) is mapped.
        // So be conservative and assume that c-string ends before the
        // end of the page. In case it _hasn't_ ended then we try on the
        // next page and so forth.
        let end_of_page: RemotePtr<Void> = ceil_page_size(p.as_usize() + 1).into();
        let nbytes: usize = end_of_page - p;
        let mut buf = vec![0; nbytes];
        task.read_bytes_helper(p, &mut buf, None);
        for i in 0..nbytes {
            if 0 == buf[i] {
                // We have already checked it so unsafe is OK!
                return unsafe { CString::from_vec_unchecked(s) };
            }
            s.push(buf[i]);
        }
        p = end_of_page;
    }
}

/// This is NOT a forwarded method
///
/// This function exists to work around
/// <https://bugzilla.kernel.org/show_bug.cgi?id=99101>
/// On some kernels pwrite() to /proc/.../mem fails when writing to a region
/// that's PROT_NONE.
/// Also, writing through MAP_SHARED readonly mappings fails (even if the
/// file was opened read-write originally), so we handle that here too.
pub(super) fn safe_pwrite64(t: &dyn Task, buf: &[u8], addr: RemotePtr<Void>) -> Result<usize, ()> {
    let mut mappings_to_fix: Vec<(MemoryRangeKey, ProtFlags)> = Vec::new();
    let buf_size = buf.len();
    for (k, m) in &t.vm().maps_containing_or_after(floor_page_size(addr)) {
        if m.map.start() >= ceil_page_size(addr + buf_size) {
            break;
        }

        if m.map.prot().contains(ProtFlags::PROT_WRITE) {
            continue;
        }

        if !(m.map.prot().contains(ProtFlags::PROT_READ))
            || (m.map.flags().contains(MapFlags::MAP_SHARED))
        {
            mappings_to_fix.push((*k, m.map.prot()));
        }
    }

    if mappings_to_fix.is_empty() {
        return pwrite_all_fallible(t.vm().mem_fd().unwrap(), buf, addr.as_isize());
    }

    let mem_fd = t.vm().mem_fd().unwrap();
    let mprotect_syscallno: i32 = syscall_number_for_mprotect(t.arch());
    let mut remote = AutoRemoteSyscalls::new(t);
    for m in &mappings_to_fix {
        rd_infallible_syscall!(
            remote,
            mprotect_syscallno,
            m.0.start().as_usize(),
            m.0.len(),
            (m.1 | ProtFlags::PROT_WRITE).bits()
        );
    }

    let nwritten_result: Result<usize, ()> = pwrite_all_fallible(mem_fd, buf, addr.as_isize());

    for m in &mappings_to_fix {
        rd_infallible_syscall!(
            remote,
            mprotect_syscallno,
            m.0.start().as_usize(),
            m.0.len(),
            m.1.bits()
        );
    }

    nwritten_result
}

/// Forwarded method definition
///
/// `flags` is bits from WriteFlags.
pub(super) fn write_bytes_helper_common<T: Task>(
    task: &T,
    addr: RemotePtr<Void>,
    buf: &[u8],
    maybe_ok: Option<&mut bool>,
    flags: WriteFlags,
) {
    let buf_size = buf.len();
    if 0 == buf_size {
        return;
    }

    if let Some(local) = task.vm().local_mapping_mut(addr, buf_size) {
        local[0..buf.len()].copy_from_slice(buf);
        return;
    }

    if !task.vm().mem_fd().is_open() {
        let nwritten = task.write_bytes_ptrace(addr, buf);
        if nwritten > 0 {
            task.vm().notify_written(addr, nwritten, flags);
        }

        if let Some(ok) = maybe_ok {
            if nwritten < buf_size {
                *ok = false;
            }
        }
        return;
    }

    Errno::clear();
    let nwritten_result = safe_pwrite64(task, buf, addr);
    // See comment in read_bytes_helper().
    if let Ok(0) = nwritten_result {
        task.open_mem_fd();
        // Try again
        return task.write_bytes_helper(addr, buf, maybe_ok, flags);
    }
    if errno() == EPERM {
        fatal!(
            "Can't write to /proc/{}/mem\n\
                        Maybe you need to disable grsecurity MPROTECT with:\n\
                           setfattr -n user.pax.flags -v 'emr' <executable>",
            task.tid()
        );
    }

    let nwritten = nwritten_result.unwrap_or(0);
    if let Some(ok) = maybe_ok {
        if nwritten < buf_size {
            *ok = false;
        }
    } else {
        ed_assert_eq!(
            task,
            nwritten,
            buf_size,
            "Should have written {} bytes to {}, but only wrote {}",
            buf_size,
            addr,
            nwritten,
        );
    }
    if nwritten > 0 {
        task.vm().notify_written(addr, nwritten, flags);
    }
}

/// NOT Forwarded method definition
///
/// Read `val` from `child_addr`.
/// If the data can't all be read, then if `ok` is non-null
/// sets *ok to false, otherwise asserts.
pub fn read_val_mem<D>(task: &dyn Task, child_addr: RemotePtr<D>, ok: Option<&mut bool>) -> D {
    let mut v: D = unsafe { zeroed() };
    let u8_slice = unsafe { slice::from_raw_parts_mut(&raw mut v as *mut u8, size_of::<D>()) };
    task.read_bytes_helper(RemotePtr::cast(child_addr), u8_slice, ok);
    v
}

/// Just like read_val_mem() for those occations where unsafe { zeroed() } for init
/// is not a good idea.
pub fn read_val_with_default_mem<D: Default>(
    task: &dyn Task,
    child_addr: RemotePtr<D>,
    ok: Option<&mut bool>,
) -> D {
    let mut v: D = Default::default();
    let u8_slice = unsafe { slice::from_raw_parts_mut(&raw mut v as *mut u8, size_of::<D>()) };
    task.read_bytes_helper(RemotePtr::cast(child_addr), u8_slice, ok);
    v
}

/// NOT Forwarded method definition
///
/// Read `count` values from `child_addr`.
pub fn read_mem<D: Clone>(
    task: &dyn Task,
    child_addr: RemotePtr<D>,
    count: usize,
    ok: Option<&mut bool>,
) -> Vec<D> {
    let mut v: Vec<D> = vec![unsafe { zeroed() }; count];
    let u8_slice =
        unsafe { slice::from_raw_parts_mut(v.as_mut_ptr() as *mut u8, count * size_of::<D>()) };
    task.read_bytes_helper(RemotePtr::cast(child_addr), u8_slice, ok);
    v
}

/// Forwarded method definition
///
pub(super) fn syscallbuf_data_size_common<T: Task>(task: &T) -> usize {
    let addr: RemotePtr<u32> = RemotePtr::cast(task.syscallbuf_child.get());
    read_val_mem::<u32>(task, addr + offset_of!(syscallbuf_hdr, num_rec_bytes), None) as usize
        + size_of::<syscallbuf_hdr>()
}

/// Forwarded method definition
///
/// Write `N` bytes from `buf` to `child_addr`, or don't return.
pub(super) fn write_bytes_common<T: Task>(task: &T, child_addr: RemotePtr<Void>, buf: &[u8]) {
    write_bytes_helper_common(task, child_addr, buf, None, WriteFlags::empty())
}

/// Forwarded method definition
///
pub(super) fn next_syscallbuf_record_common<T: Task>(task: &T) -> RemotePtr<syscallbuf_record> {
    // Next syscallbuf record is size_of the syscallbuf header + number of bytes in buffer
    let addr = RemotePtr::<u8>::cast(task.syscallbuf_child.get() + 1usize);
    let num_rec_bytes_addr = RemotePtr::<u8>::cast(task.syscallbuf_child.get())
        + offset_of!(syscallbuf_hdr, num_rec_bytes);

    // @TODO: Here we have used our knowledge that `num_rec_bytes` is a u32.
    // Explore if there a generic way to get that information
    let num_rec_bytes = read_val_mem(task, RemotePtr::<u32>::cast(num_rec_bytes_addr), None);
    RemotePtr::cast(addr + num_rec_bytes)
}

/// Forwarded method definition
///
pub(super) fn stored_record_size_common<T: Task>(
    task: &T,
    record: RemotePtr<syscallbuf_record>,
) -> usize {
    let size_field_addr: RemotePtr<u8> =
        RemotePtr::cast(record) + offset_of!(syscallbuf_record, size);

    // @TODO Here we have used our knowledge that `size` is a u32.
    // Explore a  generic way to get that information automatically
    preload_interface::stored_record_size(read_val_mem::<u32>(
        task,
        RemotePtr::cast(size_field_addr),
        None,
    )) as usize
}

/// NOT Forwarded method definition
///
/// Write single `val` to `child_addr`.
pub fn write_val_mem<D: 'static>(
    task: &dyn Task,
    child_addr: RemotePtr<D>,
    val: &D,
    ok: Option<&mut bool>,
) {
    write_val_mem_with_flags(task, child_addr, val, ok, WriteFlags::empty())
}

/// NOT Forwarded method definition
///
/// Write single `val` to `child_addr` and optionally specify a flag.
pub fn write_val_mem_with_flags<D: 'static>(
    task: &dyn Task,
    child_addr: RemotePtr<D>,
    val: &D,
    ok: Option<&mut bool>,
    flags: WriteFlags,
) {
    debug_assert!(type_has_no_holes::<D>());
    let data_slice = unsafe { slice::from_raw_parts(val as *const _ as *const u8, size_of::<D>()) };

    task.write_bytes_helper(RemotePtr::cast(child_addr), data_slice, ok, flags);
}

/// NOT Forwarded method definition
///
/// Write array of `val`s to `child_addr`.
pub fn write_mem<D: 'static>(
    task: &dyn Task,
    child_addr: RemotePtr<D>,
    val: &[D],
    ok: Option<&mut bool>,
) {
    debug_assert!(type_has_no_holes::<D>());
    let data_slice =
        unsafe { slice::from_raw_parts(val.as_ptr().cast::<u8>(), val.len() * size_of::<D>()) };
    task.write_bytes_helper(
        RemotePtr::cast(child_addr),
        data_slice,
        ok,
        WriteFlags::empty(),
    );
}

/// Forwarded method definition
///
/// Force the wait status of `task` to `status`, as if
/// `wait()/try_wait()` had returned it. Call this whenever a waitpid
/// returned activity for this past.
pub(super) fn did_waitpid_common<T: Task>(task: &T, mut status: WaitStatus) {
    // After PTRACE_INTERRUPT, any next two stops may be a group stop caused by
    // that PTRACE_INTERRUPT (or neither may be). This is because PTRACE_INTERRUPT
    // generally lets other stops win (and thus doesn't inject it's own stop), but
    // if the other stop was already done processing, even we didn't see it yet,
    // the stop will still be queued, so we could see the other stop and then the
    // PTRACE_INTERRUPT group stop.
    // When we issue PTRACE_INTERRUPT, we this set this counter to 2, and here
    // we decrement it on every stop such that while this counter is positive,
    // any group-stop could be one induced by PTRACE_INTERRUPT
    let mut siginfo_overridden = false;
    if task.expecting_ptrace_interrupt_stop.get() > 0 {
        task.expecting_ptrace_interrupt_stop
            .set(task.expecting_ptrace_interrupt_stop.get() - 1);
        if is_signal_triggered_by_ptrace_interrupt(status.maybe_group_stop_sig()) {
            // Assume this was PTRACE_INTERRUPT and thus treat this as
            // TIME_SLICE_SIGNAL instead.
            if task.session().is_recording() {
                // Force this timeslice to end
                task.session()
                    .as_record()
                    .unwrap()
                    .scheduler()
                    .expire_timeslice();
            }
            status = WaitStatus::for_stop_sig(TIME_SLICE_SIGNAL);
            let mut pending_siginfo = siginfo_t {
                si_code: POLL_IN as i32,
                si_signo: TIME_SLICE_SIGNAL.as_raw(),
                ..Default::default()
            };
            pending_siginfo._sifields._sigpoll.si_fd = task.hpc.borrow().ticks_interrupt_fd();
            task.pending_siginfo.set(pending_siginfo);
            siginfo_overridden = true;
            task.expecting_ptrace_interrupt_stop.set(0);
        }
    }

    if !siginfo_overridden && status.maybe_stop_sig().is_sig() {
        let mut local_pending_siginfo = Default::default();
        if !task.ptrace_if_alive(
            PTRACE_GETSIGINFO,
            RemotePtr::null(),
            &mut PtraceData::WriteInto(u8_slice_mut(&mut local_pending_siginfo)),
        ) {
            log!(LogDebug, "Unexpected process death for {}", task.tid());
            status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
        }
        task.pending_siginfo.set(local_pending_siginfo);
    }

    let original_syscallno = task.registers.borrow().original_syscallno();
    log!(LogDebug, "  (refreshing register cache)");
    // An unstable exit can cause a task to exit without us having run it, in
    // which case we might have pending register changes for it that are now
    // irrelevant. In that case we just throw away our register changes and use
    // whatever the kernel now has.
    if status.maybe_ptrace_event() != PTRACE_EVENT_EXIT {
        ed_assert!(
            task,
            !task.registers_dirty.get(),
            "Registers shouldn't already be dirty"
        );
    }
    // If the task was not stopped, we don't need to read the registers.
    // In fact if we didn't start the thread, we may not have flushed dirty
    // registers but still received a PTRACE_EVENT_EXIT, in which case the
    // task's register values are not what they should be.
    if !task.is_stopped.get() {
        let mut ptrace_regs: native_user_regs_struct = Default::default();
        if task.ptrace_if_alive(
            PTRACE_GETREGS,
            RemotePtr::null(),
            &mut PtraceData::WriteInto(u8_slice_mut(&mut ptrace_regs)),
        ) {
            task.registers.borrow_mut().set_from_ptrace(&ptrace_regs);
            // @TODO rr does an if-defined here
            // Check the architecture of the task by looking at the
            // cs segment register and checking if that segment is a long mode segment
            // (Linux always uses GDT entries for this, which are globally the same).
            let a: SupportedArch = if is_long_mode_segment(task.registers.borrow().cs() as u32) {
                SupportedArch::X64
            } else {
                SupportedArch::X86
            };
            if a != task.registers.borrow().arch() {
                *task.registers.borrow_mut() = Registers::new(a);
                task.registers.borrow_mut().set_from_ptrace(&ptrace_regs);
            }
        } else {
            log!(LogDebug, "Unexpected process death for {}", task.tid());
            status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
        }
    }

    task.is_stopped.set(true);
    task.wait_status.set(status);
    let more_ticks: Ticks = task.hpc.borrow().read_ticks(task);
    // We stop counting here because there may be things we want to do to the
    // tracee that would otherwise generate ticks.
    task.hpc.borrow_mut().stop_counting();
    task.session().accumulate_ticks_processed(more_ticks);
    task.ticks.set(task.ticks.get() + more_ticks);

    if status.maybe_ptrace_event() == PTRACE_EVENT_EXIT {
        task.seen_ptrace_exit_event.set(true);
    } else {
        if task.registers.borrow().singlestep_flag() {
            task.registers.borrow_mut().clear_singlestep_flag();
            task.registers_dirty.set(true);
        }

        if task.last_resume_orig_cx.get() != 0 {
            let new_cx: usize = task.registers.borrow().cx();
            // Un-fudge registers, if we fudged them to work around the KNL hardware quirk
            let cutoff: usize = single_step_coalesce_cutoff();
            ed_assert!(task, new_cx == cutoff - 1 || new_cx == cutoff);
            let local_last_resume_orig_cx = task.last_resume_orig_cx.get();
            task.registers
                .borrow_mut()
                .set_cx(local_last_resume_orig_cx - cutoff + new_cx);
            task.registers_dirty.set(true);
        }
        task.last_resume_orig_cx.set(0);

        if task.did_set_breakpoint_after_cpuid.get() {
            let bkpt_addr: RemoteCodePtr = task.address_of_last_execution_resume.get()
                + trapped_instruction_len(task.singlestepping_instruction.get());
            if task.ip() == bkpt_addr.increment_by_bkpt_insn_length(task.arch()) {
                let mut r = task.regs_ref().clone();
                r.set_ip(bkpt_addr);
                task.set_regs(&r);
            }
            task.vm()
                .remove_breakpoint(bkpt_addr, BreakpointType::Internal);
            task.did_set_breakpoint_after_cpuid.set(false);
        }
        if (task.singlestepping_instruction.get() == TrappedInstruction::Pushf
            || task.singlestepping_instruction.get() == TrappedInstruction::Pushf16)
            && task.ip()
                == task.address_of_last_execution_resume.get()
                    + trapped_instruction_len(task.singlestepping_instruction.get())
        {
            // We singlestepped through a pushf. Clear TF bit on stack.
            let sp: RemotePtr<u16> = RemotePtr::cast(task.regs_ref().sp());
            // If this address is invalid then we should have segfaulted instead of
            // retiring the instruction!
            let val: u16 = read_val_mem(task, sp, None);
            let write_val = val & !(X86_TF_FLAG as u16);
            write_val_mem(task, sp, &write_val, None);
        }
        task.singlestepping_instruction
            .set(TrappedInstruction::None);

        // We might have singlestepped at the resumption address and just exited
        // the kernel without executing the breakpoint at that address.
        // The kernel usually (always?) singlesteps an extra instruction when
        // we do this with PTRACE_SYSEMU_SINGLESTEP, but rd's ptrace emulation
        // doesn't and it's kind of a kernel bug.
        if task
            .vm()
            .get_breakpoint_type_at_addr(task.address_of_last_execution_resume.get())
            != BreakpointType::None
            && task.maybe_stop_sig() == SIGTRAP
            && !task.maybe_ptrace_event().is_ptrace_event()
            && task.ip()
                == task
                    .address_of_last_execution_resume
                    .get()
                    .increment_by_bkpt_insn_length(task.arch())
        {
            ed_assert_eq!(task, more_ticks, 0);
            // When we resume execution and immediately hit a breakpoint, the original
            // syscall number can be reset to -1. Undo that, so that the register
            // state matches the state we'd be in if we hadn't resumed. ReplayTimeline
            // depends on resume-at-a-breakpoint being a noop.
            task.registers
                .borrow_mut()
                .set_original_syscallno(original_syscallno);
            task.registers_dirty.set(true);
        }

        // If we're in the rd page,  we may have just returned from an untraced
        // syscall there and while in the rd page registers need to be consistent
        // between record and replay. During replay most untraced syscalls are
        // replaced with "xor eax,eax" (right after a "movq -1, %rcx") so
        // rcx is always -1, but during recording it sometimes isn't after we've
        // done a real syscall.
        if task.is_in_rd_page() {
            let arch = task.arch();
            // N.B.: Cross architecture syscalls don't go through the rd page, so we
            // know what the architecture is.
            task.canonicalize_regs(arch);
        }
    }

    task.did_wait();
}

const AR_L: u32 = 1 << 21;

/// Helper method
fn is_long_mode_segment(segment: u32) -> bool {
    let ar: u32;
    unsafe { llvm_asm!("lar $1, $0" : "=r"(ar) : "r"(segment)) };
    ar & AR_L == AR_L
}

/// Helper method
///
/// The value of rcx above which the CPU doesn't properly handle singlestep for
/// string instructions. Right now, since only once CPU has this quirk, this
/// value is hardcoded, but could depend on the CPU architecture in the future.
const fn single_step_coalesce_cutoff() -> usize {
    16
}

/// Forwarded method definition
///
/// Resume execution `how`, deliverying `sig` if nonzero.
/// After resuming, `wait_how`. In replay, reset hpcs and
/// request a tick period of tick_period. The default value
/// of tick_period is 0, which means effectively infinite.
/// If interrupt_after_elapsed is nonzero, we interrupt the task
/// after that many seconds have elapsed.
///
/// All tracee execution goes through here.
pub(super) fn resume_execution_common<T: Task>(
    task: &T,
    how: ResumeRequest,
    wait_how: WaitRequest,
    tick_period: TicksRequest,
    maybe_sig: Option<Sig>,
) {
    task.will_resume_execution(how, wait_how, tick_period, maybe_sig);
    match tick_period {
        TicksRequest::ResumeNoTicks => (),
        TicksRequest::ResumeUnlimitedTicks => {
            task.hpc.borrow_mut().reset(0);
            task.activate_preload_thread_locals();
        }
        TicksRequest::ResumeWithTicksRequest(tr) => {
            ed_assert!(task, tr <= MAX_TICKS_REQUEST);
            let adjusted_tr = max(1, tr);
            task.hpc.borrow_mut().reset(adjusted_tr);
            task.activate_preload_thread_locals();
        }
    }
    let sig_string = match maybe_sig {
        Some(sig) => format!(", signal: {}", sig),
        None => String::new(),
    };

    log!(
        LogDebug,
        "resuming execution of tid: {} with: {}{} tick_period: {:?}",
        task.tid(),
        ptrace_req_name(how as u32),
        sig_string,
        tick_period
    );
    task.address_of_last_execution_resume.set(task.ip());
    task.how_last_execution_resumed.set(how);
    task.set_debug_status(0);

    if is_singlestep_resume(how) {
        work_around_knl_string_singlestep_bug(task);
        let ti = trapped_instruction_at(task, task.ip());
        task.singlestepping_instruction.set(ti);
        if task.singlestepping_instruction.get() == TrappedInstruction::CpuId {
            // In KVM virtual machines (and maybe others), singlestepping over CPUID
            // executes the following instruction as well. Work around that.
            let ip = task.ip();
            let len = trapped_instruction_len(task.singlestepping_instruction.get());
            let local_did_set_breakpoint_after_cpuid =
                task.vm().add_breakpoint(ip + len, BreakpointType::Internal);
            task.did_set_breakpoint_after_cpuid
                .set(local_did_set_breakpoint_after_cpuid);
        }
    }

    task.flush_regs();

    let mut wait_ret: pid_t = 0;
    if task.session().is_recording() {
        // There's a nasty race where a stopped task gets woken up by a SIGKILL
        // and advances to the PTRACE_EXIT_EVENT ptrace-stop just before we
        // send a PTRACE_CONT. Our PTRACE_CONT will cause it to continue and exit,
        // which means we don't get a chance to clean up robust futexes etc.
        // Avoid that by doing a waitpid() here to see if it has exited.
        // This doesn't fully close the race since in theory we could be preempted
        // between the waitpid and the ptrace_if_alive, giving another task
        // a chance to SIGKILL our tracee and advance it to the PTRACE_EXIT_EVENT,
        // or just letting the tracee be scheduled to process its pending SIGKILL.
        //
        let mut raw_status: i32 = 0;
        // tid is already stopped but like it was described above, the task may have gotten
        // woken up by a SIGKILL -- in that case we can try waiting on it with a WNOHANG.
        wait_ret = unsafe { waitpid(task.tid(), &mut raw_status, WNOHANG | __WALL) };
        ed_assert!(
            task,
            0 <= wait_ret,
            "waitpid({}, NOHANG) failed with: {}",
            task.tid(),
            wait_ret
        );
        let status = WaitStatus::new(raw_status);
        if wait_ret == task.tid() {
            // In some (but not all) cases where the child was killed with SIGKILL,
            // we don't get PTRACE_EVENT_EXIT before it just exits.
            ed_assert!(
                task,
                status.maybe_ptrace_event() == PTRACE_EVENT_EXIT
                    || status.fatal_sig().map_or(false, |s| s == sig::SIGKILL),
                "got {:?}",
                status
            );
        } else {
            // 0 here means that no pids have changed state (WNOHANG)
            ed_assert!(
                task,
                0 == wait_ret,
                "waitpid({}, NOHANG) failed with: {}",
                task.tid(),
                wait_ret
            );
        }
    }
    // @TODO DIFF NOTE: Its more accurate to check if `wait_ret == task.tid` instead of
    // saying wait_ret > 0 but we leave it be for now to be consistent with rr.
    if wait_ret > 0 {
        log!(LogDebug, "Task: {} exited unexpectedly", task.tid());
        // wait() will see this and report the ptrace-exit event.
        task.detected_unexpected_exit.set(true);
    } else {
        match maybe_sig {
            None => {
                task.ptrace_if_alive(how as u32, RemotePtr::null(), &mut PtraceData::None);
            }
            Some(sig) => {
                task.ptrace_if_alive(
                    how as u32,
                    RemotePtr::null(),
                    &mut PtraceData::ReadWord(sig.as_raw() as usize),
                );
            }
        }
    }

    task.is_stopped.set(false);
    *task.extra_registers.borrow_mut() = None;
    if WaitRequest::ResumeWait == wait_how {
        task.wait(None);
    }
}

fn work_around_knl_string_singlestep_bug<T: Task>(task: &T) {
    let cx: usize = task.regs_ref().cx();
    let cutoff: usize = single_step_coalesce_cutoff();
    // The extra cx >= cutoff check is just an optimization, to avoid the
    // moderately expensive load from ip() if we can
    if cpu_has_knl_string_singlestep_bug() && cx > cutoff && at_x86_string_instruction(task) {
        // KNL has a quirk where single-stepping a string instruction can step up
        // to 64 iterations. Work around this by fudging registers to force the
        // processor to execute one iteration and one interation only.
        log!(
            LogDebug,
            "Working around KNL single-step hardware bug (cx={})",
            cx
        );
        if cx > cutoff {
            task.last_resume_orig_cx.set(cx);
            let mut r = task.regs_ref().clone();
            // An arbitrary value < cutoff would work fine here, except 1, since
            // the last iteration of the loop behaves differently
            r.set_cx(cutoff);
            task.set_regs(&r);
        }
    }
}

lazy_static! {
    static ref CPU_HAS_KNL_STRING_SINGLESTEP_BUG_INIT: bool =
        cpu_has_knl_string_singlestep_bug_init();
}

fn cpu_has_knl_string_singlestep_bug_init() -> bool {
    (cpuid(CPUID_GETFEATURES, 0).eax & 0xF0FF0) == 0x50670
}

fn cpu_has_knl_string_singlestep_bug() -> bool {
    *CPU_HAS_KNL_STRING_SINGLESTEP_BUG_INIT
}

pub(in super::super) fn os_clone_into(
    state: &CapturedState,
    remote: &mut AutoRemoteSyscalls,
) -> TaskSharedPtr {
    let session = remote.task().session();
    os_clone(
        CloneReason::SessionCloneNonLeader,
        session,
        remote,
        state.rec_tid,
        state.serial,
        // We don't actually /need/ to specify the
        // SIGHAND/SYSVMEM flags because those things
        // are emulated in the tracee.  But we use the
        // same flags as glibc to be on the safe side
        // wrt kernel bugs.
        //
        // We don't pass CLONE_SETTLS here *only*
        // because we'll do it later in
        // `copy_state()`.
        //
        // See `os_fork_into()` above for discussion
        // of the CTID flags.
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM,
        Some(state.top_of_stack),
        None,
        None,
        None,
    )
}

/// Make the OS-level calls to create a new fork or clone that
/// will eventually be a copy of this task and return that Task
/// metadata.  These methods are used in concert with
/// `Task::copy_state()` to create task copies during
/// checkpointing.
///
/// For `os_fork_into()`, `session` will be tracking the
/// returned fork child.
///
/// For `os_clone_into()`, `task_leader` is the "main thread"
/// in the process into which the copy of this task will be
/// created.  `task_leader` will perform the actual OS calls to
/// create the new child.
pub(in super::super) fn os_fork_into(t: &dyn Task, session: SessionSharedPtr) -> TaskSharedPtr {
    let rec_tid = t.rec_tid();
    let serial = t.serial.get();
    let mut remote =
        AutoRemoteSyscalls::new_with_mem_params(t, MemParamsEnabled::DisableMemoryParams);

    let child: TaskSharedPtr = os_clone(
        CloneReason::SessionCloneLeader,
        session,
        &mut remote,
        rec_tid,
        serial,
        // Most likely, we'll be setting up a
        // CLEARTID futex.  That's not done
        // here, but rather later in
        // |copy_state()|.
        //
        // We also don't use any of the SETTID
        // flags because that earlier work will
        // be copied by fork()ing the address
        // space.
        //
        SIGCHLD,
        None,
        None,
        None,
        None,
    );

    // When we forked ourselves, the child inherited the setup we
    // did to make the clone() call.  So we have to "finish" the
    // remote calls (i.e. undo fudged state) in the child too,
    // even though we never made any syscalls there.
    remote.restore_state_to(Some(&**child));

    child
}

fn on_syscall_exit_common_arch<Arch: Architecture>(t: &dyn Task, sys: i32, regs: &Registers) {
    t.session().accumulate_syscall_performed();

    if regs.original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO {
        return;
    }

    // mprotect can change the protection status of some mapped regions before
    // failing.
    // SYS_rdcall_mprotect_record always fails with ENOSYS, though we want to
    // note its usage here.
    if regs.syscall_failed()
        && !is_mprotect_syscall(sys, regs.arch())
        && sys != Arch::RDCALL_MPROTECT_RECORD
    {
        return;
    }

    if sys == Arch::BRK || sys == Arch::MMAP || sys == Arch::MMAP2 || sys == Arch::MREMAP {
        log!(
            LogDebug,
            "(brk/mmap/mmap2/mremap will receive / has received direct processing)"
        );
        return;
    }

    if sys == Arch::RDCALL_MPROTECT_RECORD {
        // When we record an rd replay of a tracee which does a syscallbuf'ed
        // `mprotect`, neither the replay nor its recording see the mprotect
        // syscall, since it's untraced during both recording and replay. rd
        // replay is notified of the syscall via the `mprotect_records`
        // mechanism; if it's being recorded, it forwards that notification to
        // the recorder by calling this syscall.
        let tid = regs.arg1() as pid_t;
        let addr = RemotePtr::from(regs.arg2());
        let num_bytes = regs.arg3();
        let prot = regs.arg4_signed() as i32;
        if tid == t.rec_tid() {
            return t
                .vm()
                .protect(t, addr, num_bytes, ProtFlags::from_bits(prot).unwrap());
        } else {
            match t.session().find_task_from_rec_tid(tid) {
                None => {
                    ed_assert!(
                        t,
                        false,
                        "Could not find task with rec tid: {} in session",
                        tid
                    );
                }
                Some(found_t) => {
                    return found_t.vm().protect(
                        &**found_t,
                        addr,
                        num_bytes,
                        ProtFlags::from_bits(prot).unwrap(),
                    );
                }
            }
        }
    }

    if sys == Arch::MPROTECT {
        let addr: RemotePtr<Void> = regs.arg1().into();
        let num_bytes: usize = regs.arg2();
        let prot = regs.arg3_signed() as i32;
        let prot_flags = ProtFlags::from_bits(prot).unwrap();
        t.vm().protect(t, addr, num_bytes, prot_flags);
    }

    if sys == Arch::MUNMAP {
        let addr: RemotePtr<Void> = regs.arg1().into();
        let num_bytes: usize = regs.arg2();
        return t.vm().unmap(t, addr, num_bytes);
    }

    if sys == Arch::SHMDT {
        return process_shmdt(t, regs.arg1().into());
    }

    if sys == Arch::MADVISE {
        let addr: RemotePtr<Void> = regs.arg1().into();
        let num_bytes: usize = regs.arg2();
        let advice = regs.arg3() as i32;
        return t.vm().advise(t, addr, num_bytes, advice);
    }

    if sys == Arch::IPC {
        match regs.arg1() as u32 {
            SHMDT => return process_shmdt(t, regs.arg5().into()),
            _ => return,
        }
    }

    if sys == Arch::SET_THREAD_AREA {
        t.set_thread_area(regs.arg1().into());
        return;
    }

    if sys == Arch::PRCTL {
        let arg1 = t.regs_ref().arg1_signed() as i32;
        match arg1 {
            PR_SET_SECCOMP => {
                if t.regs_ref().arg2() == SECCOMP_MODE_FILTER as usize && t.session().is_recording()
                {
                    t.seccomp_bpf_enabled.set(true);
                }
            }

            PR_SET_NAME => {
                let arg2 = t.regs_ref().arg2();
                t.update_prname(arg2.into());
            }

            _ => (),
        }
        return;
    }

    if sys == Arch::DUP || sys == Arch::DUP2 || sys == Arch::DUP3 {
        t.fd_table()
            .did_dup(regs.arg1() as i32, regs.syscall_result() as i32);
        return;
    }

    if sys == Arch::FCNTL64 || sys == Arch::FCNTL {
        if regs.arg2() == FcntlOperation::DUPFD as usize
            || regs.arg2() == FcntlOperation::DUPFD_CLOEXEC as usize
        {
            t.fd_table()
                .did_dup(regs.arg1() as i32, regs.syscall_result() as i32);
        }
        return;
    }

    if sys == Arch::CLOSE {
        t.fd_table().did_close(regs.arg1() as i32);
        return;
    }

    if sys == Arch::UNSHARE {
        if regs.arg1() & CLONE_FILES as usize != 0 {
            t.fd_table().task_set_mut().erase_task(t);
            *t.fds.borrow_mut() = Some(t.fd_table().clone_into_task(t));
        }
        return;
    }

    if sys == Arch::PWRITE64 || sys == Arch::WRITE {
        let fd: i32 = regs.arg1_signed() as i32;
        let mut ranges: Vec<file_monitor::Range> = Vec::new();
        let amount: isize = regs.syscall_result_signed();
        if amount > 0 {
            ranges.push(file_monitor::Range::new(
                regs.arg2().into(),
                amount as usize,
            ));
        }
        let offset = LazyOffset::new(t, regs, sys);
        offset.task().fd_table().did_write(fd, &ranges, &offset);
        return;
    }

    if sys == Arch::PWRITEV || sys == Arch::WRITEV {
        let fd: i32 = regs.arg1_signed() as i32;
        let mut ranges: Vec<file_monitor::Range> = Vec::new();
        let iovecs = read_mem(
            t,
            RemotePtr::<iovec<Arch>>::new(regs.arg2()),
            regs.arg3(),
            None,
        );
        let mut written = regs.syscall_result_signed();
        ed_assert!(t, written >= 0);
        for v in iovecs {
            let iov_remote_ptr = Arch::as_rptr(v.iov_base);
            let iov_len = Arch::size_t_as_usize(v.iov_len);
            let amount = min(written, iov_len.try_into().unwrap());
            if amount > 0 {
                ranges.push(file_monitor::Range::new(iov_remote_ptr, amount as usize));
                written -= amount;
            }
        }
        let offset = LazyOffset::new(t, regs, sys);
        offset.task().fd_table().did_write(fd, &ranges, &offset);
        return;
    }

    if sys == Arch::PTRACE {
        process_ptrace::<Arch>(regs, t);
        return;
    }
}

/// Forwarded method definition
///
/// Call this hook just before exiting a syscall.  Often Task
/// attributes need to be updated based on the finishing syscall.
/// Use 'regs' instead of t.regs_ref() because some registers may not be
/// set properly in the task yet.
pub(super) fn on_syscall_exit_common(
    t: &dyn Task,
    syscallno: i32,
    arch: SupportedArch,
    regs: &Registers,
) {
    with_converted_registers(regs, arch, |regs| {
        rd_arch_function_selfless!(on_syscall_exit_common_arch, arch, t, syscallno, regs);
    })
}

/// Among other things this function makes sure:
/// - Remote system calls can be made, mem fd is setup
/// - rd page, preload thread locals page is mapped in
/// - cpuid calls generate a SIGSEGV
///
/// Call this method when this task has exited a successful execve() syscall.
/// At this point it is safe to make remote syscalls.
pub(super) fn post_exec_syscall_common(t: &dyn Task) {
    let arch = t.arch();
    t.canonicalize_regs(arch);
    t.vm().post_exec_syscall(t);

    if SessionInner::has_cpuid_faulting() {
        // A SIGSEGV will be generated henceforward for every cpuid instruction
        // This setting needs to be set afresh for every execve.
        // (It gets propogated on fork and clone syscalls)
        let mut remote = AutoRemoteSyscalls::new(t);
        rd_infallible_syscall!(
            remote,
            syscall_number_for_arch_prctl(arch),
            ARCH_SET_CPUID,
            0
        );
    }
}

/// Forwarded method definition
///
/// DIFF NOTE: Simply called post_exec(...) in rr
/// Not to be confused with another post_exec() in rr that does not
/// take any arguments
pub(super) fn post_exec_for_exe_common<T: Task>(t: &T, exe_file: &OsStr) {
    let mut stopped_task_in_address_space = None;
    let mut other_task_in_address_space = false;
    for task in t.vm().task_set().iter_except(t.weak_self_clone()) {
        other_task_in_address_space = true;
        if task.is_stopped.get() {
            stopped_task_in_address_space = Some(task);
            break;
        }
    }
    match stopped_task_in_address_space {
        Some(stopped) => {
            // Note this is `t` and NOT `stopped`
            let syscallbuf_child = t.syscallbuf_child.get();
            let syscallbuf_size = t.syscallbuf_size.get();
            let scratch_ptr = t.scratch_ptr.get();
            let scratch_size = t.scratch_size.get();

            let mut remote_stopped = AutoRemoteSyscalls::new(&**stopped);
            unmap_buffers_for(
                &mut remote_stopped,
                Some(t),
                syscallbuf_child,
                syscallbuf_size,
                scratch_ptr,
                scratch_size,
            );
        }
        None => {
            if other_task_in_address_space {
                // We should clean up our syscallbuf/scratch but that's too hard since we
                // have no stopped task to use for that :-(.
                // (We can't clean up those buffers *before* the exec completes, because it
                // might fail in which case we shouldn't have cleaned them up.)
                // Just let the buffers leak. The AddressSpace will clean up our local
                // shared buffer when it's destroyed.
                log!(
                    LogWarn,
                    "Intentionally leaking syscallbuf after exec for task {}",
                    t.tid()
                );
            }
        }
    }
    t.session().post_exec(t);

    // As t has exec-ed, it now has different address space
    // So remove it from the current one
    t.vm().task_set_mut().erase_task(t);
    // Similarly it has a new fd table
    t.fd_table().task_set_mut().erase_task(t);

    *t.extra_registers.borrow_mut() = None;
    let mut e = t.extra_regs_ref().clone();
    // Reset to post-exec initial state
    e.reset();
    t.set_extra_regs(&e);

    t.syscallbuf_child.set(RemotePtr::null());
    t.syscallbuf_size.set(0);
    t.scratch_ptr.set(RemotePtr::null());
    t.cloned_file_data_fd_child.set(-1);
    t.desched_fd_child.set(-1);
    t.stopping_breakpoint_table.set(RemoteCodePtr::null());
    t.stopping_breakpoint_table_entry_size.set(0);
    t.preload_globals.set(Default::default());
    t.thread_group().borrow_mut().execed = true;
    t.thread_areas_.borrow_mut().clear();
    *t.thread_locals.borrow_mut() = [0u8; PRELOAD_THREAD_LOCALS_SIZE];

    // Take the t's old vm's exec count and add 1 to it
    let exec_count = t.vm().uid().exec_count() + 1;

    // Its time for the task to get a brand new AddressSpace!
    // Now t.vm() will point to the new vm
    *t.as_.borrow_mut() = Some(t.session().create_vm(t, Some(exe_file), Some(exec_count)));

    // It's barely-documented, but Linux unshares the fd table on exec
    *t.fds.borrow_mut() = Some(t.fd_table().clone_into_task(t));

    let prname = prname_from_exe_image(t.vm().exe_image()).to_owned();
    *t.prname.borrow_mut() = prname;
}

fn prname_from_exe_image(exe_image: &OsStr) -> &OsStr {
    let len = exe_image.as_bytes().len();
    debug_assert!(len > 0);
    let maybe_pos = exe_image.as_bytes().iter().rposition(|&c| c == b'/');
    let pos = match maybe_pos {
        Some(loc) if loc == len => {
            fatal!("empty prname?? {:?}", exe_image);
        }
        Some(loc) => loc + 1,
        None => 0,
    };
    OsStr::from_bytes(&exe_image.as_bytes()[pos..])
}

/// Forwarded method definition
///
/// Determine why a SIGTRAP occurred. Uses debug_status() but doesn't
/// consume it.
pub(super) fn compute_trap_reasons_common<T: Task>(t: &T) -> TrapReasons {
    ed_assert_eq!(t, t.maybe_stop_sig(), SIGTRAP);
    let mut reasons = TrapReasons::default();
    let status = t.debug_status();
    reasons.singlestep = status & DebugStatus::DsSingleStep as usize != 0;

    let addr_last_execution_resume = t.address_of_last_execution_resume.get();
    if is_singlestep_resume(t.how_last_execution_resumed.get()) {
        if is_at_syscall_instruction(t, addr_last_execution_resume)
            && t.ip() == addr_last_execution_resume + syscall_instruction_length(t.arch())
        {
            // During replay we execute syscall instructions in certain cases, e.g.
            // mprotect with syscallbuf. The kernel does not set DS_SINGLESTEP when we
            // step over those instructions so we need to detect that here.
            reasons.singlestep = true;
        } else {
            let ti: TrappedInstruction = trapped_instruction_at(t, addr_last_execution_resume);
            #[allow(clippy::if_same_then_else)]
            if ti == TrappedInstruction::CpuId
                && t.ip()
                    == addr_last_execution_resume
                        + trapped_instruction_len(TrappedInstruction::CpuId)
            {
                // Likewise we emulate CPUID instructions and must forcibly detect that
                // here.
                reasons.singlestep = true;
            // This also takes care of the did_set_breakpoint_after_cpuid workaround case
            } else if ti == TrappedInstruction::Int3
                && t.ip()
                    == addr_last_execution_resume
                        + trapped_instruction_len(TrappedInstruction::Int3)
            {
                // INT3 instructions should also be turned into a singlestep here.
                reasons.singlestep = true;
            }
        }
    }

    // In VMWare Player 6.0.4 build-2249910, 32-bit Ubuntu x86 guest,
    // single-stepping does not trigger watchpoints :-(. So we have to
    // check watchpoints here. fast_forward also hides watchpoint changes.
    // Write-watchpoints will detect that their value has changed and trigger.
    // XXX Read/exec watchpoints can't be detected this way so they're still
    // broken in the above configuration :-(.
    if status & (DebugStatus::DsWatchpointAny as usize | DebugStatus::DsSingleStep as usize) != 0 {
        t.vm().notify_watchpoint_fired(
            status,
            if is_singlestep_resume(t.how_last_execution_resumed.get()) {
                addr_last_execution_resume
            } else {
                RemoteCodePtr::null()
            },
        );
    }
    reasons.watchpoint = t.vm().has_any_watchpoint_changes()
        || (status & DebugStatus::DsWatchpointAny as usize != 0);

    // If we triggered a breakpoint, this would be the address of the breakpoint
    let ip_at_breakpoint: RemoteCodePtr = t.ip().decrement_by_bkpt_insn_length(t.arch());
    // Don't trust siginfo to report execution of a breakpoint if singlestep or
    // watchpoint triggered.
    if reasons.singlestep {
        reasons.breakpoint = AddressSpace::is_breakpoint_instruction(t, addr_last_execution_resume);
        if reasons.breakpoint {
            ed_assert_eq!(t, addr_last_execution_resume, ip_at_breakpoint);
        }
    } else if reasons.watchpoint {
        // We didn't singlestep, so watchpoint state is completely accurate.
        // The only way the last instruction could have triggered a watchpoint
        // and be a breakpoint instruction is if an EXEC watchpoint fired
        // at the breakpoint address.
        reasons.breakpoint = t.vm().has_exec_watchpoint_fired(ip_at_breakpoint)
            && AddressSpace::is_breakpoint_instruction(t, ip_at_breakpoint);
    } else {
        let si = t.get_siginfo();
        ed_assert_eq!(t, SIGTRAP, si.si_signo, " expected SIGTRAP, got {:?}", si);
        reasons.breakpoint = is_kernel_trap(si.si_code);

        let is_a_breakpoint = AddressSpace::is_breakpoint_instruction(t, ip_at_breakpoint);
        if reasons.breakpoint {
            ed_assert!(
                t,
                is_a_breakpoint,
                " expected breakpoint at {}, got siginfo {:?}",
                ip_at_breakpoint,
                si
            )
        }
    }
    reasons
}

pub(super) fn at_preload_init_common<T: Task>(t: &T) {
    t.vm().at_preload_init(t);
    do_preload_init(t);

    t.fd_table().init_syscallbuf_fds_disabled(t);
}

fn do_preload_init_arch<Arch: Architecture, T: Task>(t: &T) {
    let addr_val = t.regs_ref().arg1();
    let params = read_val_mem(
        t,
        RemotePtr::<rdcall_init_preload_params<Arch>>::new(addr_val),
        None,
    );

    t.preload_globals.set(Arch::as_rptr(params.globals));
    t.stopping_breakpoint_table
        .set(Arch::as_rptr(params.breakpoint_table).to_code_ptr());
    t.stopping_breakpoint_table_entry_size
        .set(params.breakpoint_table_entry_size.try_into().unwrap());
    for tt in t.vm().task_set().iter_except(t.weak_self_clone()) {
        tt.preload_globals.set(Arch::as_rptr(params.globals));

        tt.stopping_breakpoint_table
            .set(Arch::as_rptr(params.breakpoint_table).to_code_ptr());
        tt.stopping_breakpoint_table_entry_size
            .set(params.breakpoint_table_entry_size.try_into().unwrap());
    }

    assert!(!t.preload_globals.get().is_null());
    let preload_globals_ptr: RemotePtr<bool> = RemotePtr::cast(t.preload_globals.get());
    let addr = preload_globals_ptr + offset_of!(preload_globals, in_replay);
    let is_replaying = t.session().is_replaying();
    write_val_mem(t, addr, &is_replaying, None);
}

fn do_preload_init<T: Task>(t: &T) {
    rd_arch_task_function_selfless!(T, do_preload_init_arch, t.arch(), t);
}

/// Prior to calling this method a new process was created in the OS with
/// tid `new_tid`. The broad job of this method is to create all the state within
/// rd that will track this new process henceforward. Notice that the method
/// returns a TaskSharedPtr representing the new process. By the time the
/// method returns, the new process will point correctly to its address space,
/// fd_table etc. The new process will also be placed in the appropriate session.
pub(in super::super) fn clone_task_common(
    clone_this: &dyn Task,
    reason: CloneReason,
    flags: CloneFlags,
    stack: RemotePtr<Void>,
    tls: RemotePtr<Void>,
    _cleartid_addr: RemotePtr<i32>,
    new_tid: pid_t,
    new_rec_tid: Option<pid_t>,
    new_serial: u32,
    maybe_other_session: Option<SessionSharedPtr>,
) -> TaskSharedPtr {
    // By default the value of new_task_session is the same session as the session of clone_this task
    let mut new_task_session = clone_this.session();
    match maybe_other_session {
        Some(other_session) if !Rc::ptr_eq(&new_task_session, &other_session) => {
            ed_assert_eq!(clone_this, reason, CloneReason::SessionCloneLeader);
            new_task_session = other_session;
        }
        _ => {
            ed_assert!(
                clone_this,
                reason == CloneReason::TraceeClone || reason == CloneReason::SessionCloneNonLeader
            );
        }
    }
    // No longer mutable. Note that the LHS variable and RHS variable have the
    // same name
    let new_task_session = new_task_session;

    let rc_t = Rc::new_cyclic(|weak_self| {
        let t: Box<dyn Task> = new_task_session.new_task(
            new_tid,
            new_rec_tid,
            new_serial,
            clone_this.arch(),
            weak_self.clone(),
        );

        if flags.contains(CloneFlags::CLONE_SHARE_VM) {
            ed_assert!(
                clone_this,
                reason == CloneReason::TraceeClone || reason == CloneReason::SessionCloneNonLeader
            );
            // The cloned task has the same AddressSpace
            *t.as_.borrow_mut() = clone_this.as_.borrow().clone();
            if !stack.is_null() {
                let last_stack_byte: RemotePtr<Void> = stack - 1usize;
                if let Some(mapping) = t.vm().mapping_of(last_stack_byte) {
                    if !mapping.recorded_map.is_heap() {
                        let m: &KernelMapping = &mapping.map;
                        log!(LogDebug, "mapping stack for {} at {}", new_tid, m);
                        let m_start = m.start();
                        let m_len = m.len();
                        let m_prot = m.prot();
                        let m_flags = m.flags();
                        let m_file_offset_bytes = m.file_offset_bytes();
                        let m_device = m.device();
                        let m_inode = m.inode();

                        // Release the borrow because we may want to modify the vm MemoryMap
                        drop(mapping);
                        t.vm().map(
                            &*t,
                            m_start,
                            m_len,
                            m_prot,
                            m_flags,
                            m_file_offset_bytes,
                            OsStr::new("[stack]"),
                            m_device,
                            m_inode,
                            None,
                            None,
                            None,
                            None,
                            None,
                        );
                    }
                };
            }
        } else {
            // This will work both for session cloning related forks or within the
            // same session clones that _don't_ specify CLONE_SHARE_VM
            *t.as_.borrow_mut() = Some(new_task_session.clone_vm(&*t, clone_this.vm()));
        }

        t.syscallbuf_size.set(clone_this.syscallbuf_size.get());
        t.stopping_breakpoint_table
            .set(clone_this.stopping_breakpoint_table.get());
        t.stopping_breakpoint_table_entry_size
            .set(clone_this.stopping_breakpoint_table_entry_size.get());
        t.preload_globals.set(clone_this.preload_globals.get());
        t.seccomp_bpf_enabled
            .set(clone_this.seccomp_bpf_enabled.get());

        t
    });

    // FdTable is either shared or copied, so the contents of
    // syscallbuf_fds_disabled_child are still valid.
    if flags.contains(CloneFlags::CLONE_SHARE_FILES) {
        *rc_t.fds.borrow_mut() = clone_this.fds.borrow().clone();
        rc_t.fd_table().task_set_mut().insert_task(&**rc_t);
    } else {
        *rc_t.fds.borrow_mut() = Some(clone_this.fd_table().clone_into_task(&**rc_t));
    }

    rc_t.top_of_stack.set(stack);
    // Clone children, both thread and fork, inherit the parent
    // prname.
    *rc_t.prname.borrow_mut() = clone_this.prname.borrow().clone();

    // wait() before trying to do anything that might need to
    // use ptrace to access memory
    rc_t.wait(None);

    rc_t.post_wait_clone(clone_this, flags);
    if flags.contains(CloneFlags::CLONE_SHARE_THREAD_GROUP) {
        *rc_t.tg.borrow_mut() = clone_this.tg.borrow().clone();
    } else {
        *rc_t.tg.borrow_mut() = Some(new_task_session.clone_tg(&**rc_t, clone_this.thread_group()));
    }
    rc_t.thread_group()
        .borrow_mut()
        .task_set_mut()
        .insert_task(&**rc_t);

    rc_t.open_mem_fd_if_needed();
    *rc_t.thread_areas_.borrow_mut() = clone_this.thread_areas_.borrow().clone();
    if flags.contains(CloneFlags::CLONE_SET_TLS) {
        set_thread_area_from_clone(&**rc_t, tls);
    }

    rc_t.vm().task_set_mut().insert_task(&**rc_t);

    if reason == CloneReason::TraceeClone {
        if !flags.contains(CloneFlags::CLONE_SHARE_VM) {
            // Unmap syscallbuf and scratch for tasks running the original address
            // space.
            let mut remote = AutoRemoteSyscalls::new(&**rc_t);
            // Leak the scratch buffer for the task we cloned from. We need to do
            // this because we may be using part of it for the syscallbuf stack
            // and unmapping it now would cause a crash in the new task.
            for tt in clone_this
                .vm()
                .task_set()
                .iter_except(clone_this.weak_self_clone())
            {
                unmap_buffers_for(
                    &mut remote,
                    None,
                    tt.syscallbuf_child.get(),
                    tt.syscallbuf_size.get(),
                    tt.scratch_ptr.get(),
                    tt.scratch_size.get(),
                );
            }
            clone_this.vm().did_fork_into(remote.task());
        }

        if flags.contains(CloneFlags::CLONE_SHARE_FILES) {
            // Clear our desched_fd_child so that we don't try to close it.
            // It should only be closed in `clone_this`.
            rc_t.desched_fd_child.set(-1);
            rc_t.cloned_file_data_fd_child.set(-1);
        } else {
            // Close syscallbuf fds for tasks using the original fd table.
            let mut remote = AutoRemoteSyscalls::new(&**rc_t);
            close_buffers_for(&mut remote, Some(clone_this));
            for tt in clone_this
                .fd_table()
                .task_set()
                .iter_except(clone_this.weak_self_clone())
            {
                close_buffers_for(&mut remote, Some(&**tt))
            }
        }
    }

    rc_t.post_vm_clone(reason, flags, clone_this);

    rc_t
}

fn set_thread_area_from_clone(t: &dyn Task, tls: RemotePtr<u8>) {
    rd_arch_function_selfless!(set_thread_area_from_clone_arch, t.arch(), t, tls)
}

fn set_thread_area_from_clone_arch<Arch: Architecture>(t: &dyn Task, tls: RemotePtr<Void>) {
    if Arch::CLONE_TLS_TYPE == CloneTLSType::UserDescPointer {
        t.set_thread_area(RemotePtr::cast(tls));
    }
}

/// A function that does some buffer related cleanups
///
/// `remote` is used for the actual syscall munmap of mapping
/// `maybe_unmap_for` (if available) is used to remove
/// the mapping from our data structure, otherwise remote.task()
/// is used
///
/// DIFF NOTE: Param list different from rr version
fn unmap_buffers_for(
    remote: &mut AutoRemoteSyscalls,
    maybe_unmap_for: Option<&dyn Task>,
    other_syscallbuf_child: RemotePtr<syscallbuf_hdr>,
    other_syscallbuf_size: usize,
    other_scratch_ptr: RemotePtr<Void>,
    other_scratch_size: usize,
) {
    let arch = remote.task().arch();
    if !other_scratch_ptr.is_null() {
        rd_infallible_syscall!(
            remote,
            syscall_number_for_munmap(arch),
            other_scratch_ptr.as_usize(),
            other_scratch_size
        );
        match maybe_unmap_for {
            None => remote
                .task()
                .vm()
                .unmap(remote.task(), other_scratch_ptr, other_scratch_size),
            Some(unmap_for) => {
                unmap_for
                    .vm()
                    .unmap(unmap_for, other_scratch_ptr, other_scratch_size)
            }
        }
    }
    if !other_syscallbuf_child.is_null() {
        rd_infallible_syscall!(
            remote,
            syscall_number_for_munmap(arch),
            other_syscallbuf_child.as_usize(),
            other_syscallbuf_size
        );
        match maybe_unmap_for {
            None => remote.task().vm().unmap(
                remote.task(),
                RemotePtr::<Void>::cast(other_syscallbuf_child),
                other_syscallbuf_size,
            ),
            Some(unmap_for) => unmap_for.vm().unmap(
                unmap_for,
                RemotePtr::<Void>::cast(other_syscallbuf_child),
                other_syscallbuf_size,
            ),
        }
    }
}

// DIFF NOTE: Param list slightly different from rr version. Additional param `maybe_other` is an Option<>
pub fn close_buffers_for(remote: &mut AutoRemoteSyscalls, maybe_other: Option<&dyn Task>) {
    let arch = remote.task().arch();
    let (desched_fd_child, cloned_file_data_fd_child) = match maybe_other {
        Some(other) => (
            other.desched_fd_child.get(),
            other.cloned_file_data_fd_child.get(),
        ),
        None => (
            remote.task().desched_fd_child.get(),
            remote.task().cloned_file_data_fd_child.get(),
        ),
    };
    let mut v = Vec::new();
    if let Some(other) = maybe_other {
        v.push(other)
    }
    if desched_fd_child >= 0 {
        if remote.task().session().is_recording() {
            rd_infallible_syscall!(remote, syscall_number_for_close(arch), desched_fd_child);
        }

        remote.task().fd_table().did_close(desched_fd_child);
    }
    if cloned_file_data_fd_child >= 0 {
        rd_infallible_syscall!(
            remote,
            syscall_number_for_close(arch),
            cloned_file_data_fd_child
        );
        remote
            .task()
            .fd_table()
            .did_close(cloned_file_data_fd_child);
    }
}

pub(super) fn post_vm_clone_common<T: Task>(
    t: &T,
    reason: CloneReason,
    flags: CloneFlags,
    origin: &dyn Task,
) -> bool {
    let mut created_preload_thread_locals_mapping: bool = false;
    if !flags.contains(CloneFlags::CLONE_SHARE_VM) {
        created_preload_thread_locals_mapping = t.vm().post_vm_clone(t);
    }

    if reason == CloneReason::TraceeClone {
        t.setup_preload_thread_locals_from_clone(origin);
    }

    created_preload_thread_locals_mapping
}

/// Forwarded method definition
///
pub(super) fn destroy_buffers_common<T: Task>(t: &T) {
    let saved_syscallbuf_child = t.syscallbuf_child.get();
    let mut remote = AutoRemoteSyscalls::new(t);
    // Clear syscallbuf_child now so nothing tries to use it while tearing
    // down buffers.
    remote.task().syscallbuf_child.set(RemotePtr::null());
    let syscallbuf_size = remote.task().syscallbuf_size.get();
    let scratch_ptr = remote.task().scratch_ptr.get();
    let scratch_size = remote.task().scratch_size.get();
    unmap_buffers_for(
        &mut remote,
        None,
        saved_syscallbuf_child,
        syscallbuf_size,
        scratch_ptr,
        scratch_size,
    );
    remote.task().scratch_ptr.set(RemotePtr::null());
    close_buffers_for(&mut remote, None);
    remote.task().desched_fd_child.set(-1);
    remote.task().cloned_file_data_fd_child.set(-1);
}

pub(super) fn task_cleanup_common<T: Task>(t: &T, sess: &dyn Session) {
    if t.unstable.get() {
        log!(
            LogWarn,
            "{} is unstable; not blocking on its termination",
            t.tid()
        );
        // This will probably leak a zombie process for rd's lifetime.

        // Destroying a Session may result in unstable exits during which
        // destroy_buffers() will not have been called.
        if !t.syscallbuf_child.get().is_null() {
            t.vm().unmap(
                t,
                RemotePtr::cast(t.syscallbuf_child.get()),
                t.syscallbuf_size.get(),
            );
        }
        // The session is being dropped so we cant run things like
        // finish_initializing() that is run in fn tasks_mut()
        // This is a workaround
        if t.try_session().is_none() {
            if sess.is_recording() {
                sess.as_record()
                    .unwrap()
                    .scheduler()
                    .on_destroy_task(t.as_rec_unwrap());
            }
            sess.as_session_inner()
                .task_map
                .borrow_mut()
                .remove(&t.rec_tid());
        } else {
            sess.on_destroy_task(t);
        }
    } else {
        ed_assert!(t, t.seen_ptrace_exit_event.get());
        ed_assert!(t, t.syscallbuf_child.get().is_null());

        if t.thread_group().borrow().task_set().is_empty() && !t.session().is_recording() {
            // Reap the zombie.
            let ret =
                unsafe { waitpid(t.thread_group().borrow().real_tgid, ptr::null_mut(), __WALL) };
            if ret == -1 {
                ed_assert!(t, errno() == ECHILD || errno() == ESRCH);
            } else {
                ed_assert_eq!(t, ret, t.thread_group().borrow().real_tgid);
            }
        }

        sess.on_destroy_task(t);
    }

    t.thread_group().borrow_mut().task_set_mut().erase_task(t);
    t.vm().task_set_mut().erase_task(t);
    t.fd_table().task_set_mut().erase_task(t);

    log!(LogDebug, "  dead");
}

/// Forwarded method definition
///
pub(super) fn set_thread_area_common<T: Task>(t: &T, tls: RemotePtr<user_desc>) {
    // We rely on the fact that user_desc is word-size-independent.
    let desc: user_desc = read_val_mem(t, tls, None);
    set_thread_area_core(&mut t.thread_areas_.borrow_mut(), desc)
}

pub(super) fn set_thread_area_core(thread_areas: &mut Vec<user_desc>, desc: user_desc) {
    for t in thread_areas.iter_mut() {
        if t.entry_number == desc.entry_number {
            *t = desc;
            return;
        }
    }

    thread_areas.push(desc);
}

fn process_shmdt(t: &dyn Task, addr: RemotePtr<Void>) {
    let size: usize = t.vm().get_shm_size(addr);
    t.vm().remove_shm_size(addr);
    t.vm().unmap(t, addr, size);
}

fn process_ptrace<Arch: Architecture>(regs: &Registers, t: &dyn Task) {
    let pid = regs.arg2_signed() as pid_t;
    let maybe_tracee = t.session().find_task_from_rec_tid(pid);
    match regs.arg1() as u32 {
        PTRACE_SETREGS => {
            let tracee = maybe_tracee.unwrap();
            let data = read_mem(
                t,
                RemotePtr::<u8>::from(regs.arg4()),
                size_of::<Arch::user_regs_struct>(),
                None,
            );
            let mut r: Registers = tracee.regs_ref().clone();
            r.set_from_ptrace_for_arch(Arch::arch(), &data);
            tracee.set_regs(&r);
            return;
        }
        PTRACE_SETFPREGS => {
            let data = read_mem(
                t,
                RemotePtr::<u8>::from(regs.arg4()),
                size_of::<Arch::user_fpregs_struct>(),
                None,
            );
            let mut r = t.extra_regs_ref().clone();
            r.set_user_fpregs_struct(t, Arch::arch(), &data);
            t.set_extra_regs(&r);
            return;
        }
        PTRACE_SETFPXREGS => {
            let data = read_val_mem(
                t,
                RemotePtr::<x86::user_fpxregs_struct>::from(regs.arg4()),
                None,
            );
            let mut r = t.extra_regs_ref().clone();
            r.set_user_fpxregs_struct(t, &data);
            t.set_extra_regs(&r);
            return;
        }
        PTRACE_SETREGSET => {
            match regs.arg3() as u32 {
                NT_PRSTATUS => {
                    let tracee = maybe_tracee.unwrap();
                    let set =
                        ptrace_get_regs_set::<Arch>(t, regs, size_of::<Arch::user_regs_struct>());
                    let mut r = tracee.regs_ref().clone();
                    r.set_from_ptrace_for_arch(Arch::arch(), &set);
                    tracee.set_regs(&r);
                }
                NT_FPREGSET => {
                    let tracee = maybe_tracee.unwrap();
                    let set =
                        ptrace_get_regs_set::<Arch>(t, regs, size_of::<Arch::user_fpregs_struct>());
                    let mut r: ExtraRegisters = tracee.extra_regs_ref().clone();
                    r.set_user_fpregs_struct(t, Arch::arch(), &set);
                    tracee.set_extra_regs(&r);
                }
                NT_X86_XSTATE => {
                    let tracee = maybe_tracee.unwrap();
                    let format = tracee.extra_regs_ref().format();
                    match format {
                        Format::XSave => {
                            let set = ptrace_get_regs_set::<Arch>(
                                t,
                                regs,
                                tracee.extra_regs_ref().data_size(),
                            );
                            let mut r = ExtraRegisters::default();
                            let layout: XSaveLayout;
                            let session = t.session();
                            let maybe_replay = session.as_replay();
                            match maybe_replay {
                                Some(replay) => {
                                    layout = xsave_layout_from_trace(
                                        replay.trace_reader().cpuid_records(),
                                    );
                                }
                                None => {
                                    layout = xsave_native_layout().clone();
                                }
                            };
                            let ok = r.set_to_raw_data(tracee.arch(), Format::XSave, &set, layout);
                            ed_assert!(t, ok, "Invalid XSAVE data");
                            tracee.set_extra_regs(&r);
                        }
                        _ => {
                            ed_assert!(
                                t,
                                false,
                                "Unknown ExtraRegisters format; \n\
                                         Should have been caught during \n\
                                         prepare_ptrace"
                            );
                        }
                    }
                }
                _ => {
                    ed_assert!(
                        t,
                        false,
                        "Unknown regset type; Should have been \n\
                                        caught during prepare_ptrace"
                    );
                }
            }
            return;
        }
        PTRACE_POKEUSER => {
            let tracee = maybe_tracee.unwrap();
            let addr: usize = regs.arg3();
            let data: Arch::unsigned_word = Arch::as_unsigned_word(regs.arg4());
            if addr < size_of::<Arch::user_regs_struct>() {
                let mut r: Registers = tracee.regs_ref().clone();
                r.write_register_by_user_offset(addr, regs.arg4());
                tracee.set_regs(&r);
            } else {
                let u_debugreg_offset: usize = match Arch::arch() {
                    // Unfortunately we can't do something like offset_of!(Arch::user, u_debugreg)
                    // as rustc complains. Revisit to see if we can make this more generic.
                    SupportedArch::X64 => offset_of!(x64::user, u_debugreg),
                    SupportedArch::X86 => offset_of!(x86::user, u_debugreg),
                };

                // Assumes that there would be no fields added after u_debugreg[7]
                if addr >= u_debugreg_offset && addr < size_of::<Arch::user>() {
                    let regno: usize = (addr - u_debugreg_offset) / size_of_val(&data);
                    tracee.set_debug_reg(regno, regs.arg4());
                }
            }
            return;
        }
        PTRACE_ARCH_PRCTL => {
            let code = regs.arg4() as u32;
            match code {
                ARCH_GET_FS | ARCH_GET_GS => (),
                ARCH_SET_FS | ARCH_SET_GS => {
                    let tracee = maybe_tracee.unwrap();
                    let mut r: Registers = tracee.regs_ref().clone();
                    if regs.arg3() == 0 {
                        // Work around a kernel bug in pre-4.7 kernels, where setting
                        // the gs/fs base to 0 via PTRACE_REGSET did not work correctly.
                        tracee.ptrace_if_alive(
                            PTRACE_ARCH_PRCTL,
                            regs.arg3().into(),
                            &mut PtraceData::ReadWord(regs.arg4()),
                        );
                    }
                    if code == ARCH_SET_FS {
                        r.set_fs_base(regs.arg3() as u64);
                    } else {
                        r.set_gs_base(regs.arg3() as u64);
                    }
                    tracee.set_regs(&r);
                }
                _ => {
                    let tracee_rc = maybe_tracee.unwrap();
                    ed_assert!(
                        tracee_rc.as_ref(),
                        false,
                        "Should have detected this earlier"
                    );
                }
            };
            return;
        }
        _ => (),
    }
}

fn ptrace_get_regs_set<Arch: Architecture>(
    t: &dyn Task,
    regs: &Registers,
    min_size: usize,
) -> Vec<u8> {
    let iov = read_val_mem(t, RemotePtr::<iovec<Arch>>::from(regs.arg4()), None);
    let remote_ptr = Arch::as_rptr(iov.iov_base);
    let iov_len = Arch::size_t_as_usize(iov.iov_len);
    ed_assert!(
        t,
        iov_len >= min_size,
        "Should have been caught during prepare_ptrace"
    );
    read_mem(t, remote_ptr, iov_len, None)
}

/// Forwarded method definition
///
pub(super) fn detect_syscall_arch_common<T: Task>(task: &T) -> SupportedArch {
    let mut syscall_arch = SupportedArch::X64;
    let arch = task.arch();
    let code_ptr = task.regs_ref().ip().decrement_by_syscall_insn_length(arch);
    let ok = get_syscall_instruction_arch(task, code_ptr, &mut syscall_arch);
    ed_assert!(task, ok);
    syscall_arch
}

/// Forwarded method definition
///
pub(super) fn set_syscallbuf_locked_common<T: Task>(t: &T, locked: bool) {
    if t.syscallbuf_child.get().is_null() {
        return;
    }
    let remote_addr: RemotePtr<u8> =
        RemotePtr::<u8>::cast(t.syscallbuf_child.get()) + offset_of!(syscallbuf_hdr, locked);
    let locked_before =
        read_val_mem::<syscallbuf_locked_why>(t, RemotePtr::cast(remote_addr), None);

    let new_locked: syscallbuf_locked_why = if locked {
        locked_before | syscallbuf_locked_why::SYSCALLBUF_LOCKED_TRACER
    } else {
        locked_before & !syscallbuf_locked_why::SYSCALLBUF_LOCKED_TRACER
    };

    if new_locked != locked_before {
        write_val_mem(t, RemotePtr::cast(remote_addr), &new_locked, None);
    }
}

/// Forwarded method definition
///
pub(super) fn reset_syscallbuf_common<T: Task>(t: &T) {
    let syscallbuf_child_addr = t.syscallbuf_child.get();
    if syscallbuf_child_addr.is_null() {
        return;
    }

    if t.is_in_untraced_syscall() {
        let check = !read_val_mem::<syscallbuf_locked_why>(
            t,
            RemotePtr::cast(
                RemotePtr::<u8>::cast(syscallbuf_child_addr) + offset_of!(syscallbuf_hdr, locked),
            ),
            None,
        )
        .contains(syscallbuf_locked_why::SYSCALLBUF_LOCKED_TRACEE);
        ed_assert!(t, check);
    }

    let num_rec_bytes: u32 = read_val_mem(
        t,
        RemotePtr::<u32>::cast(
            RemotePtr::<u8>::cast(syscallbuf_child_addr)
                + offset_of!(syscallbuf_hdr, num_rec_bytes),
        ),
        None,
    );
    let m = t
        .vm()
        .local_mapping_mut(
            RemotePtr::<u8>::cast(syscallbuf_child_addr + 1usize),
            num_rec_bytes as usize,
        )
        .unwrap();
    m.fill(0);

    let zero = 0u32;
    write_val_mem(
        t,
        RemotePtr::<u32>::cast(
            RemotePtr::<u8>::cast(syscallbuf_child_addr)
                + offset_of!(syscallbuf_hdr, num_rec_bytes),
        ),
        &zero,
        None,
    );
    write_val_mem(
        t,
        RemotePtr::<u32>::cast(
            RemotePtr::<u8>::cast(syscallbuf_child_addr)
                + offset_of!(syscallbuf_hdr, mprotect_record_count),
        ),
        &zero,
        None,
    );
    write_val_mem(
        t,
        RemotePtr::<u32>::cast(
            RemotePtr::<u8>::cast(syscallbuf_child_addr)
                + offset_of!(syscallbuf_hdr, mprotect_record_count_completed),
        ),
        &zero,
        None,
    );
    write_val_mem(
        t,
        RemotePtr::<u32>::cast(
            RemotePtr::<u8>::cast(syscallbuf_child_addr)
                + offset_of!(syscallbuf_hdr, blocked_sigs_generation),
        ),
        &zero,
        None,
    );
}

/// Make this task look like an identical copy of the task whose state
/// was captured by capture_task_state(), in
/// every way relevant to replay.  This task should have been
/// created by calling `os_clone_into()` or `os_fork_into()`,
/// and if it wasn't results are undefined.
///
/// Some task state must be copied into this by injecting and
/// running syscalls in this task.  Other state is metadata
/// that can simply be copied over in local memory
pub(in super::super) fn copy_state(t: &dyn Task, state: &CapturedState) {
    t.set_regs(&state.regs);
    t.set_extra_regs(&state.extra_regs);
    {
        let mut remote = AutoRemoteSyscalls::new(t);
        {
            let arch = remote.arch();
            let mut remote_prname =
                AutoRestoreMem::push_cstr(&mut remote, state.prname.as_os_str());
            log!(LogDebug, "    setting name to {:?}", state.prname);
            let child_addr = remote_prname.get().unwrap();
            rd_infallible_syscall!(
                remote_prname,
                syscall_number_for_prctl(arch),
                PR_SET_NAME,
                child_addr.as_usize()
            );
            remote_prname.task().update_prname(child_addr);
        }

        copy_tls(state, &mut remote);
        *remote.task().thread_areas_.borrow_mut() = state.thread_areas.clone();
        remote.task().syscallbuf_size.set(state.syscallbuf_size);

        ed_assert!(
            remote.task(),
            remote.task().syscallbuf_child.get().is_null(),
            "Syscallbuf should not already be initialized in clone"
        );
        if !state.syscallbuf_child.is_null() {
            // All these fields are preserved by the fork.
            remote.task().desched_fd_child.set(state.desched_fd_child);
            remote
                .task()
                .cloned_file_data_fd_child
                .set(state.cloned_file_data_fd_child);
            if state.cloned_file_data_fd_child >= 0 {
                remote.infallible_lseek_syscall(
                    state.cloned_file_data_fd_child,
                    state.cloned_file_data_offset.try_into().unwrap(),
                    SEEK_SET,
                );
            }
            remote.task().syscallbuf_child.set(state.syscallbuf_child);
        }
    }

    t.preload_globals.set(state.preload_globals);
    ed_assert!(t, t.vm().thread_locals_tuid() != t.tuid());
    *t.thread_locals.borrow_mut() = state.thread_locals;
    // The scratch buffer (for now) is merely a private mapping in
    // the remote task.  The CoW copy made by fork()'ing the
    // address space has the semantics we want.  It's not used in
    // replay anyway.
    t.scratch_ptr.set(state.scratch_ptr);
    t.scratch_size.set(state.scratch_size);

    // Whatever |from|'s last wait status was is what ours would
    // have been.
    t.wait_status.set(state.wait_status);

    t.ticks.set(state.ticks);
}

fn copy_tls(state: &CapturedState, remote: &mut AutoRemoteSyscalls) {
    let arch = remote.arch();
    rd_arch_function_selfless!(copy_tls_arch, arch, state, remote);
}

fn copy_tls_arch<Arch: Architecture>(state: &CapturedState, remote: &mut AutoRemoteSyscalls) {
    if Arch::CLONE_TLS_TYPE == CloneTLSType::UserDescPointer {
        for t in &state.thread_areas {
            let data: &[u8] = unsafe {
                slice::from_raw_parts(t as *const user_desc as *const u8, size_of::<user_desc>())
            };
            let arch = remote.arch();
            let mut remote_tls = AutoRestoreMem::new(remote, Some(data), data.len());
            let addr = remote_tls.get().unwrap();
            log!(LogDebug, "    setting tls {}", addr);
            rd_infallible_syscall!(
                remote_tls,
                syscall_number_for_set_thread_area(arch),
                addr.as_usize()
            );
        }
    }
}

/// Make the OS-level calls to clone `parent` into `session`
/// and return the resulting Task metadata for that new
/// process.  This is as opposed to `Task::clone()`, which only
/// attaches Task metadata to an /existing/ process.
///
/// The new clone will be tracked in `session`.  The other
/// arguments are as for `Task::clone()` above.
///
/// NOTE: This method corresponds to static method Task::os_clone() in rr
fn os_clone(
    reason: CloneReason,
    session: SessionSharedPtr,
    remote: &mut AutoRemoteSyscalls,
    rec_child_tid: pid_t,
    new_serial: u32,
    base_flags: i32,
    maybe_stack: Option<RemotePtr<Void>>,
    maybe_ptid: Option<RemotePtr<i32>>,
    maybe_tls: Option<RemotePtr<Void>>,
    maybe_ctid: Option<RemotePtr<i32>>,
) -> TaskSharedPtr {
    let stack = maybe_stack.unwrap_or_default();
    let ptid = maybe_ptid.unwrap_or_default();
    let tls = maybe_tls.unwrap_or_default();
    let ctid = maybe_ctid.unwrap_or_default();

    let mut ret: isize;
    loop {
        ret = perform_remote_clone(remote, base_flags, stack, ptid, tls, ctid);
        if ret != EAGAIN as isize {
            break;
        }
    }
    ed_assert!(
        remote.task(),
        ret >= 0,
        "remote clone failed with errno {}",
        errno_name(-ret as i32)
    );

    // This should have been set in the remote clone syscall made in perform_remote_clone()
    let new_tid = remote.new_tid().unwrap();
    let child = remote.task().clone_task(
        reason,
        clone_flags_to_task_flags(base_flags),
        stack,
        tls,
        ctid,
        new_tid,
        Some(rec_child_tid),
        new_serial,
        Some(session),
    );

    child
}

fn perform_remote_clone(
    remote: &mut AutoRemoteSyscalls,
    base_flags: i32,
    stack: RemotePtr<u8>,
    ptid: RemotePtr<i32>,
    tls: RemotePtr<u8>,
    ctid: RemotePtr<i32>,
) -> isize {
    let arch = remote.arch();
    rd_arch_function_selfless!(
        perform_remote_clone_arch,
        arch,
        remote,
        base_flags,
        stack,
        ptid,
        tls,
        ctid
    )
}

fn perform_remote_clone_arch<Arch: Architecture>(
    remote: &mut AutoRemoteSyscalls,
    base_flags: i32,
    stack: RemotePtr<u8>,
    ptid: RemotePtr<i32>,
    tls: RemotePtr<u8>,
    ctid: RemotePtr<i32>,
) -> isize {
    match Arch::CLONE_PARAMETER_ORDERING {
        CloneParameterOrdering::FlagsStackParentTLSChild => rd_syscall!(
            remote,
            Arch::CLONE,
            base_flags,
            stack.as_usize(),
            ptid.as_usize(),
            tls.as_usize(),
            ctid.as_usize()
        ),
        CloneParameterOrdering::FlagsStackParentChildTLS => rd_syscall!(
            remote,
            Arch::CLONE,
            base_flags,
            stack.as_usize(),
            ptid.as_usize(),
            ctid.as_usize(),
            tls.as_usize()
        ),
    }
}

/// Forwarded method definition
///
pub(super) fn destroy_common<T: Task>(t: &T, maybe_detach: Option<bool>) {
    let detach = maybe_detach.unwrap_or(true);
    if detach {
        log!(
            LogDebug,
            "task {} (rec:{}) is dying ...",
            t.tid(),
            t.rec_tid()
        );

        t.fallible_ptrace(PTRACE_DETACH, RemotePtr::null(), &mut PtraceData::None);
    }
}

/// Forwarded method definition
///
/// Currently does nothing
pub(super) fn post_wait_clone_common<T: Task>(
    _clone_to: &T,
    _clone_from: &dyn Task,
    _flags: CloneFlags,
) {
    // Do nothing
}
