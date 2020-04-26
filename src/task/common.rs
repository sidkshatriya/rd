//! This file contains all methods that are:
//! (a) Common between ReplayTask and Record tasks. These methods are called from forwarding stubs
//!     in the trait impls. These stubs are needed because default methods in the trait
//!     implementation have an implicit ?Sized constraint. By calling the stubs that call the
//!     methods in this file we get Sized for "free" because both ReplayTask and RecordTask are
//!     Sized.
//! (b) Some utility methods which because of their template parameters cannot be added to the
//!     Task trait. This makes calling them a tad bit more inconvenient as we _cannot_ invoke using
//!     the self.func_name() style. They are included in this file because they take &dyn Task or
//!     &mut dyn Task as their first parameter. It would have been confusing to include them
//!     in task_inner.rs

use crate::address_space::memory_range::MemoryRangeKey;
use crate::auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem};
use crate::bindings::kernel::{itimerval, setitimer};
use crate::bindings::ptrace::{PTRACE_EVENT_EXIT, PTRACE_INTERRUPT};
use crate::core::type_has_no_holes;
use crate::kernel_abi::common::preload_interface;
use crate::kernel_abi::common::preload_interface::{syscallbuf_hdr, syscallbuf_record};
use crate::kernel_abi::{
    syscall_number_for_close, syscall_number_for_mprotect, syscall_number_for_openat,
};
use crate::log::LogLevel::{LogDebug, LogInfo, LogWarn};
use crate::rd::RD_RESERVED_ROOT_DIR_FD;
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::task::task_inner::task_inner::{PtraceData, WriteFlags};
use crate::task::Task;
use crate::util::{
    ceil_page_size, floor_page_size, is_zombie_process, pwrite_all_fallible, to_timeval,
};
use crate::wait_status::WaitStatus;
use libc::{__errno_location, pid_t, pread64, waitpid, EPERM, ESRCH, ITIMER_REAL};
use nix::errno::errno;
use nix::fcntl::OFlag;
use nix::sys::mman::{MapFlags, ProtFlags};
use std::convert::TryInto;
use std::ffi::c_void;
use std::ffi::{CStr, CString};
use std::mem::{size_of, zeroed};
use std::path::Path;
use std::{ptr, slice};

/// Forwarded method definition
///
/// Open /proc/{tid}/mem fd for our AddressSpace, closing the old one
/// first. If necessary we force the tracee to open the file
/// itself and smuggle the fd back to us.
/// Returns false if the process no longer exists.
pub(super) fn open_mem_fd<T: Task>(task: &mut T) -> bool {
    // Use ptrace to read/write during open_mem_fd
    task.as_.borrow_mut().set_mem_fd(ScopedFd::new());

    if !task.is_stopped {
        log!(
            LogWarn,
            "Can't retrieve mem fd for {}; process not stopped, racing with exec?",
            task.tid
        );
        return false;
    }

    // We could try opening /proc/<pid>/mem directly first and
    // only do this dance if that fails. But it's simpler to
    // always take this path, and gives better test coverage. On Ubuntu
    // the child has to open its own mem file (unless rr is root).
    let path = CStr::from_bytes_with_nul(b"/proc/self/mem\0").unwrap();

    let arch = task.arch();
    let mut remote = AutoRemoteSyscalls::new(task);
    let remote_fd: i32;
    {
        let mut remote_path: AutoRestoreMem = AutoRestoreMem::push_cstr(&mut remote, path);
        if remote_path.get().is_some() {
            let remote_arch = remote_path.arch();
            let remote_addr = remote_path.get().unwrap();
            // AutoRestoreMem DerefMut-s to AutoRemoteSyscalls
            // skip leading '/' since we want the path to be relative to the root fd
            remote_fd = rd_syscall!(
                remote_path,
                syscall_number_for_openat(remote_arch),
                RD_RESERVED_ROOT_DIR_FD,
                // Skip the leading '/' in the path as this is a relative path.
                (remote_addr + 1usize).as_usize(),
                libc::O_RDWR
            )
            .try_into()
            .unwrap();
        } else {
            remote_fd = -ESRCH;
        }
    }
    let mut fd: ScopedFd = ScopedFd::new();
    if remote_fd != -ESRCH {
        if remote_fd < 0 {
            // This can happen when a process fork()s after setuid; it can no longer
            // open its own /proc/self/mem. Hopefully we can read the child's
            // mem file in this case (because rr is probably running as root).
            let buf: String = format!("/proc/{}/mem", remote.task().tid);
            fd = ScopedFd::open_path(Path::new(&buf), OFlag::O_RDWR);
        } else {
            fd = rd_arch_function!(remote, retrieve_fd_arch, arch, remote_fd);
            // Leak fd if the syscall fails due to the task being SIGKILLed unexpectedly
            rd_syscall!(remote, syscall_number_for_close(remote.arch()), remote_fd);
        }
    }
    if !fd.is_open() {
        log!(
            LogInfo,
            "Can't retrieve mem fd for {}; process no longer exists?",
            remote.task().tid
        );
        return false;
    }
    remote
        .task()
        .as_
        .borrow_mut()
        .set_mem_fd(fd.try_into().unwrap());
    true
}

/// Forwarded method definition
///
/// Read/write the number of bytes.
/// Number of bytes read can be less than desired
/// - Returns Err(()) if No bytes could be read at all AND there was an error
/// - Returns Ok(usize) if 0 or more bytes could be read. All bytes requested may not have been
/// read.
pub(super) fn read_bytes_fallible<T: Task>(
    task: &mut T,
    addr: RemotePtr<Void>,
    buf: &mut [u8],
) -> Result<usize, ()> {
    if buf.len() == 0 {
        return Ok(0);
    }

    match task.vm().local_mapping(addr, buf.len()) {
        Some(found) => {
            buf.copy_from_slice(&found[0..buf.len()]);
            return Ok(buf.len());
        }
        None => (),
    }

    if !task.vm().mem_fd().is_open() {
        return Ok(task.read_bytes_ptrace(addr, buf));
    }

    let mut all_read = 0;
    while all_read < buf.len() {
        unsafe { *(__errno_location()) = 0 };
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
                // @TODO is this a wise decision?
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
                unsafe { *(__errno_location()) = 0 };
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
/// If the data can't all be read, then if `ok` is non-null, sets *ok to
/// false, otherwise asserts.
pub(super) fn read_bytes_helper<T: Task>(
    task: &mut T,
    addr: RemotePtr<Void>,
    buf: &mut [u8],
    ok: Option<&mut bool>,
) {
    // pread64 etc can't handle addresses that appear to be negative ...
    // like [vsyscall].
    let result_nread = task.read_bytes_fallible(addr, buf);
    match result_nread {
        Ok(nread) if nread == buf.len() => (),
        _ => {
            let nread = result_nread.unwrap_or(0);
            if ok.is_some() {
                *ok.unwrap() = false;
            } else {
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

/// NOT a Forwarded method due to extra template parameter
///
/// If the data can't all be read, then if `ok` is non-null, sets *ok to
/// false, otherwise asserts.
pub fn read_bytes_helper_for<T: Task, D>(
    task: &mut dyn Task,
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
pub(super) fn read_c_str<T: Task>(task: &mut T, child_addr: RemotePtr<u8>) -> CString {
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
        let mut buf = Vec::<u8>::with_capacity(nbytes);
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
/// https://bugzilla.kernel.org/show_bug.cgi?id=99101.
/// On some kernels pwrite() to /proc/.../mem fails when writing to a region
/// that's PROT_NONE.
/// Also, writing through MAP_SHARED readonly mappings fails (even if the
/// file was opened read-write originally), so we handle that here too.
pub(super) fn safe_pwrite64(
    t: &mut dyn Task,
    buf: &[u8],
    addr: RemotePtr<Void>,
) -> Result<usize, ()> {
    let mut mappings_to_fix: Vec<(MemoryRangeKey, ProtFlags)> = Vec::new();
    let buf_size = buf.len();
    for (k, m) in t.vm().maps_containing_or_after(floor_page_size(addr)) {
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
            m.0.size(),
            (m.1 | ProtFlags::PROT_WRITE).bits()
        );
    }

    let nwritten_result: Result<usize, ()> = pwrite_all_fallible(mem_fd, buf, addr.as_isize());

    for m in &mappings_to_fix {
        rd_infallible_syscall!(
            remote,
            mprotect_syscallno,
            m.0.start().as_usize(),
            m.0.size(),
            m.1.bits()
        );
    }

    nwritten_result
}

/// Forwarded method definition
///
/// `flags` is bits from WriteFlags.
pub(super) fn write_bytes_helper<T: Task>(
    task: &mut T,
    addr: RemotePtr<Void>,
    buf: &[u8],
    ok: Option<&mut bool>,
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
            task.vm_mut().notify_written(addr, nwritten, flags);
        }

        if ok.is_some() && nwritten < buf_size {
            *ok.unwrap() = false;
        }
        return;
    }

    unsafe {
        *(__errno_location()) = 0;
    }
    let nwritten_result = safe_pwrite64(task, buf, addr);
    // See comment in read_bytes_helper().
    if let Ok(0) = nwritten_result {
        task.open_mem_fd();
        // Try again
        return task.write_bytes_helper(addr, buf, ok, flags);
    }
    if errno() == EPERM {
        fatal!(
            "Can't write to /proc/{}/mem\n\
                        Maybe you need to disable grsecurity MPROTECT with:\n\
                           setfattr -n user.pax.flags -v 'emr' <executable>",
            task.tid
        );
    }

    let nwritten = nwritten_result.unwrap_or(0);
    if ok.is_some() {
        if nwritten < buf_size {
            *ok.unwrap() = false;
        }
    } else {
        ed_assert!(
            task,
            nwritten == buf_size,
            "Should have written {} bytes to {}, but only wrote {}",
            addr,
            buf_size,
            nwritten,
        );
    }
    if nwritten > 0 {
        task.vm_mut().notify_written(addr, nwritten, flags);
    }
}

/// NOT Forwarded method definition
///
/// Read `val` from `child_addr`.
/// If the data can't all be read, then if `ok` is non-null
/// sets *ok to false, otherwise asserts.
pub fn read_val_mem<D>(task: &mut dyn Task, child_addr: RemotePtr<D>, ok: Option<&mut bool>) -> D {
    let mut v: D = unsafe { zeroed() };
    let u8_slice = unsafe { slice::from_raw_parts_mut(&raw mut v as *mut u8, size_of::<D>()) };
    task.read_bytes_helper(RemotePtr::cast(child_addr), u8_slice, ok);
    return v;
}

/// NOT Forwarded method definition
///
/// Read `count` values from `child_addr`.
pub fn read_mem<D: Clone>(
    task: &mut dyn Task,
    child_addr: RemotePtr<D>,
    count: usize,
    ok: Option<&mut bool>,
) -> Vec<D> {
    let mut v: Vec<D> = Vec::with_capacity(count);
    v.resize(count, unsafe { zeroed() });
    let u8_slice =
        unsafe { slice::from_raw_parts_mut(v.as_mut_ptr() as *mut u8, count * size_of::<D>()) };
    task.read_bytes_helper(RemotePtr::cast(child_addr), u8_slice, ok);
    v
}

/// Forwarded method definition
///
pub(super) fn syscallbuf_data_size<T: Task>(task: &mut T) -> usize {
    let addr: RemotePtr<u32> = RemotePtr::cast(task.syscallbuf_child);
    read_val_mem::<u32>(task, addr + offset_of!(syscallbuf_hdr, num_rec_bytes), None) as usize
        + size_of::<syscallbuf_hdr>()
}

/// Forwarded method definition
///
/// Write `N` bytes from `buf` to `child_addr`, or don't return.
pub(super) fn write_bytes<T: Task>(task: &mut T, child_addr: RemotePtr<Void>, buf: &[u8]) {
    write_bytes_helper(task, child_addr, buf, None, WriteFlags::empty())
}

/// Forwarded method definition
///
pub(super) fn next_syscallbuf_record<T: Task>(task: &mut T) -> RemotePtr<syscallbuf_record> {
    // Next syscallbuf record is size_of the syscallbuf header + number of bytes in buffer
    let addr = RemotePtr::<u8>::cast(task.syscallbuf_child + 1usize);
    let num_rec_bytes_addr =
        RemotePtr::<u8>::cast(task.syscallbuf_child) + offset_of!(syscallbuf_hdr, num_rec_bytes);

    // @TODO: Here we have used our knowledge that `num_rec_bytes` is a u32.
    // There does not seem to be a generic way to get that information -- explore more later.
    let num_rec_bytes = read_val_mem(task, RemotePtr::<u32>::cast(num_rec_bytes_addr), None);
    RemotePtr::cast(addr + num_rec_bytes)
}

/// Forwarded method definition
///
pub(super) fn stored_record_size<T: Task>(
    task: &mut T,
    record: RemotePtr<syscallbuf_record>,
) -> u32 {
    let size_field_addr = RemotePtr::<u8>::cast(record) + offset_of!(syscallbuf_record, size);

    // @TODO: Here we have used our knowledge that `size` is a u32.
    // There does not seem to be a generic way to get that information -- explore more later.
    preload_interface::stored_record_size(read_val_mem(
        task,
        RemotePtr::<u32>::cast(size_field_addr),
        None,
    ))
}

/// NOT Forwarded method definition
///
/// Write single `val` to `child_addr`.
pub fn write_val_mem<D: 'static>(
    task: &mut dyn Task,
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
    task: &mut dyn Task,
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
    task: &mut dyn Task,
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

pub(super) fn wait<T: Task>(task: &mut T, interrupt_after_elapsed: f64) {
    debug_assert!(interrupt_after_elapsed >= 0.0);
    log!(LogDebug, "going into blocking waitpid({}) ...", task.tid);
    ed_assert!(task, !task.unstable, "Don't wait for unstable tasks");
    ed_assert!(
        task,
        task.session().borrow().is_recording() || interrupt_after_elapsed == 0.0
    );

    if task.wait_unexpected_exit() {
        return;
    }

    let mut status: WaitStatus;
    let mut sent_wait_interrupt = false;
    let mut ret: pid_t;
    loop {
        if interrupt_after_elapsed > 0.0 {
            let mut timer: itimerval = unsafe { zeroed() };
            timer.it_value = to_timeval(interrupt_after_elapsed);
            unsafe {
                setitimer(ITIMER_REAL as u32, &timer, ptr::null_mut());
            }
        }
        let mut raw_status: i32 = 0;
        ret = unsafe { waitpid(task.tid, &mut raw_status, libc::__WALL) };
        status = WaitStatus::new(raw_status);
        if interrupt_after_elapsed > 0.0 {
            let timer: itimerval = unsafe { zeroed() };
            unsafe { setitimer(ITIMER_REAL as u32, &timer, ptr::null_mut()) };
        }
        if ret >= 0 || errno() != libc::EINTR {
            // waitpid was not interrupted by the alarm.
            break;
        }

        if is_zombie_process(task.real_tgid()) {
            // The process is dead. We must stop waiting on it now
            // or we might never make progress.
            // XXX it's not clear why the waitpid() syscall
            // doesn't return immediately in this case, but in
            // some cases it doesn't return normally at all!

            // Fake a PTRACE_EVENT_EXIT for this task.
            log!(
                LogWarn,
                "Synthesizing PTRACE_EVENT_EXIT for zombie process {}",
                task.tid
            );
            status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
            ret = task.tid;
            // XXX could this leave unreaped zombies lying around?
            break;
        }

        if !sent_wait_interrupt && (interrupt_after_elapsed > 0.0) {
            task.ptrace_if_alive(PTRACE_INTERRUPT, RemotePtr::null(), PtraceData::None);
            sent_wait_interrupt = true;
            task.expecting_ptrace_interrupt_stop = 2;
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
            task,
            !task.seen_ptrace_exit_event,
            "A PTRACE_EXIT_EVENT was observed for this task, but somehow forgotten"
        );

        // Turn this into a PTRACE_EXIT_EVENT.
        log!(
            LogWarn,
            "Synthesizing PTRACE_EVENT_EXIT for process {} exited with {}",
            task.tid,
            status.exit_code().unwrap()
        );
        status = WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT);
    }

    log!(
        LogDebug,
        "  waitpid({}) returns {}; status {}",
        task.tid,
        ret,
        status
    );
    ed_assert!(
        task,
        task.tid == ret,
        "waitpid({}) failed with {}",
        task.tid,
        ret
    );

    if sent_wait_interrupt {
        log!(LogWarn, "Forced to PTRACE_INTERRUPT tracee");
        if !is_signal_triggered_by_ptrace_interrupt(status.group_stop_sig()) {
            log!(
                LogWarn,
                "  PTRACE_INTERRUPT raced with another event {:?}",
                status
            );
        }
    }
    task.did_waitpid(status);
}

fn is_signal_triggered_by_ptrace_interrupt(group_stop_sig: Option<i32>) -> bool {
    group_stop_sig.map_or(false, |sig| match sig {
        // We sometimes see SIGSTOP at interrupts, though the
        // docs don't mention that.
        libc::SIGTRAP | libc::SIGSTOP => true,
        _ => false,
    })
}
