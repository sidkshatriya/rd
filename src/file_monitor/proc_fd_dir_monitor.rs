use libc::pid_t;

use crate::{
    arch::{Architecture, X64Arch},
    arch_structs::dirent,
    auto_remote_syscalls::AutoRemoteSyscalls,
    file_monitor::{FileMonitor, FileMonitorType},
    remote_ptr::RemotePtr,
    session::task::{
        record_task::RecordTask,
        task_common::{read_mem, write_mem},
        Task,
    },
    taskish_uid::TaskUid,
};
use std::{
    ffi::OsStr,
    mem,
    os::unix::ffi::OsStrExt,
    path::{Component, Path},
    ptr,
};

/// A FileMonitor to intercept enumerations of /proc/<pid>/fd so that entries
/// for rd's private fds can be hidden when <pid> is a tracee.
pub struct ProcFdDirMonitor {
    /// None if this does not refer to a tracee's proc fd
    /// DIFF NOTE: in rr this is a "0" instead of None.
    maybe_tuid: Option<TaskUid>,
}

impl FileMonitor for ProcFdDirMonitor {
    fn file_monitor_type(&self) -> FileMonitorType {
        FileMonitorType::ProcFd
    }

    fn filter_getdents(&self, t: &mut RecordTask) {
        ed_assert!(t, !t.session().is_replaying());
        match self.maybe_tuid {
            None => (),
            Some(tuid) => match t.session().find_task_from_task_uid(tuid) {
                None => (),
                Some(_target) => filter_dirents(t),
            },
        }
    }
}

impl ProcFdDirMonitor {
    pub fn new(t: &dyn Task, pathname: &OsStr) -> ProcFdDirMonitor {
        // XXX this makes some assumptions about namespaces... Probably fails
        // if `t` is not the same pid namespace as rd
        let pathname = Path::new(pathname);
        let mut components = pathname.components();
        let maybe_rootdir = components.next();
        let maybe_proc = components.next();
        let maybe_tid_os_str = components.next();
        let maybe_fd = components.next();
        if (maybe_rootdir, maybe_proc, maybe_fd)
            == (
                Some(Component::RootDir),
                Some(Component::Normal(OsStr::new("proc"))),
                Some(Component::Normal(OsStr::new("fd"))),
            )
        {
            match maybe_tid_os_str {
                Some(Component::Normal(tid_os_str)) => {
                    let tid_str = String::from_utf8_lossy(tid_os_str.as_bytes());
                    let maybe_tid = tid_str.parse::<pid_t>();
                    let tid = maybe_tid.unwrap();
                    let maybe_found = if t.rec_tid == tid {
                        Some(t.tuid())
                    } else {
                        t.session()
                            .find_task_from_rec_tid(tid)
                            .map_or(None, |ft| Some(ft.borrow().tuid()))
                    };

                    return Self {
                        maybe_tuid: maybe_found,
                    };
                }
                _ => (),
            }
        }

        Self { maybe_tuid: None }
    }
}

/// returns the length of valid dirent structs left in the buffer
fn filter_dirent_structs<Arch: Architecture>(t: &RecordTask, buf: &mut Vec<u8>) -> usize {
    let mut bytes: usize = 0;
    let mut current_offset: usize = 0;
    let mut size = buf.len();
    loop {
        if current_offset == size {
            break;
        }

        let current_struct: dirent<Arch> =
            unsafe { mem::transmute_copy(buf.as_ptr().add(current_offset).as_ref().unwrap()) };
        let mut next_off = current_offset + current_struct.d_reclen as usize;

        let mut skip = false;
        let null_at = current_struct
            .d_name
            .iter()
            .enumerate()
            .find(|(_, c)| **c == 0);

        match null_at {
            Some((loc, _)) => {
                let fd_data = String::from_utf8_lossy(&current_struct.d_name[0..loc]);
                let maybe_fd = fd_data.parse::<i32>();
                match maybe_fd.ok() {
                    Some(fd) if t.fd_table().is_rd_fd(fd) => {
                        skip = true;
                        // Skip this entry.
                        unsafe {
                            ptr::copy(
                                buf.as_ptr().add(next_off),
                                buf.as_mut_ptr().add(current_offset),
                                size - next_off,
                            )
                        };
                        size -= next_off - current_offset;
                        next_off = current_offset;
                    }
                    _ => (),
                }
            }
            None => (),
        }

        if !skip {
            // Either this is a tracee fd or not an fd at all (e.g. '.')
            bytes += current_struct.d_reclen as usize;
        }

        current_offset = next_off;
    }

    buf.resize(bytes, 0);
    bytes
}

fn filter_dirents_arch<Arch: Architecture>(t: &mut RecordTask) {
    let mut regs = t.regs_ref().clone();
    let ptr = RemotePtr::<u8>::from(regs.arg2());
    let len: usize = regs.arg3();

    if regs.syscall_failed() || regs.syscall_result() == 0 {
        return;
    }

    loop {
        let mut buf: Vec<u8> = read_mem(t, ptr, len, None);
        let mut bytes: usize = regs.syscall_result();
        buf.resize(bytes, 0);
        if regs.original_syscallno() == Arch::GETDENTS64 as isize {
            // This one is a bit an inelegant kludge.
            // If we're in X86, GETDENTS64 causes the struct `dirent` to be the same as `dirent64`
            // The alternative is more code duplication -- have a two copies for fn filter_dirent_structs
            // i.e. one for `dirent` and the other for `dirent64`. Avoid the alternative.
            bytes = filter_dirent_structs::<X64Arch>(t, &mut buf);
        } else {
            bytes = filter_dirent_structs::<Arch>(t, &mut buf);
        }

        if bytes > 0 {
            write_mem(t, ptr, &buf, None);
            regs.set_syscall_result(bytes);
            t.set_regs(&regs);
            // Explicitly record what the kernel may have touched and we discarded,
            // because it's userspace modification that will not be caught otherwise.
            if len > bytes {
                t.record_remote(ptr + bytes, len - bytes);
            }
            return;
        }

        // We filtered out all the entries, so we need to repeat the syscall.
        {
            let mut remote = AutoRemoteSyscalls::new(t);
            remote.syscall(
                regs.original_syscallno() as i32,
                &[regs.arg1(), regs.arg2(), regs.arg3()],
            );
            // Only copy over the syscall result. In particular, we don't want to
            // copy the AutoRemoteSyscalls ip().
            regs.set_syscall_result(remote.task().regs_ref().syscall_result());
        }

        if regs.syscall_failed() || regs.syscall_result() == 0 {
            // Save the new syscall result, and record the buffer we will otherwise
            // ignore.
            t.record_remote(ptr, len);
            t.set_regs(&regs);
            return;
        }
    }
}

fn filter_dirents(t: &mut RecordTask) {
    let arch = t.arch();
    rd_arch_function_selfless!(filter_dirents_arch, arch, t);
}
