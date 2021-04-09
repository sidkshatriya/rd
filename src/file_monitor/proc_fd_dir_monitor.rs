use libc::pid_t;

use crate::{
    arch::{Architecture, X64Arch, X86Arch},
    arch_structs::{linux_dirent, linux_dirent64},
    auto_remote_syscalls::AutoRemoteSyscalls,
    file_monitor::{FileMonitor, FileMonitorType},
    kernel_abi::SupportedArch,
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

    fn filter_getdents(&self, t: &RecordTask) {
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
                    let maybe_found = if t.rec_tid() == tid {
                        Some(t.tuid())
                    } else {
                        t.session()
                            .find_task_from_rec_tid(tid)
                            .map_or(None, |ft| Some(ft.tuid()))
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

fn get_lengths_dirent(arch: SupportedArch, buf: &[u8]) -> (usize, usize) {
    match arch {
        SupportedArch::X86 => {
            let current_struct: linux_dirent<X86Arch> =
                unsafe { mem::transmute_copy(buf.as_ptr().as_ref().unwrap()) };
            (
                current_struct.d_reclen as usize,
                offset_of!(linux_dirent<X86Arch>, d_name),
            )
        }
        SupportedArch::X64 => {
            let current_struct: linux_dirent<X64Arch> =
                unsafe { mem::transmute_copy(buf.as_ptr().as_ref().unwrap()) };
            (
                current_struct.d_reclen as usize,
                offset_of!(linux_dirent<X64Arch>, d_name),
            )
        }
    }
}

fn get_lengths_dirent64(_arch: SupportedArch, buf: &[u8]) -> (usize, usize) {
    let current_struct: linux_dirent64 =
        unsafe { mem::transmute_copy(buf.as_ptr().as_ref().unwrap()) };
    (
        current_struct.d_reclen as usize,
        offset_of!(linux_dirent64, d_name),
    )
}

/// returns the length of valid dirent structs left in the buffer
fn filter_dirent_structs<Arch: Architecture>(
    t: &RecordTask,
    buf: &mut Vec<u8>,
    f: &dyn Fn(SupportedArch, &[u8]) -> (usize, usize),
) -> usize {
    let mut bytes: usize = 0;
    let mut current_offset: usize = 0;
    let mut size = buf.len();
    loop {
        if current_offset == size {
            break;
        }

        let (current_struct_d_reclen, inner_offset) = f(Arch::arch(), &buf[current_offset..]);
        let mut next_off = current_offset + current_struct_d_reclen as usize;

        let mut skip = false;

        let null_at = buf[current_offset + inner_offset..]
            .iter()
            .enumerate()
            .find(|(_, c)| **c == 0)
            .unwrap()
            .0;

        let fd_data = String::from_utf8_lossy(
            &buf[current_offset + inner_offset..current_offset + inner_offset + null_at],
        );
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

        if !skip {
            // Either this is a tracee fd or not an fd at all (e.g. '.')
            bytes += current_struct_d_reclen as usize;
        }

        current_offset = next_off;
    }

    buf.resize(bytes, 0);
    bytes
}

fn filter_dirents_arch<Arch: Architecture>(t: &RecordTask) {
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
            bytes = filter_dirent_structs::<Arch>(t, &mut buf, &get_lengths_dirent64);
        } else {
            bytes = filter_dirent_structs::<Arch>(t, &mut buf, &get_lengths_dirent);
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

fn filter_dirents(t: &RecordTask) {
    let arch = t.arch();
    rd_arch_function_selfless!(filter_dirents_arch, arch, t);
}
