use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::task_interface::task::task::Task;

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
pub struct AutoRemoteSyscalls {}

impl AutoRemoteSyscalls {
    pub fn new(t: &Task) -> AutoRemoteSyscalls {
        unimplemented!()
    }

    /// Arranges for 'fd' to be transmitted to this process and returns
    /// our opened version of it.
    /// Returns a closed fd if the process dies or has died.
    pub fn retrieve_fd(&self, fd: i32) -> ScopedFd {
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
}
