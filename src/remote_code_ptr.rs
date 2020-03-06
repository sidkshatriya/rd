use crate::kernel_abi::syscall_instruction_length;
use crate::kernel_abi::SupportedArch;
use crate::remote_ptr::RemotePtr;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::ops::Add;
use std::ops::Sub;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct RemoteCodePtr {
    ptr: usize,
}

impl RemoteCodePtr {
    pub fn new() -> RemoteCodePtr {
        RemoteCodePtr { ptr: 0 }
    }

    pub fn from_val(val: usize) -> RemoteCodePtr {
        RemoteCodePtr { ptr: val }
    }

    pub fn as_usize(&self) -> usize {
        self.ptr
    }

    /// As the name indicates this is just a cast. No try_into().unwrap() here!
    pub fn as_isize(&self) -> isize {
        self.ptr as isize
    }

    pub fn is_null(&self) -> bool {
        self.ptr == 0
    }

    pub fn decrement_by_syscall_insn_length(self, arch: SupportedArch) -> RemoteCodePtr {
        self - syscall_instruction_length(arch)
    }
    pub fn increment_by_syscall_insn_length(self, arch: SupportedArch) -> RemoteCodePtr {
        self + syscall_instruction_length(arch)
    }

    pub fn decrement_by_bkpt_insn_length(self, _arch: SupportedArch) -> RemoteCodePtr {
        self - 1 as usize
    }

    pub fn increment_by_bkpt_insn_length(self, _arch: SupportedArch) -> RemoteCodePtr {
        self + 1 as usize
    }

    pub fn to_data_ptr<T>(&self) -> RemotePtr<T> {
        RemotePtr::<T>::new_from_val(self.as_usize())
    }

    pub fn register_value(&self) -> usize {
        self.as_usize()
    }
}

impl Display for RemoteCodePtr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:#x}", self.ptr)
    }
}

impl Add<usize> for RemoteCodePtr {
    type Output = Self;

    fn add(self, delta: usize) -> Self::Output {
        Self::from_val(self.as_usize() + delta)
    }
}

impl Sub<usize> for RemoteCodePtr {
    type Output = Self;

    fn sub(self, delta: usize) -> Self::Output {
        Self::from_val(self.as_usize() - delta)
    }
}

// ! Note that there is NO impl Add<isize> for RemoteCodePtr<T> and impl Sub<isize> for
// RemoteCodePtr<T> !

impl Sub<RemoteCodePtr> for RemoteCodePtr {
    type Output = isize;

    fn sub(self, rhs: RemoteCodePtr) -> Self::Output {
        self.as_isize() - rhs.as_isize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_test() {
        let a = RemoteCodePtr::new();
        assert_eq!(0, a.as_usize());
    }
}
