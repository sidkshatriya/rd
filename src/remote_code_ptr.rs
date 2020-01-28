use crate::kernel_abi::syscall_instruction_length;
use crate::kernel_abi::SupportedArch;
use crate::remote_ptr::RemotePtr;
use std::cmp::Ordering;
use std::convert::TryInto;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::ops::Add;
use std::ops::Sub;

#[derive(Copy, Clone)]
pub struct RemoteCodePtr {
    ptr: usize,
}

impl RemoteCodePtr {
    pub fn new() -> RemoteCodePtr {
        RemoteCodePtr { ptr: 0 }
    }

    pub fn new_from_val(val: usize) -> RemoteCodePtr {
        RemoteCodePtr { ptr: val }
    }

    pub fn as_usize(&self) -> usize {
        self.ptr
    }

    pub fn as_isize(&self) -> isize {
        self.ptr.try_into().unwrap()
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

impl Add<isize> for RemoteCodePtr {
    type Output = Self;

    fn add(self, delta: isize) -> Self::Output {
        let result: isize = self.as_isize() + delta;
        Self::new_from_val(result.try_into().unwrap())
    }
}

impl Add<usize> for RemoteCodePtr {
    type Output = Self;

    fn add(self, delta: usize) -> Self::Output {
        Self::new_from_val(self.as_usize() + delta)
    }
}

impl Sub<isize> for RemoteCodePtr {
    type Output = Self;

    fn sub(self, delta: isize) -> Self::Output {
        let result: isize = self.as_isize() - delta;
        Self::new_from_val(result.try_into().unwrap())
    }
}

impl Sub<usize> for RemoteCodePtr {
    type Output = Self;

    fn sub(self, delta: usize) -> Self::Output {
        Self::new_from_val(self.as_usize() - delta)
    }
}

impl Sub<RemoteCodePtr> for RemoteCodePtr {
    type Output = isize;

    fn sub(self, rhs: RemoteCodePtr) -> Self::Output {
        self.as_isize() - rhs.as_isize()
    }
}

impl PartialOrd for RemoteCodePtr {
    fn partial_cmp(&self, other: &RemoteCodePtr) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RemoteCodePtr {
    fn cmp(&self, other: &RemoteCodePtr) -> Ordering {
        if self.ptr < other.ptr {
            Ordering::Less
        } else if self.ptr == other.ptr {
            Ordering::Equal
        } else {
            Ordering::Greater
        }
    }
}

impl PartialEq for RemoteCodePtr {
    fn eq(&self, other: &RemoteCodePtr) -> bool {
        self.ptr == other.ptr
    }
}

impl Eq for RemoteCodePtr {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_test() {
        let a = RemoteCodePtr::new();
        assert_eq!(0, a.as_usize());
    }
}
