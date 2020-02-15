use super::memory_range::MemoryRange;
use crate::remote_ptr::RemotePtr;
use crate::util::page_size;
use libc::{c_long, dev_t, ino_t, stat, PROT_EXEC, PROT_READ, PROT_WRITE};
use libc::{MAP_ANONYMOUS, MAP_GROWSDOWN, MAP_NORESERVE, MAP_PRIVATE, MAP_SHARED, MAP_STACK};
use nix::sys::stat::{major, minor};
use std::convert::TryInto;
use std::fmt::{Display, Formatter, Result};
use std::mem::zeroed;
use std::ops::{Deref, DerefMut};

/// These are the flags we track internally to distinguish
/// between adjacent segments.  For example, the kernel
/// considers a NORESERVE anonynmous mapping that's adjacent to
/// a non-NORESERVE mapping distinct, even if all other
/// metadata are the same.  See |is_adjacent_mapping()|.
pub const MAP_FLAGS_MASK: i32 =
    MAP_ANONYMOUS | MAP_NORESERVE | MAP_PRIVATE | MAP_SHARED | MAP_STACK | MAP_GROWSDOWN;
pub const CHECKABLE_FLAGS_MASK: i32 = MAP_PRIVATE | MAP_SHARED;
pub const NO_DEVICE: dev_t = 0;
pub const NO_INODE: ino_t = 0;

/// Clone trait is manually derived. See below.
pub struct KernelMapping {
    mr: MemoryRange,
    /// The kernel's name for the mapping, as per /proc/<pid>/maps. This must
    /// be exactly correct.
    fsname_: String,
    /// Note that btrfs has weird behavior and /proc/.../maps can show a different
    /// device number to the device from stat()ing the file that was mapped.
    /// https://www.mail-archive.com/linux-btrfs@vger.kernel.org/msg57667.html
    /// We store here the device number obtained from fstat()ing the file.
    /// This also seems to be consistent with what we read from populate_address_space
    /// for the initial post-exec mappings. It is NOT consistent with what we get
    /// from reading /proc/.../maps for non-initial mappings.
    device_: dev_t,
    inode_: ino_t,
    prot_: i32,
    flags_: i32,
    offset: u64,
}

impl KernelMapping {
    pub fn new() -> KernelMapping {
        KernelMapping {
            device_: 0,
            inode_: 0,
            prot_: 0,
            flags_: 0,
            offset: 0,
            // @TODO Is this OK?
            fsname_: String::new(),
            mr: MemoryRange::new(),
        }
    }

    pub fn new_with_opts(
        start: RemotePtr<u8>,
        end: RemotePtr<u8>,
        fsname: &str,
        device: dev_t,
        inode: ino_t,
        prot: i32,
        flags: i32,
        offset: u64,
    ) -> KernelMapping {
        let result = KernelMapping {
            device_: device,
            inode_: inode,
            prot_: prot,
            flags_: flags,
            offset: offset,
            fsname_: fsname.into(),
            mr: MemoryRange::new_from_range(start, end),
        };
        result.assert_valid();
        result
    }

    pub fn assert_valid(&self) {
        debug_assert!(self.end() >= self.start());
        debug_assert!(self.size() % page_size() == 0);
        debug_assert!(self.flags_ & !MAP_FLAGS_MASK == 0);
        debug_assert!(self.offset % page_size() as u64 == 0);
    }

    pub fn extend(&self, end: RemotePtr<u8>) -> KernelMapping {
        debug_assert!(end >= self.end());
        KernelMapping::new_with_opts(
            self.start(),
            end,
            &self.fsname_,
            self.device_,
            self.inode_,
            self.prot_,
            self.flags_,
            self.offset,
        )
    }
    pub fn set_range(&self, start: RemotePtr<u8>, end: RemotePtr<u8>) -> KernelMapping {
        KernelMapping::new_with_opts(
            start,
            end,
            &self.fsname_,
            self.device_,
            self.inode_,
            self.prot_,
            self.flags_,
            self.offset,
        )
    }
    pub fn subrange(&self, start: RemotePtr<u8>, end: RemotePtr<u8>) -> KernelMapping {
        debug_assert!(start >= self.start() && end <= self.end());
        let start_addr: u64 = if self.is_real_device() {
            (start - self.start()).try_into().unwrap()
        } else {
            0
        };
        KernelMapping::new_with_opts(
            start,
            end,
            &self.fsname_,
            self.device_,
            self.inode_,
            self.prot_,
            self.flags_,
            self.offset + start_addr,
        )
    }
    pub fn set_prot(&self, prot: i32) -> KernelMapping {
        KernelMapping::new_with_opts(
            self.start(),
            self.end(),
            &self.fsname_,
            self.device_,
            self.inode_,
            prot,
            self.flags_,
            self.offset,
        )
    }

    pub fn fsname(&self) -> String {
        self.fsname_.clone()
    }
    pub fn device(&self) -> dev_t {
        self.device_
    }
    pub fn inode(&self) -> ino_t {
        self.inode_
    }
    pub fn prot(&self) -> i32 {
        self.prot_
    }
    pub fn flags(&self) -> i32 {
        self.flags_
    }
    pub fn file_offset_bytes(&self) -> u64 {
        self.offset
    }

    /// Return true if this file is/was backed by an external
    /// device, as opposed to a transient RAM mapping.
    pub fn is_real_device(&self) -> bool {
        self.device() > NO_DEVICE
    }
    pub fn is_vdso(&self) -> bool {
        self.fsname() == "[vdso]"
    }
    pub fn is_heap(&self) -> bool {
        self.fsname() == "[heap]"
    }
    pub fn is_stack(&self) -> bool {
        if let Some(loc) = self.fsname().find("[stack") {
            loc == 0
        } else {
            false
        }
    }
    pub fn is_vvar(&self) -> bool {
        self.fsname() == "[vvar]"
    }
    pub fn is_vsyscall(&self) -> bool {
        self.fsname() == "[vsyscall]"
    }

    pub fn fake_stat(&self) -> stat {
        let mut fake_stat: stat = unsafe { zeroed() };
        fake_stat.st_dev = self.device();
        fake_stat.st_ino = self.inode();
        fake_stat.st_size = self.size() as c_long;
        fake_stat
    }

    /// Dump a representation of |self| to a string in a format
    /// similar to the former part of /proc/[tid]/maps.
    pub fn str(&self) -> String {
        let map_shared = if MAP_SHARED & self.flags_ == MAP_SHARED {
            's'
        } else {
            'p'
        };

        // @TODO this needs to be checked.
        let s = format!(
            "{:8x}-{:8x} {}{} {:08x} {:02x}:{:02x} {:<10} ",
            self.start().as_usize(),
            self.end().as_usize(),
            self.prot_string(),
            map_shared,
            self.offset,
            major(self.device()),
            minor(self.device()),
            self.inode()
        );
        s + &self.fsname()
    }

    fn prot_string(&self) -> String {
        let mut s = String::with_capacity(3);
        if PROT_READ & self.prot_ == PROT_READ {
            s += "r";
        } else {
            s += "-";
        }

        if PROT_WRITE & self.prot_ == PROT_WRITE {
            s += "w";
        } else {
            s += "-";
        }

        if PROT_EXEC & self.prot_ == PROT_EXEC {
            s += "x";
        } else {
            s += "-";
        }

        s
    }
}

impl Clone for KernelMapping {
    fn clone(&self) -> Self {
        let result = KernelMapping {
            device_: self.device_,
            inode_: self.inode_,
            prot_: self.prot_,
            flags_: self.flags_,
            offset: self.offset,
            fsname_: self.fsname_.clone(),
            mr: self.mr,
        };
        result.assert_valid();
        result
    }
}

impl Deref for KernelMapping {
    type Target = MemoryRange;
    fn deref(&self) -> &Self::Target {
        &self.mr
    }
}

impl DerefMut for KernelMapping {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mr
    }
}

impl Display for KernelMapping {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.str())
    }
}
