use super::memory_range::MemoryRange;
use crate::{
    remote_ptr::{RemotePtr, Void},
    util::{find, page_size},
};
use libc::{
    c_long, dev_t, ino_t, stat, MAP_ANONYMOUS, MAP_GROWSDOWN, MAP_NORESERVE, MAP_PRIVATE,
    MAP_SHARED, MAP_STACK,
};
use nix::sys::{
    mman::{MapFlags, ProtFlags},
    stat::{major, minor},
};
use std::{
    ffi::{OsStr, OsString},
    fmt::{Display, Formatter, Result},
    mem::zeroed,
    ops::{Deref, DerefMut},
    os::unix::ffi::OsStrExt,
};

/// Clone trait is manually derived. See below.
/// This type cannot be Copy as fsname_, an OsString, is not Copy.
#[derive(Debug)]
pub struct KernelMapping {
    mr: MemoryRange,
    /// The kernel's name for the mapping, as per /proc/<pid>/maps. This must
    /// be exactly correct.
    fsname_: OsString,
    /// Note that btrfs has weird behavior and /proc/.../maps can show a different
    /// device number to the device from stat()ing the file that was mapped.
    /// <https://www.mail-archive.com/linux-btrfs@vger.kernel.org/msg57667.html>
    /// We store here the device number obtained from fstat()ing the file.
    /// This also seems to be consistent with what we read from populate_address_space
    /// for the initial post-exec mappings. It is NOT consistent with what we get
    /// from reading /proc/.../maps for non-initial mappings.
    device_: dev_t,
    inode_: ino_t,
    prot_: ProtFlags,
    flags_: MapFlags,
    offset: u64,
}

impl Default for KernelMapping {
    fn default() -> Self {
        KernelMapping {
            device_: 0,
            inode_: 0,
            prot_: ProtFlags::empty(),
            flags_: MapFlags::empty(),
            offset: 0,
            fsname_: OsString::from(""),
            mr: MemoryRange::default(),
        }
    }
}

impl KernelMapping {
    pub const NO_DEVICE: dev_t = 0;
    pub const NO_INODE: ino_t = 0;
    pub const CHECKABLE_FLAGS_MASK: MapFlags =
        MapFlags::from_bits_truncate(MAP_PRIVATE | MAP_SHARED);

    /// These are the flags we track internally to distinguish
    /// between adjacent segments.  For example, the kernel
    /// considers a NORESERVE anonynmous mapping that's adjacent to
    /// a non-NORESERVE mapping distinct, even if all other
    /// metadata are the same.  See `is_adjacent_mapping()`.
    pub const MAP_FLAGS_MASK: MapFlags = MapFlags::from_bits_truncate(
        MAP_ANONYMOUS | MAP_NORESERVE | MAP_PRIVATE | MAP_SHARED | MAP_STACK | MAP_GROWSDOWN,
    );

    pub fn new_with_opts(
        start: RemotePtr<Void>,
        end: RemotePtr<Void>,
        fsname: &OsStr,
        device: dev_t,
        inode: ino_t,
        prot: ProtFlags,
        flags: MapFlags,
        offset: u64,
    ) -> KernelMapping {
        let result = KernelMapping {
            device_: device,
            inode_: inode,
            prot_: prot,
            flags_: flags & Self::MAP_FLAGS_MASK,
            offset,
            fsname_: fsname.into(),
            mr: MemoryRange::from_range(start, end),
        };
        result.assert_valid();
        result
    }

    pub fn assert_valid(&self) {
        debug_assert!(self.end() >= self.start());
        debug_assert_eq!(self.len() % page_size(), 0);
        debug_assert!((self.flags_ & !KernelMapping::MAP_FLAGS_MASK).is_empty());
        debug_assert_eq!(self.offset % page_size() as u64, 0);
    }

    pub fn extend(&self, end: RemotePtr<Void>) -> KernelMapping {
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

    pub fn set_range(&self, start: RemotePtr<Void>, end: RemotePtr<Void>) -> KernelMapping {
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

    pub fn subrange(&self, start: RemotePtr<Void>, end: RemotePtr<Void>) -> KernelMapping {
        debug_assert!(start >= self.start() && end <= self.end());
        let start_addr: u64 = if self.is_real_device() {
            (start - self.start()) as u64
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

    pub fn set_prot(&self, prot: ProtFlags) -> KernelMapping {
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

    pub fn fsname(&self) -> &OsStr {
        &self.fsname_
    }

    pub fn device(&self) -> dev_t {
        self.device_
    }

    pub fn inode(&self) -> ino_t {
        self.inode_
    }

    pub fn prot(&self) -> ProtFlags {
        self.prot_
    }

    pub fn flags(&self) -> MapFlags {
        self.flags_
    }

    pub fn file_offset_bytes(&self) -> u64 {
        self.offset
    }

    /// Return true if this file is/was backed by an external
    /// device, as opposed to a transient RAM mapping.
    pub fn is_real_device(&self) -> bool {
        self.device() > Self::NO_DEVICE
    }

    pub fn is_vdso(&self) -> bool {
        self.fsname() == "[vdso]"
    }

    pub fn is_heap(&self) -> bool {
        self.fsname() == "[heap]"
    }

    pub fn is_stack(&self) -> bool {
        // Note the lack of ending `]` in match string
        if let Some(loc) = find(self.fsname().as_bytes(), b"[stack") {
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
        fake_stat.st_size = self.len() as c_long;
        fake_stat
    }

    /// Dump a representation of `self` to a string in a format
    /// similar to the former part of /proc/{tid}/maps.
    pub fn str(&self, hex_prefix: bool) -> String {
        let map_shared = if self.flags_.contains(MapFlags::MAP_SHARED) {
            's'
        } else {
            'p'
        };

        let s = if hex_prefix {
            format!(
                "{:#8x}-{:#8x} {}{} {:08x} {:02x}:{:02x} {:<10} {:?}",
                self.start().as_usize(),
                self.end().as_usize(),
                self.prot_string(),
                map_shared,
                self.offset,
                major(self.device()),
                minor(self.device()),
                self.inode(),
                self.fsname()
            )
        } else {
            format!(
                "{:8x}-{:8x} {}{} {:08x} {:02x}:{:02x} {:<10} {:?}",
                self.start().as_usize(),
                self.end().as_usize(),
                self.prot_string(),
                map_shared,
                self.offset,
                major(self.device()),
                minor(self.device()),
                self.inode(),
                self.fsname()
            )
        };

        s
    }

    fn prot_string(&self) -> String {
        let mut s = String::with_capacity(3);
        if self.prot_.contains(ProtFlags::PROT_READ) {
            s += "r";
        } else {
            s += "-";
        }

        if self.prot_.contains(ProtFlags::PROT_WRITE) {
            s += "w";
        } else {
            s += "-";
        }

        if self.prot_.contains(ProtFlags::PROT_EXEC) {
            s += "x";
        } else {
            s += "-";
        }

        s
    }
}

/// Need to implement this manually because of the assert_valid() check
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
        write!(f, "{}", self.str(true))
    }
}
