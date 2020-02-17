//! Implement an "emulated file system" consisting of files that were
//! mmap'd shared during recording.  These files require special
//! treatment because (i) they were most likely modified during
//! recording, so (ii) the original file contents only exist as
//! snapshots in the trace, but (iii) all mappings of the file must
//! point at the same underling resource, so that modifications are
//! seen by all mappees.
//!
//! The rr EmuFs creates "emulated files" in shared memory during
//! replay.  Each efile is uniquely identified at a given event in the
//! trace by |(edev, einode)| (i.e., the recorded device ID and inode).
//! "What about inode recycling", you're probably thinking to yourself.
//! This scheme can cope with inode recycling, given a very important
//! assumption discussed below.
//!
//! Why is inode recycling not a problem?  Assume that an mmap'd file
//! F_0 at trace time t_0 has the same (device, inode) ID as a
//! different file F_1 at trace time t_1.  By definition, if the inode
//! ID was recycled in [t_0, t_1), then all references to F_0 must have
//! been dropped in that interval.  A corollary of that is that all
//! memory mappings of F_0 must have been fully unmapped in the
//! interval.  As per the first long comment in |gc()| below, an
//! emulated file can only be "live" during replay if some tracee still
//! has a mapping of it.  Tracees' mappings of emulated files is a
//! subset of the ways they can create references to real files during
//! recording.  Therefore the event during replay that drops the last
//! reference to the emulated F_0 must be a tracee unmapping of F_0.
//!
//! So as long as we GC emulated F_0 at the event of its fatal
//! unmapping, the lifetimes of emulated F_0 and emulated F_1 must be
//! disjoint.  And F_0 being GC'd at that point is the important
//! assumption mentioned above.

use crate::address_space::kernel_mapping::KernelMapping;
use crate::log::LogDebug;
use crate::scoped_fd::ScopedFd;
use crate::util::resize_shmem_segment;
use libc::{dev_t, ino_t};
use nix::unistd::getpid;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};

pub type EmuFsSharedPtr = Rc<EmuFs>;
pub type EmuFileSharedPtr = Rc<EmuFile>;

type FileMap = HashMap<FileId, Weak<EmuFile>>;

// We DONT want this to be either Copy or Clone.
pub struct EmuFile {
    // @TODO Should we be using OSString here?
    orig_path: String,
    tmp_path: String,
    file: ScopedFd,
    /// The lifetime of the reference is the same as the lifetime on EmuFs.
    owner: Weak<RefCell<EmuFs>>,
    size_: u64,
    device_: dev_t,
    inode_: ino_t,
}

impl EmuFile {
    /// Note this is NOT pub. Note the move for ScopedFd and owner.
    fn new(
        owner: Rc<RefCell<EmuFs>>,
        fd: ScopedFd,
        orig_path: &str,
        real_path: &str,
        device: dev_t,
        inode: ino_t,
        file_size: u64,
    ) -> EmuFile {
        EmuFile {
            orig_path: orig_path.to_owned(),
            tmp_path: real_path.to_owned(),
            file: fd,
            owner: Rc::downgrade(&owner),
            size_: file_size,
            device_: device,
            inode_: inode,
        }
    }
    /// Return the fd of the real file backing this.
    pub fn fd(&self) -> &ScopedFd {
        &self.file
    }

    /// Return a pathname referring to the fd of this in this
    /// tracer's address space.  For example, "/proc/12345/fd/5".
    pub fn proc_path(&self) -> String {
        let pid = getpid();
        format!("/proc/{}/fd/{}", pid, self.fd().as_raw())
    }

    /// Return the path of the original file from recording, the
    /// one this is emulating.
    pub fn emu_path(&self) -> String {
        self.orig_path.clone()
    }

    pub fn real_path(&self) -> String {
        self.tmp_path.clone()
    }

    pub fn device(&self) -> dev_t {
        self.device_
    }

    pub fn inode(&self) -> ino_t {
        self.inode_
    }

    pub fn ensure_size(&mut self, size: u64) {
        if self.size_ < size {
            resize_shmem_segment(&self.file, size);
            self.size_ = size;
        }
    }

    /// Return a copy of this file.  See |create()| for the meaning
    /// of |fs_tag|.
    fn clone(&self, owner: &EmuFs) -> EmuFileSharedPtr {
        unimplemented!()
    }

    /// Ensure that the emulated file is sized to match a later
    /// stat() of it.
    fn update(&mut self, device: dev_t, inode: ino_t, size: u64) {
        unimplemented!()
    }

    /// Create a new emulated file for |orig_path| that will
    /// emulate the recorded attributes |est|.  |tag| is used to
    /// uniquely identify this file among multiple EmuFs's that
    /// might exist concurrently in this tracer process.
    fn create(
        owner: &EmuFs,
        orig_path: &str,
        orig_device: dev_t,
        orig_inode: ino_t,
        orig_file_size: u64,
    ) -> EmuFileSharedPtr {
        unimplemented!()
    }
}

impl Drop for EmuFile {
    fn drop(&mut self) {
        log!(
            LogDebug,
            "     emufs::emu_file::Drop(einode:{})",
            self.inode_
        );
        // @TODO should we avoid unwrap() here? Can this fail?
        self.owner
            .upgrade()
            .unwrap()
            .borrow_mut()
            .destroyed_file(self);
    }
}

// We DONT want this to be either Copy or Clone.
pub struct EmuFs {
    files: FileMap,
}

impl EmuFs {
    /// Create and return a new emufs.
    pub fn create() -> EmuFsSharedPtr {
        unimplemented!()
    }

    /// Return the EmuFile for |recorded_map|, which must exist or this won't
    /// return.
    pub fn at(&self, recorded_map: &KernelMapping) -> EmuFileSharedPtr {
        unimplemented!()
    }

    pub fn has_file_for(&self, recorded_map: &KernelMapping) -> bool {
        unimplemented!()
    }

    pub fn clone_file(&mut self, emu_file: EmuFileSharedPtr) -> EmuFileSharedPtr {
        unimplemented!()
    }

    /// Return an emulated file representing the recorded shared mapping
    /// |recorded_km|.
    pub fn get_or_create(&mut self, recorded_map: &KernelMapping) -> EmuFileSharedPtr {
        unimplemented!()
    }

    /// Return an already-existing emulated file for the given device/inode.
    /// Returns null if not found.
    pub fn find(&self, device: dev_t, inode: ino_t) -> Option<EmuFileSharedPtr> {
        unimplemented!()
    }

    /// Dump information about this emufs to the "error" log.
    pub fn log(&self) {
        unimplemented!()
    }

    pub fn size(&self) -> usize {
        self.files.len()
    }

    pub fn destroyed_file(&mut self, emu_file: &EmuFile) {
        self.files.remove(&FileId::from_emu_file(emu_file));
    }
}

/// Internal struct
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct FileId {
    pub device: dev_t,
    pub inode: ino_t,
}

impl FileId {
    pub fn new(device: dev_t, inode: ino_t) -> FileId {
        FileId { device, inode }
    }

    pub fn from_kernel_mapping(recorded_map: &KernelMapping) -> FileId {
        FileId {
            device: recorded_map.device(),
            inode: recorded_map.inode(),
        }
    }

    pub fn from_emu_file(emu_file: &EmuFile) -> FileId {
        FileId {
            device: emu_file.device_,
            inode: emu_file.inode_,
        }
    }
}
