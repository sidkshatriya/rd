use super::EmuFs;
use crate::log::LogDebug;
use crate::scoped_fd::ScopedFd;
use crate::util::resize_shmem_segment;
use libc::{dev_t, ino_t};
use nix::unistd::getpid;
use std::cell::RefCell;
use std::rc::Rc;

pub type SharedPtr = Rc<EmuFile>;

// We DONT want this to be either Copy or Clone.
pub struct EmuFile {
    // @TODO Should we be using OSString here?
    pub(super) orig_path: String,
    pub(super) tmp_path: String,
    pub(super) file: ScopedFd,
    /// The lifetime of the reference is the same as the lifetime on EmuFs.
    pub(super) owner: Rc<RefCell<EmuFs>>,
    pub(super) size_: u64,
    pub(super) device_: dev_t,
    pub(super) inode_: ino_t,
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
            owner: owner,
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
}

impl Drop for EmuFile {
    fn drop(&mut self) {
        log!(
            LogDebug,
            "     emufs::emu_file::Drop(einode:{})",
            self.inode_
        );
        self.owner.borrow_mut().destroyed_file(self);
    }
}
