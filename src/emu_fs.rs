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
//! trace by `(edev, einode)` (i.e., the recorded device ID and inode).
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
//! interval.  As per the first long comment in `gc()` below, an
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

use crate::{
    address_space::kernel_mapping::KernelMapping,
    log::{LogDebug, LogError},
    scoped_fd::ScopedFd,
    util::resize_shmem_segment,
};
use libc::{c_void, dev_t, ino_t, pread64, pwrite64};
use nix::{
    sys::memfd::{memfd_create, MemFdCreateFlag},
    unistd::getpid,
};
use std::{
    cell::RefCell,
    cmp::min,
    collections::HashMap,
    convert::TryInto,
    ffi::{CString, OsStr, OsString},
    io::Write,
    os::unix::ffi::{OsStrExt, OsStringExt},
    rc::{Rc, Weak},
};

pub type EmuFsSharedPtr = Rc<RefCell<EmuFs>>;
pub type EmuFileSharedPtr = Rc<RefCell<EmuFile>>;
pub type EmuFsSharedWeakPtr = Weak<RefCell<EmuFs>>;
pub type EmuFileSharedWeakPtr = Weak<RefCell<EmuFile>>;

type FileMap = HashMap<FileId, Weak<RefCell<EmuFile>>>;

/// We DONT want this to be either Copy or Clone.
pub struct EmuFile {
    orig_path: OsString,
    tmp_path: OsString,
    file: ScopedFd,
    owner: EmuFsSharedWeakPtr,
    size_: u64,
    device_: dev_t,
    inode_: ino_t,
    weak_self: EmuFileSharedWeakPtr,
}

impl EmuFile {
    const BUF_LEN: usize = 65536 / std::mem::size_of::<u64>();

    fn owner(&self) -> EmuFsSharedPtr {
        self.owner.upgrade().unwrap()
    }

    /// Note this is NOT pub.
    /// Also note the move for ScopedFd.
    fn new(
        owner: EmuFsSharedWeakPtr,
        fd: ScopedFd,
        orig_path: &OsStr,
        real_path: &OsStr,
        device: dev_t,
        inode: ino_t,
        file_size: u64,
    ) -> EmuFileSharedPtr {
        let file = EmuFile {
            orig_path: orig_path.to_owned(),
            tmp_path: real_path.to_owned(),
            file: fd,
            owner,
            size_: file_size,
            device_: device,
            inode_: inode,
            weak_self: Weak::new(),
        };
        let file_shared = Rc::new(RefCell::new(file));
        file_shared.borrow_mut().weak_self = Rc::downgrade(&file_shared);
        file_shared
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
    pub fn emu_path(&self) -> &OsStr {
        &self.orig_path
    }

    pub fn real_path(&self) -> &OsStr {
        &self.tmp_path
    }

    pub fn device(&self) -> dev_t {
        self.device_
    }

    pub fn inode(&self) -> ino_t {
        self.inode_
    }

    pub fn ensure_size(&mut self, size: u64) {
        if self.size_ < size {
            resize_shmem_segment(&self.file, size.try_into().unwrap());
            self.size_ = size;
        }
    }

    /// Return a copy of this file.  See `create()` for the meaning
    /// of `fs_tag`.
    fn clone_file(&self) -> EmuFileSharedPtr {
        let f = EmuFile::create(
            self.owner.clone(),
            &self.emu_path(),
            self.device(),
            self.inode(),
            self.size_,
        );

        let mut data = [0u64; Self::BUF_LEN];
        let mut offset: u64 = 0;

        while offset < self.size_ {
            let mut amount: usize = min((self.size_ - offset).try_into().unwrap(), Self::BUF_LEN);
            let mut ret: isize = unsafe {
                pread64(
                    self.fd().as_raw(),
                    data.as_mut_ptr().cast::<c_void>(),
                    amount,
                    offset as i64,
                )
            };
            if ret <= 0 {
                fatal!("Couldn't read all the data");
            }
            // There could have been a short read
            // Note: The if condition above ensures ret > 0
            amount = ret as usize;
            let mut data_ptr = data.as_ptr().cast::<u8>();
            while amount > 0 {
                ret = unsafe {
                    pwrite64(
                        f.borrow().fd().as_raw(),
                        data_ptr.cast(),
                        amount,
                        offset as i64,
                    )
                };
                if ret <= 0 {
                    fatal!("Couldn't write all the data");
                }
                if amount as isize - ret < 0 {
                    fatal!("Impossible situation. Read more than asked for")
                }
                // Note: The if condition above ensures ret > 0
                unsafe {
                    data_ptr = data_ptr.add(ret as usize);
                }
                offset += ret as u64;
            }
        }

        f
    }

    /// Ensure that the emulated file is sized to match a later
    /// stat() of it.
    fn update(&mut self, device: dev_t, inode: ino_t, size: u64) {
        debug_assert!(self.device_ == device && self.inode_ == inode);
        self.ensure_size(size);
    }

    /// Create a new emulated file for `orig_path` that will
    /// emulate the recorded attributes `est`.  `tag` is used to
    /// uniquely identify this file among multiple EmuFs's that
    /// might exist concurrently in this tracer process.
    fn create(
        owner: EmuFsSharedWeakPtr,
        orig_path: &OsStr,
        orig_device: dev_t,
        orig_inode: ino_t,
        orig_file_size: u64,
    ) -> EmuFileSharedPtr {
        let mut fd_and_name: Option<(ScopedFd, OsString)> =
            create_memfd_file(orig_path, orig_device, orig_inode);
        if fd_and_name.is_none() {
            fd_and_name = create_tmpfs_file(orig_path, orig_device, orig_inode);
            if fd_and_name.is_none() {
                fatal!(
                    "Failed to create shmem segment for {}:{} {:?}",
                    orig_device,
                    orig_inode,
                    orig_path
                );
            }
        }

        let (fd, real_name) = fd_and_name.unwrap();
        resize_shmem_segment(&fd, orig_file_size.try_into().unwrap());

        let f = EmuFile::new(
            owner,
            fd,
            orig_path,
            &real_name,
            orig_device,
            orig_inode,
            orig_file_size,
        );

        log!(
            LogDebug,
            "created emulated file for {:?} as {:?}",
            orig_path,
            real_name
        );

        f
    }
}

impl Drop for EmuFile {
    fn drop(&mut self) {
        log!(
            LogDebug,
            "     emufs::emu_file::Drop(einode:{})",
            self.inode_
        );
        self.owner().borrow_mut().destroyed_file(self);
    }
}

// We DONT want this to be either Copy or Clone.
pub struct EmuFs {
    files: FileMap,
    weak_self: EmuFsSharedWeakPtr,
}

impl EmuFs {
    /// Create and return a new emufs.
    pub fn create() -> EmuFsSharedPtr {
        EmuFs::new()
    }

    /// Note that this is a NOT pub
    fn new() -> EmuFsSharedPtr {
        let fs = EmuFs {
            files: HashMap::new(),
            weak_self: Weak::new(),
        };
        let shared_fs = Rc::new(RefCell::new(fs));
        shared_fs.borrow_mut().weak_self = Rc::downgrade(&shared_fs);
        shared_fs
    }

    /// Return the EmuFile for `recorded_map`, which must exist or this won't
    /// return.
    pub fn at(&self, recorded_map: &KernelMapping) -> Option<EmuFileSharedPtr> {
        // @TODO Assuming upgrade() always works.
        self.files
            .get(&FileId::from_kernel_mapping(recorded_map))
            .map(|val| val.upgrade().unwrap())
    }

    pub fn has_file_for(&self, recorded_map: &KernelMapping) -> bool {
        self.files
            .get(&FileId::from_kernel_mapping(recorded_map))
            .is_some()
    }

    pub fn clone_file(&mut self, emu_file: EmuFileSharedPtr) -> EmuFileSharedPtr {
        let f = emu_file.borrow().clone_file();
        self.files
            .insert(FileId::from_emu_file(&emu_file.borrow()), Rc::downgrade(&f));
        f
    }

    /// Return an emulated file representing the recorded shared mapping
    /// `recorded_km`.
    pub fn get_or_create(&mut self, recorded_km: &KernelMapping) -> EmuFileSharedPtr {
        let file_id = FileId::from_kernel_mapping(recorded_km);
        let maybe_file_weak_ptr = self.files.get(&file_id);
        let min_file_size: u64 = recorded_km.file_offset_bytes() + recorded_km.size() as u64;
        if maybe_file_weak_ptr.is_some() {
            let rc = maybe_file_weak_ptr.unwrap().upgrade().unwrap();
            rc.borrow_mut()
                .update(recorded_km.device(), recorded_km.inode(), min_file_size);
            return rc;
        }

        let vf = EmuFile::create(
            self.weak_self.clone(),
            &recorded_km.fsname(),
            recorded_km.device(),
            recorded_km.inode(),
            min_file_size,
        );
        self.files.insert(file_id, Rc::downgrade(&vf));
        vf
    }

    /// Return an already-existing emulated file for the given device/inode.
    /// Returns null if not found.
    pub fn find(&self, device: dev_t, inode: ino_t) -> Option<EmuFileSharedPtr> {
        let file_id = FileId::new(device, inode);
        let maybe_file_weak_ptr = self.files.get(&file_id);
        maybe_file_weak_ptr.map(|file_weak_ptr| file_weak_ptr.upgrade().unwrap())
    }

    /// Dump information about this emufs to the "error" log.
    pub fn log(&self) {
        let addr = self as *const _ as *const u8 as usize;
        log!(LogError, "EmuFs {:x} with {} files:", addr, self.size());
        for (_, v) in &self.files {
            let emu_path = v.upgrade().unwrap().borrow().emu_path().to_owned();
            log!(LogError, "  {:?}", emu_path);
        }
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

fn create_memfd_file(
    orig_path: &OsStr,
    orig_device: dev_t,
    orig_inode: ino_t,
) -> Option<(ScopedFd, OsString)> {
    let mut name: Vec<u8> = Vec::new();
    write!(
        name,
        "rr-emufs-{}-dev-{}-inode-{}-",
        getpid(),
        orig_device,
        orig_inode
    )
    .unwrap();
    name.extend_from_slice(orig_path.as_bytes());
    name.truncate(255);

    let cname = CString::new(name.clone()).unwrap();
    let result = memfd_create(&cname, MemFdCreateFlag::empty());
    if result.is_ok() {
        Some((
            ScopedFd::from_raw(result.unwrap()),
            OsString::from_vec(name),
        ))
    } else {
        None
    }
}

/// Used only when memfd_create is not available, i.e. Linux < 3.17
fn create_tmpfs_file(
    _orig_path: &OsStr,
    _orig_device: dev_t,
    _orig_inode: ino_t,
) -> Option<(ScopedFd, OsString)> {
    unimplemented!()
}
