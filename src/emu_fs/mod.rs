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

pub mod emu_file;

use crate::address_space::kernel_mapping::KernelMapping;
use emu_file::EmuFile;
use libc::{dev_t, ino_t};
use std::collections::HashMap;
use std::rc::{Rc, Weak};

pub type SharedPtr = Rc<EmuFs>;

type FileMap = HashMap<FileId, Weak<EmuFile>>;

// We DONT want this to be either Copy or Clone.
pub struct EmuFs {
    files: FileMap,
}

impl EmuFs {
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
