//! Support tracees that share memory read-only with a non-tracee that
//! writes to the memory. Currently this just supports limited cases that
//! suffice for dconf: no remapping, coalescing or splitting of the memory is
//! allowed (`subrange` below just asserts). It doesn't handle mappings where
//! the mapping has more pages than the file.
//!
//! After such memory is mapped in the tracee, we also map it in rd at `real_mem`
//! and replace the tracee's mapping with a "shadow buffer" that's only shared
//! with rd. Then periodically rd reads the real memory, and if it doesn't match
//! the shadow buffer, we update the shadow buffer with the new values and
//! record that we did so.
//!
//! Currently we check the real memory after each syscall exit. This ensures
//! that if the tracee is woken up by some IPC mechanism (or after sched_yield),
//! it will get a chance to see updated memory values.

use crate::{
    auto_remote_syscalls::{AutoRemoteSyscalls, PreserveContents},
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::{address_space, memory_range::MemoryRangeKey},
        task::record_task::RecordTask,
    },
};
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use std::{
    cell::RefCell,
    convert::TryInto,
    ffi::OsStr,
    path::{Component, Path},
    ptr,
    rc::{Rc, Weak},
    slice,
};

pub type MonitoredSharedMemorySharedPtr = Rc<RefCell<MonitoredSharedMemory>>;
pub type MonitoredSharedMemorySharedWeakPtr = Weak<RefCell<MonitoredSharedMemory>>;

pub struct MonitoredSharedMemory {
    real_mem: &'static [u8],
}

impl MonitoredSharedMemory {
    pub fn maybe_monitor(
        t: &RecordTask,
        filename: &OsStr,
        m: address_space::Mapping,
        tracee_fd: i32,
        offset: u64,
    ) {
        // filename should end with /dconf/user
        let pathname = Path::new(filename);
        let mut components = pathname.components();
        let maybe_user = components.next_back();
        let maybe_dconf = components.next_back();
        if (maybe_dconf, maybe_user)
            != (
                Some(Component::Normal(OsStr::new("dconf"))),
                Some(Component::Normal(OsStr::new("user"))),
            )
            || components.next_back().is_none()
        {
            return;
        }

        let mut remote = AutoRemoteSyscalls::new(t);

        let fd: ScopedFd = remote.retrieve_fd(tracee_fd);
        let real_mem_ptr = unsafe {
            mmap(
                ptr::null_mut(),
                m.map.size(),
                ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED,
                fd.as_raw(),
                offset.try_into().unwrap(),
            )
            .unwrap()
        };

        let real_mem = unsafe { slice::from_raw_parts(real_mem_ptr as *const u8, m.map.size()) };
        let result = Rc::new(RefCell::new(MonitoredSharedMemory::new(real_mem)));
        let shared = remote.steal_mapping(m, Some(result));
        // m may be invalid now
        let copy_to = remote
            .vm()
            .local_mapping_mut(shared.map.start(), shared.map.size())
            .unwrap();
        copy_to.copy_from_slice(real_mem);
    }

    pub fn check_all(t: &RecordTask) {
        let mut addrs = Vec::<RemotePtr<Void>>::new();
        for a in t.vm().monitored_addrs().iter() {
            addrs.push(*a);
        }
        for a in addrs {
            let rc_v = t.vm_shr_ptr();
            let m = rc_v.mapping_of(a).unwrap().clone();
            let maybe_mm = m.monitored_shared_memory.clone();
            match maybe_mm {
                Some(mm) => mm.borrow().check_for_changes(t, m),
                None => (),
            }
        }
    }

    /// This feature is currently unsupported
    pub fn subrange(&self, _start: usize, _size: usize) -> MonitoredSharedMemorySharedPtr {
        assert!(
            false,
            "Subranges in monitored shared memory not supported yet!"
        );

        unimplemented!()
    }

    fn check_for_changes(&self, t: &RecordTask, m: address_space::Mapping) {
        ed_assert_eq!(t, m.map.size(), self.real_mem.len());
        let local_slice: &'static mut [u8] = match m.local_addr {
            None => {
                // reestablish local mapping after a fork or whatever
                let mut remote = AutoRemoteSyscalls::new(t);
                let msm = m.monitored_shared_memory;
                let mrk = MemoryRangeKey(*m.map);
                let addr =
                    remote.recreate_shared_mmap(mrk, Some(PreserveContents::DiscardContents), msm);
                remote
                    .vm()
                    .local_mapping_mut(addr, self.real_mem.len())
                    .unwrap()
            }
            Some(_) => t
                .vm()
                .local_mapping_mut(m.map.start(), self.real_mem.len())
                .unwrap(),
        };
        // If our capture of shared memory matches what is in actual shared memory then we're done
        if local_slice == self.real_mem {
            return;
        }

        local_slice.copy_from_slice(self.real_mem);
        t.record_local(m.map.start(), self.real_mem);
    }

    /// real_mem is pointer within rd's address space to the memory shared between
    /// the tracee (which just becomes a "shadow buffer") and the non-rd process.
    /// See description above.
    fn new(real_mem: &'static [u8]) -> MonitoredSharedMemory {
        MonitoredSharedMemory { real_mem }
    }
}
