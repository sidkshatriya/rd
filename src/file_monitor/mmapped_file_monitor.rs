use crate::{
    emu_fs::EmuFileSharedPtr,
    event::{
        Switchable,
        Switchable::{AllowSwitch, PreventSwitch},
    },
    file_monitor::{FileMonitor, FileMonitorType, LazyOffset, Range},
    log::LogLevel::LogWarn,
    session::{
        address_space::{kernel_mapping::KernelMapping, memory_range::MemoryRange},
        task::Task,
    },
};
use libc::{dev_t, ino_t};
use nix::sys::mman::MapFlags;
use std::convert::TryInto;

/// A FileMonitor to track writes to files that are mmapped in so they can be
/// replayed.
pub struct MmappedFileMonitor {
    /// Whether this monitor is still actively monitoring
    dead_: bool,
    device_: dev_t,
    inode_: ino_t,
}

impl MmappedFileMonitor {
    pub fn new(t: &dyn Task, fd: i32) -> MmappedFileMonitor {
        ed_assert!(t, !t.session().is_replaying());
        let stat = t.stat_fd(fd);
        MmappedFileMonitor {
            dead_: false,
            device_: stat.st_dev,
            inode_: stat.st_ino,
        }
    }

    pub fn revive(&mut self) {
        self.dead_ = false;
    }

    pub fn new_from_emufile(t: &dyn Task, f: EmuFileSharedPtr) -> MmappedFileMonitor {
        ed_assert!(t, t.session().is_replaying());
        MmappedFileMonitor {
            dead_: false,
            device_: f.borrow().device(),
            inode_: f.borrow().inode(),
        }
    }
}

impl FileMonitor for MmappedFileMonitor {
    fn file_monitor_type(&self) -> FileMonitorType {
        FileMonitorType::Mmapped
    }

    fn as_mmapped_file_monitor_mut(&mut self) -> Option<&mut MmappedFileMonitor> {
        Some(self)
    }

    fn as_mmapped_file_monitor(&self) -> Option<&MmappedFileMonitor> {
        Some(self)
    }

    fn will_write(&self, _t: &dyn Task) -> Switchable {
        if self.dead_ {
            AllowSwitch
        } else {
            PreventSwitch
        }
    }

    fn did_write<'b, 'a: 'b>(&mut self, ranges: &[Range], offset: &mut LazyOffset<'b, 'a>) {
        // If there are no remaining mappings that we care about, those can't reappear
        // without going through mmap again, at which point this will be reset to
        // false.
        if self.dead_ {
            return;
        }

        if ranges.is_empty() {
            return;
        }

        // Dead until proven otherwise
        self.dead_ = true;
        // DIFF NOTE: This is signed in rr. We make this unsigned.
        let mut realized_offset: u64 = 0;

        let is_replay = offset.t.session().is_replaying();
        for v in &offset.t.session().vms() {
            for (_, m) in &v.maps() {
                let km: &KernelMapping = &m.map;

                if is_replay {
                    if m.emu_file.is_none()
                        || m.emu_file.as_ref().unwrap().borrow().device() != self.device_
                        || m.emu_file.as_ref().unwrap().borrow().inode() != self.inode_
                    {
                        continue;
                    }
                } else {
                    if km.device() != self.device_ || km.inode() != self.inode_ {
                        continue;
                    }
                    // If the mapping is MAP_PRIVATE then this write is dangerous
                    // because it's unpredictable what will be seen in the mapping.
                    // However, it could be OK if the application doesn't read from
                    // this part of the mapping. Just optimistically assume this mapping
                    // is not affected.
                    if !km.flags().contains(MapFlags::MAP_SHARED) {
                        log!(LogWarn, "MAP_PRIVATE mapping affected by write");
                        continue;
                    }
                }

                // We're discovering a mapping we care about
                if self.dead_ {
                    self.dead_ = false;
                    realized_offset = offset.retrieve(true).unwrap();
                }

                // stat matches.
                let mapping_offset: u64 = km.file_offset_bytes();
                let mut local_offset: u64 = realized_offset;
                for r in ranges {
                    let start: usize = (km.start().as_usize() as u64 + local_offset
                        - mapping_offset)
                        .try_into()
                        .unwrap();
                    let mr = MemoryRange::new_range(start.into(), r.length);
                    if km.intersects(&mr) {
                        if is_replay {
                            // If we're writing beyond the EmuFile's end, resize it.
                            m.emu_file
                                .as_ref()
                                .unwrap()
                                .borrow_mut()
                                .ensure_size(local_offset + r.length as u64);
                        } else {
                            ed_assert!(offset.t, !v.task_set().inner_hashset().is_empty());
                            // We will record multiple writes if the file is mapped multiple
                            // times. This is inefficient --- one is sufficient --- but not
                            // wrong.
                            // Make sure we use a task for this address space. `t` might have
                            // a different address space.
                            for t_rc in v.task_set().iter() {
                                // If the task here has execed, we may not be able to record its
                                // memory any longer, so loop through all tasks in this address
                                // space in turn in case any *didn't* exec.
                                let mut rt_ref = t_rc.borrow_mut();
                                let result = rt_ref
                                    .as_record_task_mut()
                                    .unwrap()
                                    .record_remote_range_fallible(km.intersect(&mr));
                                if let Ok(nread) = result {
                                    if nread > 0 {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    local_offset = local_offset + r.length as u64;
                }
            }
        }
    }
}
