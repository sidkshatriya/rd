use crate::{
    event::Switchable,
    file_monitor::{FileMonitor, FileMonitorType, LazyOffset, Range},
    remote_ptr::RemotePtr,
    session::task::Task,
    taskish_uid::TaskUid,
};
use libc::pid_t;
use std::{
    convert::TryInto,
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Component, Path},
};

pub struct ProcMemMonitor {
    maybe_tuid: Option<TaskUid>,
}

impl ProcMemMonitor {
    pub fn new(t: &dyn Task, pathname: &OsStr) -> ProcMemMonitor {
        let pathname = Path::new(pathname);
        let mut components = pathname.components();
        let maybe_rootdir = components.next();
        let maybe_proc = components.next();
        let maybe_tid_os_str = components.next();
        let maybe_mem = components.next();
        if (maybe_rootdir, maybe_proc, maybe_mem)
            == (
                Some(Component::RootDir),
                Some(Component::Normal(OsStr::new("proc"))),
                Some(Component::Normal(OsStr::new("mem"))),
            )
        {
            match maybe_tid_os_str {
                Some(Component::Normal(tid_os_str)) => {
                    let tid_str = String::from_utf8_lossy(tid_os_str.as_bytes());
                    let maybe_tid = tid_str.parse::<pid_t>();
                    let tid = maybe_tid.unwrap();
                    let maybe_found = if t.rec_tid() == tid {
                        Some(t.tuid())
                    } else {
                        t.session().find_task_from_rec_tid(tid).map(|ft| ft.tuid())
                    };

                    return ProcMemMonitor {
                        maybe_tuid: maybe_found,
                    };
                }
                _ => (),
            }
        }
        ProcMemMonitor { maybe_tuid: None }
    }
}
impl FileMonitor for ProcMemMonitor {
    fn file_monitor_type(&self) -> FileMonitorType {
        FileMonitorType::ProcMem
    }

    /// We need to PREVENT_SWITCH, since the timing of the write is otherwise
    /// unpredictable from our perspective.
    fn will_write(&self, _t: &dyn Task) -> Switchable {
        Switchable::PreventSwitch
    }

    fn did_write<'b, 'a: 'b>(&mut self, ranges: &[Range], lazy_offset: &LazyOffset<'b, 'a>) {
        if self.maybe_tuid.is_none() {
            return;
        }

        let tuid = self.maybe_tuid.unwrap();
        if lazy_offset.t.session().is_replaying() || ranges.is_empty() {
            return;
        }

        let mut offset = lazy_offset.retrieve(false).unwrap();
        let target_rc;
        let task: &dyn Task = if lazy_offset.t.tuid() == tuid {
            &*lazy_offset.t
        } else {
            let maybe_target = lazy_offset.t.session().find_task_from_task_uid(tuid);
            match maybe_target {
                None => return,
                Some(target) => {
                    target_rc = target;
                    &**target_rc
                }
            }
        };

        let record_task = task.as_record_task().unwrap();
        for r in ranges {
            record_task.record_remote(RemotePtr::new(offset.try_into().unwrap()), r.length);
            offset += r.length as u64;
        }
    }
}
