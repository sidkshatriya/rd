use crate::event::Switchable;
use crate::file_monitor::{FileMonitor, FileMonitorType, LazyOffset, Range};
use crate::remote_ptr::RemotePtr;
use crate::task::record_task::record_task::RecordTask;
use crate::task::Task;
use crate::taskish_uid::TaskUid;
use std::convert::TryInto;

pub struct ProcMemMonitor {
    maybe_tuid: Option<TaskUid>,
}

impl FileMonitor for ProcMemMonitor {
    fn file_monitor_type(&self) -> FileMonitorType {
        unimplemented!()
    }

    /// We need to PREVENT_SWITCH, since the timing of the write is otherwise
    /// unpredictable from our perspective.
    fn will_write(&self, t: &dyn Task) -> Switchable {
        Switchable::PreventSwitch
    }

    fn did_write<'b, 'a: 'b>(&mut self, ranges: &[Range], lazy_offset: &mut LazyOffset<'b, 'a>) {
        if self.maybe_tuid.is_none() {
            return;
        }
        if lazy_offset.t.session().borrow().is_replaying() || ranges.is_empty() {
            return;
        }

        let session_rc = lazy_offset.t.session();
        let session_ref = session_rc.borrow();

        let maybe_target = session_ref.find_task_from_task_uid(&self.maybe_tuid.unwrap());

        match maybe_target {
            None => return,
            Some(target) => {
                let record_task = target.as_record_task().unwrap();
                let mut offset = lazy_offset.retrieve(false);
                for r in ranges {
                    record_task.record_remote(
                        RemotePtr::new_from_val(offset.try_into().unwrap()),
                        r.length,
                    );
                    offset += r.length as u64;
                }
            }
        }
    }
}
