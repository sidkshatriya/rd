use crate::file_monitor::FileMonitorType::MagicSaveData;
use crate::file_monitor::{FileMonitor, FileMonitorType, LazyOffset, Range};
use crate::remote_ptr::{RemotePtr, Void};
use crate::task::replay_task::ReplayTask;

pub struct MagicSaveDataMonitor;

impl FileMonitor for MagicSaveDataMonitor {
    fn file_monitor_type(&self) -> FileMonitorType {
        MagicSaveData
    }

    fn did_write<'b, 'a: 'b>(&self, rv: &[Range], l: &mut LazyOffset<'b, 'a>) {
        for r in rv {
            if l.t.session().borrow().is_recording() {
                let rec_task = l.t.as_record_task().unwrap();
                rec_task.record_remote(r.data, r.length);
            } else if l.t.session().borrow().is_replaying() {
                let mut bytes: Vec<u8> = Vec::with_capacity(r.length);
                bytes.resize(r.length, 0u8);
                l.t.read_bytes_helper(r.data, &mut bytes, None);
                let rep_task = l.t.as_replay_task().unwrap();
                let rec = rep_task.trace_reader().read_raw_data();
                if rec.data != bytes {
                    notify_save_data_error(rep_task, rec.addr, &rec.data, &bytes);
                }
            }
        }
    }
}

fn notify_save_data_error(t: &ReplayTask, addr: RemotePtr<Void>, rec_buf: &[u8], rep_buf: &[u8]) {
    unimplemented!()
}
