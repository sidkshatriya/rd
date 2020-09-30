use crate::{event::Switchable, session::task::record_task::RecordTask};

pub fn rec_prepare_syscall(_t: &RecordTask) -> Switchable {
    unimplemented!()
}

pub fn rec_prepare_restart_syscall(_t: &RecordTask) {
    unimplemented!()
}

pub fn rec_process_syscall(_t: &RecordTask) {
    unimplemented!()
}
