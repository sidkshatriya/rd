use crate::{arch::Architecture, session::task::record_task::RecordTask};

#[derive(Clone)]
pub struct MonkeyPatcher {}

impl MonkeyPatcher {
    pub fn new() -> MonkeyPatcher {
        MonkeyPatcher {}
    }
    pub fn patch_at_preload_init(&self, t: &RecordTask) {
        // NB: the tracee can't be interrupted with a signal while
        // we're processing the rdcall, because it's masked off all
        // signals.
        rd_arch_function_selfless!(patch_at_preload_init_arch, t.arch(), t, self);
    }
}

fn patch_at_preload_init_arch<Arch: Architecture>(_t: &RecordTask, _patcher: &MonkeyPatcher) {
    unimplemented!()
}
