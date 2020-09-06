use crate::{
    bindings::{perf_event::perf_event_attr, signal::siginfo_t},
    file_monitor::{FileMonitor, FileMonitorSharedPtr, FileMonitorType, LazyOffset, Range},
    session::task::{record_task::RecordTask, Task},
    sig::Sig,
    taskish_uid::TaskUid,
    ticks::Ticks,
};
use libc::pid_t;

const VIRTUAL_PERF_COUNTER_SIGNAL_SI_ERRNO: i32 = -1337;

/// A FileMonitor to virtualize the performance counter that rr uses to count
/// ticks. Note that this doesn't support interrupts yet so recording rr replays
/// that involve async signals will not work!
pub struct VirtualPerfCounterMonitor {
    initial_ticks: Ticks,
    target_ticks_: Ticks,
    target_tuid_: TaskUid,
    owner_tid: pid_t,
    flags: i32,
    sig: Sig,
    enabled: bool,
}

impl Drop for VirtualPerfCounterMonitor {
    fn drop(&mut self) {
        self.disable_interrupt();
    }
}

impl VirtualPerfCounterMonitor {
    pub fn should_virtualize(_attr: &perf_event_attr) -> bool {
        unimplemented!()
    }

    pub fn new(_t: &dyn Task, _target: &dyn Task, _attr: &perf_event_attr) {
        unimplemented!()
    }

    pub fn target_ticks(&self) -> Ticks {
        self.target_ticks_
    }

    pub fn target_tuid(&self) -> TaskUid {
        self.target_tuid_
    }

    pub fn synthesize_signal(&self, _t: &RecordTask) {
        unimplemented!()
    }

    pub fn is_virtual_perf_counter_signal(s: &siginfo_t) -> bool {
        s.si_errno == VIRTUAL_PERF_COUNTER_SIGNAL_SI_ERRNO
    }

    pub fn interrupting_virtual_pmc_for_task(t: &dyn Task) -> Option<FileMonitorSharedPtr> {
        let tuid = t.tuid();
        t.tasks_with_interrupts
            .get(&tuid)
            .map(|f| f.upgrade().unwrap())
    }

    fn maybe_enable_interrupt(&self, _t: &dyn Task, _after: u64) {
        unimplemented!()
    }

    fn disable_interrupt(&self) {
        unimplemented!()
    }
}

impl FileMonitor for VirtualPerfCounterMonitor {
    fn as_virtual_perf_counter_monitor(&self) -> Option<&VirtualPerfCounterMonitor> {
        Some(self)
    }

    fn as_virtual_perf_counter_monitor_mut(&mut self) -> Option<&mut VirtualPerfCounterMonitor> {
        Some(self)
    }

    fn file_monitor_type(&self) -> FileMonitorType {
        FileMonitorType::VirtualPerfCounter
    }

    fn emulate_ioctl(&mut self, _t: &RecordTask, _r: &mut u64) -> bool {
        unimplemented!()
    }

    fn emulate_fcntl(&self, _t: &RecordTask, _r: &mut u64) -> bool {
        unimplemented!()
    }

    fn emulate_read(
        &self,
        _t: &RecordTask,
        _vr: &Vec<Range>,
        _o: &LazyOffset,
        _l: &mut u64,
    ) -> bool {
        unimplemented!()
    }
}
