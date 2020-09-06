use crate::{
    bindings::{perf_event::perf_event_attr, signal::siginfo_t},
    file_monitor::{
        FileMonitor,
        FileMonitorSharedPtr,
        FileMonitorSharedWeakPtr,
        FileMonitorType,
        LazyOffset,
        Range,
    },
    perf_counters::PerfCounters,
    session::{
        task::{record_task::RecordTask, Task},
        SessionSharedWeakPtr,
    },
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
    sig: Option<Sig>,
    enabled: bool,
    session: SessionSharedWeakPtr,
    pub weak_self: FileMonitorSharedWeakPtr,
}

impl Drop for VirtualPerfCounterMonitor {
    fn drop(&mut self) {
        self.disable_interrupt();
    }
}

impl VirtualPerfCounterMonitor {
    pub fn should_virtualize(attr: &perf_event_attr) -> bool {
        PerfCounters::is_rd_ticks_attr(attr)
    }

    pub fn new(
        t: &dyn Task,
        target: &dyn Task,
        attr: &perf_event_attr,
    ) -> VirtualPerfCounterMonitor {
        let v = VirtualPerfCounterMonitor {
            session: t.session().weak_self_ptr(),
            initial_ticks: target.tick_count(),
            target_ticks_: 0,
            target_tuid_: target.tuid(),
            owner_tid: 0,
            flags: 0,
            sig: None,
            enabled: false,
            weak_self: Default::default(),
        };

        ed_assert!(t, VirtualPerfCounterMonitor::should_virtualize(attr));
        if t.session().is_recording() {
            v.maybe_enable_interrupt(t.as_record_task().unwrap(), unsafe {
                attr.__bindgen_anon_1.sample_period
            });
        }
        v
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
        t.session()
            .tasks_with_interrupts
            .borrow()
            .get(&tuid)
            .map(|f| f.upgrade().unwrap())
    }

    fn maybe_enable_interrupt(&self, _t: &RecordTask, _after: u64) {
        unimplemented!()
    }

    fn disable_interrupt(&self) {
        let session = self.session.upgrade().unwrap();
        let tuid = self.target_tuid();
        let maybe_v = session.tasks_with_interrupts.borrow().get(&tuid).cloned();
        match maybe_v {
            Some(v) if v.ptr_eq(&self.weak_self) => {
                session.tasks_with_interrupts.borrow_mut().remove(&tuid);
            }
            _ => (),
        }
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
