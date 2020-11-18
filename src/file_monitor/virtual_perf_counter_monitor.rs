use crate::{
    bindings::{
        fcntl::{f_owner_ex, F_OWNER_TID, F_SETFL, F_SETOWN_EX, F_SETSIG},
        perf_event::{
            perf_event_attr,
            PERF_EVENT_IOC_DISABLE,
            PERF_EVENT_IOC_ENABLE,
            PERF_EVENT_IOC_PERIOD,
            PERF_EVENT_IOC_RESET,
        },
        signal::siginfo_t,
    },
    file_monitor::{
        FileMonitor,
        FileMonitorSharedPtr,
        FileMonitorSharedWeakPtr,
        FileMonitorType,
        LazyOffset,
        Range,
    },
    perf_counters::PerfCounters,
    remote_ptr::RemotePtr,
    session::{
        task::{record_task::RecordTask, task_common::read_val_mem, task_inner::WriteFlags, Task},
        SessionSharedWeakPtr,
    },
    sig::Sig,
    taskish_uid::TaskUid,
    ticks::Ticks,
};
use libc::{pid_t, EINVAL, O_ASYNC};
use std::{cmp::min, convert::TryFrom};

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

    pub fn synthesize_signal(&mut self, _t: &mut RecordTask) {
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

    fn emulate_ioctl(&mut self, t: &mut RecordTask, result: &mut usize) -> bool {
        match t.regs_ref().arg2() as _ {
            PERF_EVENT_IOC_ENABLE => {
                *result = 0;
                self.enabled = true;
            }
            PERF_EVENT_IOC_DISABLE => {
                *result = 0;
                self.enabled = false;
            }
            PERF_EVENT_IOC_RESET => {
                *result = 0;
                let target_tid = self.target_tuid().tid();
                if target_tid == t.tid {
                    self.initial_ticks = t.tick_count();
                } else {
                    let target = t.session().find_task_from_rec_tid(target_tid).unwrap();
                    self.initial_ticks = target.borrow().tick_count();
                }
            }
            PERF_EVENT_IOC_PERIOD => {
                *result = 0;
                let child_addr = RemotePtr::<u64>::from(t.regs_ref().arg3());
                let after = read_val_mem(t, child_addr, None);
                self.maybe_enable_interrupt(t, after);
            }
            _ => {
                ed_assert!(
                    t,
                    false,
                    "Unsupported perf event ioctl {:#x}",
                    t.regs_ref().arg2() as u32
                );
            }
        }

        true
    }

    fn emulate_fcntl(&mut self, t: &mut RecordTask, result: &mut usize) -> bool {
        *result = (-EINVAL as isize) as usize;
        match t.regs_ref().arg2() as u32 {
            F_SETOWN_EX => {
                let child_addr = RemotePtr::<f_owner_ex>::from(t.regs_ref().arg3());
                let owner = read_val_mem(t, child_addr, None);
                ed_assert_eq!(
                    t,
                    owner.type_,
                    F_OWNER_TID,
                    "Unsupported perf event F_SETOWN_EX type {}",
                    owner.type_
                );
                ed_assert_eq!(
                    t,
                    owner.pid,
                    self.target_tuid().tid(),
                    "Perf event F_SETOWN_EX is only supported to the target tid"
                );
                self.owner_tid = owner.pid;
                *result = 0;
            }
            F_SETFL => {
                ed_assert_eq!(
                    t,
                    t.regs_ref().arg3() as i32 & !O_ASYNC,
                    0,
                    "Unsupported perf event flags {}",
                    t.regs_ref().arg3() as i32
                );
                self.flags = t.regs_ref().arg3() as i32;
                *result = 0;
            }
            F_SETSIG => {
                self.sig = Sig::try_from(t.regs_ref().arg3() as i32).ok();
                *result = 0;
            }
            _ => {
                ed_assert!(
                    t,
                    false,
                    "Unsupported perf event fnctl {}",
                    t.regs_ref().arg2() as i32
                );
            }
        }
        true
    }

    fn emulate_read(
        &self,
        ranges: &[Range],
        lazy_offset: &mut LazyOffset,
        result: &mut usize,
    ) -> bool {
        let maybe_target = lazy_offset
            .t
            .session()
            .find_task_from_task_uid(self.target_tuid());
        match maybe_target {
            Some(target) => {
                let val = if lazy_offset.t.tid == self.target_tuid().tid() {
                    lazy_offset.t.tick_count() - self.initial_ticks
                } else {
                    target.borrow().tick_count() - self.initial_ticks
                };
                *result = write_ranges(lazy_offset.t, ranges, &val.to_le_bytes());
            }
            None => {
                *result = 0;
            }
        }

        true
    }
}

fn write_ranges(t: &mut dyn Task, ranges: &[Range], p: &[u8]) -> usize {
    let mut s: usize = p.len();
    let mut result: usize = 0;
    for r in ranges {
        let bytes = min(s, r.length);
        t.write_bytes_helper(r.data, &p[0..bytes], None, WriteFlags::empty());
        s -= bytes;
        result += bytes;
    }

    result
}
