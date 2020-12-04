use crate::{
    event::Switchable,
    file_monitor::{FileMonitor, FileMonitorSharedPtr, LazyOffset, Range},
    log::LogLevel::LogDebug,
    preload_interface::{preload_globals, SYSCALLBUF_FDS_DISABLED_SIZE},
    remote_ptr::RemotePtr,
    session::{
        address_space::address_space::AddressSpace,
        task::{
            record_task::RecordTask,
            replay_task::ReplayTask,
            Task,
            TaskSharedWeakPtr,
            WeakTaskPtrSet,
        },
    },
    taskish_uid::AddressSpaceUid,
    weak_ptr_set::WeakPtrSet,
};
use nix::sys::stat::lstat;
use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    collections::{HashMap, HashSet},
    rc::{Rc, Weak},
};

pub type FdTableSharedPtr = Rc<FdTable>;
pub type FdTableSharedWeakPtr = Weak<FdTable>;

#[derive(Clone)]
pub struct FdTable {
    tasks: RefCell<WeakTaskPtrSet>,
    fds: RefCell<HashMap<i32, FileMonitorSharedPtr>>,
    /// Number of elements of `fds` that are >= SYSCALLBUF_FDS_DISABLED_SIZE
    fd_count_beyond_limit: Cell<u32>,
}

/// We DO NOT want Copy or Clone traits
impl FdTable {
    pub fn task_set(&self) -> Ref<'_, WeakTaskPtrSet> {
        self.tasks.borrow()
    }

    pub fn task_set_mut(&self) -> RefMut<'_, WeakTaskPtrSet> {
        self.tasks.borrow_mut()
    }

    pub fn add_monitor(&self, t: &mut dyn Task, fd: i32, monitor: Box<dyn FileMonitor>) {
        // In the future we could support multiple monitors on an fd, but we don't
        // need to yet.
        ed_assert!(
            t,
            !self.is_monitoring(fd),
            "Task {} already monitoring fd {}",
            t.rec_tid,
            fd
        );
        if fd >= SYSCALLBUF_FDS_DISABLED_SIZE && !self.fds.borrow().contains_key(&fd) {
            self.fd_count_beyond_limit
                .set(self.fd_count_beyond_limit.get() + 1);
        }

        let rc = Rc::new(RefCell::new(monitor));
        let weak = Rc::downgrade(&rc);
        match rc.borrow_mut().as_virtual_perf_counter_monitor_mut() {
            None => (),
            Some(v) => v.weak_self = weak,
        }

        self.fds.borrow_mut().insert(fd, rc);
        self.update_syscallbuf_fds_disabled(fd, t, None);
    }

    /// DIFF NOTE: Changed this from u64 to usize
    pub fn emulate_ioctl(&self, fd: i32, t: &mut RecordTask, result: &mut usize) -> bool {
        match self.fds.borrow().get(&fd) {
            Some(f) => f.borrow_mut().emulate_ioctl(t, result),
            None => false,
        }
    }

    /// DIFF NOTE: Changed this from u64 to usize
    pub fn emulate_fcntl(&self, fd: i32, t: &mut RecordTask, result: &mut usize) -> bool {
        match self.fds.borrow().get(&fd) {
            Some(f) => f.borrow_mut().emulate_fcntl(t, result),
            None => false,
        }
    }

    /// DIFF NOTE: We don't need to pass in task param because we have that in offset itself
    pub fn emulate_read(
        &self,
        fd: i32,
        ranges: &[Range],
        offset: &mut LazyOffset,
        result: &mut usize,
    ) -> bool {
        match self.fds.borrow().get(&fd) {
            Some(f) => f.borrow().emulate_read(ranges, offset, result),
            None => false,
        }
    }

    pub fn filter_getdents(&self, fd: i32, t: &mut RecordTask) {
        match self.fds.borrow().get(&fd) {
            Some(f) => f.borrow().filter_getdents(t),
            None => (),
        }
    }

    pub fn is_rd_fd(&self, fd: i32) -> bool {
        match self.fds.borrow().get(&fd) {
            Some(f) => f.borrow().is_rd_fd(),
            None => false,
        }
    }

    pub fn will_write(&self, t: &dyn Task, fd: i32) -> Switchable {
        match self.fds.borrow().get(&fd) {
            Some(f) => f.borrow().will_write(t),
            None => Switchable::AllowSwitch,
        }
    }

    /// @TODO Do we want offset to be a move?
    pub fn did_write(&self, fd: i32, ranges: Vec<Range>, offset: &mut LazyOffset) {
        match self.fds.borrow().get(&fd) {
            Some(f) => f.borrow_mut().did_write(&ranges, offset),
            None => (),
        }
    }

    /// DIFF NOTE: Additional param `active_task` to solve borrow issues.
    pub fn did_dup(&self, from: i32, to: i32, active_task: &mut dyn Task) {
        if self.fds.borrow().contains_key(&from) {
            if to >= SYSCALLBUF_FDS_DISABLED_SIZE && !self.fds.borrow().contains_key(&to) {
                self.fd_count_beyond_limit
                    .set(self.fd_count_beyond_limit.get() + 1);
            }
            let val = self.fds.borrow()[&from].clone();
            self.fds.borrow_mut().insert(to, val);
        } else {
            if to >= SYSCALLBUF_FDS_DISABLED_SIZE && self.fds.borrow().contains_key(&to) {
                self.fd_count_beyond_limit
                    .set(self.fd_count_beyond_limit.get() - 1);
            }
            self.fds.borrow_mut().remove(&to);
        }
        self.update_syscallbuf_fds_disabled(to, active_task, None);
    }

    /// DIFF NOTE: Additional param `active_task` to solve borrow possibility
    /// DIFF NOTE: Additional param `maybe_other_task` to solve borrow possibility due to a clone happening.
    pub fn did_close(
        &self,
        fd: i32,
        active_task: &mut dyn Task,
        maybe_other_task: Option<&dyn Task>,
    ) {
        log!(LogDebug, "Close fd {}", fd);
        if fd >= SYSCALLBUF_FDS_DISABLED_SIZE && self.fds.borrow().contains_key(&fd) {
            self.fd_count_beyond_limit
                .set(self.fd_count_beyond_limit.get() - 1);
        }
        self.fds.borrow_mut().remove(&fd);
        self.update_syscallbuf_fds_disabled(fd, active_task, maybe_other_task);
    }

    /// Method is called clone() in rr
    pub fn clone_into_task(&self, t: &mut dyn Task) -> FdTableSharedPtr {
        let file_mon = FdTable {
            tasks: Default::default(),
            fds: RefCell::new(self.fds.borrow().clone()),
            fd_count_beyond_limit: Cell::new(self.fd_count_beyond_limit.get()),
        };

        file_mon.tasks.borrow_mut().insert(t.weak_self_ptr());
        Rc::new(file_mon)
    }

    pub fn create(wt: TaskSharedWeakPtr) -> FdTableSharedPtr {
        let file_mon = FdTable {
            tasks: RefCell::new(WeakPtrSet::new()),
            fds: Default::default(),
            fd_count_beyond_limit: Cell::new(0),
        };

        file_mon.tasks.borrow_mut().insert(wt);
        Rc::new(file_mon)
    }

    pub fn is_monitoring(&self, fd: i32) -> bool {
        self.fds.borrow().contains_key(&fd)
    }

    pub fn count_beyond_limit(&self) -> u32 {
        self.fd_count_beyond_limit.get()
    }

    pub fn get_monitor(&self, fd: i32) -> Option<FileMonitorSharedPtr> {
        self.fds.borrow().get(&fd).map(|f| f.clone())
    }

    /// Regenerate syscallbuf_fds_disabled in task `t`.
    /// Called during initialization of the preload library.
    pub fn init_syscallbuf_fds_disabled(&self, t: &mut dyn Task) {
        if !t.session().is_recording() {
            return;
        }

        let rt = t.as_record_task_mut().unwrap();

        ed_assert!(&rt, self.task_set().has(rt.weak_self_ptr()));

        let preload_globals = match rt.preload_globals {
            None => return,
            Some(pr) => pr,
        };

        let mut disabled: [u8; SYSCALLBUF_FDS_DISABLED_SIZE as usize] =
            [0u8; SYSCALLBUF_FDS_DISABLED_SIZE as usize];

        // It's possible that some tasks in this address space have a different
        // FdTable. We need to disable syscallbuf for an fd if any tasks for this
        // address space are monitoring the fd.
        for &fd in rt.fd_table().fds.borrow().keys() {
            debug_assert!(fd >= 0);
            let mut adjusted_fd = fd;
            if fd >= SYSCALLBUF_FDS_DISABLED_SIZE {
                adjusted_fd = SYSCALLBUF_FDS_DISABLED_SIZE - 1;
            }
            disabled[adjusted_fd as usize] = 1;
        }

        for vm_t in rt.vm().task_set().iter_except(rt.weak_self_ptr()) {
            for &fd in vm_t.borrow().fd_table().fds.borrow().keys() {
                debug_assert!(fd >= 0);
                let mut adjusted_fd = fd;
                if fd >= SYSCALLBUF_FDS_DISABLED_SIZE {
                    adjusted_fd = SYSCALLBUF_FDS_DISABLED_SIZE - 1;
                }
                disabled[adjusted_fd as usize] = 1;
            }
        }

        let addr: RemotePtr<u8> =
            RemotePtr::cast(preload_globals) + offset_of!(preload_globals, syscallbuf_fds_disabled);
        rt.write_bytes(addr, &disabled);
        rt.record_local(addr, &disabled);
    }

    /// Get list of fds that have been closed after `t` has done an execve.
    /// Rather than tracking CLOEXEC flags (which would be complicated), we just
    /// scan /proc/<pid>/fd during recording and note any monitored fds that have
    /// been closed.
    /// This also updates our table to match reality.
    pub fn fds_to_close_after_exec(&self, t: &mut RecordTask) -> Vec<i32> {
        ed_assert!(t, self.task_set().has(t.weak_self_ptr()));

        let mut fds_to_close: Vec<i32> = Vec::new();
        for &fd in self.fds.borrow().keys() {
            if !is_fd_open(t, fd) {
                fds_to_close.push(fd);
            }
        }
        for &fd in &fds_to_close {
            self.did_close(fd, t, None);
        }

        fds_to_close
    }

    /// Close fds in list after an exec.
    pub fn close_after_exec(&self, t: &mut ReplayTask, fds_to_close: &[i32]) {
        ed_assert!(t, self.task_set().has(t.weak_self_ptr()));

        for &fd in fds_to_close {
            self.did_close(fd, t, None)
        }
    }

    fn new() -> FdTable {
        FdTable {
            tasks: Default::default(),
            fds: Default::default(),
            fd_count_beyond_limit: Cell::new(0),
        }
    }

    /// DIFF NOTE: Additional param `active_task` to solve borrow issues.
    /// DIFF NOTE: Additional param `maybe_other_task` to solve borrow issues arising out of a clone happening
    fn update_syscallbuf_fds_disabled(
        &self,
        mut fd: i32,
        active_task: &mut dyn Task,
        maybe_other_task: Option<&dyn Task>,
    ) {
        debug_assert!(fd >= 0);
        debug_assert!(!self.task_set().is_empty());

        let mut vms_updated: HashSet<AddressSpaceUid> = HashSet::new();

        let mut process = |rt: &mut RecordTask, maybe_other_task: Option<&dyn Task>| -> () {
            let vm_uid = rt.vm().uid();
            if vms_updated.contains(&vm_uid) {
                return;
            }
            vms_updated.insert(vm_uid);

            match rt.preload_globals {
                Some(pg) => {
                    if fd >= SYSCALLBUF_FDS_DISABLED_SIZE {
                        fd = SYSCALLBUF_FDS_DISABLED_SIZE - 1;
                    }
                    let disable: u8 =
                        if is_fd_monitored_in_any_task(&rt.vm(), fd, rt, maybe_other_task) {
                            1
                        } else {
                            0
                        };

                    let addr: RemotePtr<u8> =
                        remote_ptr_field!(pg, preload_globals, syscallbuf_fds_disabled)
                            + fd as usize;
                    rt.write_bytes(addr, &disable.to_le_bytes());
                    rt.record_local(addr, &disable.to_le_bytes());
                }
                None => (),
            }
        };

        // It's possible for tasks with different VMs to share this fd table.
        // But tasks with the same VM might have different fd tables...
        if active_task.session().is_recording() {
            process(active_task.as_record_task_mut().unwrap(), maybe_other_task);
        } else {
            return;
        }
        for t in self.task_set().iter_except(active_task.weak_self_ptr()) {
            ed_assert!(active_task, t.borrow().session().is_recording());

            let mut t_ref_task = t.borrow_mut();
            let rt: &mut RecordTask = t_ref_task.as_record_task_mut().unwrap();
            process(rt, maybe_other_task);
        }
    }
}

fn is_fd_open(t: &dyn Task, fd: i32) -> bool {
    let path = format!("/proc/{}/fd/{}", t.tid, fd);
    lstat(path.as_str()).is_ok()
}

/// DIFF NOTE: Extra param `vm_task` to solve already borrowed possibility
/// DIFF NOTE: Extra param `maybe_other_task` to solve already borrowed possibility arising from a clone happening
fn is_fd_monitored_in_any_task(
    vm: &AddressSpace,
    fd: i32,
    vm_task: &dyn Task,
    maybe_other_task: Option<&dyn Task>,
) -> bool {
    if vm_task.fd_table().is_monitoring(fd)
        || (fd >= SYSCALLBUF_FDS_DISABLED_SIZE - 1 && vm_task.fd_table().count_beyond_limit() > 0)
    {
        return true;
    }
    let maybe_rc_other = match maybe_other_task {
        Some(other) => Some(other.weak_self_ptr().upgrade().unwrap()),
        None => None,
    };
    for rc in vm.task_set().iter_except(vm_task.weak_self_ptr()) {
        let rc_b;
        let t = match maybe_rc_other.as_ref() {
            Some(rc_other) if Rc::ptr_eq(rc_other, &rc) => maybe_other_task.unwrap(),
            _ => {
                rc_b = rc.borrow();
                rc_b.as_ref()
            }
        };
        if t.fd_table().is_monitoring(fd)
            || (fd >= SYSCALLBUF_FDS_DISABLED_SIZE - 1 && t.fd_table().count_beyond_limit() > 0)
        {
            return true;
        }
    }

    false
}
