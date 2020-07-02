use crate::{
    auto_remote_syscalls::AutoRemoteSyscalls,
    emu_fs::EmuFs,
    kernel_abi::SupportedArch,
    remote_ptr::{RemotePtr, Void},
    session::{
        address_space::{address_space::AddressSpaceSharedPtr, MappingFlags},
        diversion_session::DiversionSession,
        record_session::RecordSession,
        replay_session::ReplaySession,
        session_inner::session_inner::{AddressSpaceMap, SessionInner, TaskMap, ThreadGroupMap},
        task::{
            common,
            task_inner::{task_inner::WriteFlags, CloneFlags},
            Task,
            TaskSharedPtr,
        },
    },
    taskish_uid::{AddressSpaceUid, TaskUid, ThreadGroupUid},
    thread_group::ThreadGroupSharedPtr,
    trace::trace_stream::TraceStream,
};
use libc::pid_t;
use std::{
    cell::{Ref, RefMut},
    ops::DerefMut,
    rc::{Rc, Weak},
};

pub mod address_space;
pub mod diversion_session;
pub mod record_session;
pub mod replay_session;
pub mod session_inner;
pub mod task;

/// Note that this is NOT Rc<RefCell<Box<dyn Session>>>
/// Session will be shared.
/// Individual parts of the session can be wrapped in RefCell<> as required
pub type SessionSharedPtr = Rc<Box<dyn Session>>;
pub type SessionSharedWeakPtr = Weak<Box<dyn Session>>;

pub trait Session: DerefMut<Target = SessionInner> {
    fn as_session_inner(&self) -> &SessionInner;
    fn as_session_inner_mut(&mut self) -> &mut SessionInner;

    fn on_destroy(&self, _t: &dyn Task) {
        unimplemented!()
    }

    fn as_record(&self) -> Option<&RecordSession> {
        None
    }
    fn as_record_mut(&self) -> Option<&mut RecordSession> {
        None
    }

    fn as_replay(&self) -> Option<&ReplaySession> {
        None
    }

    fn as_diversion(&self) -> Option<&DiversionSession> {
        None
    }
    fn as_diversion_mut(&mut self) -> Option<&DiversionSession> {
        None
    }

    /// Avoid using this boolean methods. Use the `as_*` methods that return Option<> instead.
    fn is_recording(&self) -> bool {
        self.as_record().is_some()
    }
    fn is_replaying(&self) -> bool {
        self.as_replay().is_some()
    }
    fn is_diversion(&self) -> bool {
        self.as_diversion().is_some()
    }

    fn new_task(
        &self,
        _tid: pid_t,
        _rec_tid: pid_t,
        _serial: u32,
        _a: SupportedArch,
    ) -> Box<dyn Task> {
        unimplemented!()
    }

    fn trace_stream(&self) -> Option<Ref<'_, TraceStream>> {
        None
    }
    fn trace_stream_mut(&self) -> Option<RefMut<'_, TraceStream>> {
        None
    }
    fn cpu_binding(&self, trace: &TraceStream) -> Option<u32> {
        trace.bound_to_cpu()
    }

    fn on_create(&self, t: TaskSharedPtr) {
        let rec_tid = t.borrow().rec_tid;
        self.task_map.borrow_mut().insert(rec_tid, t);
    }

    /// NOTE: called Session::copy_state_to() in rr.
    fn copy_state_to_session(&self, _dest: &SessionInner, _emu_fs: &EmuFs, _dest_emu_fs: EmuFs) {
        unimplemented!()
    }

    /// Call this before doing anything that requires access to the full set
    /// of tasks (i.e., almost anything!).
    fn finish_initializing(&self) {
        if self.clone_completion.borrow().is_none() {
            return;
        }

        // DIFF NOTE: We're setting clone completion to None here instead of at the end of the
        // method.
        let cc = self.clone_completion.replace(None).unwrap();
        for tgleader in &cc.address_spaces {
            let rc = tgleader.clone_leader.upgrade().unwrap();
            let mut leader = rc.borrow_mut();
            {
                let mut found_syscall_buf = None;
                let mut remote = AutoRemoteSyscalls::new(leader.as_mut());
                for (&mk, m) in remote.vm().maps() {
                    if m.flags.contains(MappingFlags::IS_SYSCALLBUF) {
                        // DIFF NOTE: The whole reason why this approach is a bit different from rr because its
                        // its tougher to iterate and modify a map at the same time in rust vs c++.
                        found_syscall_buf = Some(mk);
                        // DIFF NOTE: We are assuming only a single syscall buffer in the memory maps.
                        break;
                    }
                }

                match found_syscall_buf {
                    Some(k) => {
                        // Creating this mapping was delayed in capture_state for performance
                        remote.recreate_shared_mmap(k, None, None);
                    }
                    None => (),
                }
            }

            for (rptr, captured_mem) in &tgleader.captured_memory {
                leader.write_bytes_helper(*rptr, captured_mem, None, WriteFlags::empty());
            }

            {
                let mut remote2 = AutoRemoteSyscalls::new(leader.as_mut());
                for tgmember in &tgleader.member_states {
                    let t_clone = common::os_clone_into(tgmember, &mut remote2);
                    self.on_create(t_clone);
                }
            }

            tgleader
                .clone_leader
                .upgrade()
                .unwrap()
                .borrow_mut()
                .copy_state(&tgleader.clone_leader_state);
        }
        // Don't need to set clone completion to `None`. Its already been done!
    }

    /// See Task::clone().
    /// This method is simply called Session::clone in rr.
    fn clone_task(
        &self,
        _p: &dyn Task,
        _flags: CloneFlags,
        _stack: Option<RemotePtr<Void>>,
        _tls: Option<RemotePtr<Void>>,
        _cleartid_addr: Option<RemotePtr<i32>>,
        _new_tid: pid_t,
        _new_rec_tid: Option<pid_t>,
    ) -> &mut dyn Task {
        unimplemented!()
    }

    /// Return the task created with `rec_tid`, or None if no such
    /// task exists.
    /// NOTE: Method is simply called Session::find task() in rr
    fn find_task_from_rec_tid(&self, rec_tid: pid_t) -> Option<TaskSharedPtr> {
        self.finish_initializing();
        self.tasks()
            .get(&rec_tid)
            .map_or(None, |shr_ptr| Some(shr_ptr.clone()))
    }

    /// NOTE: Method is simply called Session::find task() in rr
    fn find_task_from_task_uid(&self, tuid: TaskUid) -> Option<TaskSharedPtr> {
        self.find_task_from_rec_tid(tuid.tid())
    }

    /// Return the thread group whose unique ID is `tguid`, or None if no such
    /// thread group exists.
    /// NOTE: Method is simply called Session::find thread_group() in rr
    fn find_thread_group_from_tguid(
        &mut self,
        tguid: ThreadGroupUid,
    ) -> Option<ThreadGroupSharedPtr> {
        self.finish_initializing();
        self.thread_group_map()
            .get(&tguid)
            .map(|t| t.upgrade().unwrap())
    }

    /// Find the thread group for a specific pid
    /// NOTE: Method is simply called Session::find thread_group() in rr
    fn find_thread_group_from_pid(&mut self, pid: pid_t) -> Option<ThreadGroupSharedPtr> {
        self.finish_initializing();
        for (tguid, tg) in self.thread_group_map().iter() {
            if tguid.tid() == pid {
                return Some(tg.upgrade().unwrap());
            }
        }
        None
    }

    /// Return the AddressSpace whose unique ID is `vmuid`, or None if no such
    /// address space exists.
    fn find_address_space(&mut self, vmuid: AddressSpaceUid) -> Option<AddressSpaceSharedPtr> {
        self.finish_initializing();
        // If the weak ptr was found, we _must_ be able to upgrade it!;
        self.vm_map().get(&vmuid).map(|a| a.upgrade().unwrap())
    }

    /// Return a copy of `tg` with the same mappings.
    /// NOTE: Called simply Session::clone() in rr
    fn clone_tg(&mut self, _t: &dyn Task, _tg: ThreadGroupSharedPtr) -> ThreadGroupSharedPtr {
        unimplemented!()
    }

    /// Return the set of Tasks being traced in this session.
    fn tasks(&self) -> Ref<'_, TaskMap> {
        self.finish_initializing();
        self.as_session_inner().task_map.borrow()
    }

    fn tasks_mut(&self) -> RefMut<'_, TaskMap> {
        self.finish_initializing();
        self.as_session_inner().task_map.borrow_mut()
    }

    fn thread_group_map(&self) -> Ref<'_, ThreadGroupMap> {
        self.as_session_inner().thread_group_map.borrow()
    }

    fn thread_group_map_mut(&self) -> RefMut<'_, ThreadGroupMap> {
        self.as_session_inner().thread_group_map.borrow_mut()
    }

    fn vm_map(&self) -> Ref<'_, AddressSpaceMap> {
        self.as_session_inner().vm_map.borrow()
    }

    fn vm_map_mut(&self) -> RefMut<'_, AddressSpaceMap> {
        self.as_session_inner().vm_map.borrow_mut()
    }

    /// Call `post_exec()` immediately after a tracee has successfully
    /// `execve()`'d.  After that, `done_initial_exec()` returns true.
    /// This is called while we're still in the execve syscall so it's not safe
    /// to perform remote syscalls in this method.
    ///
    /// Tracee state can't be validated before the first exec,
    /// because the address space inside the rr process for |rr
    /// replay| will be different than it was for `rr record`.
    /// After the first exec, we're running tracee code, and
    /// everything must be the same.
    ///
    /// DIFF NOTE: Unlike rr this takes in param `t`. Makes things simpler.
    fn post_exec(&self, t: &mut dyn Task) {
        // We just saw a successful exec(), so from now on we know
        // that the address space layout for the replay tasks will
        // (should!) be the same as for the recorded tasks.  So we can
        // start validating registers at events. */
        self.assert_fully_initialized();
        if self.done_initial_exec() {
            return;
        }
        self.done_initial_exec_.set(true);
        debug_assert!(self.tasks().len() == 1);
        t.flush_inconsistent_state();
        self.spawned_task_error_fd_.borrow_mut().close();
    }
}
