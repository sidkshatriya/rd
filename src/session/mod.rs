use crate::{
    address_space::address_space::AddressSpaceSharedPtr,
    emu_fs::EmuFs,
    kernel_abi::SupportedArch,
    remote_ptr::{RemotePtr, Void},
    session::{
        diversion_session::DiversionSession,
        record_session::RecordSession,
        replay_session::ReplaySession,
        session_inner::session_inner::{AddressSpaceMap, SessionInner, TaskMap, ThreadGroupMap},
    },
    task::{task_inner::CloneFlags, Task},
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

pub mod diversion_session;
pub mod record_session;
pub mod replay_session;
pub mod session_inner;

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

    /// @TODO Is the return type what we want?
    fn new_task(
        &self,
        _tid: pid_t,
        _rec_tid: pid_t,
        _serial: u32,
        _a: SupportedArch,
    ) -> &mut dyn Task {
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

    fn on_create(&mut self, _t: Box<dyn Task>) {
        unimplemented!()
    }

    /// NOTE: called Session::copy_state_to() in rr.
    fn copy_state_to_session(&self, _dest: &SessionInner, _emu_fs: &EmuFs, _dest_emu_fs: EmuFs) {
        unimplemented!()
    }

    /// Call this before doing anything that requires access to the full set
    /// of tasks (i.e., almost anything!).
    fn finish_initializing(&self) {
        unimplemented!()
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
    fn find_task_from_rec_tid(&self, rec_tid: pid_t) -> Option<Ref<'_, Box<dyn Task>>> {
        self.finish_initializing();
        self.tasks().get(&rec_tid).map(|t| t.borrow())
    }
    fn find_task_from_rec_tid_mut(&self, rec_tid: pid_t) -> Option<RefMut<'_, Box<dyn Task>>> {
        self.finish_initializing();
        self.tasks().get(&rec_tid).map(|t| t.borrow_mut())
    }

    /// NOTE: Method is simply called Session::find task() in rr
    fn find_task_from_task_uid(&self, tuid: TaskUid) -> Option<Ref<'_, Box<dyn Task>>> {
        self.find_task_from_rec_tid(tuid.tid())
    }
    fn find_task_from_task_uid_mut(&self, tuid: TaskUid) -> Option<RefMut<'_, Box<dyn Task>>> {
        self.find_task_from_rec_tid_mut(tuid.tid())
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
        for (tguid, tg) in self.thread_group_map() {
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
        self.vm_map().get(&vmuid).map(|a| a.upgrade().unwrap())
    }

    /// Return a copy of `tg` with the same mappings.
    /// NOTE: Called simply Session::clone() in rr
    fn clone_tg(&mut self, _t: &dyn Task, _tg: ThreadGroupSharedPtr) -> ThreadGroupSharedPtr {
        unimplemented!()
    }

    /// Return the set of Tasks being traced in this session.
    /// Shouldn't need for this to be mutable but it is due to finish_initializing()
    fn tasks(&self) -> &TaskMap {
        self.finish_initializing();
        &self.as_session_inner().task_map
    }

    fn thread_group_map(&self) -> &ThreadGroupMap {
        &self.as_session_inner().thread_group_map
    }

    fn vm_map(&self) -> &AddressSpaceMap {
        &self.as_session_inner().vm_map
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
    fn post_exec(&mut self) {
        unimplemented!()
    }
}
