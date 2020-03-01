use crate::address_space::address_space::AddressSpace;
use crate::diversion_session::DiversionSession;
use crate::emu_fs::EmuFs;
use crate::kernel_abi::SupportedArch;
use crate::record_session::RecordSession;
use crate::remote_ptr::{RemotePtr, Void};
use crate::replay_session::ReplaySession;
use crate::session_interface::session::session::{Session, TaskMap};
use crate::task_interface::TaskInterface;
use crate::taskish_uid::{AddressSpaceUid, TaskUid, ThreadGroupUid};
use crate::thread_group::{ThreadGroup, ThreadGroupSharedPtr};
use crate::trace_stream::TraceStream;
use libc::pid_t;
use std::ops::{Deref, DerefMut};

pub mod session;

pub trait SessionInterface {
    fn as_session(&self) -> &Session;
    fn as_session_mut(&self) -> &mut Session;

    fn on_destroy(&self, t: &dyn TaskInterface);
    fn as_record(&self) -> Option<&RecordSession> {
        None
    }
    fn as_replay(&self) -> Option<&ReplaySession> {
        None
    }
    fn as_diversion(&self) -> Option<&DiversionSession> {
        None
    }
    fn is_recording(&self) -> bool {
        self.as_record().is_some()
    }
    fn is_replaying(&self) -> bool {
        self.as_replay().is_some()
    }
    fn is_diversion(&self) -> bool {
        self.as_diversion().is_some()
    }
    fn new_task(&self, tid: pid_t, rec_tid: pid_t, serial: u32, a: SupportedArch);
    fn trace_stream(&self) -> Option<&TraceStream> {
        None
    }
    fn cpu_binding(&self, trace: &TraceStream) -> Option<u32>;
    fn on_create(&self, t: &dyn TaskInterface);

    /// NOTE: called Session::copy_state_to() in rr.
    fn copy_state_to_session(&self, dest: &Session, emu_fs: &EmuFs, dest_emu_fs: EmuFs) {
        unimplemented!()
    }

    /// Call this before doing anything that requires access to the full set
    /// of tasks (i.e., almost anything!).
    fn finish_initializing(&mut self) {
        unimplemented!()
    }

    /// See Task::clone().
    /// This method is simply called Session::clone in rr.
    fn clone_task(
        &mut self,
        p: &dyn TaskInterface,
        flags: i32,
        stack: RemotePtr<Void>,
        tls: RemotePtr<Void>,
        cleartid_addr: RemotePtr<i32>,
        new_tid: pid_t,
        new_rec_tid: Option<pid_t>,
    ) -> &dyn TaskInterface {
        unimplemented!()
    }

    /// Return the task created with |rec_tid|, or None if no such
    /// task exists.
    /// NOTE: Method is simply called Session::find task() in rr
    fn find_task_from_rec_tid(&self, rec_tid: pid_t) -> Option<&dyn TaskInterface> {
        unimplemented!()
    }

    /// NOTE: Method is simply called Session::find task() in rr
    fn find_task_from_task_uid(&self, tuid: &TaskUid) -> Option<&dyn TaskInterface> {
        unimplemented!()
    }

    /// Return the thread group whose unique ID is |tguid|, or None if no such
    /// thread group exists.
    /// NOTE: Method is simply called Session::find thread_group() in rr
    fn find_thread_group_from_tguid(&self, tguid: &ThreadGroupUid) -> Option<&ThreadGroup> {
        unimplemented!()
    }

    /// Find the thread group for a specific pid
    /// NOTE: Method is simply called Session::find thread_group() in rr
    fn find_thread_group_from_pid(&self, pid: pid_t) -> Option<&ThreadGroup> {
        unimplemented!()
    }

    /// Return the AddressSpace whose unique ID is |vmuid|, or None if no such
    /// address space exists.
    fn find_address_space(&self, vmuid: &AddressSpaceUid) -> Option<&AddressSpace> {
        unimplemented!()
    }

    /// Return a copy of |tg| with the same mappings.
    /// NOTE: Called simply Session::clone() in rr
    fn clone_tg(
        &mut self,
        t: &dyn TaskInterface,
        tg: ThreadGroupSharedPtr,
    ) -> ThreadGroupSharedPtr {
        unimplemented!()
    }

    /// Return the set of Tasks being traced in this session.
    /// @TODO shouldn't need for this to be mutable but it is due to finish_initializing()
    fn tasks(&mut self) -> &TaskMap {
        self.finish_initializing();
        &self.as_session().task_map
    }

    /// Call |post_exec()| immediately after a tracee has successfully
    /// |execve()|'d.  After that, |done_initial_exec()| returns true.
    /// This is called while we're still in the execve syscall so it's not safe
    /// to perform remote syscalls in this method.
    ///
    /// Tracee state can't be validated before the first exec,
    /// because the address space inside the rr process for |rr
    /// replay| will be different than it was for |rr record|.
    /// After the first exec, we're running tracee code, and
    /// everything must be the same.
    fn post_exec(&mut self) {
        unimplemented!()
    }
}

impl<'a> Deref for dyn SessionInterface + 'a {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        self.as_session()
    }
}

impl<'a> DerefMut for dyn SessionInterface + 'a {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_session_mut()
    }
}
