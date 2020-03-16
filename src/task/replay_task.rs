use crate::arch::Architecture;
use crate::kernel_abi::SupportedArch;
use crate::registers::Registers;
use crate::remote_ptr::{RemotePtr, Void};
use crate::session::{Session, SessionSharedWeakPtr};
use crate::task::record_task::record_task::RecordTask;
use crate::task::task_inner::task_inner::WriteFlags;
use crate::task::task_inner::task_inner::{CloneReason, TaskInner};
use crate::task::Task;
use crate::trace_frame::{FrameTime, TraceFrame};
use crate::trace_stream::trace_reader::TraceReader;
use libc::pid_t;
use std::ffi::CString;
use std::ops::{Deref, DerefMut};

pub struct ReplayTask {
    pub task_inner: TaskInner,
}

impl Deref for ReplayTask {
    type Target = TaskInner;

    fn deref(&self) -> &Self::Target {
        &self.task_inner
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ReplayTaskIgnore {
    IgnoreNone = 0,
    /// The x86 linux 3.5.0-36 kernel packaged with Ubuntu
    /// 12.04 has been observed to mutate $esi across
    /// syscall entry/exit.  (This has been verified
    /// outside of rr as well; not an rr bug.)  It's not
    /// clear whether this is a ptrace bug or a kernel bug,
    /// but either way it's not supposed to happen.  So we
    /// allow validate_args to cover up that bug.
    IgnoreEsi = 0x01,
}

impl ReplayTask {
    pub fn new(
        session: SessionSharedWeakPtr,
        tid: pid_t,
        rec_tid: pid_t,
        serial: u32,
        arch: SupportedArch,
    ) -> ReplayTask {
        unimplemented!()
    }

    pub fn trace_reader(&self) -> &TraceReader {
        unimplemented!()
    }

    /// Initialize tracee buffers in this, i.e., implement
    /// RRCALL_init_syscall_buffer.  This task must be at the point
    /// of *exit from* the rrcall.  Registers will be updated with
    /// the return value from the rrcall, which is also returned
    /// from this call.  |map_hint| suggests where to map the
    /// region; see |init_syscallbuf_buffer()|.
    pub fn init_buffers(map_hint: RemotePtr<Void>) {
        unimplemented!()
    }

    /// Call this method when the exec has completed.
    pub fn post_exec_syscall(&self, replay_exe: &str) {
        unimplemented!()
    }

    /// Assert that the current register values match the values in the
    ///  current trace record.
    pub fn validate_regs(&self, flags: ReplayTaskIgnore) {
        unimplemented!()
    }

    pub fn current_trace_frame(&self) -> &TraceFrame {
        unimplemented!()
    }

    pub fn current_frame_time(&self) -> FrameTime {
        unimplemented!()
    }

    /// Restore the next chunk of saved data from the trace to this.
    pub fn set_data_from_trace(&mut self) -> usize {
        unimplemented!()
    }

    /// Restore all remaining chunks of saved data for the current trace frame.
    pub fn apply_all_data_records_from_trace(&mut self) {
        unimplemented!()
    }

    /// Set the syscall-return-value register of this to what was
    /// saved in the current trace frame.
    pub fn set_return_value_from_trace(&mut self) {
        unimplemented!()
    }

    /// Used when an execve changes the tid of a non-main-thread to the
    /// thread-group leader.
    pub fn set_real_tid_and_update_serial(&mut self, tid: pid_t) {
        unimplemented!()
    }

    /// Note: This method is private
    fn init_buffers_arch<Arch: Architecture>(map_hint: RemotePtr<Void>) {
        unimplemented!()
    }
}

impl DerefMut for ReplayTask {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.task_inner
    }
}

impl Task for ReplayTask {
    fn as_task_inner(&self) -> &TaskInner {
        unimplemented!()
    }

    fn as_task_inner_mut(&mut self) -> &mut TaskInner {
        unimplemented!()
    }

    fn as_record_task(&self) -> Option<&RecordTask> {
        unimplemented!()
    }

    fn as_record_task_mut(&mut self) -> Option<&mut RecordTask> {
        unimplemented!()
    }

    fn as_replay_task(&self) -> Option<&ReplayTask> {
        unimplemented!()
    }

    fn as_replay_task_mut(&mut self) -> Option<&mut ReplayTask> {
        unimplemented!()
    }

    fn on_syscall_exit(&self, syscallno: i32, arch: SupportedArch, regs: &Registers) {
        unimplemented!()
    }

    fn at_preload_init(&self) {
        unimplemented!()
    }

    fn clone_task(
        &self,
        reason: CloneReason,
        flags: i32,
        stack: RemotePtr<u8>,
        tls: RemotePtr<u8>,
        cleartid_addr: RemotePtr<i32>,
        new_tid: i32,
        new_rec_tid: i32,
        new_serial: u32,
        other_session: Option<&dyn Session>,
    ) -> &TaskInner {
        unimplemented!()
    }

    fn open_mem_fd(&mut self) -> bool {
        unimplemented!()
    }

    fn read_bytes_fallible(&mut self, addr: RemotePtr<u8>, buf: &mut [u8]) -> Result<usize, ()> {
        unimplemented!()
    }

    fn read_bytes_helper(&mut self, addr: RemotePtr<u8>, buf: &mut [u8], ok: Option<&mut bool>) {
        unimplemented!()
    }

    fn read_c_str(&mut self, child_addr: RemotePtr<u8>) -> CString {
        unimplemented!()
    }

    fn write_bytes_helper(
        &mut self,
        addr: RemotePtr<u8>,
        buf: &[u8],
        ok: Option<&mut bool>,
        flags: WriteFlags,
    ) {
        unimplemented!()
    }

    fn syscallbuf_data_size(&mut self) -> usize {
        unimplemented!()
    }

    fn write_bytes(&mut self, child_addr: RemotePtr<u8>, buf: &[u8]) {
        unimplemented!()
    }
}
