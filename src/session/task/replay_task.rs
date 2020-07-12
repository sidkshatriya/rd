use super::{
    task_common::{compute_trap_reasons, on_syscall_exit, post_exec_for_exe, post_exec_syscall},
    task_inner::TrapReasons,
};
use crate::{
    arch::Architecture,
    kernel_abi::{common::preload_interface::syscallbuf_record, SupportedArch},
    log::LogLevel::LogWarn,
    registers::{MismatchBehavior, Registers},
    remote_ptr::{RemotePtr, Void},
    session::{
        task::{
            task_common::{
                did_waitpid,
                next_syscallbuf_record,
                open_mem_fd,
                read_bytes_fallible,
                read_bytes_helper,
                read_c_str,
                resume_execution,
                stored_record_size,
                syscallbuf_data_size,
                write_bytes,
                write_bytes_helper,
            },
            task_inner::{
                task_inner::{CloneReason, TaskInner, WriteFlags},
                CloneFlags,
                ResumeRequest,
                TicksRequest,
                WaitRequest,
            },
            Task,
        },
        Session,
        SessionSharedPtr,
    },
    trace::{
        trace_frame::{FrameTime, TraceFrame},
        trace_reader::TraceReader,
    },
    wait_status::WaitStatus,
};
use libc::pid_t;
use owning_ref::OwningHandle;
use std::{
    cell::{Ref, RefMut},
    ffi::{CString, OsStr},
    ops::{Deref, DerefMut},
};

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

impl Default for ReplayTaskIgnore {
    fn default() -> Self {
        Self::IgnoreNone
    }
}

impl ReplayTask {
    pub fn new(
        session: &dyn Session,
        tid: pid_t,
        rec_tid: pid_t,
        serial: u32,
        arch: SupportedArch,
    ) -> ReplayTask {
        ReplayTask {
            task_inner: TaskInner::new(session, tid, rec_tid, serial, arch),
        }
    }

    /// Initialize tracee buffers in this, i.e., implement
    /// RRCALL_init_syscall_buffer.  This task must be at the point
    /// of *exit from* the rrcall.  Registers will be updated with
    /// the return value from the rrcall, which is also returned
    /// from this call.  |map_hint| suggests where to map the
    /// region; see |init_syscallbuf_buffer()|.
    pub fn init_buffers(_map_hint: RemotePtr<Void>) {
        unimplemented!()
    }

    /// DIFF NOTE: Simply called ReplayTask::post_exec_syscall(...) in rr
    /// Not to be confused with post_exec_syscall() in rr which does not take any arguments
    /// Call this method when the exec has completed.
    pub fn post_exec_syscall_for_replay_exe(&mut self, replay_exe: &OsStr) {
        self.post_exec_for_exe(replay_exe);

        // Perform post-exec-syscall tasks now (e.g. opening mem_fd) before we
        // switch registers. This lets us perform AutoRemoteSyscalls using the
        // regular stack instead of having to search the address space for usable
        // pages (which is error prone, e.g. if we happen to find the scratch space
        // allocated by an rr recorder under which we're running).
        post_exec_syscall(self);

        // Delay setting the replay_regs until here so the original registers
        // are set while we populate AddressSpace. We need that for the kernel
        // to identify the original stack region correctly.
        let r = self.current_trace_frame().regs_ref().clone();
        self.set_regs(&r);
        let extra_registers = self.current_trace_frame().extra_regs_ref().clone();
        ed_assert!(self, !extra_registers.is_empty());
        self.set_extra_regs(&extra_registers);
    }

    /// Assert that the current register values match the values in the
    ///  current trace record.
    pub fn validate_regs(&self, flags: ReplayTaskIgnore) {
        // don't validate anything before execve is done as the actual
        // *process did not start prior to this point
        if !self.session().done_initial_exec() {
            return;
        }

        // @TODO When this `if` triggers trace frame may already be borrowed.
        // This could run into a borrow mut error.
        if flags == ReplayTaskIgnore::IgnoreEsi {
            let mut trace_frame = self.current_trace_frame_mut();
            let rec_regs = trace_frame.regs_mut();
            if self.regs_ref().arg4() != rec_regs.arg4() {
                log!(
                    LogWarn,
                    "Probably saw kernel bug mutating $esi across pread/write64\n\
                call: recorded:{:#x}; replaying:{:#x}.  Fudging registers.",
                    rec_regs.arg4(),
                    self.regs_ref().arg4()
                );
                rec_regs.set_arg4(self.regs_ref().arg4());
            }
        }

        // TODO: add perf counter validations (hw int, page faults, insts)
        let trace_frame = self.current_trace_frame();
        let rec_regs = trace_frame.regs_ref();
        Registers::compare_register_files(
            Some(self),
            "replaying",
            self.regs_ref(),
            "recorded",
            rec_regs,
            MismatchBehavior::BailOnMismatch,
        );
    }

    pub fn current_trace_frame(&self) -> OwningHandle<SessionSharedPtr, Ref<'_, TraceFrame>> {
        let sess = self.session();
        // @TODO remove this unsafety by implementing ToHandle??
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_replay() }.unwrap().current_trace_frame()
        });
        owning_handle
    }

    pub fn current_trace_frame_mut(
        &self,
    ) -> OwningHandle<SessionSharedPtr, RefMut<'_, TraceFrame>> {
        let sess = self.session();
        // @TODO remove this unsafety by implementing ToHandle??
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_replay() }
                .unwrap()
                .current_trace_frame_mut()
        });
        owning_handle
    }

    pub fn current_frame_time(&self) -> FrameTime {
        self.current_trace_frame().time()
    }

    /// Restore the next chunk of saved data from the trace to this.
    pub fn set_data_from_trace(&mut self) -> usize {
        unimplemented!()
    }

    pub fn trace_reader(&self) -> OwningHandle<SessionSharedPtr, Ref<'_, TraceReader>> {
        let sess = self.session();
        // @TODO remove this unsafety by implementing ToHandle??
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_replay() }.unwrap().trace_reader()
        });
        owning_handle
    }

    pub fn trace_reader_mut(&self) -> OwningHandle<SessionSharedPtr, RefMut<'_, TraceReader>> {
        let sess = self.session();
        // @TODO remove this unsafety by implementing ToHandle??
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_replay() }.unwrap().trace_reader_mut()
        });
        owning_handle
    }

    /// Restore all remaining chunks of saved data for the current trace frame.
    pub fn apply_all_data_records_from_trace(&mut self) {
        loop {
            let maybe_buf = self.trace_reader_mut().read_raw_data_for_frame().clone();
            match maybe_buf {
                Some(buf) => {
                    if !buf.addr.is_null() && buf.data.len() > 0 {
                        if buf.rec_tid == self.rec_tid {
                            self.write_bytes_helper(buf.addr, &buf.data, None, WriteFlags::empty());
                            self.vm_shr_ptr().maybe_update_breakpoints(
                                self,
                                buf.addr,
                                buf.data.len(),
                            );
                        } else {
                            let t = self.session().find_task_from_rec_tid(buf.rec_tid).unwrap();
                            t.borrow_mut().write_bytes_helper(
                                buf.addr,
                                &buf.data,
                                None,
                                WriteFlags::empty(),
                            );
                            let vm_shr = t.borrow().vm_shr_ptr();
                            vm_shr.maybe_update_breakpoints(
                                t.borrow_mut().as_mut(),
                                buf.addr,
                                buf.data.len(),
                            );
                        };
                    }
                }
                None => break,
            }
        }
    }

    /// Set the syscall-return-value register of this to what was
    /// saved in the current trace frame.
    pub fn set_return_value_from_trace(&mut self) {
        let mut r = self.regs_ref().clone();
        r.set_syscall_result(self.current_trace_frame().regs_ref().syscall_result());
        // In some cases (e.g. syscalls forced to return an error by tracee
        // seccomp filters) we need to emulate a change to the original_syscallno
        // (to -1 in that case).
        r.set_original_syscallno(self.current_trace_frame().regs_ref().original_syscallno());
        self.set_regs(&r);
    }

    /// Used when an execve changes the tid of a non-main-thread to the
    /// thread-group leader.
    pub fn set_real_tid_and_update_serial(&mut self, _tid: pid_t) {
        unimplemented!()
    }

    /// Note: This method is private
    fn init_buffers_arch<Arch: Architecture>(_map_hint: RemotePtr<Void>) {
        unimplemented!()
    }
}

impl DerefMut for ReplayTask {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.task_inner
    }
}

impl Task for ReplayTask {
    /// Forwarded method
    fn post_exec_for_exe(&mut self, exe_file: &OsStr) {
        post_exec_for_exe(self, exe_file)
    }

    /// Forwarded method
    fn resume_execution(
        &mut self,
        how: ResumeRequest,
        wait_how: WaitRequest,
        tick_period: TicksRequest,
        maybe_sig: Option<i32>,
    ) {
        resume_execution(self, how, wait_how, tick_period, maybe_sig)
    }

    /// Forwarded method
    fn stored_record_size(&mut self, record: RemotePtr<syscallbuf_record>) -> u32 {
        stored_record_size(self, record)
    }

    /// Forwarded method
    fn did_waitpid(&mut self, status: WaitStatus) {
        did_waitpid(self, status)
    }

    /// Forwarded method
    fn next_syscallbuf_record(&mut self) -> RemotePtr<syscallbuf_record> {
        next_syscallbuf_record(self)
    }

    fn as_task_inner(&self) -> &TaskInner {
        unimplemented!()
    }

    fn as_task_inner_mut(&mut self) -> &mut TaskInner {
        unimplemented!()
    }

    fn as_replay_task(&self) -> Option<&ReplayTask> {
        Some(self)
    }

    fn as_replay_task_mut(&mut self) -> Option<&mut ReplayTask> {
        Some(self)
    }

    fn on_syscall_exit(&mut self, syscallno: i32, arch: SupportedArch, regs: &Registers) {
        on_syscall_exit(self, syscallno, arch, regs)
    }

    fn at_preload_init(&self) {
        unimplemented!()
    }

    /// Forwarded method
    /// @TODO Forwarded method as this would be a non-overridden implementation
    fn clone_task(
        &self,
        _reason: CloneReason,
        _flags: CloneFlags,
        _stack: Option<RemotePtr<Void>>,
        _tls: Option<RemotePtr<Void>>,
        _cleartid_addr: Option<RemotePtr<i32>>,
        _new_tid: i32,
        _new_rec_tid: i32,
        _new_serial: u32,
        _other_session: Option<&dyn Session>,
    ) -> &TaskInner {
        unimplemented!()
    }

    /// Forwarded method
    fn open_mem_fd(&mut self) -> bool {
        open_mem_fd(self)
    }

    /// Forwarded method
    fn read_bytes_fallible(&mut self, addr: RemotePtr<u8>, buf: &mut [u8]) -> Result<usize, ()> {
        read_bytes_fallible(self, addr, buf)
    }

    /// Forwarded method
    fn read_bytes_helper(&mut self, addr: RemotePtr<Void>, buf: &mut [u8], ok: Option<&mut bool>) {
        read_bytes_helper(self, addr, buf, ok)
    }

    /// Forwarded method
    fn read_c_str(&mut self, child_addr: RemotePtr<u8>) -> CString {
        read_c_str(self, child_addr)
    }

    /// Forwarded method
    fn write_bytes_helper(
        &mut self,
        addr: RemotePtr<u8>,
        buf: &[u8],
        ok: Option<&mut bool>,
        flags: WriteFlags,
    ) {
        write_bytes_helper(self, addr, buf, ok, flags)
    }

    /// Forwarded method
    fn syscallbuf_data_size(&mut self) -> usize {
        syscallbuf_data_size(self)
    }

    /// Forwarded method
    fn write_bytes(&mut self, child_addr: RemotePtr<u8>, buf: &[u8]) {
        write_bytes(self, child_addr, buf);
    }
    /// Forwarded method
    fn post_exec_syscall(&mut self) {
        post_exec_syscall(self)
    }

    // Forwarded method
    fn compute_trap_reasons(&mut self) -> TrapReasons {
        compute_trap_reasons(self)
    }
}
