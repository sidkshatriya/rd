use super::{
    task_common::{
        at_preload_init_common, clone_task_common, compute_trap_reasons_common,
        destroy_buffers_common, destroy_common, detect_syscall_arch_common, on_syscall_exit_common,
        post_exec_for_exe_common, post_exec_syscall_common, post_vm_clone_common,
        post_wait_clone_common, read_val_mem, reset_syscallbuf_common,
        set_syscallbuf_locked_common, task_cleanup_common,
    },
    task_inner::{CloneFlags, CloneReason, TrapReasons},
    TaskSharedPtr, TaskSharedWeakPtr,
};
use crate::{
    arch::Architecture,
    auto_remote_syscalls::AutoRemoteSyscalls,
    bindings::kernel::user_desc,
    file_monitor::preserve_file_monitor::PreserveFileMonitor,
    kernel_abi::{syscall_number_for_close, syscall_number_for_dup3, SupportedArch},
    log::LogLevel::LogWarn,
    preload_interface::syscallbuf_record,
    preload_interface_arch::rdcall_init_buffers_params,
    registers::{MismatchBehavior, Registers},
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::AddressSpace,
        task::{
            task_common::{
                did_waitpid_common, next_syscallbuf_record_common, open_mem_fd_common,
                read_bytes_fallible_common, read_bytes_helper_common, read_c_str_common,
                resume_execution_common, set_thread_area_common, stored_record_size_common,
                syscallbuf_data_size_common, write_bytes_common, write_bytes_helper_common,
            },
            task_inner::{ResumeRequest, TaskInner, TicksRequest, WaitRequest, WriteFlags},
            Task,
        },
        Session, SessionSharedPtr,
    },
    sig::Sig,
    trace::{
        trace_frame::{FrameTime, TraceFrame},
        trace_reader::{RawData, TraceReader},
        trace_stream::MappedData,
    },
    util::page_size,
    wait_status::WaitStatus,
};
use libc::{pid_t, O_CLOEXEC};
use nix::fcntl::OFlag;
use owning_ref::OwningHandle;
use std::{
    cell::{Ref, RefMut},
    ffi::{CString, OsStr},
    ops::Deref,
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
    /// outside as well; not bug.)  It's not
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
        rec_tid: Option<pid_t>,
        serial: u32,
        arch: SupportedArch,
        weak_self: TaskSharedWeakPtr,
    ) -> ReplayTask {
        ReplayTask {
            task_inner: TaskInner::new(session, tid, rec_tid, serial, arch, weak_self),
        }
    }

    /// Initialize tracee buffers in this, i.e., implement
    /// RDCALL_init_syscall_buffer.  This task must be at the point
    /// of *exit from* the rrcall.  Registers will be updated with
    /// the return value from the rrcall, which is also returned
    /// from this call.  `map_hint` suggests where to map the
    /// region; see `init_syscallbuf_buffer()`.
    pub fn init_buffers(&self, map_hint: RemotePtr<Void>) {
        rd_arch_function!(self, init_buffers_arch, self.arch(), map_hint)
    }

    /// DIFF NOTE: Simply called ReplayTask::post_exec_syscall(...) in rr
    /// Not to be confused with post_exec_syscall() in rr which does not take any arguments
    /// Call this method when the exec has completed.
    pub fn post_exec_syscall_for_replay_exe(&self, replay_exe: &OsStr) {
        self.post_exec_for_exe(replay_exe);

        // Perform post-exec-syscall tasks now (e.g. opening mem_fd) before we
        // switch registers. This lets us perform AutoRemoteSyscalls using the
        // regular stack instead of having to search the address space for usable
        // pages (which is error prone, e.g. if we happen to find the scratch space
        // allocated by an rd recorder under which we're running).
        self.post_exec_syscall();

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
            &self.regs_ref(),
            "recorded",
            rec_regs,
            MismatchBehavior::BailOnMismatch,
        );
    }

    pub fn current_trace_frame(&self) -> OwningHandle<SessionSharedPtr, Ref<'_, TraceFrame>> {
        let sess = self.session();
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_replay() }.unwrap().current_trace_frame()
        });
        owning_handle
    }

    pub fn current_trace_frame_mut(
        &self,
    ) -> OwningHandle<SessionSharedPtr, RefMut<'_, TraceFrame>> {
        let sess = self.session();
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

    /// @TODO More elegant approach??
    /// Restore the next chunk of saved data from the trace to this.
    pub fn set_data_from_trace(&self, maybe_other: Option<&ReplayTask>) -> usize {
        let buf: RawData = self.trace_reader_mut().read_raw_data();
        if !buf.addr.is_null() && !buf.data.is_empty() {
            if buf.rec_tid == self.rec_tid() {
                self.write_bytes_helper(buf.addr, &buf.data, None, WriteFlags::empty());
                self.vm()
                    .maybe_update_breakpoints(self, buf.addr, buf.data.len());
            } else if maybe_other
                .as_ref()
                .map_or(false, |o| o.rec_tid() == buf.rec_tid)
            {
                let other = maybe_other.unwrap();
                other.write_bytes_helper(buf.addr, &buf.data, None, WriteFlags::empty());
                other
                    .vm()
                    .maybe_update_breakpoints(other, buf.addr, buf.data.len());
            } else {
                let t = self.session().find_task_from_rec_tid(buf.rec_tid).unwrap();

                t.write_bytes_helper(buf.addr, &buf.data, None, WriteFlags::empty());
                t.vm()
                    .maybe_update_breakpoints(&**t, buf.addr, buf.data.len());
            }
        }

        buf.data.len()
    }

    pub fn trace_reader(&self) -> OwningHandle<SessionSharedPtr, Ref<'_, TraceReader>> {
        let sess = self.session();
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_replay() }.unwrap().trace_reader()
        });
        owning_handle
    }

    pub fn trace_reader_mut(&self) -> OwningHandle<SessionSharedPtr, RefMut<'_, TraceReader>> {
        let sess = self.session();
        let owning_handle = OwningHandle::new_with_fn(sess, |o| {
            unsafe { (*o).as_replay() }.unwrap().trace_reader_mut()
        });
        owning_handle
    }

    /// Restore all remaining chunks of saved data for the current trace frame.
    pub fn apply_all_data_records_from_trace(&self) {
        loop {
            let maybe_buf = self.trace_reader_mut().read_raw_data_for_frame();
            match maybe_buf {
                Some(buf) => {
                    if !buf.addr.is_null() && !buf.data.is_empty() {
                        if buf.rec_tid == self.rec_tid() {
                            self.write_bytes_helper(buf.addr, &buf.data, None, WriteFlags::empty());
                            self.vm()
                                .maybe_update_breakpoints(self, buf.addr, buf.data.len());
                        } else {
                            let t = self.session().find_task_from_rec_tid(buf.rec_tid).unwrap();
                            t.write_bytes_helper(buf.addr, &buf.data, None, WriteFlags::empty());
                            t.vm()
                                .maybe_update_breakpoints(&**t, buf.addr, buf.data.len());
                        };
                    }
                }
                None => break,
            }
        }
    }

    /// Set the syscall-return-value register of this to what was
    /// saved in the current trace frame.
    pub fn set_return_value_from_trace(&self) {
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
    pub fn set_real_tid_and_update_serial(&self, tid: pid_t) {
        self.hpc.borrow_mut().set_tid(tid);
        self.tid.set(tid);
        self.serial.set(self.session().next_task_serial());
    }

    /// Note: This method is private
    fn init_buffers_arch<Arch: Architecture>(&self, map_hint: RemotePtr<Void>) {
        self.apply_all_data_records_from_trace();

        let child_args: RemotePtr<rdcall_init_buffers_params<Arch>> =
            RemotePtr::from(self.regs_ref().arg1());
        let args = read_val_mem(self, child_args, None);

        let syscallbuf_ptr = Arch::as_rptr(args.syscallbuf_ptr);
        let syscallbuf_size = args.syscallbuf_size as usize;
        let desched_counter_fd = args.desched_counter_fd;
        let cloned_file_data_fd = args.cloned_file_data_fd;

        let tuid = self.tuid();

        let mut remote = AutoRemoteSyscalls::new(self);
        if !syscallbuf_ptr.is_null() {
            remote.task().syscallbuf_size.set(syscallbuf_size);
            remote.init_syscall_buffer(map_hint);
            remote.task().desched_fd_child.set(desched_counter_fd);
            // Prevent the child from closing this fd
            remote.task().fd_table().add_monitor(
                remote.task(),
                desched_counter_fd,
                Box::new(PreserveFileMonitor::new()),
            );

            // Skip mmap record. It exists mainly to inform non-replay code
            // (e.g. RemixModule) that this memory will be mapped.
            remote
                .task()
                .as_replay_task()
                .unwrap()
                .trace_reader_mut()
                .read_mapped_region(None, None, None, None, None);

            if cloned_file_data_fd >= 0 {
                remote
                    .task()
                    .cloned_file_data_fd_child
                    .set(cloned_file_data_fd);
                let arch = remote.arch();
                let clone_file_name = remote
                    .task()
                    .as_replay_task()
                    .unwrap()
                    .trace_reader()
                    .trace_stream()
                    .file_data_clone_file_name(tuid);

                let clone_file = ScopedFd::open_path(clone_file_name.as_os_str(), OFlag::O_RDONLY);
                let fd = remote.send_fd(&clone_file) as i32;
                if fd != cloned_file_data_fd {
                    let ret = rd_infallible_syscall!(
                        remote,
                        syscall_number_for_dup3(arch),
                        fd,
                        cloned_file_data_fd,
                        O_CLOEXEC
                    ) as i32;
                    ed_assert_eq!(remote.task(), ret, cloned_file_data_fd);
                    rd_infallible_syscall!(remote, syscall_number_for_close(arch), fd);
                }
                remote.task().fd_table().add_monitor(
                    remote.task(),
                    cloned_file_data_fd,
                    Box::new(PreserveFileMonitor::new()),
                );
            }
        }

        let syscallbuf_child_addr = remote.task().syscallbuf_child.get().as_usize();
        remote
            .initial_regs_mut()
            .set_syscall_result(syscallbuf_child_addr);
    }
}

impl Task for ReplayTask {
    fn clone_task(
        &self,
        reason: CloneReason,
        flags: CloneFlags,
        stack: RemotePtr<Void>,
        tls: RemotePtr<Void>,
        cleartid_addr: RemotePtr<i32>,
        new_tid: pid_t,
        new_rec_tid: Option<pid_t>,
        new_serial: u32,
        maybe_other_session: Option<SessionSharedPtr>,
    ) -> TaskSharedPtr {
        clone_task_common(
            self,
            reason,
            flags,
            stack,
            tls,
            cleartid_addr,
            new_tid,
            new_rec_tid,
            new_serial,
            maybe_other_session,
        )
    }

    fn post_wait_clone(&self, clone_from: &dyn Task, flags: CloneFlags) {
        post_wait_clone_common(self, clone_from, flags)
    }

    /// Forwarded method
    fn destroy(&self, maybe_detach: Option<bool>, sess: &dyn Session) {
        destroy_common(self, maybe_detach);
        task_cleanup_common(self, sess);
    }

    /// Forwarded method
    fn detect_syscall_arch(&self) -> SupportedArch {
        detect_syscall_arch_common(self)
    }

    /// Forwarded method
    fn destroy_buffers(&self) {
        destroy_buffers_common(self)
    }

    /// Forwarded method
    fn post_exec_for_exe(&self, exe_file: &OsStr) {
        post_exec_for_exe_common(self, exe_file)
    }

    /// Forwarded method
    fn resume_execution(
        &self,
        how: ResumeRequest,
        wait_how: WaitRequest,
        tick_period: TicksRequest,
        maybe_sig: Option<Sig>,
    ) {
        resume_execution_common(self, how, wait_how, tick_period, maybe_sig)
    }

    /// Forwarded method
    fn stored_record_size(&self, record: RemotePtr<syscallbuf_record>) -> usize {
        stored_record_size_common(self, record)
    }

    /// Forwarded method
    fn did_waitpid(&self, status: WaitStatus) {
        did_waitpid_common(self, status)
    }

    /// Forwarded method
    fn next_syscallbuf_record(&self) -> RemotePtr<syscallbuf_record> {
        next_syscallbuf_record_common(self)
    }

    fn as_task_inner(&self) -> &TaskInner {
        &self.task_inner
    }

    fn as_replay_task(&self) -> Option<&ReplayTask> {
        Some(self)
    }

    fn on_syscall_exit(&self, syscallno: i32, arch: SupportedArch, regs: &Registers) {
        on_syscall_exit_common(self, syscallno, arch, regs)
    }

    // Forwarded method
    fn at_preload_init(&self) {
        at_preload_init_common(self)
    }

    /// Forwarded method
    fn open_mem_fd(&self) -> bool {
        open_mem_fd_common(self)
    }

    /// Forwarded method
    fn read_bytes_fallible(&self, addr: RemotePtr<u8>, buf: &mut [u8]) -> Result<usize, ()> {
        read_bytes_fallible_common(self, addr, buf)
    }

    /// Forwarded method
    fn read_bytes_helper(&self, addr: RemotePtr<Void>, buf: &mut [u8], ok: Option<&mut bool>) {
        read_bytes_helper_common(self, addr, buf, ok)
    }

    fn read_bytes(&self, addr: RemotePtr<Void>, buf: &mut [u8]) {
        read_bytes_helper_common(self, addr, buf, None)
    }

    /// Forwarded method
    fn read_c_str(&self, child_addr: RemotePtr<u8>) -> CString {
        read_c_str_common(self, child_addr)
    }

    /// Forwarded method
    fn write_bytes_helper(
        &self,
        addr: RemotePtr<u8>,
        buf: &[u8],
        ok: Option<&mut bool>,
        flags: WriteFlags,
    ) {
        write_bytes_helper_common(self, addr, buf, ok, flags)
    }

    /// Forwarded method
    fn syscallbuf_data_size(&self) -> usize {
        syscallbuf_data_size_common(self)
    }

    /// Forwarded method
    fn write_bytes(&self, child_addr: RemotePtr<u8>, buf: &[u8]) {
        write_bytes_common(self, child_addr, buf);
    }

    /// Forwarded method
    fn post_exec_syscall(&self) {
        post_exec_syscall_common(self)
    }

    // Forwarded method
    fn compute_trap_reasons(&self) -> TrapReasons {
        compute_trap_reasons_common(self)
    }

    fn post_vm_clone(&self, reason: CloneReason, flags: CloneFlags, origin: &dyn Task) -> bool {
        if post_vm_clone_common(self, reason, flags, origin)
            && reason == CloneReason::TraceeClone
            && self.trace_reader().preload_thread_locals_recorded()
        {
            // Consume the mapping.
            let mut data = MappedData::default();
            let km = self
                .trace_reader_mut()
                .read_mapped_region(Some(&mut data), None, None, None, None)
                .unwrap();
            ed_assert!(
                self,
                km.start() == AddressSpace::preload_thread_locals_start()
                    && km.size() == page_size()
            );
            true
        } else {
            false
        }
    }

    // Forwarded method
    fn set_thread_area(&self, tls: RemotePtr<user_desc>) {
        set_thread_area_common(self, tls)
    }

    /// Forwarded method
    fn reset_syscallbuf(&self) {
        reset_syscallbuf_common(self);
    }

    /// Forwarded method
    fn set_syscallbuf_locked(&self, locked: bool) {
        set_syscallbuf_locked_common(self, locked);
    }
}
