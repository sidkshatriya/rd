#[cfg(feature = "verify_syscall_numbers")]
include!(concat!(
    env!("OUT_DIR"),
    "/check_syscall_numbers_generated.rs"
));
use crate::{
    arch::Architecture,
    auto_remote_syscalls::{
        AutoRemoteSyscalls,
        AutoRestoreMem,
        MemParamsEnabled,
        PreserveContents::PreserveContents,
    },
    kernel_abi::{
        common::preload_interface::{syscallbuf_hdr, SYS_rdcall_reload_auxv},
        is_rdcall_notify_syscall_hook_exit_syscall,
        is_restart_syscall_syscall,
        is_write_syscall,
        syscall_number_for_execve,
        syscall_number_for_munmap,
        syscall_number_for_prctl,
        CloneTLSType,
        SupportedArch,
        RD_NATIVE_ARCH,
    },
    kernel_metadata::{is_sigreturn, syscall_name},
    log::LogLevel::LogDebug,
    registers::{with_converted_registers, Registers},
    remote_ptr::RemotePtr,
    seccomp_filter_rewriter::SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO,
    session::{
        address_space::{
            address_space::AddressSpace,
            kernel_mapping::KernelMapping,
            memory_range::MemoryRangeKey,
            MappingFlags,
        },
        replay_session::{
            ReplaySession,
            ReplayTraceStep,
            ReplayTraceStepData,
            ReplayTraceStepSyscall,
            ReplayTraceStepType,
        },
        task::{
            common::{read_mem, write_mem, write_val_mem},
            replay_task::ReplayTask,
            task_inner::{task_inner::WriteFlags, ResumeRequest, TicksRequest, WaitRequest},
            Task,
        },
    },
    trace::{
        trace_frame::FrameTime,
        trace_stream,
        trace_stream::MappedData,
        trace_task_event::{TraceTaskEvent, TraceTaskEventType},
    },
    util::{
        clone_flags_to_task_flags,
        extract_clone_parameters,
        floor_page_size,
        resource_path,
        CloneParameters,
    },
    wait_status::WaitStatus,
};
use libc::{
    __errno_location,
    pid_t,
    syscall,
    CLONE_CHILD_CLEARTID,
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNET,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUSER,
    CLONE_NEWUTS,
    CLONE_UNTRACED,
    CLONE_VFORK,
    CLONE_VM,
    ENOENT,
    ENOSYS,
    PR_SET_NAME,
};
use nix::{
    errno::errno,
    sys::mman::{MapFlags, ProtFlags},
    unistd::{access, AccessFlags},
};
use std::{
    cmp::min,
    convert::TryInto,
    ffi::{CString, OsStr, OsString},
    mem::size_of,
    os::unix::ffi::{OsStrExt, OsStringExt},
};

/// Proceeds until the next system call, which is being executed.
///
/// DIFF NOTE: Params maybe_expect_syscallno2 and maybe_new_tid and treatment slightly different.
fn __ptrace_cont(
    t: &mut ReplayTask,
    resume_how: ResumeRequest,
    syscall_arch: SupportedArch,
    expect_syscallno: i32,
    maybe_expect_syscallno2: Option<i32>,
    maybe_new_tid: Option<pid_t>,
) {
    maybe_expect_syscallno2.map(|n| debug_assert!(n >= 0));
    maybe_new_tid.map(|n| assert!(n > 0));
    let new_tid = maybe_new_tid.unwrap_or(-1);
    let expect_syscallno2 = maybe_expect_syscallno2.unwrap_or(-1);
    t.resume_execution(
        resume_how,
        WaitRequest::ResumeNonblocking,
        TicksRequest::ResumeNoTicks,
        None,
    );
    loop {
        if t.wait_unexpected_exit() {
            break;
        }
        let mut raw_status: i32 = 0;
        // Do our own waitpid instead of calling Task::wait() so we can detect and
        // handle tid changes due to off-main-thread execve.
        // When we're expecting a tid change, we can't pass a tid here because we
        // don't know which tid to wait for.
        // Passing the original tid seems to cause a hang in some kernels
        // (e.g. 4.10.0-19-generic) if the tid change races with our waitpid
        let ret = unsafe { libc::waitpid(new_tid, &mut raw_status, libc::__WALL) };
        ed_assert!(t, ret >= 0);
        if ret == new_tid {
            // Check that we only do this once
            ed_assert!(t, t.tid != new_tid);
            // Update the serial as if this task was really created by cloning the old task.
            t.set_real_tid_and_update_serial(new_tid);
        }
        ed_assert!(t, ret == t.tid);
        t.did_waitpid(WaitStatus::new(raw_status));

        // DIFF NOTE: @TODO The `if` statement logic may create a slight divergence from rr.
        // May need to think about this more deeply and make sure this will work like rr.
        if t.status().maybe_stop_sig().is_sig()
            && ReplaySession::is_ignored_signal(t.status().maybe_stop_sig().unwrap_sig())
        {
            t.resume_execution(
                resume_how,
                WaitRequest::ResumeNonblocking,
                TicksRequest::ResumeNoTicks,
                None,
            );
        } else {
            break;
        }
    }

    ed_assert!(
        t,
        !t.maybe_stop_sig().is_sig(),
        "Expected no pending signal, but got: {}",
        t.maybe_stop_sig().unwrap_sig()
    );

    // check if we are synchronized with the trace -- should never fail
    let current_syscall = t.regs_ref().original_syscallno() as i32;
    // DIFF NOTE: Minor differences arising out of maybe_dump_written_string() behavior.
    ed_assert!(
        t,
        current_syscall == expect_syscallno || current_syscall == expect_syscallno2,
        "Should be at {}, but instead at {} ({:?})",
        syscall_name(expect_syscallno, syscall_arch),
        syscall_name(current_syscall, syscall_arch),
        maybe_dump_written_string(t)
    );
}

/// DIFF NOTE: In rd we're returning a `None` if this was not a write syscall
fn maybe_dump_written_string(t: &mut ReplayTask) -> Option<OsString> {
    if !is_write_syscall(t.regs_ref().original_syscallno() as i32, t.arch()) {
        return None;
    }
    let len = min(1000, t.regs_ref().arg3());
    let mut buf = Vec::<u8>::with_capacity(len);
    buf.resize(len, 0u8);
    // DIFF NOTE: Here we're actually expecting there to be no Err(_), hence the unwrap()
    let nread = t
        .read_bytes_fallible(t.regs_ref().arg2().into(), &mut buf)
        .unwrap();
    buf.truncate(nread);
    Some(OsString::from_vec(buf))
}

fn init_scratch_memory(t: &mut ReplayTask, km: &KernelMapping, data: &trace_stream::MappedData) {
    ed_assert!(t, data.source == trace_stream::MappedDataSource::SourceZero);

    t.scratch_ptr = km.start();
    t.scratch_size = km.size();
    let sz = t.scratch_size;
    let scratch_ptr = t.scratch_ptr;
    // Make the scratch buffer read/write during replay so that
    // preload's sys_read can use it to buffer cloned data.
    ed_assert!(
        t,
        km.prot()
            .contains(ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
    );
    ed_assert!(
        t,
        km.flags()
            .contains(MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS)
    );

    {
        {
            let mut remote = AutoRemoteSyscalls::new(t);
            remote.infallible_mmap_syscall(
                Some(scratch_ptr),
                sz,
                km.prot(),
                km.flags() | MapFlags::MAP_FIXED,
                -1,
                0,
            );
        }
        t.vm().map(
            t,
            t.scratch_ptr,
            sz,
            km.prot(),
            km.flags(),
            0,
            OsStr::new(""),
            KernelMapping::NO_DEVICE,
            KernelMapping::NO_INODE,
            None,
            Some(&km),
            None,
            None,
            None,
        );
    }
    t.setup_preload_thread_locals();
}

/// If scratch data was incidentally recorded for the current desched'd
/// but write-only syscall, then do a no-op restore of that saved data
/// to keep the trace in sync.
///
/// Syscalls like `write()` that may-block and are wrapped in the
/// preload library can be desched'd.  When this happens, we save the
/// syscall record's "extra data" as if it were normal scratch space,
/// since it's used that way in effect.  But syscalls like `write()`
/// that don't actually use scratch space don't ever try to restore
/// saved scratch memory during replay.  So, this helper can be used
/// for that class of syscalls.
fn maybe_noop_restore_syscallbuf_scratch(t: &mut ReplayTask) {
    if t.is_in_untraced_syscall() {
        // Untraced syscalls always have t's arch
        log!(
            LogDebug,
            "  noop-restoring scratch for write-only desched'd {}",
            syscall_name(t.regs_ref().original_syscallno() as i32, t.arch())
        );
        t.set_data_from_trace();
    }
}

fn read_task_trace_event(t: &ReplayTask, task_event_type: TraceTaskEventType) -> TraceTaskEvent {
    let mut tte: Option<TraceTaskEvent>;
    let mut time: FrameTime = 0;
    let shr_ptr = t.session();

    let mut tr = shr_ptr.as_replay().unwrap().trace_reader_mut();
    loop {
        tte = tr.read_task_event(Some(&mut time));
        if tte.is_none() {
            ed_assert!(
                t,
                false,
                "Unable to find TraceTaskEvent; trace is corrupt (did you kill -9 rd?)"
            )
        }

        if time >= t.current_frame_time() && tte.as_ref().unwrap().event_type() == task_event_type {
            break;
        }
    }
    ed_assert!(t, time == t.current_frame_time());
    tte.unwrap()
}

fn prepare_clone<Arch: Architecture>(t: &mut ReplayTask) {
    let trace_frame = t.current_trace_frame();
    let trace_frame_regs = trace_frame.regs_ref().clone();
    let syscall_event = trace_frame.event().syscall_event();
    let syscall_event_arch = syscall_event.arch();

    // We're being called with the syscall entry event, so we can't inspect the result
    // of the syscall exit to see whether the clone succeeded (that event can happen
    // much later, even after the spawned task has run).
    if syscall_event.failed_during_preparation {
        // creation failed, nothing special to do
        return;
    }
    drop(trace_frame);

    let mut r = t.regs_ref().clone();
    let mut sys: i32 = r.original_syscallno() as i32;
    let mut flags: i32 = 0;
    if Arch::CLONE == sys {
        // If we allow CLONE_UNTRACED then the child would escape from rr control
        // and we can't allow that.
        // Block CLONE_CHILD_CLEARTID because we'll emulate that ourselves.
        // Block CLONE_VFORK for the reasons below.
        // Block CLONE_NEW* from replay, any effects it had were dealt with during
        // recording.
        let disallowed_clone_flags = CLONE_UNTRACED
            | CLONE_CHILD_CLEARTID
            | CLONE_VFORK
            | CLONE_NEWIPC
            | CLONE_NEWNET
            | CLONE_NEWNS
            | CLONE_NEWPID
            | CLONE_NEWUSER
            | CLONE_NEWUTS
            | CLONE_NEWCGROUP;
        flags = r.arg1() as i32 & !disallowed_clone_flags;
        r.set_arg1(flags as usize);
    } else if Arch::VFORK == sys {
        // We can't perform a real vfork, because the kernel won't let the vfork
        // parent return from the syscall until the vfork child has execed or
        // exited, and it is an invariant of replay that tasks are not in the kernel
        // except when we need them to execute a specific syscall on rr's behalf.
        // So instead we do a regular fork but use the CLONE_VM flag to share
        // address spaces between the parent and child. That's just like a vfork
        // except the parent is immediately runnable. This is no problem for replay
        // since we follow the recorded schedule in which the vfork parent did not
        // run until the vfork child exited.
        sys = Arch::CLONE;
        flags = CLONE_VM;
        r.set_arg1(flags as usize);
        r.set_arg2(0);
    }
    r.set_syscallno(sys as isize);
    r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
    t.set_regs(&r);
    let entry_regs = r.clone();

    // Run; we will be interrupted by PTRACE_EVENT_CLONE/FORK/VFORK.
    __ptrace_cont(
        t,
        ResumeRequest::ResumeCont,
        Arch::arch(),
        sys as i32,
        None,
        None,
    );

    let mut new_tid: Option<pid_t> = None;
    while !t.clone_syscall_is_complete(&mut new_tid, Arch::arch()) {
        // clone() calls sometimes fail with -EAGAIN due to load issues or
        // whatever. We need to retry the system call until it succeeds. Reset
        // state to try the syscall again.
        ed_assert!(
            t,
            t.regs_ref().syscall_result_signed() == -libc::EAGAIN as isize
        );
        t.set_regs(&entry_regs);
        __ptrace_cont(
            t,
            ResumeRequest::ResumeCont,
            Arch::arch(),
            sys as i32,
            None,
            None,
        );
    }

    // Get out of the syscall
    __ptrace_cont(
        t,
        ResumeRequest::ResumeSyscall,
        Arch::arch(),
        sys as i32,
        None,
        None,
    );

    ed_assert!(
        t,
        t.maybe_ptrace_event().is_ptrace_event(),
        "Unexpected ptrace event while waiting for syscall exit; got {}",
        t.maybe_ptrace_event()
    );

    r = t.regs_ref().clone();
    // Restore the saved flags, to hide the fact that we may have
    // masked out CLONE_UNTRACED/CLONE_CHILD_CLEARTID or changed from vfork to
    // clone.
    r.set_arg1(trace_frame_regs.arg1());
    r.set_arg2(trace_frame_regs.arg2());
    // Pretend we're still in the system call
    r.set_syscall_result(-ENOSYS as usize);
    r.set_original_syscallno(trace_frame_regs.original_syscallno());
    t.set_regs(&r);
    t.canonicalize_regs(syscall_event_arch);

    // Dig the recorded tid out out of the trace. The tid value returned in
    // the recorded registers could be in a different pid namespace from rr's,
    // so we can't use it directly.
    let tte = read_task_trace_event(t, TraceTaskEventType::Clone);
    ed_assert!(
        t,
        tte.clone_variant().parent_tid() == t.rec_tid,
        "Expected tid {}, got {}",
        t.rec_tid,
        tte.clone_variant().parent_tid()
    );
    let rec_tid = tte.tid();

    let mut params: CloneParameters = Default::default();
    if Arch::CLONE as isize == t.regs_ref().original_syscallno() {
        params = extract_clone_parameters(t);
    }
    let shr_ptr = t.session();

    let new_task: &mut ReplayTask = shr_ptr
        .clone_task(
            t,
            clone_flags_to_task_flags(flags),
            params.stack,
            params.tls,
            params.ctid,
            new_tid.unwrap(),
            Some(rec_tid),
        )
        .as_replay_task_mut()
        .unwrap();

    if Arch::CLONE as isize == t.regs_ref().original_syscallno() {
        // FIXME: what if registers are non-null and contain an invalid address?
        t.set_data_from_trace();

        if Arch::CLONE_TLS_TYPE == CloneTLSType::UserDescPointer {
            t.set_data_from_trace();
            new_task.set_data_from_trace();
        } else {
            debug_assert!(Arch::CLONE_TLS_TYPE == CloneTLSType::PthreadStructurePointer);
        }
        new_task.set_data_from_trace();
        new_task.set_data_from_trace();
    }

    // Fix registers in new task
    let mut new_r = new_task.regs_ref().clone();
    let new_task_arch = new_r.arch();
    new_r.set_original_syscallno(trace_frame_regs.original_syscallno());
    new_r.set_arg1(trace_frame_regs.arg1());
    new_r.set_arg2(trace_frame_regs.arg2());
    new_task.set_regs(&new_r);
    new_task.canonicalize_regs(new_task_arch);

    if Arch::CLONE as isize != t.regs_ref().original_syscallno()
        || !(CLONE_VM as usize & r.arg1() == CLONE_VM as usize)
    {
        // It's hard to imagine a scenario in which it would
        // be useful to inherit breakpoints (along with their
        // refcounts) across a non-VM-sharing clone, but for
        // now we never want to do this.
        new_task.vm().remove_all_breakpoints();
        new_task.vm().remove_all_watchpoints();

        let mut remote = AutoRemoteSyscalls::new(new_task);
        for (&k, m) in &t.vm().maps() {
            // Recreate any tracee-shared mappings
            if m.local_addr.is_some()
                && !m
                    .flags
                    .contains(MappingFlags::IS_THREAD_LOCALS | MappingFlags::IS_SYSCALLBUF)
            {
                remote.recreate_shared_mmap(k, Some(PreserveContents), None);
            }
        }
    }

    let mut data: MappedData = Default::default();
    let km: KernelMapping;
    {
        let shr_ptr = t.session();

        let replay_session = shr_ptr.as_replay().unwrap();
        km = replay_session
            .trace_reader_mut()
            .read_mapped_region(Some(&mut data), None, None, None, None)
            .unwrap();
    }

    init_scratch_memory(new_task, &km, &data);

    new_task.vm().after_clone();
}

/// DIFF NOTE: This simply returns a ReplayTraceStep instead of modifying one.
pub fn rep_prepare_run_to_syscall(t: &mut ReplayTask) -> ReplayTraceStep {
    let step: ReplayTraceStep;
    let sys_num = t.current_trace_frame().event().syscall_event().number;
    let sys_arch = t.current_trace_frame().event().syscall_event().arch();
    let sys_name = t
        .current_trace_frame()
        .event()
        .syscall_event()
        .syscall_name();
    log!(LogDebug, "processing {} (entry)", sys_name);

    if is_restart_syscall_syscall(sys_num, sys_arch) {
        ed_assert!(t, t.tick_count() == t.current_trace_frame().ticks());
        let regs = t.current_trace_frame().regs_ref().clone();
        t.set_regs(&regs);
        t.apply_all_data_records_from_trace();
        step = ReplayTraceStep {
            action: ReplayTraceStepType::TstepRetire,
            data: Default::default(),
        };
        return step;
    }

    step = ReplayTraceStep {
        action: ReplayTraceStepType::TstepEnterSyscall,
        data: ReplayTraceStepData::Syscall(ReplayTraceStepSyscall {
            // @TODO Check again: is this what we want for arch?
            arch: sys_arch,
            number: sys_num,
        }),
    };

    // Don't let a negative incoming syscall number be treated as a real
    // system call that we assigned a negative number because it doesn't
    // exist in this architecture.
    if is_rdcall_notify_syscall_hook_exit_syscall(sys_num, sys_arch) {
        ed_assert!(t, !t.syscallbuf_child.is_null());
        let child_addr = RemotePtr::<u8>::cast(t.syscallbuf_child)
            + offset_of!(syscallbuf_hdr, notify_on_syscall_hook_exit);
        write_val_mem(t, child_addr, &1u8, None);
    }

    step
}

pub fn rep_process_syscall(t: &mut ReplayTask) -> ReplayTraceStep {
    let arch: SupportedArch;
    let trace_regs: Registers;
    {
        let trace_frame = t.current_trace_frame();
        arch = trace_frame.event().syscall_event().arch();
        trace_regs = trace_frame.regs_ref().clone()
    }
    with_converted_registers(&trace_regs, arch, |converted_regs| {
        rd_arch_function_selfless!(rep_process_syscall_arch, arch, t, converted_regs)
    })
}

fn rep_process_syscall_arch<Arch: Architecture>(
    t: &mut ReplayTask,
    trace_regs: &Registers,
) -> ReplayTraceStep {
    let mut sys = t.current_trace_frame().event().syscall_event().number;

    log!(
        LogDebug,
        "processing {} (exit)",
        syscall_name(sys, Arch::arch())
    );
    // sigreturns are never restartable, and the value of the
    // syscall-result register after a sigreturn is not actually the
    // syscall result.
    if trace_regs.syscall_may_restart() && !is_sigreturn(sys, Arch::arch()) {
        // During recording, when a sys exits with a
        // restart "error", the kernel sometimes restarts the
        // tracee by resetting its $ip to the syscall entry
        // point, but other times restarts the syscall without
        // changing the $ip.
        t.apply_all_data_records_from_trace();
        t.set_return_value_from_trace();
        log!(
            LogDebug,
            "  {} interrupted by {} at {}, may restart",
            syscall_name(sys, Arch::arch()),
            trace_regs.syscall_result(),
            trace_regs.ip()
        );
        return ReplayTraceStep {
            action: ReplayTraceStepType::TstepRetire,
            data: Default::default(),
        };
    }

    if sys == Arch::RESTART_SYSCALL {
        sys = t.regs_ref().original_syscallno().try_into().unwrap();
    }

    let step = ReplayTraceStep {
        action: ReplayTraceStepType::TstepExitSyscall,
        data: ReplayTraceStepData::Syscall(ReplayTraceStepSyscall {
            arch: Arch::arch(),
            number: sys,
        }),
    };
    if trace_regs.original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO {
        // rd vetoed this syscall. Don't do any post-processing. Do set registers
        // to match any registers rd modified to fool the signal handler.
        t.set_regs(&trace_regs);
        return step;
    }

    let nsys: i32 = non_negative_syscall(sys);
    if trace_regs.syscall_failed() {
        if nsys != Arch::MADVISE
            && nsys != Arch::MPROTECT
            && nsys != Arch::SIGRETURN
            && nsys != Arch::RT_SIGRETURN
        {
            return step;
        }
    }

    // Manual implementations of irregular syscalls that need to do more during
    // replay than just modify register and memory state.
    // Don't let a negative incoming syscall number be treated as a real
    // system call that we assigned a negative number because it doesn't
    // exist in this architecture.
    // All invalid/unsupported syscalls get the default emulation treatment.
    if nsys == Arch::EXECVE {
        return process_execve(t);
    }

    if nsys == Arch::BRK {
        unimplemented!();
    }

    if nsys == Arch::MMAP {
        unimplemented!();
    }

    if nsys == Arch::MMAP2 {
        unimplemented!();
    }
    if nsys == Arch::SHMAT {
        unimplemented!();
    }
    if nsys == Arch::SHMDT {
        unimplemented!();
    }
    if nsys == Arch::MREMAP {
        unimplemented!();
    }
    if nsys == Arch::MADVISE {
        unimplemented!();
    }
    if nsys == Arch::MADVISE || nsys == Arch::ARCH_PRCTL {
        unimplemented!();
    }
    if nsys == Arch::MADVISE
        || nsys == Arch::ARCH_PRCTL
        || nsys == Arch::MUNMAP
        || nsys == Arch::MPROTECT
        || nsys == Arch::MODIFY_LDT
        || nsys == Arch::SET_THREAD_AREA
    {
        unimplemented!();
    }
    if nsys == Arch::IPC {
        unimplemented!()
    }
    if nsys == Arch::SIGRETURN || nsys == Arch::RT_SIGRETURN {
        unimplemented!();
    }
    if nsys == Arch::PERF_EVENT_OPEN {
        unimplemented!();
    }
    if nsys == Arch::PERF_EVENT_OPEN
        || nsys == Arch::RECVMSG
        || nsys == Arch::RECVMMSG
        || nsys == Arch::SOCKETCALL
        || nsys == Arch::RDCALL_NOTIFY_CONTROL_MSG
    {
        unimplemented!();
    }
    if nsys == Arch::OPENAT {
        unimplemented!();
    }
    if nsys == Arch::OPEN {
        unimplemented!();
    }

    if nsys == Arch::WRITE || nsys == Arch::WRITEV {
        unimplemented!();
    }
    if nsys == Arch::PROCESS_VM_WRITEV {
        unimplemented!()
    }

    if nsys == Arch::READ {
        unimplemented!();
    }

    if nsys == Arch::RDCALL_INIT_BUFFERS {
        unimplemented!();
    }
    if nsys == Arch::RDCALL_INIT_PRELOAD {
        unimplemented!();
    }

    if nsys == Arch::RDCALL_RELOAD_AUXV {
        unimplemented!();
    }
    step
}

fn non_negative_syscall(sys: i32) -> i32 {
    if sys < 0 {
        i32::MAX
    } else {
        sys
    }
}

/// Call this when |t| has just entered a syscall.
pub fn rep_after_enter_syscall(t: &mut ReplayTask) {
    rd_arch_function_selfless!(rep_after_enter_syscall_arch, t.arch(), t)
}

fn rep_after_enter_syscall_arch<Arch: Architecture>(t: &mut ReplayTask) {
    let sys: i32 = non_negative_syscall(t.regs_ref().original_syscallno().try_into().unwrap());

    if sys == Arch::WRITE || sys == Arch::WRITEV {
        let fd: i32 = t.regs_ref().arg1_signed() as i32;
        t.fd_table().will_write(t, fd);
    }

    if sys == Arch::CLONE || sys == Arch::VFORK || sys == Arch::FORK {
        // Create the new task now. It needs to exist before clone/fork/vfork
        // returns so that a ptracer can touch it during PTRACE_EVENT handling.
        unimplemented!()
    }

    if sys == Arch::PTRACE {
        unimplemented!()
    }

    if sys == Arch::EXIT {
        // Destroy buffers now to match when we destroyed them during recording.
        // It's possible for another mapping to be created overlapping our
        // buffers before this task truly exits, and we don't want to trash
        // that mapping by destroying our buffers then.
        t.destroy_buffers();
    }

    if sys == Arch::EXIT_GROUP {
        unimplemented!()
    }

    t.apply_all_data_records_from_trace();
}

// DIFF NOTE: This does not take an extra param `trace_frame` as it can be
// obtained from `t` itself
pub fn process_execve(t: &mut ReplayTask) -> ReplayTraceStep {
    let step = ReplayTraceStep {
        action: ReplayTraceStepType::TstepRetire,
        data: Default::default(),
    };
    let frame_arch = t.current_trace_frame().regs_ref().arch();
    // First, exec a stub program
    let stub_filename: CString = find_exec_stub(frame_arch);

    // Setup memory and registers for the execve call. We may not have to save
    // the old values since they're going to be wiped out by execve. We can
    // determine this by checking if this address space has any tasks with a
    // different tgid.
    let mut maybe_memory_task = None;
    for task in t.vm().task_set().iter_except(t.weak_self_ptr()) {
        if task.borrow().tgid() != t.tgid() {
            maybe_memory_task = Some(task);
            break;
        }
    }

    // Old data if required
    let mut saved_data: Vec<u8> = Vec::new();

    // Set up everything
    let mut regs = t.regs_ref().clone();
    regs.set_ip(t.vm().traced_syscall_ip());
    let remote_mem: RemotePtr<u8> = floor_page_size(regs.sp());

    // Determine how much memory we'll need
    let filename_size: usize = stub_filename.to_bytes_with_nul().len();
    let total_size: usize = size_of::<usize>() + filename_size;
    if maybe_memory_task.is_some() {
        saved_data = read_mem(t, RemotePtr::<u8>::cast(remote_mem), total_size, None);
    }

    // We write a zero word in the host size, not t's size, but that's OK,
    // since the host size must be bigger than t's size.
    // We pass no argv or envp, so exec params 2 and 3 just point to the NULL
    // word.
    write_val_mem(t, RemotePtr::<usize>::cast(remote_mem), &0usize, None);
    regs.set_arg2_from_remote_ptr(remote_mem);
    regs.set_arg3_from_remote_ptr(remote_mem);
    let filename_addr: RemotePtr<u8> = remote_mem + size_of::<usize>();
    t.write_bytes_helper(
        filename_addr,
        stub_filename.to_bytes_with_nul(),
        None,
        WriteFlags::empty(),
    );
    regs.set_arg1_from_remote_ptr(filename_addr);
    // The original_syscallno is execve in the old architecture. The kernel does
    // not update the original_syscallno when the architecture changes across
    // an exec.
    // We're using the dedicated traced-syscall IP so its arch is t's arch.
    let expect_syscallno: i32 = syscall_number_for_execve(t.arch());
    regs.set_syscallno(expect_syscallno as isize);
    t.set_regs(&regs);

    log!(LogDebug, "Beginning execve");
    // Enter our execve syscall.
    __ptrace_cont(
        t,
        ResumeRequest::ResumeSyscall,
        t.arch(),
        expect_syscallno,
        None,
        None,
    );
    ed_assert!(
        t,
        t.maybe_stop_sig().is_not_sig(),
        "Stub exec failed on entry"
    );
    // Complete the syscall. The tid of the task will be the thread-group-leader
    // tid, no matter what tid it was before.
    let tgid: pid_t = t.thread_group().real_tgid;
    __ptrace_cont(
        t,
        ResumeRequest::ResumeSyscall,
        t.arch(),
        expect_syscallno,
        Some(syscall_number_for_execve(frame_arch)),
        if tgid == t.tid { None } else { Some(tgid) },
    );
    if t.regs_ref().syscall_result() != 0 {
        // @TODO check this. Is this what we want -- especially the cast to i32?
        unsafe { *__errno_location() = -(t.regs_ref().syscall_result() as i32) };
        if access(stub_filename.as_c_str(), AccessFlags::F_OK).is_err()
            && errno() == ENOENT
            && frame_arch == SupportedArch::X86
        {
            fatal!("Cannot find exec stub {:?} to replay this 32-bit process; you probably built rr with disable32bit", stub_filename);
        }
        ed_assert!(t, false, "Exec of stub {:?} failed", stub_filename);
    }

    // Restore any memory if required. We need to do this through memory_task,
    // since the new task is now on the new address space. Do it now because
    // later we may try to unmap this task's syscallbuf.
    if maybe_memory_task.is_some() {
        write_mem(
            maybe_memory_task.as_ref().unwrap().borrow_mut().as_mut(),
            RemotePtr::cast::<u8>(remote_mem),
            saved_data.as_slice(),
            None,
        );
    }

    let mut kms: Vec<KernelMapping> = Vec::new();
    let mut datas: Vec<trace_stream::MappedData> = Vec::new();

    let maybe_exec = read_task_trace_event(t, TraceTaskEventType::Exec);
    let tte = maybe_exec.exec_variant();

    // Find the text mapping of the main executable. This is complicated by the
    // fact that the kernel also loads the dynamic linker (if the main
    // executable specifies an interpreter).
    let mut exe_km_option1: Option<usize> = None;
    loop {
        let mut data: trace_stream::MappedData = Default::default();
        let maybe_km: Option<KernelMapping> =
            t.trace_reader_mut()
                .read_mapped_region(Some(&mut data), None, None, None, None);
        if maybe_km.is_none() {
            break;
        }
        let km = maybe_km.unwrap();
        if km.start() == AddressSpace::rd_page_start()
            || km.start() == AddressSpace::preload_thread_locals_start()
        {
            // Skip rd-page mapping record, that gets mapped automatically
            continue;
        }

        if !tte.exe_base().is_null() {
            // We recorded the executable's start address so we can just use that
            if tte.exe_base() == km.start() {
                exe_km_option1 = Some(kms.len());
            }
        } else {
            // To disambiguate, we use the following criterion: The dynamic linker
            // (if it exists) is a different file (identified via fsname) that has
            // an executable segment that contains the ip. To compute this, we find
            // (up to) two kms that have different fsnames but do each have an
            // executable segment, as well as the km that contains the ip. This is
            // slightly complicated, but should handle the case where either file has
            // more than one executable segment.
            unimplemented!()
        }
        kms.push(km);
        datas.push(data);
    }

    ed_assert!(t, exe_km_option1.is_some(), "No executable mapping?");

    let exe_km = exe_km_option1.unwrap();
    // DIFF NOTE: @TODO Omit a code snippet relating to exe_km_option2
    // This is because we assume that the trace format is a newer one and
    // always contains the exe_base

    ed_assert!(t, kms[0].is_stack(), "Can't find stack");

    // The exe name we pass in here will be passed to gdb. Pass the backing file
    // name if there is one, otherwise pass the original file name (which means
    // we declined to copy it to the trace file during recording for whatever
    // reason).
    let exe_name: &OsStr = if datas[exe_km].filename.is_empty() {
        kms[exe_km].fsname()
    } else {
        &datas[exe_km].filename
    };
    t.post_exec_syscall_for_replay_exe(exe_name);

    t.fd_table_mut().close_after_exec(
        t,
        &t.current_trace_frame()
            .event()
            .syscall_event()
            .exec_fds_to_close,
    );

    {
        let arch = t.arch();

        // Now fix up the address space. First unmap all the mappings other than
        // our rd page.
        let mut unmaps: Vec<MemoryRangeKey> = Vec::new();
        for (&k, m) in &t.vm().maps() {
            // Do not attempt to unmap [vsyscall] --- it doesn't work.
            if m.map.start() != AddressSpace::rd_page_start()
                && m.map.start() != AddressSpace::preload_thread_locals_start()
                && !m.map.is_vsyscall()
            {
                unmaps.push(k);
            }
        }
        // Tell AutoRemoteSyscalls that we don't need memory parameters. This will
        // stop it from having trouble if our current stack pointer (the value
        // from the replay) isn't in the [stack] mapping created for our stub.
        let mut remote =
            AutoRemoteSyscalls::new_with_mem_params(t, MemParamsEnabled::DisableMemoryParams);
        for m in unmaps {
            rd_infallible_syscall!(
                remote,
                syscall_number_for_munmap(arch),
                m.start().as_usize(),
                m.size()
            );
            remote
                .task()
                .vm_shr_ptr()
                .unmap(remote.task_mut(), m.start(), m.size());
        }
        // We will have unmapped the stack memory that |remote| would have used for
        // memory parameters. Fortunately process_mapped_region below doesn't
        // need any memory parameters for its remote syscalls.

        // Process the [stack] mapping.
        restore_mapped_region(&mut remote, &kms[0], &datas[0]);
    }

    let recorded_exe_name: &OsStr = kms[exe_km].fsname();

    {
        let arch = t.arch();
        // Now that [stack] is mapped, reinitialize AutoRemoteSyscalls with
        // memory parameters enabled.
        let mut remote = AutoRemoteSyscalls::new(t);

        // Now map in all the mappings that we recorded from the real exec.
        for i in 1..kms.len() {
            restore_mapped_region(&mut remote, &kms[i], &datas[i]);
        }

        let mut name: Vec<u8> = Vec::new();
        name.extend_from_slice(b"rd:");
        let pos = recorded_exe_name
            .as_bytes()
            .iter()
            .rposition(|&c| c == b'/')
            .unwrap_or(0);
        debug_assert!(recorded_exe_name.as_bytes().len() != pos + 1);
        name.extend_from_slice(&recorded_exe_name.as_bytes()[pos + 1..]);
        name.extend_from_slice(b"\0");
        let mut mem = AutoRestoreMem::new(&mut remote, Some(&name), name.len());
        let addr = mem.get().unwrap();
        rd_infallible_syscall!(
            mem,
            syscall_number_for_prctl(arch),
            PR_SET_NAME,
            addr.as_usize()
        );
    }

    init_scratch_memory(t, kms.last().unwrap(), datas.last().unwrap());

    // Apply final data records --- fixing up the last page in each data segment
    // for zeroing applied by the kernel, and applying monkeypatches.
    t.apply_all_data_records_from_trace();

    // Now it's safe to save the auxv data
    t.vm_shr_ptr().save_auxv(t);

    // Notify outer rd if there is one
    unsafe { syscall(SYS_rdcall_reload_auxv as i64, t.tid) };

    step
}

fn restore_mapped_region(
    _remote: &mut AutoRemoteSyscalls,
    _km: &KernelMapping,
    _data: &trace_stream::MappedData,
) {
    unimplemented!()
}

fn find_exec_stub(arch: SupportedArch) -> CString {
    let mut exe_path: Vec<u8> = Vec::new();
    exe_path.extend_from_slice(resource_path().as_bytes());
    exe_path.extend_from_slice(b"bin/");
    if arch == SupportedArch::X86 && RD_NATIVE_ARCH == SupportedArch::X64 {
        exe_path.extend_from_slice(b"rr_exec_stub_32");
    } else {
        exe_path.extend_from_slice(b"rr_exec_stub");
    }
    CString::new(exe_path).unwrap()
}
