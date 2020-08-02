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
    bindings::{
        kernel::{user_desc, SHMAT, SHMDT},
        ptrace::{
            PTRACE_CONT,
            PTRACE_DETACH,
            PTRACE_POKEDATA,
            PTRACE_POKETEXT,
            PTRACE_SET_THREAD_AREA,
            PTRACE_SINGLESTEP,
            PTRACE_SYSCALL,
            PTRACE_SYSEMU,
            PTRACE_SYSEMU_SINGLESTEP,
        },
    },
    emu_fs::EmuFileSharedPtr,
    file_monitor::{
        base_file_monitor::BaseFileMonitor,
        mmapped_file_monitor::MmappedFileMonitor,
        proc_fd_dir_monitor::ProcFdDirMonitor,
        proc_mem_monitor::ProcMemMonitor,
        stdio_monitor::StdioMonitor,
        FileMonitor,
        FileMonitorType,
    },
    kernel_abi::{
        common::preload_interface::{syscallbuf_hdr, SYS_rdcall_reload_auxv},
        is_rdcall_notify_syscall_hook_exit_syscall,
        is_restart_syscall_syscall,
        is_write_syscall,
        syscall_number_for_close,
        syscall_number_for_execve,
        syscall_number_for_munmap,
        syscall_number_for_open,
        syscall_number_for_prctl,
        CloneTLSType,
        MmapCallingSemantics,
        SupportedArch,
        RD_NATIVE_ARCH,
    },
    kernel_metadata::{is_sigreturn, shm_flags_to_mmap_prot, syscall_name},
    kernel_supplement::{ARCH_GET_CPUID, ARCH_SET_CPUID},
    log::LogLevel::LogDebug,
    registers::{with_converted_registers, Registers},
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    seccomp_filter_rewriter::SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO,
    session::{
        address_space::{
            address_space::AddressSpace,
            kernel_mapping::KernelMapping,
            memory_range::{MemoryRange, MemoryRangeKey},
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
            replay_task::{ReplayTask, ReplayTaskIgnore},
            task_common::{read_mem, read_val_mem, write_mem, write_val_mem},
            task_inner::{task_inner::WriteFlags, ResumeRequest, TicksRequest, WaitRequest},
            Task,
            TaskSharedPtr,
        },
    },
    trace::{
        trace_frame::FrameTime,
        trace_reader::{TimeConstraint, ValidateSourceFile},
        trace_stream,
        trace_stream::MappedData,
        trace_task_event::{TraceTaskEvent, TraceTaskEventType},
    },
    util::{
        ceil_page_size,
        ceil_page_u64,
        clone_flags_to_task_flags,
        extract_clone_parameters,
        floor_page_size,
        is_proc_fd_dir,
        is_proc_mem_file,
        page_size,
        resource_path,
        CloneParameters,
    },
    wait_status::WaitStatus,
};
use libc::{
    __errno_location,
    dev_t,
    ino_t,
    off_t,
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
    MADV_DONTNEED,
    MADV_REMOVE,
    MAP_SYNC,
    MREMAP_FIXED,
    MREMAP_MAYMOVE,
    PR_SET_NAME,
    SEEK_CUR,
    STDERR_FILENO,
};
use nix::{
    errno::errno,
    fcntl::OFlag,
    sys::{
        mman::{MapFlags, ProtFlags},
        stat::{stat, FileStat},
    },
    unistd::{access, lseek, read, AccessFlags, Whence},
};
use std::{
    cell::RefMut,
    cmp::min,
    convert::TryInto,
    ffi::{CString, OsStr, OsString},
    mem::size_of,
    os::unix::ffi::{OsStrExt, OsStringExt},
};
use trace_stream::{MappedDataSource, TraceRemoteFd};

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
        // If we allow CLONE_UNTRACED then the child would escape from rd control
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
        !t.maybe_ptrace_event().is_ptrace_event(),
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

    let new_task_shr_ptr: TaskSharedPtr = shr_ptr.clone_task(
        t,
        clone_flags_to_task_flags(flags),
        params.stack,
        params.tls,
        params.ctid,
        new_tid.unwrap(),
        Some(rec_tid),
    );

    let mut new_task_ref = new_task_shr_ptr.borrow_mut();
    let new_task: &mut ReplayTask = new_task_ref.as_replay_task_mut().unwrap();

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
        new_task.vm_shr_ptr().remove_all_breakpoints(new_task);
        new_task
            .vm_shr_ptr()
            .remove_all_watchpoints(new_task, Some(t));

        let mut remote = AutoRemoteSyscalls::new(new_task);
        for (&k, m) in &t.vm().maps() {
            // Recreate any tracee-shared mappings
            if m.local_addr.is_some()
                && !m
                    .flags
                    .intersects(MappingFlags::IS_THREAD_LOCALS | MappingFlags::IS_SYSCALLBUF)
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

    new_task.vm_shr_ptr().after_clone(new_task, Some(t));
}

/// DIFF NOTE: This simply returns a ReplayTraceStep instead of modifying one.
pub fn rep_prepare_run_to_syscall(t: &mut ReplayTask, step: &mut ReplayTraceStep) {
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
        step.action = ReplayTraceStepType::TstepRetire;
        return;
    }

    // DIFF NOTE: @TODO In rr only the syscall number and action are set
    *step = ReplayTraceStep {
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
}

pub fn rep_process_syscall(t: &mut ReplayTask, step: &mut ReplayTraceStep) {
    let arch: SupportedArch;
    let trace_regs: Registers;
    {
        let trace_frame = t.current_trace_frame();
        arch = trace_frame.event().syscall_event().arch();
        trace_regs = trace_frame.regs_ref().clone()
    }
    with_converted_registers(&trace_regs, arch, |converted_regs| {
        rd_arch_function_selfless!(rep_process_syscall_arch, arch, t, step, converted_regs)
    })
}

fn rep_process_syscall_arch<Arch: Architecture>(
    t: &mut ReplayTask,
    step: &mut ReplayTraceStep,
    trace_regs: &Registers,
) {
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
    }

    if sys == Arch::RESTART_SYSCALL {
        sys = t.regs_ref().original_syscallno().try_into().unwrap();
    }

    *step = ReplayTraceStep {
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
        return;
    }

    let nsys: i32 = non_negative_syscall(sys);
    if trace_regs.syscall_failed() {
        if nsys != Arch::MADVISE
            && nsys != Arch::MPROTECT
            && nsys != Arch::SIGRETURN
            && nsys != Arch::RT_SIGRETURN
        {
            return;
        }
    }

    // Manual implementations of irregular syscalls that need to do more during
    // replay than just modify register and memory state.
    // Don't let a negative incoming syscall number be treated as a real
    // system call that we assigned a negative number because it doesn't
    // exist in this architecture.
    // All invalid/unsupported syscalls get the default emulation treatment.
    if nsys == Arch::EXECVE {
        return process_execve(t, step);
    }

    if nsys == Arch::BRK {
        return process_brk(t);
    }

    if nsys == Arch::MMAP {
        match Arch::MMAP_SEMANTICS {
            MmapCallingSemantics::StructArguments => unimplemented!(),
            MmapCallingSemantics::RegisterArguments => {
                return process_mmap(
                    t,
                    trace_regs.arg2(),
                    trace_regs.arg3() as i32,
                    trace_regs.arg4() as i32,
                    trace_regs.arg5() as i32,
                    trace_regs.arg6() / page_size(),
                    step,
                );
            }
        }
    }

    if nsys == Arch::MMAP2 {
        return process_mmap(
            t,
            trace_regs.arg2(),
            trace_regs.arg3() as i32,
            trace_regs.arg4() as i32,
            trace_regs.arg5() as i32,
            trace_regs.arg6(),
            step,
        );
    }

    if nsys == Arch::SHMAT {
        return process_shmat(t, trace_regs, trace_regs.arg3() as i32, step);
    }

    if nsys == Arch::SHMDT {
        return process_shmdt(t, trace_regs, trace_regs.arg1().into(), step);
    }

    if nsys == Arch::MREMAP {
        return process_mremap(t, trace_regs, step);
    }

    if nsys == Arch::MADVISE {
        match t.regs_ref().arg3() as i32 {
            MADV_DONTNEED | MADV_REMOVE => (),
            _ => return,
        }
    }

    if nsys == Arch::MADVISE || nsys == Arch::ARCH_PRCTL {
        let arg1 = t.regs_ref().arg1();
        if sys == Arch::ARCH_PRCTL
            && (arg1 == ARCH_GET_CPUID as usize || arg1 == ARCH_SET_CPUID as usize)
        {
            return;
        }
    }

    if nsys == Arch::MADVISE
        || nsys == Arch::ARCH_PRCTL
        || nsys == Arch::MUNMAP
        || nsys == Arch::MPROTECT
        || nsys == Arch::MODIFY_LDT
        || nsys == Arch::SET_THREAD_AREA
    {
        // Using AutoRemoteSyscalls here fails for arch_prctl, not sure why.
        let mut r: Registers = t.regs_ref().clone();
        r.set_syscallno(t.regs_ref().original_syscallno());
        r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
        t.set_regs(&r);
        if nsys == Arch::MPROTECT {
            t.vm_shr_ptr().fixup_mprotect_growsdown_parameters(t);
        }
        __ptrace_cont(
            t,
            ResumeRequest::ResumeSyscall,
            Arch::arch(),
            nsys,
            None,
            None,
        );
        __ptrace_cont(
            t,
            ResumeRequest::ResumeSyscall,
            Arch::arch(),
            nsys,
            None,
            None,
        );
        ed_assert!(
            t,
            t.regs_ref().syscall_result() == trace_regs.syscall_result()
        );
        if nsys == Arch::MPROTECT {
            let mut r2: Registers = t.regs_ref().clone();
            r2.set_arg1(r.arg1());
            r2.set_arg2(r.arg2());
            r2.set_arg3(r.arg3());
            t.set_regs(&r2);
        }
        // The syscall modified registers. Re-emulate the syscall entry.
        t.canonicalize_regs(step.syscall().arch);
        return;
    }

    if nsys == Arch::IPC {
        match trace_regs.arg1() as u32 {
            SHMAT => return process_shmat(t, trace_regs, trace_regs.arg3() as i32, step),
            SHMDT => return process_shmdt(t, trace_regs, trace_regs.arg5().into(), step),
            _ => return,
        }
    }

    if nsys == Arch::SIGRETURN || nsys == Arch::RT_SIGRETURN {
        t.set_regs(trace_regs);
        let extra_regs = t.current_trace_frame().extra_regs_ref().clone();
        t.set_extra_regs(&extra_regs);
        step.action = ReplayTraceStepType::TstepRetire;
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
        handle_opened_files(t, 0);
        return;
    }

    if nsys == Arch::OPENAT {
        handle_opened_files(t, t.regs_ref().arg3() as i32);
        return;
    }

    if nsys == Arch::OPEN {
        handle_opened_files(t, t.regs_ref().arg2() as i32);
        return;
    }

    if nsys == Arch::WRITE || nsys == Arch::WRITEV {
        // write*() can be desched'd, but don't use scratch,
        // so we might have saved 0 bytes of scratch after a
        // desched.
        maybe_noop_restore_syscallbuf_scratch(t);
        return;
    }

    if nsys == Arch::PROCESS_VM_WRITEV {
        let dest_pid = t.regs_ref().arg1() as pid_t;
        let iov_cnt = t.regs_ref().arg5();
        let t_rc: TaskSharedPtr;
        let mut t_b: RefMut<Box<dyn Task>>;
        let maybe_dest = if dest_pid == t.rec_tid {
            Some(t)
        } else {
            // Recorded data records may be for another process.
            match t.session().find_task_from_rec_tid(dest_pid) {
                Some(found_rc) => {
                    t_rc = found_rc;
                    t_b = t_rc.borrow_mut();
                    Some(t_b.as_replay_task_mut().unwrap())
                }
                None => None,
            }
        };
        match maybe_dest {
            Some(dest) => {
                for _ in 0..iov_cnt {
                    dest.set_data_from_trace();
                }
            }
            None => (),
        }
        return;
    }

    if nsys == Arch::READ {
        if t.cloned_file_data_fd_child >= 0 {
            let fd: i32 = t.regs_ref().arg1() as i32;
            let file_name = t.file_name_of_fd(fd);
            if !file_name.is_empty() && file_name == t.file_name_of_fd(t.cloned_file_data_fd_child)
            {
                // This is a read of the cloned-data file. Replay logic depends on
                // this file's offset actually advancing.
                let mut remote = AutoRemoteSyscalls::new(t);
                // DIFF NOTE: rr has syscall_result() here.
                // However, signed result seems more appropriate??
                remote.infallible_lseek_syscall(
                    fd,
                    trace_regs.syscall_result_signed() as i64,
                    SEEK_CUR,
                );
            }
        }
        return;
    }

    if nsys == Arch::RDCALL_INIT_BUFFERS {
        unimplemented!();
    }

    if nsys == Arch::RDCALL_INIT_PRELOAD {
        t.at_preload_init();
        return;
    }

    if nsys == Arch::RDCALL_RELOAD_AUXV {
        unimplemented!();
    }
}

fn process_brk(t: &mut ReplayTask) {
    let mut data = MappedData::default();
    let km: KernelMapping = t
        .trace_reader_mut()
        .read_mapped_region(Some(&mut data), None, None, None, None)
        .unwrap();
    // Zero flags means it's an an unmap, or no change.
    if !km.flags().is_empty() {
        let mut remote = AutoRemoteSyscalls::new(t);
        ed_assert!(remote.task(), data.source == MappedDataSource::SourceZero);
        remote.infallible_mmap_syscall(
            Some(km.start()),
            km.size(),
            km.prot(),
            MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED | km.flags(),
            -1,
            0,
        );
        remote.task().vm_shr_ptr().map(
            remote.task(),
            km.start(),
            km.size(),
            km.prot(),
            MapFlags::MAP_ANONYMOUS | km.flags(),
            0,
            OsStr::new("[heap]"),
            KernelMapping::NO_DEVICE,
            KernelMapping::NO_INODE,
            None,
            Some(&km),
            None,
            None,
            None,
        );
    } else if km.size() > 0 {
        let arch = t.arch();
        let mut remote = AutoRemoteSyscalls::new(t);
        rd_infallible_syscall!(
            remote,
            syscall_number_for_munmap(arch),
            km.start().as_usize(),
            km.size()
        );
        remote
            .task()
            .vm_shr_ptr()
            .unmap(remote.task(), km.start(), km.size());
    }
}

fn non_negative_syscall(sys: i32) -> i32 {
    if sys < 0 {
        i32::MAX
    } else {
        sys
    }
}

/// Call this when `t` has just entered a syscall.
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
        prepare_clone::<Arch>(t);
    }

    if sys == Arch::PTRACE {
        let pid: pid_t = t.regs_ref().arg2_signed() as pid_t;
        // DIFF NOTE: This assertion is not there in rr.
        ed_assert!(t, pid != t.rec_tid);
        let maybe_target = t.session().find_task_from_rec_tid(pid);
        match maybe_target {
            None => (),
            Some(target) => match t.regs_ref().arg1() as u32 {
                PTRACE_POKETEXT | PTRACE_POKEDATA => {
                    target
                        .borrow_mut()
                        .as_replay_task_mut()
                        .unwrap()
                        .apply_all_data_records_from_trace();
                }
                PTRACE_SYSCALL
                | PTRACE_SINGLESTEP
                | PTRACE_SYSEMU
                | PTRACE_SYSEMU_SINGLESTEP
                | PTRACE_CONT
                | PTRACE_DETACH => {
                    let command = t.regs_ref().arg1() as u32;
                    target
                        .borrow()
                        .set_syscallbuf_locked(command != PTRACE_CONT && command != PTRACE_DETACH);
                }
                PTRACE_SET_THREAD_AREA => {
                    let mut ok = true;
                    let child_addr = t.regs_ref().arg4();
                    let desc: user_desc =
                        read_val_mem(t, RemotePtr::<user_desc>::from(child_addr), Some(&mut ok));
                    if ok {
                        target
                            .borrow_mut()
                            .emulate_set_thread_area(t.regs_ref().arg3() as u32, desc);
                    }
                }
                _ => (),
            },
        }
    }

    if sys == Arch::EXIT {
        // Destroy buffers now to match when we destroyed them during recording.
        // It's possible for another mapping to be created overlapping our
        // buffers before this task truly exits, and we don't want to trash
        // that mapping by destroying our buffers then.
        t.destroy_buffers();
    }

    if sys == Arch::EXIT_GROUP {
        if t.thread_group().task_set().len() == 1 {
            // See above.
            t.destroy_buffers();
        }
    }

    t.apply_all_data_records_from_trace();
}

// DIFF NOTE: This does not take an extra param `trace_frame` as it can be
// obtained from `t` itself
pub fn process_execve(t: &mut ReplayTask, step: &mut ReplayTraceStep) {
    step.action = ReplayTraceStepType::TstepRetire;
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
            fatal!("Cannot find exec stub {:?} to replay this 32-bit process; you probably built rd with disable32bit", stub_filename);
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
            //
            // @TODO Its OK to leave this `if` branch unimplemented as we're assuming
            // newer traces with the required information. The logic here is a bit
            // hairy and can always be filled in later.
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

    let fds_to_close = t
        .current_trace_frame()
        .event()
        .syscall_event()
        .exec_fds_to_close
        .clone();
    t.fd_table_shr_ptr()
        .borrow_mut()
        .close_after_exec(t, &fds_to_close);

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
        // We will have unmapped the stack memory that `remote` would have used for
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
        for i in 1..kms.len() - 1 {
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
        // Note: NOT using AutorestoreMem::push_cstr() as we already have a '\0' at the end
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
}

pub fn restore_mapped_region(
    remote: &mut AutoRemoteSyscalls,
    km: &KernelMapping,
    data: &trace_stream::MappedData,
) {
    ed_assert!(
        remote.task(),
        !km.flags().contains(MapFlags::MAP_SHARED),
        "Shared mappings after exec not supported"
    );

    let real_file_name;
    let mut device: dev_t = KernelMapping::NO_DEVICE;
    let mut inode: ino_t = KernelMapping::NO_INODE;
    let mut flags = km.flags();
    let mut offset_bytes: u64 = 0;

    match data.source {
        MappedDataSource::SourceFile => {
            let real_file: FileStat;
            offset_bytes = km.file_offset_bytes();
            // Private mapping, so O_RDONLY is always OK.
            let res = finish_direct_mmap(
                remote,
                km.start(),
                km.size(),
                km.prot(),
                km.flags(),
                &data.filename,
                OFlag::O_RDONLY,
                data.data_offset_bytes / page_size(),
            );
            real_file = res.0;
            real_file_name = res.1;
            device = real_file.st_dev;
            inode = real_file.st_ino;
        }
        MappedDataSource::SourceTrace | MappedDataSource::SourceZero => {
            real_file_name = OsString::from("");
            flags |= MapFlags::MAP_ANONYMOUS;
            remote.infallible_mmap_syscall(
                Some(km.start()),
                km.size(),
                km.prot(),
                (flags & !MapFlags::MAP_GROWSDOWN) | MapFlags::MAP_FIXED,
                -1,
                0,
            );
            // The data, if any, will be written back by
            // ReplayTask::apply_all_data_records_from_trace
        }
    }

    remote.task().vm_shr_ptr().map(
        remote.task_mut(),
        km.start(),
        km.size(),
        km.prot(),
        flags,
        offset_bytes,
        real_file_name.as_os_str(),
        device,
        inode,
        None,
        Some(&km),
        None,
        None,
        None,
    );
}

fn finish_direct_mmap(
    remote: &mut AutoRemoteSyscalls,
    rec_addr: RemotePtr<u8>,
    length: usize,
    prot: ProtFlags,
    flags: MapFlags,
    backing_filename: &OsStr,
    backing_file_open_flags: OFlag,
    backing_offset_pages: usize,
) -> (FileStat, OsString) {
    let fd: i32;
    log!(
        LogDebug,
        "directly mmap'ing {} bytes of {:?} at page offset {:#x}",
        length,
        backing_filename,
        backing_offset_pages
    );

    ed_assert!(remote.task(), !flags.contains(MapFlags::MAP_GROWSDOWN));

    // Open in the tracee the file that was mapped during
    // recording.
    {
        let arch = remote.arch();
        let mut child_mem = AutoRestoreMem::push_cstr(remote, backing_filename.as_bytes());
        let child_addr = child_mem.get().unwrap();
        fd = rd_infallible_syscall!(
            child_mem,
            syscall_number_for_open(arch),
            child_addr.as_usize(),
            backing_file_open_flags.bits()
        ) as i32;
    }
    // And mmap that file.
    remote.infallible_mmap_syscall(
        Some(rec_addr),
        length,
        // (We let SHARED|WRITEABLE
        // mappings go through while
        // they're not handled properly,
        // but we shouldn't do that.)
        prot,
        // MAP_SYNC does not seem to be present in 0.17 version of nix
        (flags & unsafe { !MapFlags::from_bits_unchecked(MAP_SYNC) }) | MapFlags::MAP_FIXED,
        fd,
        // MAP_SYNC is used to request direct mapping
        // (DAX) from the filesystem for persistent
        // memory devices (requires
        // MAP_SHARED_VALIDATE). Drop it for the
        // backing file.
        backing_offset_pages as u64,
    );

    // While it's open, grab the link reference.
    let real_file = remote.task().stat_fd(fd);
    let real_file_name = remote.task().file_name_of_fd(fd);

    // Don't leak the tmp fd.  The mmap doesn't need the fd to stay open.
    let arch = remote.arch();
    rd_infallible_syscall!(remote, syscall_number_for_close(arch), fd);
    (real_file, real_file_name)
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

fn handle_opened_files(t: &mut ReplayTask, flags_raw: i32) {
    // @TODO The from_bits_unchecked seems to be needed here cause in x86 there is a flag that
    // is not recognized here by OFlag::from_bits(flags_raw).unwrap(). Check again?
    let flags = unsafe { OFlag::from_bits_unchecked(flags_raw) };

    let opened = t.current_trace_frame().event().syscall().opened.clone();
    for o in &opened {
        // This must be kept in sync with record_syscall's handle_opened_file.
        let maybe_emu_file: Option<EmuFileSharedPtr> = t
            .session()
            .as_replay()
            .unwrap()
            .emufs()
            .find(o.device, o.inode);
        let file_monitor: Box<dyn FileMonitor>;
        if maybe_emu_file.is_some() {
            file_monitor = Box::new(MmappedFileMonitor::new_from_emufile(
                t,
                maybe_emu_file.unwrap(),
            ));
        } else if o.path == "terminal" {
            file_monitor = Box::new(StdioMonitor::new(STDERR_FILENO));
        } else if is_proc_mem_file(&o.path) {
            file_monitor = Box::new(ProcMemMonitor::new(t, &o.path));
        } else if is_proc_fd_dir(&o.path) {
            file_monitor = Box::new(ProcFdDirMonitor::new(t, &o.path));
        } else if flags.contains(OFlag::O_DIRECT) {
            file_monitor = Box::new(BaseFileMonitor::new())
        } else {
            ed_assert!(t, false, "Why did we write filename {:?}", o.path);
            unreachable!();
        }
        t.fd_table_shr_ptr()
            .borrow_mut()
            .add_monitor(t, o.fd, file_monitor);
    }
}

// DIFF NOTE: This does not take an extra param `trace_frame` as it can be
// obtained from `t` itself
fn process_mmap(
    t: &mut ReplayTask,
    mut length: usize,
    prot_raw: i32,
    flags_raw: i32,
    fd: i32,
    mut offset_pages: usize,
    step: &mut ReplayTraceStep,
) {
    let prot = ProtFlags::from_bits(prot_raw).unwrap();
    let flags = MapFlags::from_bits(flags_raw).unwrap();

    step.action = ReplayTraceStepType::TstepRetire;

    {
        let mut addr: RemotePtr<Void> = t.current_trace_frame().regs_ref().syscall_result().into();
        // Hand off actual execution of the mapping to the appropriate helper.
        let mut remote = AutoRemoteSyscalls::new_with_mem_params(
            t,
            if !flags.contains(MapFlags::MAP_SHARED) && flags.contains(MapFlags::MAP_ANONYMOUS) {
                MemParamsEnabled::DisableMemoryParams
            } else {
                MemParamsEnabled::EnableMemoryParams
            },
        );
        if flags.contains(MapFlags::MAP_ANONYMOUS) {
            let syscall_result = remote
                .task()
                .as_replay_task()
                .unwrap()
                .current_trace_frame()
                .regs_ref()
                .syscall_result();
            finish_anonymous_mmap(
                &mut remote,
                RemotePtr::new_from_val(syscall_result),
                length,
                prot,
                flags,
            );
        } else {
            let mut data = MappedData::default();
            let mut extra_fds: Vec<TraceRemoteFd> = Vec::new();
            let mut skip_monitoring_mapped_fd: bool = false;
            let mut km: KernelMapping = remote
                .task_mut()
                .as_replay_task()
                .unwrap()
                .trace_reader_mut()
                .read_mapped_region(
                    Some(&mut data),
                    Some(ValidateSourceFile::Validate),
                    Some(TimeConstraint::CurrentTimeOnly),
                    Some(&mut extra_fds),
                    Some(&mut skip_monitoring_mapped_fd),
                )
                .unwrap();

            if data.source == MappedDataSource::SourceFile
                && data.file_size_bytes > data.data_offset_bytes
            {
                let map_bytes: usize = min(
                    ceil_page_size(data.file_size_bytes) - data.data_offset_bytes,
                    length,
                );
                let (real_file, real_file_name) = finish_direct_mmap(
                    &mut remote,
                    addr,
                    map_bytes,
                    prot,
                    flags,
                    data.filename.as_os_str(),
                    OFlag::O_RDONLY,
                    data.data_offset_bytes / page_size(),
                );
                let km_sub: KernelMapping =
                    km.subrange(km.start(), km.start() + ceil_page_size(map_bytes));
                remote.task().vm_shr_ptr().map(
                    remote.task(),
                    km.start(),
                    map_bytes,
                    prot,
                    flags,
                    page_size() as u64 * offset_pages as u64,
                    real_file_name.as_os_str(),
                    real_file.st_dev,
                    real_file.st_ino,
                    None,
                    Some(&km_sub),
                    None,
                    None,
                    None,
                );
                addr += map_bytes;
                length -= map_bytes;
                offset_pages += ceil_page_size(map_bytes) / page_size();
                data.source = MappedDataSource::SourceZero;
                km = km.subrange(km_sub.end(), km.end());
            }
            if length > 0 {
                if flags.contains(MapFlags::MAP_SHARED) {
                    if !skip_monitoring_mapped_fd {
                        extra_fds.push(TraceRemoteFd {
                            tid: remote.task().rec_tid,
                            fd,
                        });
                    }
                    finish_shared_mmap(
                        &mut remote,
                        addr,
                        length,
                        prot,
                        flags,
                        &extra_fds,
                        offset_pages,
                        &km,
                        &data,
                    );
                } else {
                    ed_assert!(remote.task(), extra_fds.is_empty());
                    finish_private_mmap(
                        &mut remote,
                        addr,
                        length,
                        prot,
                        flags,
                        offset_pages,
                        km,
                        &data,
                    );
                }
            }
        }

        // This code is used to test the sharing functionality. It is in
        // general a bad idea to indiscriminately share mappings between the
        // tracer and the tracee. Instead, only mappings that have
        // sufficiently many memory access from the tracer to require
        // acceleration should be shared.
        if !flags.contains(MapFlags::MAP_SHARED)
            && remote
                .task()
                .session()
                .as_replay()
                .unwrap()
                .flags()
                .share_private_mappings
        {
            let vm_shr_ptr = remote.task().vm_shr_ptr();
            let mapping = vm_shr_ptr.mapping_of(addr).unwrap().clone();
            remote.make_private_shared(mapping);
        }

        // Finally, we finish by emulating the return value.
        let syscall_result = remote
            .task()
            .as_replay_task()
            .unwrap()
            .current_trace_frame()
            .regs_ref()
            .syscall_result();
        remote.initial_regs_mut().set_syscall_result(syscall_result);
    }
    // Monkeypatcher can emit data records that need to be applied now
    t.apply_all_data_records_from_trace();
    t.validate_regs(ReplayTaskIgnore::default());
}

fn finish_shared_mmap<'a>(
    remote: &mut AutoRemoteSyscalls<'a>,
    rec_addr: RemotePtr<u8>,
    length: usize,
    prot: ProtFlags,
    flags: MapFlags,
    fds: &[TraceRemoteFd],
    offset_pages: usize,
    km: &KernelMapping,
    data: &MappedData,
) {
    // Ensure there's a virtual file for the file that was mapped
    // during recording.
    let emufile: EmuFileSharedPtr = remote
        .task()
        .session()
        .as_replay()
        .unwrap()
        .emufs_mut()
        .get_or_create(&km);
    // Re-use the direct_map() machinery to map the virtual file.
    //
    // NB: the tracee will map the procfs link to our fd; there's
    // no "real" name for the file anywhere, to ensure that when
    // we exit/crash the kernel will clean up for us.
    // Emufs file, so open it read-write in case we want to write to it through
    // the task's mem fd.
    let (real_file, real_file_name) = finish_direct_mmap(
        remote,
        rec_addr,
        km.size(),
        prot,
        flags,
        &OsString::from(emufile.borrow().proc_path()),
        OFlag::O_RDWR,
        offset_pages,
    );
    // Write back the snapshot of the segment that we recorded.
    //
    // TODO: this is a poor man's shared segment synchronization.
    // For full generality, we also need to emulate direct file
    // modifications through write/splice/etc.
    //
    // Update AddressSpace before loading data from the trace. This ensures our
    // kernel-bug-workarounds when writing to tracee memory see the up-to-date
    // virtual map.
    let offset_bytes: u64 = page_size() as u64 * offset_pages as u64;
    remote.task().vm_shr_ptr().map(
        remote.task(),
        rec_addr,
        km.size(),
        prot,
        flags,
        offset_bytes,
        real_file_name.as_os_str(),
        real_file.st_dev,
        real_file.st_ino,
        None,
        Some(&km),
        Some(emufile.clone()),
        None,
        None,
    );

    write_mapped_data(
        remote.task_mut().as_replay_task_mut().unwrap(),
        rec_addr,
        km.size(),
        data,
    );

    log!(
        LogDebug,
        "  restored {} bytes at {:#x} to {:?} for {:?}",
        length,
        offset_bytes,
        emufile.borrow().real_path(),
        emufile.borrow().emu_path()
    );

    let process = |rt: &mut dyn Task, fd: &TraceRemoteFd| -> () {
        let maybe_mon = rt.fd_table().get_monitor(fd.fd);
        match maybe_mon {
            Some(file_mon_shr_ptr) => {
                ed_assert!(
                    rt,
                    file_mon_shr_ptr.borrow().file_monitor_type() == FileMonitorType::Mmapped
                );
                file_mon_shr_ptr
                    .borrow_mut()
                    .as_mmapped_file_monitor_mut()
                    .unwrap()
                    .revive();
            }
            None => {
                let fm = Box::new(MmappedFileMonitor::new_from_emufile(rt, emufile.clone()));
                rt.fd_table_shr_ptr()
                    .borrow_mut()
                    .add_monitor(rt, fd.fd, fm);
            }
        };
    };

    for fd in fds {
        if remote.task().rec_tid == fd.tid {
            process(remote.task_mut(), fd);
        } else {
            match remote.task().session().find_task_from_rec_tid(fd.tid) {
                Some(shr_ptr) => {
                    let mut t_b = shr_ptr.borrow_mut();
                    process(t_b.as_mut(), fd);
                }
                None => {
                    ed_assert!(remote.task(), false, "Can't find task {}", fd.tid);
                }
            };
        }
    }
}

fn finish_private_mmap(
    remote: &mut AutoRemoteSyscalls,
    rec_addr: RemotePtr<Void>,
    length: usize,
    prot: ProtFlags,
    flags: MapFlags,
    offset_pages: usize,
    km: KernelMapping,
    data: &MappedData,
) {
    log!(LogDebug, "  finishing private mmap of {:?}", km.fsname());

    remote.infallible_mmap_syscall(
        Some(rec_addr),
        length,
        prot,
        // Tell the kernel to take `rec_addr` seriously.
        (flags & !MapFlags::MAP_GROWSDOWN) | MapFlags::MAP_FIXED | MapFlags::MAP_ANONYMOUS,
        -1,
        0,
    );

    // Update AddressSpace before loading data from the trace. This ensures our
    // kernel-bug-workarounds when writing to tracee memory see the up-to-date
    // virtual map.
    remote.task().vm_shr_ptr().map(
        remote.task_mut(),
        rec_addr,
        length,
        prot,
        flags | MapFlags::MAP_ANONYMOUS,
        page_size() as u64 * offset_pages as u64,
        OsStr::new(""),
        KernelMapping::NO_DEVICE,
        KernelMapping::NO_INODE,
        None,
        Some(&km),
        None,
        None,
        None,
    );

    // Restore the map region we copied.
    write_mapped_data(
        remote.task_mut().as_replay_task_mut().unwrap(),
        rec_addr,
        km.size(),
        data,
    );
}

fn write_mapped_data(
    t: &mut ReplayTask,
    mut rec_addr: RemotePtr<Void>,
    mut size: usize,
    data: &MappedData,
) {
    match data.source {
        MappedDataSource::SourceTrace => {
            t.set_data_from_trace();
        }
        MappedDataSource::SourceFile => {
            let file = ScopedFd::open_path(data.filename.as_os_str(), OFlag::O_RDONLY);
            ed_assert!(t, file.is_open(), "Can't open {:?}", data.filename);
            let offset: off_t = lseek(
                file.as_raw(),
                data.data_offset_bytes as i64,
                Whence::SeekSet,
            )
            .unwrap();
            let d_offset: off_t = data.data_offset_bytes.try_into().unwrap();
            ed_assert!(
                t,
                offset == d_offset,
                "Couldn't seek to {}, got {}",
                data.data_offset_bytes,
                offset
            );
            let mut buf: Vec<u8> = Vec::new();
            // Read 16 pages at a time at most
            // @TODO Any performance implications of this resize??
            buf.resize(page_size() * 16, 0);
            while size > 0 {
                let to_read = min(size, buf.len());
                match read(file.as_raw(), &mut buf[0..to_read]) {
                    Err(_) => {
                        fatal!("Can't read from trace file: {:?}", data.filename);
                        unreachable!();
                    }
                    Ok(0) => {
                        break;
                    }
                    Ok(nread) => {
                        t.write_bytes_helper(rec_addr, &buf[0..nread], None, WriteFlags::empty());
                        rec_addr += nread;
                        size -= nread;
                    }
                }
            }
        }
        MappedDataSource::SourceZero => {}
    }
}

fn finish_anonymous_mmap(
    remote: &mut AutoRemoteSyscalls,
    rec_addr: RemotePtr<Void>,
    length: usize,
    prot: ProtFlags,
    flags: MapFlags,
) {
    let mut file_name = OsString::new();
    let mut device: dev_t = KernelMapping::NO_DEVICE;
    let mut inode: ino_t = KernelMapping::NO_INODE;
    let mut data = MappedData::default();
    let recorded_km: KernelMapping = remote
        .task()
        .as_replay_task()
        .unwrap()
        .trace_reader_mut()
        .read_mapped_region(Some(&mut data), None, None, None, None)
        .unwrap();
    let mut maybe_emu_file = None;
    if !flags.contains(MapFlags::MAP_SHARED) {
        remote.infallible_mmap_syscall(
            Some(rec_addr),
            length,
            prot,
            // Tell the kernel to take `rec_addr` seriously.
            (flags & !MapFlags::MAP_GROWSDOWN) | MapFlags::MAP_FIXED,
            -1,
            0,
        );
    } else {
        ed_assert!(remote.task(), data.source == MappedDataSource::SourceZero);
        let emu_file: EmuFileSharedPtr = remote
            .task()
            .session()
            .as_replay()
            .unwrap()
            .emufs_mut()
            .get_or_create(&recorded_km);

        // Emufs file, so open it read-write in case we need to write to it
        // through the task's memfd.
        let (real_file, real_file_name) = finish_direct_mmap(
            remote,
            rec_addr,
            length,
            prot,
            flags & !MapFlags::MAP_ANONYMOUS,
            OsStr::new(&emu_file.borrow().proc_path()),
            OFlag::O_RDWR,
            0,
        );
        file_name = real_file_name;
        device = real_file.st_dev;
        inode = real_file.st_ino;
        maybe_emu_file = Some(emu_file);
    }

    remote.task().vm_shr_ptr().map(
        remote.task(),
        rec_addr,
        length,
        prot,
        flags,
        0,
        &file_name,
        device,
        inode,
        None,
        Some(&recorded_km),
        maybe_emu_file,
        None,
        None,
    );
}

/// DIFF NOTE: Take trace_regs as param. rr takes trace_frame instead.
fn process_mremap(t: &mut ReplayTask, trace_regs: &Registers, step: &mut ReplayTraceStep) {
    step.action = ReplayTraceStepType::TstepRetire;

    let original_syscallno: i32 = trace_regs.original_syscallno() as i32;
    let old_addr: RemotePtr<Void> = trace_regs.arg1().into();
    let old_size: usize = ceil_page_size(trace_regs.arg2());
    let new_addr: RemotePtr<Void> = trace_regs.syscall_result().into();
    let new_size: usize = ceil_page_size(trace_regs.arg3());

    // The recorded mremap call succeeded, so we know the original mapping can be
    // treated as a single mapping.
    t.vm_shr_ptr()
        .ensure_replay_matches_single_recorded_mapping(
            t,
            MemoryRange::new_range(old_addr, old_size),
        );

    let mut data = MappedData::default();
    t.trace_reader_mut()
        .read_mapped_region(Some(&mut data), None, None, None, None);
    ed_assert!(t, data.source == MappedDataSource::SourceZero);
    // We don't need to do anything; this is the mapping record for the moved
    // data.

    // Try reading a mapping record for new data.
    let maybe_km = t
        .trace_reader_mut()
        .read_mapped_region(Some(&mut data), None, None, None, None);

    {
        // We must emulate mremap because the kernel's choice for the remap
        // destination can vary (in particular, when we emulate exec it makes
        // different decisions).
        let mut remote = AutoRemoteSyscalls::new(t);
        if new_addr == old_addr {
            // Non-moving mremap. Don't pass MREMAP_FIXED or MREMAP_MAYMOVE
            // since that triggers EINVAL when the new map overlaps the old map.
            rd_infallible_syscall_ptr!(
                remote,
                original_syscallno,
                new_addr.as_usize(),
                old_size,
                new_size,
                0
            );
        } else {
            // Force the mremap to use the destination address from recording.
            // XXX could the new mapping overlap the old, with different start
            // addresses? Hopefully the kernel doesn't do that to us!!!
            rd_infallible_syscall_ptr!(
                remote,
                original_syscallno,
                old_addr.as_usize(),
                old_size,
                new_size,
                MREMAP_MAYMOVE | MREMAP_FIXED,
                new_addr.as_usize()
            );
        }

        remote
            .initial_regs_mut()
            .set_syscall_result(new_addr.as_usize());
    }

    t.vm().remap(t, old_addr, old_size, new_addr, new_size);

    // This needs to be cloned because it might be changed/removed so we can't borrow it.
    let mut mapping = t.vm().mapping_of(new_addr).unwrap().clone();
    let maybe_f = mapping.emu_file;
    match maybe_f.as_ref() {
        Some(f) => {
            f.borrow_mut()
                .ensure_size(mapping.map.file_offset_bytes() + new_size as u64);
        }
        None if new_size > old_size && !mapping.map.fsname().is_empty() => {
            let st: FileStat;
            match stat(mapping.map.fsname()) {
                Err(_) => {
                    fatal!("Can't stat {:?}", mapping.map.fsname());
                    unreachable!();
                }
                Ok(res) => st = res,
            }
            // @TODO Should be fine to cast st_size as u64 but any edge cases?
            if ceil_page_u64(st.st_size as u64) < mapping.map.file_offset_bytes() + new_size as u64
            {
                // Replace mapping with anonymous mapping to cover full mapped region.
                // Don't just read the file data, since this could be a private mapping
                // with some data changed.
                let mut buf = Vec::<u8>::new();
                buf.resize(old_size, 0);
                t.read_bytes_helper(new_addr, &mut buf, None);
                let mut remote = AutoRemoteSyscalls::new(t);
                // Shared non-EmuFs mappings must be of immutable files so it's OK to
                // just copy the file data into a private mapping here.
                let map_flags =
                    MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED;
                remote.infallible_mmap_syscall(
                    Some(new_addr),
                    new_size,
                    mapping.map.prot(),
                    map_flags,
                    -1,
                    0,
                );
                remote
                    .task()
                    .vm_shr_ptr()
                    .unmap(remote.task(), new_addr, new_size);
                remote.task().vm_shr_ptr().map(
                    remote.task(),
                    new_addr,
                    new_size,
                    mapping.map.prot(),
                    map_flags,
                    mapping.map.file_offset_bytes(),
                    OsStr::new(""),
                    KernelMapping::NO_DEVICE,
                    KernelMapping::NO_INODE,
                    None,
                    Some(&mapping.recorded_map),
                    None,
                    None,
                    None,
                );
                remote
                    .task_mut()
                    .write_bytes_helper(new_addr, &buf, None, WriteFlags::empty());
                mapping = remote.task().vm().mapping_of(new_addr).unwrap().clone();
            }
        }
        _ => (),
    }

    // MappedDataSource::SourceFile for mapped files should be handled automatically by the mremap
    // above.
    // (If we started storing partial files, we'd have to careful to ensure this
    // is still the case.)
    match maybe_km {
        Some(_km) => {
            if data.source != MappedDataSource::SourceFile
                || maybe_f.is_some()
                || mapping.map.fsname().is_empty()
            {
                write_mapped_data(t, new_addr + old_size, new_size - old_size, &data);
            }
        }
        None => (),
    }

    t.validate_regs(ReplayTaskIgnore::default());
}

/// DIFF NOTE: Takes `trace_regs` instead of trace frame as a param
fn process_shmat(
    t: &mut ReplayTask,
    trace_regs: &Registers,
    shm_flags: i32,
    step: &mut ReplayTraceStep,
) {
    step.action = ReplayTraceStepType::TstepRetire;

    {
        let mut data = MappedData::default();
        let km: KernelMapping = t
            .trace_reader_mut()
            .read_mapped_region(Some(&mut data), None, None, None, None)
            .unwrap();
        let mut remote = AutoRemoteSyscalls::new(t);
        let prot: ProtFlags = shm_flags_to_mmap_prot(shm_flags);
        let flags: MapFlags = MapFlags::MAP_SHARED;
        finish_shared_mmap(
            &mut remote,
            km.start(),
            km.size(),
            prot,
            flags,
            &vec![],
            0,
            &km,
            &data,
        );
        remote.task().vm().set_shm_size(km.start(), km.size());

        // Finally, we finish by emulating the return value.
        // On x86-32 this is not the shm address...
        remote
            .initial_regs_mut()
            .set_syscall_result(trace_regs.syscall_result());
    }
    // on x86-32 we have an extra data record that we need to apply ---
    // the ipc syscall's klugy out-parameter.
    t.apply_all_data_records_from_trace();
    t.validate_regs(ReplayTaskIgnore::default());
}

/// DIFF NOTE: Takes `trace_regs` instead of trace frame as a param
fn process_shmdt(
    t: &mut ReplayTask,
    trace_regs: &Registers,
    addr: RemotePtr<Void>,
    step: &mut ReplayTraceStep,
) {
    step.action = ReplayTraceStepType::TstepRetire;

    {
        let size: usize = t.vm().get_shm_size(addr);
        let arch = t.arch();
        let mut remote = AutoRemoteSyscalls::new(t);
        rd_infallible_syscall!(
            remote,
            syscall_number_for_munmap(arch),
            addr.as_usize(),
            size
        );
        remote
            .initial_regs_mut()
            .set_syscall_result(trace_regs.syscall_result());
    }
    t.validate_regs(ReplayTaskIgnore::default());
}
