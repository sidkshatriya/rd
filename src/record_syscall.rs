use crate::{
    arch::Architecture,
    arch_structs::{kernel_sigaction, mmap_args},
    auto_remote_syscalls::{AutoRemoteSyscalls, MemParamsEnabled},
    bindings::{
        kernel::TIOCGWINSZ,
        prctl::{
            ARCH_GET_CPUID,
            ARCH_GET_FS,
            ARCH_GET_GS,
            ARCH_SET_CPUID,
            ARCH_SET_FS,
            ARCH_SET_GS,
            PR_CAPBSET_DROP,
            PR_CAPBSET_READ,
            PR_CAP_AMBIENT,
            PR_GET_CHILD_SUBREAPER,
            PR_GET_DUMPABLE,
            PR_GET_ENDIAN,
            PR_GET_FPEMU,
            PR_GET_FPEXC,
            PR_GET_KEEPCAPS,
            PR_GET_NAME,
            PR_GET_NO_NEW_PRIVS,
            PR_GET_PDEATHSIG,
            PR_GET_SECCOMP,
            PR_GET_SPECULATION_CTRL,
            PR_GET_TIMERSLACK,
            PR_GET_TSC,
            PR_GET_UNALIGN,
            PR_MCE_KILL,
            PR_MCE_KILL_GET,
            PR_SET_CHILD_SUBREAPER,
            PR_SET_DUMPABLE,
            PR_SET_KEEPCAPS,
            PR_SET_NAME,
            PR_SET_NO_NEW_PRIVS,
            PR_SET_PDEATHSIG,
            PR_SET_PTRACER,
            PR_SET_SECCOMP,
            PR_SET_SPECULATION_CTRL,
            PR_SET_TIMERSLACK,
            PR_SET_TSC,
            PR_TSC_ENABLE,
            PR_TSC_SIGSEGV,
        },
        ptrace::{PTRACE_EVENT_EXEC, PTRACE_EVENT_EXIT, PTRACE_O_TRACEEXEC, PTRACE_O_TRACEEXIT},
    },
    event::Switchable,
    file_monitor::{self, LazyOffset},
    kernel_abi::{
        is_at_syscall_instruction,
        is_exit_group_syscall,
        is_exit_syscall,
        syscall_instruction_length,
        syscall_number_for_munmap,
        syscall_number_for_rt_sigprocmask,
        MmapCallingSemantics,
        Ptr,
        SupportedArch,
    },
    kernel_metadata::{errno_name, is_sigreturn, syscall_name},
    kernel_supplement::sig_set_t,
    log::{LogDebug, LogWarn},
    monitored_shared_memory::MonitoredSharedMemory,
    preload_interface::{
        syscallbuf_record,
        SYS_rdcall_init_preload,
        SYS_rdcall_notify_control_msg,
        SYS_rdcall_notify_syscall_hook_exit,
    },
    registers::{with_converted_registers, Registers},
    remote_ptr::{RemotePtr, Void},
    seccomp_filter_rewriter::SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO,
    session::{
        address_space::{address_space::AddressSpace, kernel_mapping::KernelMapping},
        session_inner::SessionInner,
        task::{
            record_task::RecordTask,
            task_common::{read_mem, read_val_mem, write_mem, write_val_mem},
            Task,
            TaskSharedWeakPtr,
        },
    },
    sig,
    taskish_uid::TaskUid,
    trace::{
        trace_task_event::TraceTaskEvent,
        trace_writer::{MappingOrigin, RecordInTrace},
    },
    util::{ceil_page_size, page_size, read_auxv, word_at, word_size},
    wait_status::WaitStatus,
};
use libc::{
    AT_ENTRY,
    EINVAL,
    ENOSYS,
    ENOTTY,
    FUTEX_CMD_MASK,
    FUTEX_CMP_REQUEUE,
    FUTEX_CMP_REQUEUE_PI,
    FUTEX_LOCK_PI,
    FUTEX_TRYLOCK_PI,
    FUTEX_UNLOCK_PI,
    FUTEX_WAIT,
    FUTEX_WAIT_BITSET,
    FUTEX_WAIT_REQUEUE_PI,
    FUTEX_WAKE,
    FUTEX_WAKE_BITSET,
    FUTEX_WAKE_OP,
    MAP_32BIT,
    MAP_FIXED,
    MAP_GROWSDOWN,
    SECCOMP_MODE_FILTER,
    SECCOMP_MODE_STRICT,
    SIGKILL,
    SIGSTOP,
    SIG_BLOCK,
};
use nix::sys::{
    mman::{MapFlags, ProtFlags},
    stat,
};
use std::{
    cell::{RefCell, RefMut},
    cmp::{max, min},
    convert::TryInto,
    ffi::OsString,
    intrinsics::copy_nonoverlapping,
    mem::{self, size_of},
    os::{raw::c_uint, unix::ffi::OsStringExt},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

extern "C" {
    fn ioctl_type(nr: c_uint) -> c_uint;
    fn ioctl_size(nr: c_uint) -> c_uint;
    fn ioctl_dir(nr: c_uint) -> c_uint;
    fn ioctl_nr(nr: c_uint) -> c_uint;
}

/// Prepare |t| to enter its current syscall event.  Return ALLOW_SWITCH if
/// a context-switch is allowed for |t|, PREVENT_SWITCH if not.
pub fn rec_prepare_syscall(t: &mut RecordTask) -> Switchable {
    if t.syscall_state.is_none() {
        let mut new_ts = TaskSyscallState::new(t.tuid());
        new_ts.init(t);
        t.syscall_state = Some(Rc::new(RefCell::new(new_ts)));
    }

    let s = rec_prepare_syscall_internal(t);
    let syscallno = t.ev().syscall_event().number;
    if is_sigreturn(syscallno, t.ev().syscall_event().arch()) {
        // There isn't going to be an exit event for this syscall, so remove
        // syscall_state now.
        t.syscall_state = None;
        return s;
    }

    t.syscall_state_unwrap().borrow_mut().done_preparing(t, s)
}

/// DIFF NOTE: Does not take separate TaskSyscallState param
/// as that can be gotten from t directly
fn rec_prepare_syscall_internal(t: &mut RecordTask) -> Switchable {
    let arch: SupportedArch = t.ev().syscall_event().arch();
    let regs = t.regs_ref().clone();
    with_converted_registers(&regs, arch, |converted_regs| {
        rd_arch_function_selfless!(rec_prepare_syscall_arch, arch, t, converted_regs)
    })
}

/// DIFF NOTE: Does not take separate TaskSyscallState param
/// as that can be gotten from t directly
fn rec_prepare_syscall_arch<Arch: Architecture>(
    t: &mut RecordTask,
    regs: &Registers,
) -> Switchable {
    let sys = t.ev().syscall_event().number;

    if t.regs_ref().original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO {
        // rd vetoed this syscall. Don't do any pre-processing.
        return Switchable::PreventSwitch;
    }

    let syscall_state_shr = t.syscall_state_unwrap();
    let mut syscall_state = syscall_state_shr.borrow_mut();
    syscall_state.syscall_entry_registers = regs.clone();

    if !t.desched_rec().is_null() {
        // |t| was descheduled while in a buffered syscall.  We normally don't
        // use scratch memory for the call, because the syscallbuf itself
        // is serving that purpose. More importantly, we *can't* set up
        // scratch for |t|, because it's already in the syscall. Instead, we will
        // record the syscallbuf memory in rec_process_syscall_arch.
        //
        // However there is one case where we use scratch memory: when
        // sys_read's block-cloning path is interrupted. In that case, record
        // the scratch memory.
        if sys == Arch::READ && regs.arg2() == t.scratch_ptr.as_usize() {
            syscall_state.reg_parameter_with_size(
                2,
                ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg3()),
                Some(ArgMode::InOutNoScratch),
                None,
            );
        }

        return Switchable::AllowSwitch;
    }

    if sys < 0 {
        // Invalid syscall. Don't let it accidentally match a
        // syscall number below that's for an undefined syscall.
        syscall_state.expect_errno = ENOSYS;
        return Switchable::PreventSwitch;
    }

    if sys == Arch::GETEUID
        || sys == Arch::ACCESS
        || sys == Arch::SET_TID_ADDRESS
        || sys == Arch::SET_ROBUST_LIST
    {
        return Switchable::PreventSwitch;
    }

    if sys == Arch::UNAME {
        syscall_state.reg_parameter::<Arch::utsname>(1, None, None);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::FSTAT {
        syscall_state.reg_parameter::<Arch::stat>(2, None, None);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::IOCTL {
        return prepare_ioctl::<Arch>(t, &mut syscall_state);
    }

    if sys == Arch::EXECVE {
        let mut cmd_line = Vec::new();
        let mut argv = RemotePtr::<Arch::unsigned_word>::from(regs.arg2());
        loop {
            let p = read_val_mem(t, argv, None);
            if p == 0.into() {
                break;
            }
            let component = t.read_c_str(RemotePtr::new_from_val(p.try_into().unwrap()));
            cmd_line.push(OsString::from_vec(component.into_bytes()));
            argv += 1;
        }

        // Save the event. We can't record it here because the exec might fail.
        let raw_filename = t.read_c_str(RemotePtr::from(regs.arg1()));
        syscall_state.exec_saved_event = Some(Box::new(TraceTaskEvent::for_exec(
            t.tid,
            &OsString::from_vec(raw_filename.into_bytes()),
            &cmd_line,
        )));

        // This can trigger unstable exits of non-main threads, so we have to
        // allow them to be handled.
        return Switchable::AllowSwitch;
    }

    if sys == Arch::WRITE || sys == Arch::WRITEV {
        let fd = regs.arg1_signed() as i32;
        return t.fd_table().will_write(t, fd);
    }

    if sys == Arch::EXIT_GROUP {
        if t.thread_group().task_set().len() == 1 {
            prepare_exit(t, regs.arg1() as i32);
            return Switchable::AllowSwitch;
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::ARCH_PRCTL {
        match regs.arg1_signed() as u32 {
            ARCH_SET_FS | ARCH_SET_GS => (),

            ARCH_GET_FS | ARCH_GET_GS => {
                syscall_state.reg_parameter::<Arch::unsigned_long>(2, None, None);
            }

            ARCH_SET_CPUID => {
                if SessionInner::has_cpuid_faulting() {
                    // Prevent the actual SET_CPUID call.
                    let mut r: Registers = t.regs_ref().clone();
                    r.set_arg1_signed(-1);
                    t.set_regs(&r);
                    let val = t.regs_ref().arg2() as i32;
                    t.cpuid_mode = !!val;
                    syscall_state.emulate_result(0);
                }
            }

            ARCH_GET_CPUID => {
                if SessionInner::has_cpuid_faulting() {
                    // Prevent the actual GET_CPUID call and return our emulated state.
                    let mut r: Registers = t.regs_ref().clone();
                    r.set_arg1_signed(-1);
                    t.set_regs(&r);
                    syscall_state.emulate_result_signed(t.cpuid_mode as isize);
                }
            }

            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }

        return Switchable::PreventSwitch;
    }
    // int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned
    // long arg4, unsigned long arg5);
    if sys == Arch::PRCTL {
        // @TODO This is a arg1_signed() as i32 in rr
        match regs.arg1() as u32 {
            PR_GET_CHILD_SUBREAPER
            | PR_GET_ENDIAN
            | PR_GET_FPEMU
            | PR_GET_FPEXC
            | PR_GET_PDEATHSIG
            | PR_GET_UNALIGN => {
                syscall_state.reg_parameter::<i32>(2, None, None);
            }

            PR_GET_KEEPCAPS
            | PR_GET_NO_NEW_PRIVS
            | PR_GET_TIMERSLACK
            | PR_MCE_KILL
            | PR_MCE_KILL_GET
            | PR_SET_CHILD_SUBREAPER
            | PR_SET_KEEPCAPS
            | PR_SET_NAME
            | PR_SET_PDEATHSIG
            | PR_SET_TIMERSLACK
            | PR_CAP_AMBIENT
            | PR_CAPBSET_DROP
            | PR_CAPBSET_READ
            | PR_GET_SPECULATION_CTRL
            | PR_SET_SPECULATION_CTRL => (),

            PR_SET_DUMPABLE => {
                if regs.arg2() == 0 {
                    // Don't let processes make themselves undumpable. If a process
                    // becomes undumpable, calling perf_event_open on it fails.
                    let mut r: Registers = regs.clone();
                    r.set_arg1_signed(-1);
                    t.set_regs(&r);
                    syscall_state.emulate_result(0);
                    t.thread_group_mut().dumpable = false;
                } else if regs.arg2() == 1 {
                    t.thread_group_mut().dumpable = true;
                }
            }

            PR_GET_DUMPABLE => {
                syscall_state.emulate_result(if t.thread_group().dumpable { 1 } else { 0 });
            }

            PR_GET_SECCOMP => {
                syscall_state.emulate_result(t.prctl_seccomp_status as usize);
            }

            PR_GET_TSC => {
                // Prevent the actual GET_TSC call and return our emulated state.
                let mut r: Registers = regs.clone();
                r.set_arg1_signed(-1);
                t.set_regs(&r);
                syscall_state.emulate_result(0);
                let child_addr =
                    syscall_state.reg_parameter::<i32>(2, Some(ArgMode::InOutNoScratch), None);
                let tsc_mode = t.tsc_mode;
                write_val_mem(t, child_addr, &tsc_mode, None);
            }

            PR_SET_TSC => {
                // Prevent the actual SET_TSC call.
                let mut r: Registers = regs.clone();
                r.set_arg1_signed(-1);
                t.set_regs(&r);
                let val = regs.arg2() as i32;
                if val != PR_TSC_ENABLE as i32 && val != PR_TSC_SIGSEGV as i32 {
                    syscall_state.emulate_result_signed(-EINVAL as isize);
                } else {
                    syscall_state.emulate_result(0);
                    t.tsc_mode = val;
                }
            }

            PR_GET_NAME => {
                syscall_state.reg_parameter_with_size(2, ParamSize::from(16), None, None);
            }

            PR_SET_NO_NEW_PRIVS => {
                // @TODO in rr there is a cast to unsigned long
                if regs.arg2() != 1 {
                    syscall_state.expect_errno = EINVAL;
                }
            }

            PR_SET_SECCOMP => {
                // Allow all known seccomp calls. We must allow the seccomp call
                // that rr triggers when spawning the initial tracee.
                match regs.arg2() as u32 {
                    SECCOMP_MODE_STRICT => (),
                    SECCOMP_MODE_FILTER => {
                        // If we're bootstrapping then this must be rr's own syscall
                        // filter, so just install it normally now.
                        if t.session().done_initial_exec() {
                            // Prevent the actual prctl call. We'll fix this up afterwards.
                            let mut r: Registers = regs.clone();
                            r.set_arg1_signed(-1);
                            t.set_regs(&r);
                        }
                    }
                    _ => {
                        syscall_state.expect_errno = EINVAL;
                    }
                }
            }

            PR_SET_PTRACER => {
                // Prevent any PR_SET_PTRACER call, but pretend it succeeded, since
                // we don't want any interference with our ptracing.
                let mut r: Registers = regs.clone();
                r.set_arg1_signed(-1);
                t.set_regs(&r);
                syscall_state.emulate_result(0);
            }

            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }

        return Switchable::PreventSwitch;
    }

    if sys == Arch::BRK
        || sys == Arch::MUNMAP
        || sys == Arch::PROCESS_VM_READV
        || sys == Arch::PROCESS_VM_WRITEV
        || sys == SYS_rdcall_notify_syscall_hook_exit as i32
        || sys == Arch::MREMAP
        || sys == Arch::SHMAT
        || sys == Arch::SHMDT
    {
        return Switchable::PreventSwitch;
    }

    // futex parameters are in-out but they can't be moved to scratch
    // addresses.
    if sys == Arch::FUTEX_TIME64 || sys == Arch::FUTEX {
        let op = regs.arg2_signed() as i32;
        match op & FUTEX_CMD_MASK {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => return Switchable::AllowSwitch,

            FUTEX_CMP_REQUEUE | FUTEX_WAKE_OP => {
                syscall_state.reg_parameter::<i32>(5, Some(ArgMode::InOutNoScratch), None);
            }

            FUTEX_WAKE | FUTEX_WAKE_BITSET => (),

            FUTEX_LOCK_PI
            | FUTEX_UNLOCK_PI
            | FUTEX_TRYLOCK_PI
            | FUTEX_CMP_REQUEUE_PI
            | FUTEX_WAIT_REQUEUE_PI => {
                let mut r: Registers = regs.clone();
                r.set_arg2_signed(-1);
                t.set_regs(&r);
                syscall_state.emulate_result_signed(-ENOSYS as isize);
            }

            _ => {
                syscall_state.expect_errno = EINVAL;
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::MMAP {
        match Arch::MMAP_SEMANTICS {
            MmapCallingSemantics::StructArguments => {
                let args = read_val_mem(t, RemotePtr::<mmap_args<Arch>>::from(regs.arg1()), None);
                let mmap_flags = args.flags;
                // XXX fix this
                ed_assert!(t, mmap_flags & MAP_GROWSDOWN == 0);
            }
            MmapCallingSemantics::RegisterArguments => {
                prepare_mmap_register_params(t);
            }
        }
        return Switchable::PreventSwitch;
    }

    if sys == Arch::MPROTECT {
        // Since we're stripping MAP_GROWSDOWN from kernel mmap calls, we need
        // to implement PROT_GROWSDOWN ourselves.
        t.vm_shr_ptr().fixup_mprotect_growsdown_parameters(t);
        return Switchable::PreventSwitch;
    }

    // Various syscalls that can block but don't otherwise have behavior we need
    // to record.
    if sys == Arch::FDATASYNC
        || sys == Arch::FSYNC
        || sys == Arch::MSGSND
        || sys == Arch::MSYNC
        || sys == Arch::OPEN
        || sys == Arch::OPENAT
        || sys == Arch::SEMOP
        || sys == Arch::SEMTIMEDOP_TIME64
        || sys == Arch::SEMTIMEDOP
        || sys == Arch::SYNC
        || sys == Arch::SYNC_FILE_RANGE
        || sys == Arch::SYNCFS
    {
        return Switchable::AllowSwitch;
    }

    if sys ==  Arch::PREAD64||
    /* ssize_t read(int fd, void *buf, size_t count); */
    sys == Arch::READ
    {
        let fd = regs.arg1() as i32;
        let mut result: usize = 0;
        let mut ranges = Vec::<file_monitor::Range>::new();
        ranges.push(file_monitor::Range::new(
            RemotePtr::from(regs.arg2()),
            regs.arg3(),
        ));
        let offset = LazyOffset::new(t, regs, sys);
        if offset
            .task()
            .fd_table_shr_ptr()
            .borrow()
            .emulate_read(fd, &ranges, &offset, &mut result)
        {
            // Don't perform this syscall.
            let mut r: Registers = regs.clone();
            r.set_arg1_signed(-1);
            t.set_regs(&r);
            record_ranges(t, &ranges, result);
            syscall_state.emulate_result(result);

            return Switchable::PreventSwitch;
        }

        syscall_state.reg_parameter_with_size(
            2,
            ParamSize::from_syscall_result_with_size::<Arch::ssize_t>(regs.arg3()),
            None,
            None,
        );

        return Switchable::AllowSwitch;
    }

    if sys == SYS_rdcall_notify_control_msg as i32 || sys == SYS_rdcall_init_preload as i32 {
        syscall_state.emulate_result(0);
        return Switchable::PreventSwitch;
    }

    if sys == Arch::SIGACTION || sys == Arch::RT_SIGACTION {
        syscall_state.reg_parameter::<kernel_sigaction<Arch>>(
            2,
            Some(ArgMode::In),
            Some(Box::new(protect_rd_sigs_sa_mask)),
        );
        syscall_state.reg_parameter::<kernel_sigaction<Arch>>(3, Some(ArgMode::Out), None);
        return Switchable::PreventSwitch;
    }

    log!(
        LogDebug,
        "=====> Preparing {}",
        syscall_name(sys, Arch::arch())
    );

    unimplemented!()
}

fn protect_rd_sigs_sa_mask(
    t: &mut RecordTask,
    p: RemotePtr<Void>,
    maybe_save: Option<&mut [u8]>,
) -> bool {
    let arch = t.arch();
    rd_arch_function_selfless!(protect_rd_sigs_sa_mask_arch, arch, t, p, maybe_save)
}

fn protect_rd_sigs_sa_mask_arch<Arch: Architecture>(
    t: &mut RecordTask,
    p: RemotePtr<Void>,
    maybe_save: Option<&mut [u8]>,
) -> bool {
    let sap = RemotePtr::<kernel_sigaction<Arch>>::cast(p);
    if sap.is_null() {
        return false;
    }

    let mut sa = read_val_mem(t, sap, None);
    let mut new_sig_set = sa.sa_mask;
    // Don't let the tracee block TIME_SLICE_SIGNAL or
    // SYSCALLBUF_DESCHED_SIGNAL.
    new_sig_set &= !t.session().as_record().unwrap().rd_signal_mask();

    if sa.sa_mask == new_sig_set {
        return false;
    }

    sa.sa_mask = new_sig_set;
    write_val_mem(t, sap, &sa, None);
    match maybe_save {
        Some(save) => unsafe {
            copy_nonoverlapping(
                &raw const sa as *const u8,
                save.as_mut_ptr(),
                size_of::<kernel_sigaction<Arch>>(),
            );
        },
        None => (),
    }

    true
}

fn record_ranges(t: &mut RecordTask, ranges: &[file_monitor::Range], size: usize) {
    let mut s = size;
    for r in ranges {
        let bytes = min(s, r.length);
        if bytes > 0 {
            t.record_remote(r.data, bytes);
            s -= bytes;
        }
    }
}

fn prepare_mmap_register_params(t: &mut RecordTask) {
    let mut r: Registers = t.regs_ref().clone();
    if t.session().as_record().unwrap().enable_chaos()
        && (r.arg4_signed() & (MAP_FIXED as isize | MAP_32BIT as isize) == 0)
        && r.arg1() == 0
    {
        // No address hint was provided. Randomize the allocation address.
        let mut len: usize = r.arg2();
        if r.arg4_signed() & MAP_GROWSDOWN as isize != 0 {
            // Ensure stacks can grow to the minimum size we choose
            len = max(AddressSpace::chaos_mode_min_stack_size(), len);
        }
        let addr: RemotePtr<Void> = t.vm_shr_ptr().chaos_mode_find_free_memory(t, len);
        if !addr.is_null() {
            r.set_arg1(addr.as_usize() + len - r.arg2());
            // Note that we don't set MapFlags::MAP_FIXED here. If anything goes wrong (e.g.
            // we pick a hint address that actually can't be used on this system), the
            // kernel will pick a valid address instead.
        }
    }
    r.set_arg4_signed(r.arg4_signed() & !(MAP_GROWSDOWN as isize));
    t.set_regs(&r);
}

/// At thread exit time, undo the work that init_buffers() did.
///
/// Call this when the tracee has already entered SYS_exit/SYS_exit_group. The
/// tracee will be returned at a state in which it has entered (or
/// re-entered) SYS_exit/SYS_exit_group.
fn prepare_exit(t: &mut RecordTask, exit_code: i32) {
    // RecordSession is responsible for ensuring we don't get here with
    // pending signals.
    ed_assert!(t, !t.has_any_stashed_sig());

    t.stable_exit = true;
    t.exit_code = exit_code;
    t.session()
        .as_record()
        .unwrap()
        .scheduler_mut()
        .in_stable_exit(t);

    let mut r: Registers = t.regs_ref().clone();
    let mut exit_regs: Registers = r.clone();
    ed_assert!(
        t,
        is_exit_syscall(
            exit_regs.original_syscallno() as i32,
            t.ev().syscall_event().arch()
        ) || is_exit_group_syscall(
            exit_regs.original_syscallno() as i32,
            t.ev().syscall_event().arch()
        ),
        "Tracee should have been at exit/exit_group, but instead at {}",
        t.ev().syscall_event().syscall_name()
    );

    // The first thing we need to do is to block all signals to prevent
    // a signal being delivered to the thread (since it's going to exit and
    // won't be able to handle any more signals).
    //
    // The tracee is at the entry to SYS_exit/SYS_exit_group, but hasn't started
    // the call yet.  We can't directly start injecting syscalls
    // because the tracee is still in the kernel.  And obviously,
    // if we finish the SYS_exit/SYS_exit_group syscall, the tracee isn't around
    // anymore.
    //
    // So hijack this SYS_exit call and rewrite it into a SYS_rt_sigprocmask.
    r.set_original_syscallno(syscall_number_for_rt_sigprocmask(t.arch()) as isize);
    r.set_arg1(SIG_BLOCK as usize);
    r.set_arg2(AddressSpace::rd_page_ff_bytes().as_usize());
    r.set_arg3(0);
    r.set_arg4(size_of::<sig_set_t>());
    t.set_regs(&r);
    // This exits the SYS_rt_sigprocmask.  Now the tracee is ready to do our
    // bidding.
    t.exit_syscall();
    check_signals_while_exiting(t);

    // Do the actual buffer and fd cleanup.
    t.destroy_buffers();

    check_signals_while_exiting(t);

    // Restore these regs to what they would have been just before
    // the tracee trapped at SYS_exit/SYS_exit_group.  When we've finished
    // cleanup, we'll restart the call.
    exit_regs.set_syscallno(exit_regs.original_syscallno());
    exit_regs.set_original_syscallno(-1);
    exit_regs.set_ip(exit_regs.ip() - syscall_instruction_length(t.arch()));
    let is_at_syscall_instruction = is_at_syscall_instruction(t, exit_regs.ip());
    ed_assert!(
        t,
        is_at_syscall_instruction,
        "Tracee should have entered through int $0x80."
    );
    // Restart the SYS_exit call.
    t.set_regs(&exit_regs);
    t.enter_syscall();
    check_signals_while_exiting(t);

    if t.emulated_ptrace_options & PTRACE_O_TRACEEXIT != 0 {
        // Ensure that do_ptrace_exit_stop can run later.
        t.emulated_ptrace_queued_exit_stop = true;
        t.emulate_ptrace_stop(WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT), None, None);
    } else {
        // Only allow one stop at a time. After the PTRACE_EVENT_EXIT has been
        // processed, PTRACE_CONT will call do_ptrace_exit_stop for us.
        do_ptrace_exit_stop(t);
    }
}

fn check_signals_while_exiting(t: &mut RecordTask) {
    let maybe_s = t.peek_stashed_sig_to_deliver();
    match maybe_s {
        Some(s) => {
            // An unblockable signal (SIGKILL, SIGSTOP) might be received
            // and stashed. Since these signals are unblockable they take
            // effect no matter what and we don't need to deliver them to an exiting
            // thread.
            let siginfo = unsafe { (*s).siginfo };
            let sig = siginfo.si_signo;
            ed_assert!(
                t,
                sig == SIGKILL || sig == SIGSTOP,
                "Got unexpected signal {} (should have been blocked)",
                siginfo
            );
        }
        None => (),
    }
}

fn do_ptrace_exit_stop(t: &mut RecordTask) {
    // Notify ptracer of the exit if it's not going to receive it from the
    // kernel because it's not the parent. (The kernel has similar logic to
    // deliver two stops in this case.)
    t.emulated_ptrace_queued_exit_stop = false;
    if t.emulated_ptracer.is_some()
        && (t.is_clone_child()
            || t.get_parent_pid()
                != t.emulated_ptracer
                    .as_ref()
                    .unwrap()
                    .upgrade()
                    .unwrap()
                    .borrow()
                    .real_tgid())
    {
        // This is a bit wrong; this is an exit stop, not a signal/ptrace stop.
        t.emulate_ptrace_stop(WaitStatus::for_exit_code(t.exit_code), None, None);
    }
}

pub fn rec_prepare_restart_syscall(_t: &RecordTask) {
    unimplemented!()
}

pub fn rec_process_syscall(t: &mut RecordTask) {
    let syscall_state_shr = t.syscall_state_unwrap();
    let mut syscall_state = syscall_state_shr.borrow_mut();
    let sys_ev_arch = t.ev().syscall_event().arch();
    let sys_ev_number = t.ev().syscall_event().number;
    if sys_ev_arch != t.arch() {
        static DID_WARN: AtomicBool = AtomicBool::new(false);
        if !DID_WARN.load(Ordering::SeqCst) {
            log!(
                LogWarn,
                "Cross architecture syscall detected. Support is best effort"
            );
            DID_WARN.store(true, Ordering::SeqCst);
        }
    }
    rec_process_syscall_internal(t, sys_ev_arch, &mut syscall_state);
    syscall_state.process_syscall_results(t);
    let regs = t.regs_ref().clone();
    t.on_syscall_exit(sys_ev_number, sys_ev_arch, &regs);
    t.syscall_state = None;

    // @TODO Uncomment
    // MonitoredSharedMemory::check_all(t);
}

/// N.B.: `arch` is the the architecture of the syscall, which may be different
///         from the architecture of the call (e.g. x86_64 may invoke x86 syscalls)
///
/// DIFF NOTE: Does not have param syscall_state as that can be obtained from t
pub fn rec_process_syscall_internal(
    t: &mut RecordTask,
    arch: SupportedArch,
    syscall_state: &mut RefMut<TaskSyscallState>,
) {
    rd_arch_function_selfless!(rec_process_syscall_arch, arch, t, syscall_state)
}

/// DIFF NOTE: Don't need syscall_state param as we can get it from param t
pub fn rec_process_syscall_arch<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut RefMut<TaskSyscallState>,
) {
    let sys: i32 = t.ev().syscall_event().number;

    if t.regs_ref().original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO {
        // rr vetoed this syscall. Don't do any post-processing.
        return;
    }

    log!(
        LogDebug,
        "{}: processing: {} -- time: {}",
        t.tid,
        t.ev(),
        t.trace_time()
    );

    let rec = t.desched_rec();
    if !rec.is_null() {
        // If the syscallbuf has already been unmapped, there's no need to record
        // the entry.
        if !t.syscallbuf_child.is_null() {
            let num_bytes = read_val_mem(
                t,
                RemotePtr::<u32>::cast(rec.as_rptr_u8() + offset_of!(syscallbuf_record, size)),
                None,
            ) as usize;
            t.record_remote(
                rec.as_rptr_u8() + offset_of!(syscallbuf_record, extra_data),
                num_bytes - size_of::<syscallbuf_record>(),
            );
        }
        return;
    }
    if syscall_state.expect_errno != 0 {
        if syscall_state.expect_errno == EINVAL
            && sys == Arch::IOCTL
            && t.regs_ref().syscall_result_signed() == -ENOTTY as isize
        {
            // Unsupported ioctl was called, but is not supported for this device,
            // so we can safely ignore it.
            return;
        }
        ed_assert_eq!(
            t,
            t.regs_ref().syscall_result_signed(),
            -syscall_state.expect_errno as isize,
            "Expected {} for '{}' but got result {} (errno {}) {}",
            errno_name(syscall_state.expect_errno),
            syscall_name(sys, Arch::arch()),
            t.regs_ref().syscall_result_signed(),
            errno_name((-t.regs_ref().syscall_result_signed()).try_into().unwrap()),
            extra_expected_errno_info::<Arch>(t)
        );
        return;
    }

    // Here we handle syscalls that need work that can only happen after the
    // syscall completes --- and that our TaskSyscallState infrastructure can't
    // handle.
    if sys == Arch::EXECVE {
        process_execve(t, syscall_state);
        if t.emulated_ptracer.is_some() {
            if t.emulated_ptrace_options & PTRACE_O_TRACEEXEC != 0 {
                t.emulate_ptrace_stop(WaitStatus::for_ptrace_event(PTRACE_EVENT_EXEC), None, None);
            } else if !t.emulated_ptrace_seized {
                // Inject legacy SIGTRAP-after-exec
                t.tgkill(sig::SIGTRAP);
            }
        }
        return;
    }

    if sys == Arch::PRCTL {
        // Restore arg1 in case we modified it to disable the syscall
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        t.set_regs(&r);
        if t.regs_ref().arg1() as u32 == PR_SET_SECCOMP {
            if t.session().done_initial_exec() {
                t.session()
                    .as_record()
                    .unwrap()
                    .seccomp_filter_rewriter_mut()
                    .install_patched_seccomp_filter(t);
            }
        }

        return;
    }

    if sys == Arch::ARCH_PRCTL {
        // Restore arg1 in case we modified it to disable the syscall
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        t.set_regs(&r);
        return;
    }

    if sys == Arch::CLOSE
        || sys == Arch::DUP2
        || sys == Arch::DUP3
        || sys == Arch::FCNTL
        || sys == Arch::FCNTL64
        || sys == Arch::FUTEX_TIME64
        || sys == Arch::FUTEX
        || sys == Arch::IOCTL
        || sys == Arch::IO_SETUP
        || sys == Arch::MADVISE
        || sys == Arch::MEMFD_CREATE
        || sys == Arch::PREAD64
        || sys == Arch::PREADV
        || sys == Arch::PTRACE
        || sys == Arch::READ
        || sys == Arch::READV
        || sys == Arch::SCHED_SETAFFINITY
        || sys == Arch::MPROTECT
    {
        // Restore the registers that we may have altered.
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1(syscall_state.syscall_entry_registers.arg1());
        r.set_arg2(syscall_state.syscall_entry_registers.arg2());
        r.set_arg3(syscall_state.syscall_entry_registers.arg3());
        t.set_regs(&r);
        return;
    }

    if sys == Arch::BRK {
        let old_brk: RemotePtr<Void> = ceil_page_size(t.vm().current_brk());
        let new_brk: RemotePtr<Void> = ceil_page_size(t.regs_ref().syscall_result().into());
        let km: KernelMapping;
        if old_brk < new_brk {
            // Read the kernel's mapping. There doesn't seem to be any other way to
            // get the correct prot bits for heaps. Usually it's READ|WRITE but
            // there seem to be exceptions depending on system settings.
            let kernel_info: KernelMapping = AddressSpace::read_kernel_mapping(t, old_brk);
            // @TODO Check this
            ed_assert_eq!(t, kernel_info.device(), KernelMapping::NO_DEVICE);
            ed_assert_eq!(t, kernel_info.inode(), KernelMapping::NO_INODE);
            km = kernel_info.subrange(old_brk, new_brk);
        } else {
            // Write a dummy KernelMapping that indicates an unmap
            km = KernelMapping::new_with_opts(
                new_brk,
                old_brk,
                &OsString::new(),
                KernelMapping::NO_DEVICE,
                KernelMapping::NO_INODE,
                ProtFlags::empty(),
                MapFlags::empty(),
                0,
            );
        }
        let d = t
            .trace_writer_mut()
            .write_mapped_region(t, &km, &km.fake_stat(), &[], None, None);
        ed_assert_eq!(t, d, RecordInTrace::DontRecordInTrace);
        let addr = t.regs_ref().syscall_result().into();
        t.vm_shr_ptr().brk(t, addr, km.prot());
        return;
    }

    if sys == Arch::MMAP {
        match Arch::MMAP_SEMANTICS {
            MmapCallingSemantics::StructArguments => {
                let child_addr = RemotePtr::<mmap_args<Arch>>::from(t.regs_ref().arg1());
                let args = read_val_mem(t, child_addr, None);
                process_mmap(
                    t,
                    Arch::size_t_as_usize(args.len),
                    args.prot,
                    args.flags,
                    args.fd,
                    Arch::off_t_as_isize(args.offset) as usize / 4096,
                );
            }
            MmapCallingSemantics::RegisterArguments => {
                prepare_mmap_register_params(t);
            }
        }
        return;
    }

    // @TODO This method is incomplete
}

fn process_mmap(
    _t: &mut RecordTask,
    _len: usize,
    _prot: i32,
    _flags: i32,
    _fd: i32,
    // Ok to assume offset is always positive?
    _offset: usize,
) -> () {
    unimplemented!()
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ScratchAddrType {
    FixedAddress,
    DynamicAddress,
}

fn process_execve(t: &mut RecordTask, syscall_state: &mut RefMut<TaskSyscallState>) {
    if t.regs_ref().syscall_failed() {
        return;
    }

    t.post_exec_syscall();
    t.ev_mut().syscall_event_mut().exec_fds_to_close =
        t.fd_table_shr_ptr().borrow_mut().fds_to_close_after_exec(t);

    check_privileged_exe(t);

    let rd_page_mapping: KernelMapping = t
        .vm()
        .mapping_of(AddressSpace::rd_page_start())
        .unwrap()
        .map
        .clone();

    let mut mode = t.trace_writer_mut().write_mapped_region(
        t,
        &rd_page_mapping,
        &rd_page_mapping.fake_stat(),
        &[],
        Some(MappingOrigin::RdBufferMapping),
        None,
    );
    ed_assert_eq!(t, mode, RecordInTrace::DontRecordInTrace);

    let preload_thread_locals_mapping: KernelMapping = t
        .vm()
        .mapping_of(AddressSpace::preload_thread_locals_start())
        .unwrap()
        .map
        .clone();

    mode = t.trace_writer_mut().write_mapped_region(
        t,
        &preload_thread_locals_mapping,
        &preload_thread_locals_mapping.fake_stat(),
        &[],
        Some(MappingOrigin::RdBufferMapping),
        None,
    );
    ed_assert_eq!(t, mode, RecordInTrace::DontRecordInTrace);

    let mut maybe_vvar: Option<KernelMapping> = None;

    // get the remote executable entry point
    // with the pointer, we find out which mapping is the executable
    let exe_entry: RemotePtr<Void> = get_exe_entry(t);
    ed_assert!(t, !exe_entry.is_null(), "AT_ENTRY not found");

    // Write out stack mappings first since during replay we need to set up the
    // stack before any files get mapped.
    let mut stacks: Vec<KernelMapping> = Vec::new();
    for (_, m) in &t.vm().maps() {
        let km = m.map.clone();
        // if true, this mapping is our executable
        if km.start() <= exe_entry && exe_entry < km.end() {
            ed_assert!(
                t,
                km.prot().contains(ProtFlags::PROT_EXEC),
                "Entry point not in executable code?"
            );
            syscall_state
                .exec_saved_event
                .as_mut()
                .unwrap()
                .exec_variant_mut()
                .set_exe_base(km.start());
        }

        if km.is_stack() {
            stacks.push(km);
        } else if km.is_vvar() {
            maybe_vvar = Some(km);
        }
    }
    ed_assert!(
        t,
        !syscall_state
            .exec_saved_event
            .as_ref()
            .unwrap()
            .exec_variant()
            .exe_base()
            .is_null()
    );

    t.trace_writer_mut()
        .write_task_event(syscall_state.exec_saved_event.as_ref().unwrap());

    {
        let mut remote =
            AutoRemoteSyscalls::new_with_mem_params(t, MemParamsEnabled::DisableMemoryParams);

        match maybe_vvar {
            Some(vvar) => {
                // We're not going to map [vvar] during replay --- that wouldn't
                // make sense, since it contains data from the kernel that isn't correct
                // for replay, and we patch out the vdso syscalls that would use it.
                // Unmapping it now makes recording look more like replay.
                // Also note that under 4.0.7-300.fc22.x86_64 (at least) /proc/<pid>/mem
                // can't read the contents of [vvar].
                let munmap_no: i32 = syscall_number_for_munmap(remote.arch());
                rd_infallible_syscall!(remote, munmap_no, vvar.start().as_usize(), vvar.size());
                remote
                    .task()
                    .vm_shr_ptr()
                    .unmap(remote.task(), vvar.start(), vvar.size());
            }
            None => (),
        }

        for km in &stacks {
            mode = remote
                .task()
                .as_rec_unwrap()
                .trace_writer_mut()
                .write_mapped_region(
                    remote.task().as_rec_unwrap(),
                    km,
                    &km.fake_stat(),
                    &[],
                    Some(MappingOrigin::ExecMapping),
                    None,
                );
            ed_assert_eq!(remote.task(), mode, RecordInTrace::RecordInTrace);
            let buf = read_mem(remote.task_mut(), km.start(), km.size(), None);
            remote.task().as_rec_unwrap().trace_writer_mut().write_raw(
                remote.task().rec_tid,
                &buf,
                km.start(),
            );

            // Remove MAP_GROWSDOWN from stacks by remapping the memory and
            // writing the contents back.
            let flags = (km.flags() & !MapFlags::MAP_GROWSDOWN) | MapFlags::MAP_ANONYMOUS;
            let munmap_no: i32 = syscall_number_for_munmap(remote.arch());
            rd_infallible_syscall!(remote, munmap_no, km.start().as_usize(), km.size());
            if !remote
                .task()
                .vm()
                .mapping_of(km.start() - page_size())
                .is_some()
            {
                // Unmap an extra page at the start; this seems to be necessary
                // to properly wipe out the growsdown mapping. Doing it as a separate
                // munmap call also seems to be necessary.
                rd_infallible_syscall!(
                    remote,
                    munmap_no,
                    km.start().as_usize() - page_size(),
                    page_size()
                );
            }
            remote.infallible_mmap_syscall(Some(km.start()), km.size(), km.prot(), flags, -1, 0);
            write_mem(remote.task_mut(), km.start(), &buf, None);
        }
    }

    // The kernel may zero part of the last page in each data mapping according
    // to ELF BSS metadata. So we record the last page of each data mapping in
    // the trace.
    let mut pages_to_record: Vec<RemotePtr<Void>> = Vec::new();

    for (_, m) in &t.vm_shr_ptr().maps() {
        let km = m.map.clone();
        if km.start() == AddressSpace::rd_page_start()
            || km.start() == AddressSpace::preload_thread_locals_start()
        {
            continue;
        }
        if km.is_stack() || km.is_vsyscall() {
            // [stack] has already been handled.
            // [vsyscall] can't be read via /proc/<pid>/mem, *should*
            // be the same across all execs, and can't be munmapped so we can't fix
            // it even if it does vary. Plus no-one should be using it anymore.
            continue;
        }
        let maybe_stat = stat::stat(km.fsname());
        let st = match maybe_stat {
            Err(_) => {
                let mut fake_st = km.fake_stat();
                // Size is not real. Don't confuse the logic below
                fake_st.st_size = 0;
                fake_st
            }
            Ok(st) => st,
        };

        if t.trace_writer_mut().write_mapped_region(
            t,
            &km,
            &st,
            &[],
            Some(MappingOrigin::ExecMapping),
            None,
        ) == RecordInTrace::RecordInTrace
        {
            if st.st_size > 0 {
                let end = st.st_size as u64 - km.file_offset_bytes();
                t.record_remote(km.start(), min(end.try_into().unwrap(), km.size()));
            } else {
                // st_size is not valid. Some device files are mmappable but have zero
                // size. We also take this path if there's no file at all (vdso etc).
                t.record_remote(km.start(), km.size());
            }
        } else {
            // See https://github.com/mozilla/rr/issues/1568; in some cases
            // after exec we have memory areas that are rwx. These areas have
            // a trailing page that may be partially zeroed by the kernel. Record the
            // trailing page of every mapping just to be simple and safe.
            pages_to_record.push(km.end() - page_size());
        }
    }

    for p in pages_to_record {
        t.record_remote(p, page_size());
    }

    // Patch LD_PRELOAD and VDSO after saving the mappings. Replay will apply
    // patches to the saved mappings.
    t.vm().monkeypatcher().unwrap().patch_after_exec(t);

    init_scratch_memory(t, Some(ScratchAddrType::FixedAddress));
}
/// Pointer used when running in WINE. Memory below this address is
/// unmapped by WINE immediately after exec, so start the scratch buffer
/// here.
const FIXED_SCRATCH_PTR: usize = 0x68000000;

fn init_scratch_memory(t: &mut RecordTask, maybe_addr_type: Option<ScratchAddrType>) {
    let addr_type = maybe_addr_type.unwrap_or(ScratchAddrType::DynamicAddress);
    let scratch_size = 512 * page_size();
    // The PROT_EXEC looks scary, and it is, but it's to prevent
    // this region from being coalesced with another anonymous
    // segment mapped just after this one.  If we named this
    // segment, we could remove this hack.
    let prot = ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC;
    let flags = MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS;
    {
        // initialize the scratchpad for blocking system calls
        let mut remote = AutoRemoteSyscalls::new(t);

        if addr_type == ScratchAddrType::DynamicAddress {
            remote.task_mut().scratch_ptr =
                remote.infallible_mmap_syscall(None, scratch_size, prot, flags, -1, 0);
        } else {
            remote.task_mut().scratch_ptr = remote.infallible_mmap_syscall(
                Some(RemotePtr::from(FIXED_SCRATCH_PTR)),
                scratch_size,
                prot,
                flags | MapFlags::MAP_FIXED,
                -1,
                0,
            );
        }
        remote.task_mut().scratch_size = scratch_size;
    }

    t.setup_preload_thread_locals();

    // record this mmap for the replay
    let mut r: Registers = t.regs_ref().clone();
    let saved_result = r.syscall_result();
    r.set_syscall_result(t.scratch_ptr.as_usize());
    t.set_regs(&r);

    let km = t.vm_shr_ptr().map(
        t,
        t.scratch_ptr,
        scratch_size,
        prot,
        flags,
        0,
        &OsString::new(),
        KernelMapping::NO_DEVICE,
        KernelMapping::NO_INODE,
        None,
        None,
        None,
        None,
        None,
    );
    let stat: libc::stat = unsafe { mem::zeroed() };
    let record_in_trace = t
        .trace_writer_mut()
        .write_mapped_region(t, &km, &stat, &[], None, None);

    ed_assert_eq!(t, record_in_trace, RecordInTrace::DontRecordInTrace);

    r.set_syscall_result(saved_result);
    t.set_regs(&r);
}

fn check_privileged_exe(_t: &mut RecordTask) {
    // @TODO PENDING!
}

fn get_exe_entry(t: &mut RecordTask) -> RemotePtr<Void> {
    let v = read_auxv(t);
    let mut i: usize = 0;
    let wsize: usize = word_size(t.arch());
    while (i + 1) * wsize * 2 <= v.len() {
        if word_at(&v[i * 2 * wsize..i * 2 * wsize + wsize]) == AT_ENTRY {
            // @TODO Instead of try_into() should this just be `as usize` ?
            return RemotePtr::new_from_val(
                word_at(&v[(i * 2 + 1) * wsize..(i * 2 + 1) * wsize + wsize])
                    .try_into()
                    .unwrap(),
            );
        }
        i += 1;
    }

    RemotePtr::null()
}

type AfterSyscallAction = Box<dyn Fn(&mut RecordTask) -> ()>;
type ArgMutator = Box<dyn Fn(&mut RecordTask, RemotePtr<Void>, Option<&mut [u8]>) -> bool>;

/// When tasks enter syscalls that may block and so must be
/// prepared for a context-switch, and the syscall params
/// include (in)outparams that point to buffers, we need to
/// redirect those arguments to scratch memory.  This allows rd
/// to serialize execution of what may be multiple blocked
/// syscalls completing "simultaneously" (from rd's
/// perspective).  After the syscall exits, we restore the data
/// saved in scratch memory to the original buffers.
///
/// Then during replay, we simply restore the saved data to the
/// tracee's passed-in buffer args and continue on.
///
/// This is implemented by having rec_prepare_syscall_arch set up
/// a record in param_list for syscall in-memory  parameter (whether
/// "in" or "out"). Then done_preparing is called, which does the actual
/// scratch setup. process_syscall_results is called when the syscall is
/// done, to write back scratch results to the real parameters and
/// clean everything up.
///
/// ... a fly in this ointment is may-block buffered syscalls.
/// If a task blocks in one of those, it will look like it just
/// entered a syscall that needs a scratch buffer.  However,
/// it's too late at that point to fudge the syscall args,
/// because processing of the syscall has already begun in the
/// kernel.  But that's OK: the syscallbuf code has already
/// swapped out the original buffer-pointers for pointers into
/// the syscallbuf (which acts as its own scratch memory).  We
/// just have to worry about setting things up properly for
/// replay.
///
/// The descheduled syscall will "abort" its commit into the
/// syscallbuf, so the outparam data won't actually be saved
/// there (and thus, won't be restored during replay).  During
/// replay, we have to restore them like we restore the
/// non-buffered-syscall scratch data. This is done by recording
/// the relevant syscallbuf record data in rec_process_syscall_arch.
///
/// DIFF NOTE: The struct is pub
pub struct TaskSyscallState {
    /// DIFF NOTE: In rr a pointer to the RecordTask is stored
    tuid: TaskUid,

    param_list: Vec<MemoryParam>,
    /// Tracks the position in t's scratch_ptr buffer where we should allocate
    /// the next scratch area.
    scratch: RemotePtr<Void>,

    after_syscall_actions: Vec<AfterSyscallAction>,

    /// DIFF NOTE: Made into an Option<>
    exec_saved_event: Option<Box<TraceTaskEvent>>,
    /// DIFF NOTE: Made into an Option<>
    emulate_wait_for_child: Option<TaskSharedWeakPtr>,

    /// Saved syscall-entry registers, used by code paths that modify the
    /// registers temporarily.
    syscall_entry_registers: Registers,

    /// When nonzero, syscall is expected to return the given errno and we should
    /// die if it does not. This is set when we detect an error condition during
    /// syscall-enter preparation.
    expect_errno: i32,

    /// When should_emulate_result is true, syscall result should be adjusted to
    /// be emulated_result.
    should_emulate_result: bool,
    /// DIFF NOTE: In rr this is a u64
    emulated_result: usize,

    /// Records whether the syscall is switchable. Only valid when
    /// preparation_done is true.
    switchable: Switchable,

    /// Whether we should write back the syscall results from scratch. Only
    /// valid when preparation_done is true.
    write_back: WriteBack,

    /// When true, this syscall has already been prepared and should not
    /// be set up again.
    preparation_done: bool,

    /// When true, the scratch area is enabled, otherwise we're letting
    /// syscall outputs be written directly to their destinations.
    /// Only valid when preparation_done is true.
    scratch_enabled: bool,

    /// Miscellaneous saved data that can be used by particular syscalls
    saved_data: Vec<u8>,
}

impl TaskSyscallState {
    // DIFF NOTE: Unlike rr, you need to specify `t` (but as a tuid) right from the beginning
    pub fn new(tuid: TaskUid) -> Self {
        Self {
            tuid,
            param_list: Default::default(),
            scratch: Default::default(),
            after_syscall_actions: Default::default(),
            exec_saved_event: Default::default(),
            emulate_wait_for_child: Default::default(),
            syscall_entry_registers: Default::default(),
            expect_errno: 0,
            should_emulate_result: false,
            emulated_result: 0,
            // Arbitrarily chosen
            switchable: Switchable::PreventSwitch,
            // Arbitrarily chosen
            write_back: WriteBack::NoWriteBack,
            preparation_done: false,
            scratch_enabled: false,
            saved_data: Default::default(),
        }
    }

    pub fn init(&mut self, t: &RecordTask) {
        assert!(self.tuid == t.tuid());

        if self.preparation_done {
            return;
        }

        self.scratch = t.scratch_ptr;
    }

    /// Identify a syscall memory parameter whose address is in register 'arg'
    /// with type T.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    fn reg_parameter<T>(
        &mut self,
        arg: usize,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<T> {
        RemotePtr::<T>::cast(self.reg_parameter_with_size(
            arg,
            ParamSize::from(size_of::<T>()),
            maybe_mode,
            maybe_mutator,
        ))
    }

    /// Identify a syscall memory parameter whose address is in register 'arg'
    /// with size 'size'.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    fn reg_parameter_with_size(
        &mut self,
        arg: usize,
        param_size: ParamSize,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<Void> {
        let mode = maybe_mode.unwrap_or(ArgMode::Out);
        if self.preparation_done {
            return RemotePtr::null();
        }

        let mut param = MemoryParam::default();
        let dest = RemotePtr::from(self.syscall_entry_registers.arg(arg));
        if dest.is_null() {
            return RemotePtr::null();
        }

        param.dest = dest;
        param.num_bytes = param_size;
        param.mode = mode;
        param.maybe_mutator = maybe_mutator;
        assert!(param.maybe_mutator.is_none() || mode == ArgMode::In);

        if mode != ArgMode::InOutNoScratch {
            param.scratch = self.scratch;
            self.scratch += param.num_bytes.incoming_size;
            align_scratch(&mut self.scratch, None);
            param.ptr_in_reg = arg;
        }

        self.param_list.push(param);

        dest
    }

    /// Identify a syscall memory parameter whose address is in memory at
    /// location 'addr_of_buf_ptr' with type T.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    /// addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
    /// call.
    ///
    /// DIFF NOTE: Takes t as param
    fn mem_ptr_parameter<T>(
        &mut self,
        t: &mut RecordTask,
        addr_of_buf_ptr: RemotePtr<Void>,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<T> {
        RemotePtr::<T>::cast(self.mem_ptr_parameter_with_size(
            t,
            addr_of_buf_ptr,
            ParamSize::from(size_of::<T>()),
            maybe_mode,
            maybe_mutator,
        ))
    }

    /// Identify a syscall memory parameter whose address is in memory at
    /// location 'addr_of_buf_ptr' with type T.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    /// addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
    /// call.
    ///
    /// DIFF NOTE: Take t as param
    fn mem_ptr_parameter_inferred<Arch: Architecture, T>(
        &mut self,
        t: &mut RecordTask,
        addr_of_buf_ptr: RemotePtr<Ptr<Arch::unsigned_word, T>>,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<T> {
        RemotePtr::<T>::cast(self.mem_ptr_parameter_with_size(
            t,
            RemotePtr::<Void>::cast(addr_of_buf_ptr),
            ParamSize::from(size_of::<T>()),
            maybe_mode,
            maybe_mutator,
        ))
    }

    /// Identify a syscall memory parameter whose address is in memory at
    /// location 'addr_of_buf_ptr' with size 'size'.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    /// addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
    /// call.
    ///
    /// DIFF NOTE: Take t as param
    fn mem_ptr_parameter_with_size(
        &mut self,
        t: &mut RecordTask,
        addr_of_buf_ptr: RemotePtr<Void>,
        param_size: ParamSize,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<Void> {
        assert!(self.tuid == t.tuid());

        let mode = maybe_mode.unwrap_or(ArgMode::Out);
        if self.preparation_done || addr_of_buf_ptr.is_null() {
            return RemotePtr::null();
        }

        let mut param = MemoryParam::default();
        let dest = get_remote_ptr(t, addr_of_buf_ptr);
        if dest.is_null() {
            return RemotePtr::null();
        }

        param.dest = dest;
        param.num_bytes = param_size;
        param.mode = mode;
        param.maybe_mutator = maybe_mutator;
        ed_assert!(t, param.maybe_mutator.is_none() || mode == ArgMode::In);
        if mode != ArgMode::InOutNoScratch {
            param.scratch = self.scratch;
            self.scratch += param.num_bytes.incoming_size;
            align_scratch(&mut self.scratch, None);
            param.ptr_in_memory = addr_of_buf_ptr;
        }
        self.param_list.push(param);

        dest
    }

    fn after_syscall_action(&mut self, action: AfterSyscallAction) {
        self.after_syscall_actions.push(action)
    }

    fn emulate_result(&mut self, result: usize) {
        assert!(!self.preparation_done);
        assert!(!self.should_emulate_result);
        self.should_emulate_result = true;
        self.emulated_result = result;
    }

    /// DIFF NOTE: This method is not there in rr
    fn emulate_result_signed(&mut self, result: isize) {
        assert!(!self.preparation_done);
        assert!(!self.should_emulate_result);
        self.should_emulate_result = true;
        self.emulated_result = result as usize;
    }

    /// Internal method that takes 'ptr', an address within some memory parameter,
    /// and relocates it to the parameter's location in scratch memory.
    fn relocate_pointer_to_scratch(&self, ptr: RemotePtr<Void>) -> RemotePtr<Void> {
        let mut num_relocations: usize = 0;
        let mut result = RemotePtr::<Void>::null();
        for param in &self.param_list {
            if param.dest <= ptr && ptr < param.dest + param.num_bytes.incoming_size {
                result = param.scratch + (ptr - param.dest);
                num_relocations += 1;
            }
        }
        // DIFF NOTE: These are debug_asserts in rr
        assert!(
            num_relocations > 0,
            "Pointer in non-scratch memory being updated to point to scratch?"
        );

        assert!(
            num_relocations <= 1,
            "Overlapping buffers containing relocated pointer?"
        );

        result
    }

    /// Internal method that takes the index of a MemoryParam and a vector
    /// containing the actual sizes assigned to each param < i, and
    /// computes the actual size to use for parameter param_index.
    ///
    /// DIFF NOTE: Takes t as param
    fn eval_param_size(
        &self,
        t: &mut RecordTask,
        i: usize,
        actual_sizes: &mut Vec<usize>,
    ) -> usize {
        assert_eq!(actual_sizes.len(), i);
        assert!(self.tuid == t.tuid());

        let mut already_consumed: usize = 0;
        for j in 0usize..i {
            if self.param_list[j]
                .num_bytes
                .is_same_source(&self.param_list[i].num_bytes)
            {
                already_consumed += actual_sizes[j];
            }
        }

        let size: usize = self.param_list[i].num_bytes.eval(t, already_consumed);

        actual_sizes.push(size);

        size
    }

    /// Called when all memory parameters have been identified. If 'sw' is
    /// Switchable::AllowSwitch, sets up scratch memory and updates registers etc as
    /// necessary.
    /// If scratch can't be used for some reason, returns Switchable::PreventSwitch,
    /// otherwise returns 'sw'.
    ///
    /// DIFF NOTE: Takes t as param
    fn done_preparing(&mut self, t: &mut RecordTask, mut sw: Switchable) -> Switchable {
        assert!(self.tuid == t.tuid());

        if self.preparation_done {
            return self.switchable;
        }

        sw = self.done_preparing_internal(t, sw);
        ed_assert_eq!(t, sw, self.switchable);

        // Step 3: Execute mutators. This must run even if the scratch steps do not.
        for param in &mut self.param_list {
            if param.maybe_mutator.is_some() {
                // Mutated parameters must be IN. If we have scratch space, we don't need
                // to save anything.
                let mut saved_data_loc: Option<&mut [u8]> = None;
                if !self.scratch_enabled {
                    let prev_size = self.saved_data.len();
                    self.saved_data
                        .resize(prev_size + param.num_bytes.incoming_size, 0);
                    saved_data_loc = Some(
                        &mut self.saved_data[prev_size..prev_size + param.num_bytes.incoming_size],
                    );
                }
                if !param.maybe_mutator.as_ref().unwrap()(
                    t,
                    if self.scratch_enabled {
                        param.scratch
                    } else {
                        param.dest
                    },
                    saved_data_loc,
                ) {
                    // Nothing was modified, no need to clean up when we unwind.
                    param.maybe_mutator = None;
                    if !self.scratch_enabled {
                        self.saved_data
                            .resize(self.saved_data.len() - param.num_bytes.incoming_size, 0);
                    }
                }
            }
        }

        self.switchable
    }

    /// DIFF NOTE: Takes t as param
    fn done_preparing_internal(&mut self, t: &mut RecordTask, sw: Switchable) -> Switchable {
        ed_assert!(t, !self.preparation_done);

        self.preparation_done = true;
        self.write_back = WriteBack::WriteBack;
        self.switchable = sw;

        if t.scratch_ptr.is_null() {
            return self.switchable;
        }

        ed_assert!(t, self.scratch >= t.scratch_ptr);

        if sw == Switchable::AllowSwitch && self.scratch > t.scratch_ptr + t.usable_scratch_size() {
            log!(LogWarn,
         "`{}' needed a scratch buffer of size {}, but only {} was available.  Disabling context switching: deadlock may follow.",
             t.ev().syscall_event().syscall_name(),
        self.scratch.as_usize() - t.scratch_ptr.as_usize(),
        t.usable_scratch_size());

            self.switchable = Switchable::PreventSwitch;
        }
        if self.switchable == Switchable::PreventSwitch || self.param_list.is_empty() {
            return self.switchable;
        }

        self.scratch_enabled = true;

        // Step 1: Copy all IN/IN_OUT parameters to their scratch areas
        for param in &self.param_list {
            if param.mode == ArgMode::InOut || param.mode == ArgMode::In {
                // Initialize scratch buffer with input data
                let buf = read_mem(t, param.dest, param.num_bytes.incoming_size, None);
                write_mem(t, param.scratch, &buf, None);
            }
        }
        // Step 2: Update pointers in registers/memory to point to scratch areas
        {
            let mut r: Registers = t.regs_ref().clone();
            let mut to_adjust = Vec::<(usize, RemotePtr<Void>)>::new();
            for (i, param) in self.param_list.iter().enumerate() {
                if param.ptr_in_reg != 0 {
                    r.set_arg(param.ptr_in_reg, param.scratch.as_usize());
                }
                if !param.ptr_in_memory.is_null() {
                    // Pointers being relocated must themselves be in scratch memory.
                    // We don't want to modify non-scratch memory. Find the pointer's
                    // location
                    // in scratch memory.
                    let p = self.relocate_pointer_to_scratch(param.ptr_in_memory);
                    // Update pointer to point to scratch.
                    // Note that this can only happen after step 1 is complete and all
                    // parameter data has been copied to scratch memory.
                    set_remote_ptr(t, p, param.scratch);
                }
                // If the number of bytes to record is coming from a memory location,
                // update that location to scratch.
                if !param.num_bytes.mem_ptr.is_null() {
                    to_adjust.push((i, self.relocate_pointer_to_scratch(param.num_bytes.mem_ptr)));
                }
            }

            for (i, rptr) in to_adjust {
                self.param_list[i].num_bytes.mem_ptr = rptr;
            }

            t.set_regs(&r);
        }

        self.switchable
    }

    /// Called when a syscall exits to copy results from scratch memory to their
    /// original destinations, update registers, etc.
    ///
    /// DIFF NOTE: Takes t as param
    fn process_syscall_results(&mut self, t: &mut RecordTask) {
        assert!(self.tuid == t.tuid());
        ed_assert!(t, self.preparation_done);

        // XXX what's the best way to handle failed syscalls? Currently we just
        // record everything as if it succeeded. That handles failed syscalls that
        // wrote partial results, but doesn't handle syscalls that failed with
        // EFAULT.
        let mut actual_sizes: Vec<usize> = Vec::new();
        if self.scratch_enabled {
            let scratch_num_bytes: usize = self.scratch - t.scratch_ptr;
            let child_addr = RemotePtr::<u8>::cast(t.scratch_ptr);
            let data = read_mem(t, child_addr, scratch_num_bytes, None);
            let mut r: Registers = t.regs_ref().clone();
            // Step 1: compute actual sizes of all buffers and copy outputs
            // from scratch back to their origin
            for (i, param) in self.param_list.iter().enumerate() {
                let size: usize = self.eval_param_size(t, i, &mut actual_sizes);
                if self.write_back == WriteBack::WriteBack
                    && (param.mode == ArgMode::InOut || param.mode == ArgMode::Out)
                {
                    let offset = param.scratch.as_usize() - t.scratch_ptr.as_usize();
                    let d = &data[offset..offset + size];
                    write_mem(t, param.dest, d, None);
                }
            }

            let mut memory_cleaned_up: bool = false;
            // Step 2: restore modified in-memory pointers and registers
            for param in &self.param_list {
                if param.ptr_in_reg > 0 {
                    r.set_arg(param.ptr_in_reg, param.dest.as_usize());
                }
                if !param.ptr_in_memory.is_null() {
                    memory_cleaned_up = true;
                    set_remote_ptr(t, param.ptr_in_memory, param.dest);
                }
            }
            if self.write_back == WriteBack::WriteBack {
                // Step 3: record all output memory areas
                for (i, param) in self.param_list.iter().enumerate() {
                    let size: usize = actual_sizes[i];
                    if param.mode == ArgMode::InOutNoScratch {
                        t.record_remote(param.dest, size);
                    } else if param.mode == ArgMode::InOut || param.mode == ArgMode::Out {
                        // If pointers in memory were fixed up in step 2, then record
                        // from tracee memory to ensure we record such fixes. Otherwise we
                        // can record from our local data.
                        // XXX This optimization can be improved if necessary...
                        if memory_cleaned_up {
                            t.record_remote(param.dest, size);
                        } else {
                            let offset = param.scratch.as_usize() - t.scratch_ptr.as_usize();
                            let d = &data[offset..offset + size];
                            t.record_local(param.dest, d);
                        }
                    }
                }
            }
            t.set_regs(&r);
        } else {
            // Step 1: restore all mutated memory
            for param in &self.param_list {
                if param.maybe_mutator.is_some() {
                    let size: usize = param.num_bytes.incoming_size;
                    ed_assert!(t, self.saved_data.len() >= size);
                    write_mem(t, param.dest, &self.saved_data[0..size], None);
                    self.saved_data.drain(0..size);
                }
            }

            ed_assert!(t, self.saved_data.is_empty());
            // Step 2: record all output memory areas
            for (i, param) in self.param_list.iter().enumerate() {
                let size: usize = self.eval_param_size(t, i, &mut actual_sizes);
                t.record_remote(param.dest, size);
            }
        }

        if self.should_emulate_result {
            let mut r: Registers = t.regs_ref().clone();
            r.set_syscall_result(self.emulated_result);
            t.set_regs(&r);
        }

        for action in &self.after_syscall_actions {
            action(t);
        }
    }

    /// Called when a syscall has been completely aborted to undo any changes we
    /// made.
    ///
    /// DIFF NOTE: Takes t as param
    fn abort_syscall_results(&mut self, t: &mut RecordTask) {
        assert!(self.tuid == t.tuid());
        ed_assert!(t, self.preparation_done);

        if self.scratch_enabled {
            let mut r: Registers = t.regs_ref().clone();
            // restore modified in-memory pointers and registers
            for param in &self.param_list {
                if param.ptr_in_reg != 0 {
                    r.set_arg(param.ptr_in_reg, param.dest.as_usize());
                }
                if !param.ptr_in_memory.is_null() {
                    set_remote_ptr(t, param.ptr_in_memory, param.dest);
                }
            }
            t.set_regs(&r);
        } else {
            for param in &self.param_list {
                if param.maybe_mutator.is_some() {
                    let size: usize = param.num_bytes.incoming_size;
                    ed_assert!(t, self.saved_data.len() >= size);
                    write_mem(t, param.dest, &self.saved_data[0..size], None);
                    self.saved_data.drain(0..size);
                }
            }
        }
    }
}

/// Upon successful syscall completion, each RestoreAndRecordScratch record
/// in param_list consumes num_bytes from the t->scratch_ptr
/// buffer, copying the data to remote_dest and recording the data at
/// remote_dest. If ptr_in_reg is greater than zero, updates the task's
/// ptr_in_reg register with 'remote_dest'. If ptr_in_memory is non-null,
/// updates the ptr_in_memory location with the value 'remote_dest'.
#[derive(Default)]
struct MemoryParam {
    dest: RemotePtr<Void>,
    scratch: RemotePtr<Void>,
    num_bytes: ParamSize,
    ptr_in_memory: RemotePtr<Void>,
    /// DIFF NOTE: This is an i32 in rr
    ptr_in_reg: usize,
    mode: ArgMode,
    maybe_mutator: Option<ArgMutator>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum WriteBack {
    WriteBack,
    NoWriteBack,
}

/// Specifies how to determine the size of a syscall memory
/// parameter. There is usually an incoming size determined before the syscall
/// executes (which we need in order to allocate scratch memory), combined
/// with an optional final size taken from the syscall result or a specific
/// memory location after the syscall has executed. The minimum of the incoming
/// and final sizes is used, if both are present.
#[derive(Default, Copy, Clone)]
struct ParamSize {
    incoming_size: usize,
    /// If non-null, the size is limited by the value at this location after
    /// the syscall.
    mem_ptr: RemotePtr<Void>,
    /// Size of the value at mem_ptr or in the syscall result register.
    read_size: usize,
    /// If true, the size is limited by the value of the syscall result.
    from_syscall: bool,
}

impl From<usize> for ParamSize {
    fn from(siz: usize) -> Self {
        ParamSize {
            incoming_size: min(i32::MAX as usize, siz),
            mem_ptr: 0usize.into(),
            read_size: 0,
            from_syscall: false,
        }
    }
}

impl ParamSize {
    /// p points to a tracee location that is already initialized with a
    /// "maximum buffer size" passed in by the tracee, and which will be filled
    /// in with the size of the data by the kernel when the syscall exits.
    fn from_initialized_mem<T>(t: &mut dyn Task, p: RemotePtr<T>) -> ParamSize {
        let mut r = ParamSize::from(if p.is_null() {
            0
        } else {
            match size_of::<T>() {
                4 => read_val_mem(t, RemotePtr::<u32>::cast(p), None) as usize,
                8 => read_val_mem(t, RemotePtr::<u64>::cast(p), None)
                    .try_into()
                    .unwrap(),
                _ => {
                    ed_assert!(t, false, "Unknown read_size");
                    0
                }
            }
        });
        r.mem_ptr = RemotePtr::cast(p);
        r.read_size = size_of::<T>();

        r
    }

    /// p points to a tracee location which will be filled in with the size of
    /// the data by the kernel when the syscall exits, but the location
    /// is uninitialized before the syscall.
    fn from_mem<T>(p: RemotePtr<T>) -> ParamSize {
        let mut r = ParamSize::default();
        r.mem_ptr = RemotePtr::cast(p);
        r.read_size = size_of::<T>();

        r
    }

    /// When the syscall exits, the syscall result will be of type T and contain
    /// the size of the data. 'incoming_size', if present, is a bound on the size
    /// of the data.
    fn from_syscall_result<T>() -> ParamSize {
        let mut r = ParamSize::default();
        r.from_syscall = true;
        r.read_size = size_of::<T>();
        r
    }

    fn from_syscall_result_with_size<T>(incoming_size: usize) -> ParamSize {
        let mut r = ParamSize::from(incoming_size);
        r.from_syscall = true;
        r.read_size = size_of::<T>();
        r
    }

    /// Indicate that the size will be at most 'max'.
    fn limit_size(&self, max: usize) -> ParamSize {
        let mut r = self.clone();
        r.incoming_size = min(r.incoming_size, max);

        r
    }

    fn eval(&self, t: &mut dyn Task, already_consumed: usize) -> usize {
        let mut s: usize = self.incoming_size;
        if !self.mem_ptr.is_null() {
            let mem_size: usize;
            match self.read_size {
                4 => {
                    mem_size = read_val_mem(t, RemotePtr::<u32>::cast(self.mem_ptr), None) as usize
                }
                8 => {
                    mem_size = read_val_mem(t, RemotePtr::<u64>::cast(self.mem_ptr), None)
                        .try_into()
                        .unwrap();
                }
                _ => {
                    ed_assert!(t, false, "Unknown read_size");
                    return 0;
                }
            }

            ed_assert!(t, already_consumed <= mem_size);
            s = min(s, mem_size - already_consumed);
        }

        if self.from_syscall {
            let mut syscall_size: usize =
                max(0isize, t.regs_ref().syscall_result_signed()) as usize;
            syscall_size = match self.read_size {
                // @TODO Is this what we want?
                4 => syscall_size as u32 as usize,
                // @TODO Is this what we want?
                8 => syscall_size as u64 as usize,
                _ => {
                    ed_assert!(t, false, "Unknown read_size");
                    return 0;
                }
            };

            ed_assert!(t, already_consumed <= syscall_size);
            s = min(s, syscall_size - already_consumed);
        }

        s
    }

    /// Return true if 'other' takes its dynamic size from the same source as
    /// this.
    /// When multiple syscall memory parameters take their dynamic size from the
    /// same source, the source size is distributed among them, with the first
    /// registered parameter taking up to its max_size bytes, followed by the next,
    /// etc. This lets us efficiently record iovec buffers.
    fn is_same_source(&self, other: &ParamSize) -> bool {
        ((!self.mem_ptr.is_null() && other.mem_ptr == self.mem_ptr)
            || (self.from_syscall && other.from_syscall))
            && (self.read_size == other.read_size)
    }
}

/// Modes used to register syscall memory parameter with TaskSyscallState.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum ArgMode {
    /// Syscall memory parameter is an in-parameter only.
    /// This is only important when we want to move the buffer to scratch memory
    /// so we can modify it without making the modifications potentially visible
    /// to user code. Otherwise, such parameters can be ignored.
    In,
    /// Syscall memory parameter is out-parameter only.
    Out,
    /// Syscall memory parameter is an in-out parameter.
    InOut,
    /// Syscall memory parameter is an in-out parameter but we must not use
    /// scratch (e.g. for futexes, we must use the actual memory word).
    InOutNoScratch,
}

impl Default for ArgMode {
    fn default() -> Self {
        Self::Out
    }
}

fn set_remote_ptr_arch<Arch: Architecture>(
    t: &mut dyn Task,
    addr: RemotePtr<Void>,
    value: RemotePtr<Void>,
) {
    let typed_addr = RemotePtr::<Arch::unsigned_word>::cast(addr);
    write_val_mem(
        t,
        typed_addr,
        &Arch::as_unsigned_word(value.as_usize()),
        None,
    );
}

fn set_remote_ptr(t: &mut dyn Task, addr: RemotePtr<Void>, value: RemotePtr<Void>) {
    let arch = t.arch();
    rd_arch_function_selfless!(set_remote_ptr_arch, arch, t, addr, value);
}

fn get_remote_ptr_arch<Arch: Architecture>(
    t: &mut dyn Task,
    addr: RemotePtr<Void>,
) -> RemotePtr<Void> {
    let typed_addr = RemotePtr::<Arch::unsigned_word>::cast(addr);
    let old = read_val_mem(t, typed_addr, None);
    RemotePtr::from(old.try_into().unwrap())
}

fn get_remote_ptr(t: &mut dyn Task, addr: RemotePtr<Void>) -> RemotePtr<Void> {
    let arch = t.arch();
    rd_arch_function_selfless!(get_remote_ptr_arch, arch, t, addr)
}

fn align_scratch(scratch: &mut RemotePtr<Void>, maybe_amount: Option<usize>) {
    let amount = maybe_amount.unwrap_or(8);
    *scratch = RemotePtr::from((scratch.as_usize() + amount - 1) & !(amount - 1));
}

/// DIFF NOTE: Does not take syscall_state as param as that can be obtained from t
fn extra_expected_errno_info<Arch: Architecture>(_t: &RecordTask) -> String {
    unimplemented!()
}

fn prepare_ioctl<Arch: Architecture>(
    t: &mut RecordTask,
    syscall_state: &mut RefMut<TaskSyscallState>,
) -> Switchable {
    let fd = t.regs_ref().arg1() as i32;
    let mut result: u64 = 0;
    if t.fd_table().emulate_ioctl(fd, t, &mut result) {
        // Don't perform this syscall.
        let mut r: Registers = t.regs_ref().clone();
        r.set_arg1_signed(-1);
        t.set_regs(&r);
        syscall_state.emulate_result(result.try_into().unwrap());
        return Switchable::PreventSwitch;
    }

    let request = t.regs_ref().arg2() as u32;
    let type_: u32 = unsafe { ioctl_type(request) };
    let nr: u32 = unsafe { ioctl_nr(request) };
    let dir: u32 = unsafe { ioctl_dir(request) };
    let size: u32 = unsafe { ioctl_size(request) };

    log!(
        LogDebug,
        "handling ioctl({:#x}): type:{:#x} nr:{:#x} dir:{:#x} size:{}",
        request,
        type_,
        nr,
        dir,
        size
    );

    ed_assert!(
        t,
        !t.is_desched_event_syscall(),
        "Failed to skip past desched ioctl()"
    );

    // Some ioctl()s are irregular and don't follow the _IOC()
    // conventions.  Special case them here.
    match request {
        TIOCGWINSZ => {
            syscall_state.reg_parameter::<Arch::winsize>(3, None, None);
            return Switchable::PreventSwitch;
        }
        _ => (),
    }

    unimplemented!()
}
