use crate::{
    arch::Architecture,
    auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem, MemParamsEnabled},
    bindings::{
        perf_event::{PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE},
        ptrace::PTRACE_EVENT_SECCOMP,
        signal::{siginfo_t, POLL_IN},
    },
    event::{
        DeschedEventData, Event, EventType, SignalDeterministic, SignalEventData, SyscallEventData,
    },
    file_monitor::virtual_perf_counter_monitor::VirtualPerfCounterMonitor,
    kernel_abi::{
        is_rdcall_notify_syscall_hook_exit_syscall, is_rt_sigprocmask_syscall, native_arch,
        sigaction_sigset_size, syscall_number_for_rt_sigaction, syscall_number_for_rt_sigprocmask,
    },
    kernel_metadata::syscall_name,
    kernel_supplement::{sig_set_t, SYS_SECCOMP},
    log::LogDebug,
    perf_counters,
    preload_interface::{syscallbuf_hdr, syscallbuf_locked_why, syscallbuf_record},
    preload_interface_arch::preload_thread_locals,
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    session::{
        address_space::{kernel_mapping::KernelMapping, AddressSpace},
        session_inner::PtraceSyscallSeccompOrdering,
        task::{
            record_task::{FlushSyscallbuf, RecordTask, SignalDisposition},
            task_common::{read_val_mem, write_val_mem},
            task_inner::{ResumeRequest, TicksRequest, WaitRequest},
            Task,
        },
    },
    sig::{self, Sig},
    util::{
        ceil_page_size, cpuid, floor_page_size, page_size, signal_bit, trapped_instruction_at,
        trapped_instruction_len, TrappedInstruction,
    },
    wait_status::WaitStatus,
};
use libc::{
    ioctl, prlimit, rlimit, EAGAIN, PR_TSC_SIGSEGV, RLIMIT_STACK, RLIM_INFINITY, SIGSEGV, SIGSYS,
    SIG_BLOCK,
};
use nix::sys::mman::MapFlags;
use std::{
    cell::RefMut,
    cmp::{max, min},
    convert::TryFrom,
    ffi::OsString,
    intrinsics::copy_nonoverlapping,
    mem::size_of,
    ptr,
};

extern "C" {
    fn rdtsc() -> u64;
}

pub const SIGCHLD_SYNTHETIC: i32 = 0xbeadf00du32 as i32;

pub fn disarm_desched_event(t: &RecordTask) {
    if t.desched_fd.borrow().is_open()
        && unsafe { ioctl(t.desched_fd.borrow().as_raw(), PERF_EVENT_IOC_DISABLE, 0) } != 0
    {
        fatal!("Failed to disarm desched event");
    }
}

pub fn arm_desched_event(t: &RecordTask) {
    if t.desched_fd.borrow().is_open()
        && unsafe { ioctl(t.desched_fd.borrow().as_raw(), PERF_EVENT_IOC_ENABLE, 0) } != 0
    {
        fatal!("Failed to arm desched event");
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SignalBlocked {
    SigUnblocked = 0,
    SigBlocked = 1,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SignalHandled {
    SignalHandled,
    SignalPtraceStop,
    DeferSignal,
}

/// Handle the given signal for `t`.
/// Returns SIGNAL_HANDLED if we handled the signal, SIGNAL_PTRACE_STOP if we
/// didn't handle the signal due to an emulated ptrace-stop, and SIGNAL_DEFER
/// if we can't handle the signal right now and should try calling
/// handle_signal again later in task execution.
/// Handling the signal means we either pushed a new signal event, new
/// desched + syscall-interruption events, or no-op.
///
/// DIFF NOTE: si param passed by value and treated subtly differently
pub fn handle_signal(
    t: &RecordTask,
    mut si: siginfo_t,
    deterministic: SignalDeterministic,
    signal_was_blocked: SignalBlocked,
) -> (SignalHandled, siginfo_t) {
    let sig = Sig::try_from(si.si_signo).unwrap();
    log!(
        LogDebug,
        "{}: handling signal {} (pevent: {}, event: {})",
        t.tid(),
        sig,
        t.maybe_ptrace_event(),
        t.ev()
    );

    // Conservatively invalidate the sigmask in case just accepting a signal has
    // sigmask effects.
    t.invalidate_sigmask();

    if deterministic == SignalDeterministic::DeterministicSig {
        // When a deterministic signal is triggered, but the signal is currently
        // blocked or ignored, the kernel (in |force_sig_info|) unblocks it and
        // sets its disposition to SIG_DFL. It never undoes this (probably
        // because it expects the signal to be fatal, which it always would be
        // unless a ptracer intercepts the signal as we do). Therefore, if the
        // signal was generated for rr's purposes, we need to restore the signal
        // state ourselves.
        if sig == sig::SIGSEGV && (try_handle_trapped_instruction(t, &si) || try_grow_map(t, &si)) {
            if signal_was_blocked == SignalBlocked::SigBlocked || t.is_sig_ignored(sig) {
                restore_signal_state(t, sig, signal_was_blocked);
            }
            return (SignalHandled::SignalHandled, si);
        }

        // Since we're not undoing the kernel's changes, update our signal handler
        // state to match the kernel's.
        if signal_was_blocked == SignalBlocked::SigBlocked || t.is_sig_ignored(sig) {
            t.did_set_sig_handler_default(sig);
        }
    }

    if !VirtualPerfCounterMonitor::is_virtual_perf_counter_signal(&si) {
        // We have to check for a desched event first, because for
        // those we *do not* want to (and cannot, most of the time)
        // step the tracee out of the syscallbuf code before
        // attempting to deliver the signal.
        if t.session()
            .as_record()
            .unwrap()
            .syscallbuf_desched_sig()
            .as_raw()
            == si.si_signo
        {
            handle_desched_event(t, &si);
            return (SignalHandled::SignalHandled, si);
        }

        if !is_safe_to_deliver_signal(t, &si) {
            return (SignalHandled::DeferSignal, si);
        }

        if !t.set_siginfo_for_synthetic_sigchld(&mut si) {
            return (SignalHandled::DeferSignal, si);
        }

        if sig == perf_counters::TIME_SLICE_SIGNAL {
            t.push_event(Event::sched());
            return (SignalHandled::SignalHandled, si);
        }
    } else {
        // Clear the magic flag so it doesn't leak into the program.
        si.si_errno = 0;
    }

    // This signal was generated by the program or an external
    // source, record it normally.

    let emulated_ptracer = t.emulated_ptracer();
    match emulated_ptracer {
        Some(_tracer) => {
            t.emulate_ptrace_stop(WaitStatus::for_stop_sig(sig), Some(&si), None);
            // Record an event so that replay progresses the tracee to the
            // current point before we notify the tracer.
            // If the signal is deterministic, record it as an EV_SIGNAL so that
            // we replay it using the deterministic-signal replay path. This is
            // more efficient than emulate_async_signal. Also emulate_async_signal
            // currently assumes it won't encounter a deterministic SIGTRAP (due to
            // a hardcoded breakpoint in the tracee).
            if deterministic == SignalDeterministic::DeterministicSig {
                let resolved_disposition = t.sig_resolved_disposition(sig, deterministic);
                t.record_event(
                    Some(Event::new_signal_event(
                        EventType::EvSignal,
                        SignalEventData::new(&si, deterministic, resolved_disposition),
                    )),
                    None,
                    None,
                    None,
                );
            } else {
                t.record_event(Some(Event::sched()), None, None, None);
            }
            // ptracer has been notified, so don't deliver the signal now.
            // The signal won't be delivered for real until the ptracer calls
            // PTRACE_CONT with the signal number (which we don't support yet!).
            return (SignalHandled::SignalPtraceStop, si);
        }
        None => (),
    }

    let resolved_disposition = t.sig_resolved_disposition(sig, deterministic);
    t.push_event(Event::new_signal_event(
        EventType::EvSignal,
        SignalEventData::new(&si, deterministic, resolved_disposition),
    ));

    (SignalHandled::SignalHandled, si)
}

fn restore_sighandler_if_not_default(t: &RecordTask, sig: Sig) {
    if t.sig_disposition(sig) != SignalDisposition::SignalDefault {
        log!(LogDebug, "Restoring signal handler for {}", sig);
        let sa: Vec<u8> = t.signal_action(sig);
        let mut remote = AutoRemoteSyscalls::new(t);
        let arch = remote.arch();
        let sigset_size: usize = sigaction_sigset_size(arch);
        let mut child_sa = AutoRestoreMem::new(&mut remote, Some(&sa), sa.len());
        let child_sa_addr = child_sa.get().unwrap();
        rd_infallible_syscall!(
            child_sa,
            syscall_number_for_rt_sigaction(arch),
            sig.as_raw(),
            child_sa_addr.as_usize(),
            0,
            sigset_size
        );
    }
}

/// Restore the blocked-ness and sigaction for `sig` from `t`'s local
/// copy.
fn restore_signal_state(t: &RecordTask, sig: Sig, signal_was_blocked: SignalBlocked) {
    restore_sighandler_if_not_default(t, sig);
    if signal_was_blocked == SignalBlocked::SigBlocked {
        log!(LogDebug, "Restoring signal blocked-ness for {}", sig);
        {
            let mut remote = AutoRemoteSyscalls::new(t);
            let sigset_size: usize = sigaction_sigset_size(remote.arch());
            let mut bytes = vec![0u8; sigset_size];
            let mask: sig_set_t = signal_bit(sig);
            ed_assert!(remote.task(), sigset_size >= size_of::<sig_set_t>());
            unsafe {
                copy_nonoverlapping(
                    &raw const mask as *const u8,
                    bytes.as_mut_ptr(),
                    size_of::<sig_set_t>(),
                )
            };
            let arch = remote.arch();
            let mut child_block = AutoRestoreMem::new(&mut remote, Some(&bytes), bytes.len());
            let child_addr = child_block.get().unwrap();
            rd_infallible_syscall!(
                child_block,
                syscall_number_for_rt_sigprocmask(arch),
                SIG_BLOCK,
                child_addr.as_usize(),
                0,
                sigset_size
            );
        }
        // We just changed the sigmask ourselves.
        t.invalidate_sigmask();
    }
}

/// Return true if `t` was stopped because of a SIGSEGV resulting
/// from a disabled instruction and `t` was updated appropriately, false
/// otherwise.
fn try_handle_trapped_instruction(t: &RecordTask, si: &siginfo_t) -> bool {
    ed_assert!(t, si.si_signo == SIGSEGV);

    let trapped_instruction = trapped_instruction_at(t, t.ip());
    match trapped_instruction {
        TrappedInstruction::Rdtsc | TrappedInstruction::Rdtscp => {
            if t.tsc_mode.get() == PR_TSC_SIGSEGV {
                return false;
            }
        }
        TrappedInstruction::CpuId => {
            if t.cpuid_mode.get() == 0 {
                return false;
            }
        }
        _ => return false,
    }

    let len: usize = trapped_instruction_len(trapped_instruction);
    ed_assert!(t, len > 0);

    let mut r: Registers = t.regs_ref().clone();
    if trapped_instruction == TrappedInstruction::Rdtsc
        || trapped_instruction == TrappedInstruction::Rdtscp
    {
        let current_time = unsafe { rdtsc() };
        r.set_rdtsc_output(current_time);

        log!(LogDebug, " trapped for rdtsc: returning {}", current_time);
    } else if trapped_instruction == TrappedInstruction::CpuId {
        let eax = r.syscallno() as u32;
        let ecx = r.cx() as u32;
        let mut cpuid_data = cpuid(eax, ecx);
        t.session()
            .as_record()
            .unwrap()
            .disable_cpuid_features()
            .amend_cpuid_data(eax, ecx, &mut cpuid_data);
        r.set_cpuid_output(
            cpuid_data.eax,
            cpuid_data.ebx,
            cpuid_data.ecx,
            cpuid_data.edx,
        );
        log!(LogDebug, " trapped for cpuid: {:#x}:{:#x}", eax, ecx);
    }

    r.set_ip(r.ip() + len);
    t.set_regs(&r);

    t.push_event(Event::instruction_trap());

    true
}

/// Return true if `t` was stopped because of a SIGSEGV and we want to retry
/// the instruction after emulating MAP_GROWSDOWN.
fn try_grow_map(t: &RecordTask, si: &siginfo_t) -> bool {
    ed_assert_eq!(t, si.si_signo, SIGSEGV);

    // Use kernel_abi to avoid odd inconsistencies between distros
    let arch_si = unsafe { &*(si as *const siginfo_t as *const native_arch::siginfo_t) };
    let addr = unsafe { arch_si._sifields._sigfault.si_addr_ }.rptr();

    if t.vm().mapping_of(addr).is_some() {
        log!(LogDebug, "try_grow_map {}: address already mapped", addr);
        return false;
    }

    let it: KernelMapping;
    let mut new_start = floor_page_size(addr);
    {
        let vm_shr_ptr = t.vm();
        let maps = vm_shr_ptr.maps_starting_at(floor_page_size(addr));
        let mut maps_iter = maps.into_iter();
        let kv = maps_iter.next();
        match kv {
            None => {
                log!(
                    LogDebug,
                    "try_grow_map {}: no later map to grow downward",
                    addr
                );

                return false;
            }
            Some((_k, v)) => {
                if !v.map.flags().contains(MapFlags::MAP_GROWSDOWN) {
                    log!(
                        LogDebug,
                        "try_grow_map {}: map is not MAP_GROWSDOWN ({})",
                        addr,
                        v.map
                    );

                    return false;
                }

                it = v.map.clone();
            }
        }

        if addr.as_usize() >= page_size() && t.vm().mapping_of(addr - page_size()).is_some() {
            log!(
                LogDebug,
                "try_grow_map {}: address would be in guard page",
                addr
            );
            return false;
        }

        let mut stack_limit: rlimit = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let mut limit_bottom: RemotePtr<Void> = RemotePtr::null();
        let ret = unsafe { prlimit(t.tid(), RLIMIT_STACK, ptr::null(), &mut stack_limit) };
        if ret >= 0 && stack_limit.rlim_cur != RLIM_INFINITY {
            limit_bottom = RemotePtr::from(ceil_page_size(
                it.end().as_usize() - stack_limit.rlim_cur as usize,
            ));
            if limit_bottom > addr {
                log!(LogDebug, "try_grow_map {}: RLIMIT_STACK exceeded", addr);
                return false;
            }
        }

        // Try to grow by 64K at a time to reduce signal frequency.
        let grow_size: usize = 0x10000;
        if it.start().as_usize() >= grow_size {
            let possible_new_start = max(limit_bottom, min(new_start, it.start() - grow_size));
            // Ensure that no mapping exists between possible_new_start - page_size()
            // and new_start. If there is, possible_new_start is not valid, in which
            // case we just abandon the optimization.
            if possible_new_start.as_usize() >= page_size()
                && t.vm()
                    .mapping_of(possible_new_start - page_size())
                    .is_none()
                && t.vm()
                    .maps_starting_at(possible_new_start - page_size())
                    .into_iter()
                    .next()
                    .unwrap()
                    .1
                    .map
                    .start()
                    == it.start()
            {
                new_start = possible_new_start;
            }
        }

        log!(LogDebug, "try_grow_map {}: trying to grow map ", it);
    }

    {
        let mut remote =
            AutoRemoteSyscalls::new_with_mem_params(t, MemParamsEnabled::DisableMemoryParams);
        remote.infallible_mmap_syscall(
            Some(new_start),
            it.start() - new_start,
            it.prot(),
            (it.flags() & !MapFlags::MAP_GROWSDOWN) | MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED,
            -1,
            0,
        );
    }

    let km: KernelMapping = t.vm().map(
        t,
        new_start,
        it.start() - new_start,
        it.prot(),
        it.flags() | MapFlags::MAP_ANONYMOUS,
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

    t.trace_writer_mut()
        .write_mapped_region(t, &km, &km.fake_stat(), &[], None, None);

    // No need to flush syscallbuf here. It's safe to map these pages "early"
    // before they're really needed.
    t.record_event(
        Some(Event::grow_map()),
        Some(FlushSyscallbuf::DontFlushSyscallbuf),
        None,
        None,
    );

    t.push_event(Event::noop());
    log!(
        LogDebug,
        "try_grow_map {}: extended map {}",
        addr,
        t.vm().mapping_of(addr).unwrap().map
    );

    true
}

fn get_stub_scratch_1_arch<Arch: Architecture>(t: &RecordTask) -> RemoteCodePtr {
    let locals = read_val_mem(
        t,
        RemotePtr::<preload_thread_locals<Arch>>::cast(AddressSpace::preload_thread_locals_start()),
        None,
    );

    Arch::as_rptr(locals.stub_scratch_1).into()
}

fn get_stub_scratch_1(t: &RecordTask) -> RemoteCodePtr {
    let arch = t.arch();
    rd_arch_function_selfless!(get_stub_scratch_1_arch, arch, t)
}

/// This function is responsible for handling breakpoints we set in syscallbuf
/// code to detect sigprocmask calls and syscallbuf exit. It's called when we
/// get a SIGTRAP. Returns true if the SIGTRAP was called by one of our
/// breakpoints and should be hidden from the application.
/// If it was triggered by one of our breakpoints, we have to call
/// restore_sighandler_if_not_default(t, SIGTRAP) to make sure the SIGTRAP
/// handler is properly restored if the kernel cleared it.
pub fn handle_syscallbuf_breakpoint(t: &RecordTask) -> bool {
    if t.is_at_syscallbuf_final_instruction_breakpoint() {
        log!(
            LogDebug,
            "Reached final syscallbuf instruction, singlestepping to enable signal dispatch"
        );
        // This is a single instruction that jumps to the location stored in
        // preload_thread_locals::stub_scratch_1. Emulate it.
        let scratch = get_stub_scratch_1(t);
        t.emulate_jump(scratch);

        restore_sighandler_if_not_default(t, sig::SIGTRAP);
        // Now we're back in application code so any pending stashed signals
        // will be handled.
        return true;
    }

    if !t.is_at_syscallbuf_syscall_entry_breakpoint() {
        return false;
    }

    let mut r: Registers = t.regs_ref().clone();
    r.set_ip(r.ip().decrement_by_bkpt_insn_length(t.arch()));
    t.set_regs(&r);

    if t.is_at_traced_syscall_entry() {
        // We will automatically dispatch stashed signals now since this is an
        // allowed place to dispatch signals.
        log!(
            LogDebug,
            "Allowing signal dispatch at traced-syscall breakpoint"
        );
        restore_sighandler_if_not_default(t, sig::SIGTRAP);
        return true;
    }

    // We're at an untraced-syscall entry point.
    // To allow an AutoRemoteSyscall, we need to make sure desched signals are
    // disarmed (and rearmed afterward).
    let syscallbuf_child = t.syscallbuf_child.get();
    let res = read_val_mem(
        t,
        RemotePtr::<u8>::cast(syscallbuf_child)
            + offset_of!(syscallbuf_hdr, desched_signal_may_be_relevant),
        None,
    );

    let armed_desched_event = res != 0;
    if armed_desched_event {
        disarm_desched_event(t);
    }
    restore_sighandler_if_not_default(t, sig::SIGTRAP);
    if armed_desched_event {
        arm_desched_event(t);
    }

    // This is definitely a native-arch syscall.
    if is_rt_sigprocmask_syscall(r.syscallno() as i32, t.arch()) {
        // Don't proceed with this syscall. Emulate it returning EAGAIN.
        // Syscallbuf logic will retry using a traced syscall instead.
        r.set_syscall_result_signed(-EAGAIN as isize);
        r.set_ip(r.ip().increment_by_syscall_insn_length(t.arch()));
        t.set_regs(&r);
        let arch = t.arch();
        t.canonicalize_regs(arch);
        log!(
            LogDebug,
            "Emulated EAGAIN to avoid untraced sigprocmask with pending stashed signal"
        );
        // Leave breakpoints enabled since we want to break at the traced-syscall
        // fallback for rt_sigprocmask.
        return true;
    }

    // We can proceed with the untraced syscall. Either it will complete and
    // execution will continue until we reach some point where we can deliver our
    // signal, or it will block at which point we'll be able to deliver our
    // signal.
    log!(LogDebug, "Disabling breakpoints at untraced syscalls");
    t.break_at_syscallbuf_untraced_syscalls.set(false);

    true
}

/// Return the event needing to be processed after this desched of `t`.
/// The tracee's execution may be advanced, and if so `regs` is updated
/// to the tracee's latest state.
fn handle_desched_event(t: &RecordTask, si: &siginfo_t) {
    let desched_sig = t.session().as_record().unwrap().syscallbuf_desched_sig();
    ed_assert!(
        t,
        desched_sig.as_raw() == si.si_signo && si.si_code == POLL_IN as i32,
        "Tracee is using the syscallbuf signal ({}) ??? (siginfo={})\n\
         Try recording with --syscall-buffer-sig=<UNUSED SIGNAL>",
        desched_sig,
        *si
    );

    // If the tracee isn't in the critical section where a desched
    // event is relevant, we can ignore it.  See the long comments
    // in syscall_buffer.c.
    //
    // It's OK if the tracee is in the critical section for a
    // may-block syscall B, but this signal was delivered by an
    // event programmed by a previous may-block syscall A.
    //
    // If we're running in a signal handler inside an interrupted syscallbuf
    // system call, never do anything here. Syscall buffering is disabled and
    // the desched_signal_may_be_relevant was set by the outermost syscallbuf
    // invocation.
    let syscallbuf_child = t.syscallbuf_child.get();
    if 0 == read_val_mem(
        t,
        RemotePtr::<u8>::cast(syscallbuf_child)
            + offset_of!(syscallbuf_hdr, desched_signal_may_be_relevant),
        None,
    ) || t.running_inside_desched()
    {
        log!(LogDebug, "  (not entering may-block syscall; resuming)");
        // We have to disarm the event just in case the tracee
        // has cleared the relevancy flag, but not yet
        // disarmed the event itself.
        disarm_desched_event(t);
        t.push_event(Event::noop());
        return;
    }

    // TODO: how can signals interrupt us here?

    // The desched event just fired.  That implies that the
    // arm-desched ioctl went into effect, and that the
    // disarm-desched syscall didn't take effect.  Since a signal
    // is pending for the tracee, then if the tracee was in a
    // syscall, linux has exited it with an -ERESTART* error code.
    // That means the tracee is about to (re-)enter either
    //
    //  1. buffered syscall
    //  2. disarm-desched ioctl syscall
    //
    // We can figure out which one by simply issuing a
    // ptrace(SYSCALL) and examining the tracee's registers.
    //
    // If the tracee enters the disarm-desched ioctl, it's going
    // to commit a record of the buffered syscall to the
    // syscallbuf, and we can safely send the tracee back on its
    // way, ignoring the desched completely.
    //
    // If it enters the buffered syscall, then the desched event
    // has served its purpose and we need to prepare the tracee to
    // be context-switched.
    //
    // An annoyance of the desched signal is that when the tracer
    // is descheduled in interval (C) above, we see normally (see
    // below) see *two* signals.  The current theory of what's
    // happening is
    //
    //  o child gets descheduled, bumps counter to i and schedules
    //    signal
    //  o signal notification "schedules" child, but it doesn't
    //    actually run any application code
    //  o child is being ptraced, so we "deschedule" child to
    //    notify parent and bump counter to i+1.  (The parent
    //    hasn't had a chance to clear the counter yet.)
    //  o another counter signal is generated, but signal is
    //    already pending so this one is queued
    //  o parent is notified and sees counter value i+1
    //  o parent stops delivery of first signal and disarms
    //    counter
    //  o second signal dequeued and delivered, notififying parent
    //    (counter is disarmed now, so no pseudo-desched possible
    //    here)
    //  o parent notifiedand sees counter value i+1 again
    //  o parent stops delivery of second signal and we continue on
    //
    // So we "work around" this by the tracer expecting two signal
    // notifications, and silently discarding both.
    //
    // One really fun edge case is that sometimes the desched
    // signal will interrupt the arm-desched syscall itself.
    // Continuing to the next syscall boundary seems to restart
    // the arm-desched syscall, and advancing to the boundary
    // again exits it and we start receiving desched signals
    // again.
    //
    // That may be a kernel bug, but we handle it by just
    // continuing until we we continue past the arm-desched
    // syscall *and* stop seeing signals. */
    loop {
        // Prevent further desched notifications from firing
        // while we're advancing the tracee.  We're going to
        // leave it in a consistent state anyway, so the event
        // is no longer useful.  We have to do this in each
        // loop iteration because a restarted arm-desched
        // syscall may have re-armed the event.
        disarm_desched_event(t);

        t.resume_execution(
            ResumeRequest::ResumeSyscall,
            WaitRequest::ResumeWait,
            TicksRequest::ResumeUnlimitedTicks,
            None,
        );

        if t.status().is_syscall() {
            if t.is_arm_desched_event_syscall() {
                continue;
            }
            break;
        }

        if t.maybe_ptrace_event() == PTRACE_EVENT_SECCOMP {
            ed_assert_eq!(
                t,
                t.session().syscall_seccomp_ordering(),
                PtraceSyscallSeccompOrdering::SeccompBeforeSyscall
            );
            // This is the old kernel event ordering. This must be a SECCOMP event
            // for the buffered syscall; it's not rr-generated because this is an
            // untraced syscall, but it could be generated by a tracee's
            // seccomp filter.
            break;
        }

        // Completely ignore spurious desched signals and
        // signals that aren't going to be delivered to the
        // tracee.
        //
        // Also ignore time-slice signals.  If the tracee ends
        // up at the disarm-desched ioctl, we'll reschedule it
        // with the ticks interrupt still programmed.  At worst,
        // the tracee will get an extra time-slice out of
        // this, on average, so we don't worry too much about
        // it.
        //
        // TODO: it's theoretically possible for this to
        // happen an unbounded number of consecutive times
        // and the tracee never switched out.
        let maybe_sig = t.maybe_stop_sig();
        ed_assert!(
            t,
            maybe_sig.is_sig(),
            "expected stop-signal, got {}",
            t.status()
        );

        let sig = maybe_sig.unwrap_sig();
        if sig == sig::SIGTRAP && handle_syscallbuf_breakpoint(t) {
            // We stopped at a breakpoint on an untraced may-block syscall.
            // This can't be relevant to us since sigprocmask isn't may-block.
            log!(LogDebug, " disabling breakpoints on untraced syscalls");
            continue;
        }

        if desched_sig == sig || perf_counters::TIME_SLICE_SIGNAL == sig || t.is_sig_ignored(sig) {
            log!(LogDebug, "  dropping ignored {}", sig);
            continue;
        }

        log!(LogDebug, "  stashing {}", sig);
        t.stash_sig();
    }

    if t.is_disarm_desched_event_syscall() {
        log!(
            LogDebug,
            "  (at disarm-desched, so finished buffered syscall; resuming)"
        );
        t.push_event(Event::noop());
        return;
    }

    if !t.desched_rec().is_null() {
        // We're already processing a desched. We probably reexecuted the
        // system call (e.g. because a signal was processed) and the syscall
        // blocked again. Carry on with the current desched.
    } else {
        // This prevents the syscallbuf record counter from being
        // reset until we've finished guiding the tracee through this
        // interrupted call.  We use the record counter for
        // assertions.
        ed_assert!(t, !t.delay_syscallbuf_reset_for_desched.get());
        t.delay_syscallbuf_reset_for_desched.set(true);
        log!(LogDebug, "Desched initiated");

        // The tracee is (re-)entering the buffered syscall.  Stash
        // away this breadcrumb so that we can figure out what syscall
        // the tracee was in, and how much "scratch" space it carved
        // off the syscallbuf, if needed.
        let next_desched_rec: RemotePtr<syscallbuf_record> = t.next_syscallbuf_record();
        t.push_event(Event::new_desched_event(DeschedEventData {
            rec: next_desched_rec,
        }));
        let desched_rec_addr = t.desched_rec();
        let call = read_val_mem(
            t,
            RemotePtr::<u16>::cast(
                desched_rec_addr.as_rptr_u8() + offset_of!(syscallbuf_record, syscallno),
            ),
            None,
        ) as i32;

        // The descheduled syscall was interrupted by a signal, like
        // all other may-restart syscalls, with the exception that
        // this one has already been restarted (which we'll detect
        // back in the main loop).
        t.push_event(Event::new_syscall_interruption_event(
            SyscallEventData::new(call, t.arch()),
        ));
        let mut ev = RefMut::map(t.ev_mut(), |r| r.syscall_event_mut());
        ev.desched_rec = next_desched_rec;
    }

    {
        let regs = t.regs_ref().clone();
        let mut ev = RefMut::map(t.ev_mut(), |r| r.syscall_event_mut());
        ev.regs = regs;
    }
    // For some syscalls (at least poll) but not all (at least not read),
    // repeated cont_syscall()s above of the same interrupted syscall
    // can set $orig_eax to 0 ... for unclear reasons. Fix that up here
    // otherwise we'll get a divergence during replay, which will not
    // encounter this problem.
    let desched_rec_addr = t.desched_rec();
    let call = read_val_mem(
        t,
        RemotePtr::<u16>::cast(
            desched_rec_addr.as_rptr_u8() + offset_of!(syscallbuf_record, syscallno),
        ),
        None,
    ) as i32;

    {
        let mut ev = RefMut::map(t.ev_mut(), |r| r.syscall_event_mut());
        ev.regs.set_original_syscallno(call as isize);
    }

    let arch = t.ev().syscall_event().arch();
    let regs = t.ev().syscall_event().regs.clone();
    t.set_regs(&regs);
    // runnable_state_changed will observe us entering this syscall and change
    // state to ENTERING_SYSCALL

    log!(
        LogDebug,
        "  resuming (and probably switching out) blocked `{}`",
        syscall_name(call, arch)
    );
}

fn is_safe_to_deliver_signal(t: &RecordTask, si: &siginfo_t) -> bool {
    if !t.is_in_syscallbuf() {
        // The tracee is outside the syscallbuf code,
        // so in most cases can't possibly affect
        // syscallbuf critical sections.  The
        // exception is signal handlers "re-entering"
        // desched'd syscalls, which are OK.
        log!(
            LogDebug,
            "Safe to deliver signal at {} because not in syscallbuf",
            t.ip()
        );

        return true;
    }

    if t.is_in_traced_syscall() {
        log!(
            LogDebug,
            "Safe to deliver signal at {} because in traced syscall",
            t.ip()
        );

        return true;
    }

    // Don't deliver signals just before entering rrcall_notify_syscall_hook_exit.
    // At that point, notify_on_syscall_hook_exit will be set, but we have
    // passed the point at which syscallbuf code has checked that flag.
    // Replay will set notify_on_syscall_hook_exit when we replay towards the
    // rrcall_notify_syscall_hook_exit *after* handling this signal, but
    // that will be too late for syscallbuf to notice.
    // It's OK to delay signal delivery until after rrcall_notify_syscall_hook_exit
    // anyway.
    if t.is_at_traced_syscall_entry()
        && !is_rdcall_notify_syscall_hook_exit_syscall(t.regs_ref().syscallno() as i32, t.arch())
    {
        log!(
            LogDebug,
            "Safe to deliver signal at {} because at entry to traced syscall",
            t.ip()
        );

        return true;
    }

    if t.is_in_untraced_syscall() && !t.desched_rec().is_null() {
        let desched_rec_addr = t.desched_rec(); // Untraced syscalls always use the architecture of the process
        log!(
            LogDebug,
            "Safe to deliver signal at {} because tracee interrupted by desched of {}",
            t.ip(),
            syscall_name(
                read_val_mem(
                    t,
                    RemotePtr::<u16>::cast(
                        desched_rec_addr.as_rptr_u8() + offset_of!(syscallbuf_record, syscallno)
                    ),
                    None
                ) as i32,
                t.arch()
            )
        );
        return true;
    }

    if t.is_in_untraced_syscall() && si.si_signo == SIGSYS && si.si_code == SYS_SECCOMP as i32 {
        log!(
            LogDebug,
            "Safe to deliver signal at {} because signal is seccomp trap.",
            t.ip()
        );

        return true;
    }

    // If the syscallbuf buffer hasn't been created yet, just delay the signal
    // with no need to set notify_on_syscall_hook_exit; the signal will be
    // delivered when rrcall_init_buffers is called.
    if !t.syscallbuf_child.get().is_null() {
        let syscallbuf_child = t.syscallbuf_child.get();
        let locked_why = read_val_mem(
            t,
            RemotePtr::<syscallbuf_locked_why>::cast(
                syscallbuf_child.as_rptr_u8() + offset_of!(syscallbuf_hdr, locked),
            ),
            None,
        );

        if locked_why.contains(syscallbuf_locked_why::SYSCALLBUF_LOCKED_TRACER) {
            log!(
                LogDebug,
                "Safe to deliver signal at {} because the syscallbuf is locked",
                t.ip()
            );

            return true;
        }

        // A signal (e.g. seccomp SIGSYS) interrupted a untraced syscall in a
        // non-restartable way. Defer it until SYS_rdcall_notify_syscall_hook_exit.
        if t.is_in_untraced_syscall() {
            // Our emulation of SYS_rdcall_notify_syscall_hook_exit clears this flag.
            let syscallbuf_child = t.syscallbuf_child.get();
            write_val_mem(
                t,
                syscallbuf_child.as_rptr_u8()
                    + offset_of!(syscallbuf_hdr, notify_on_syscall_hook_exit),
                &1u8,
                None,
            );
        }
    }

    log!(LogDebug, "Not safe to deliver signal at {}", t.ip());

    false
}
