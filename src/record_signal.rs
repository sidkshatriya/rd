use crate::{
    arch::Architecture,
    auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem, MemParamsEnabled},
    bindings::{
        perf_event::{PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE},
        signal::siginfo_t,
    },
    event::{Event, SignalDeterministic},
    kernel_abi::{
        native_arch,
        sigaction_sigset_size,
        syscall_number_for_rt_sigaction,
        syscall_number_for_rt_sigprocmask,
    },
    kernel_supplement::sig_set_t,
    log::LogDebug,
    preload_interface_arch::preload_thread_locals,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    session::{
        address_space::{address_space::AddressSpace, kernel_mapping::KernelMapping},
        task::{
            record_task::{FlushSyscallbuf, RecordTask, SignalDisposition},
            task_common::read_val_mem,
        },
    },
    sig::Sig,
    util::{ceil_page_size, floor_page_size, page_size, signal_bit},
};
use libc::{ioctl, prlimit, rlimit, RLIMIT_STACK, RLIM_INFINITY, SIGSEGV, SIG_BLOCK};
use nix::sys::mman::MapFlags;
use std::{
    cmp::{max, min},
    ffi::OsString,
    intrinsics::copy_nonoverlapping,
    mem::{self, size_of},
    ptr,
};

pub const SIGCHLD_SYNTHETIC: i32 = 0xbeadf00du32 as i32;

pub fn disarm_desched_event(t: &RecordTask) {
    if t.desched_fd.is_open()
        && unsafe { ioctl(t.desched_fd.as_raw(), PERF_EVENT_IOC_DISABLE, 0) } != 0
    {
        fatal!("Failed to disarm desched event");
    }
}

pub fn arm_desched_event(t: &RecordTask) {
    if t.desched_fd.is_open()
        && unsafe { ioctl(t.desched_fd.as_raw(), PERF_EVENT_IOC_ENABLE, 0) } != 0
    {
        fatal!("Failed to arm desched event");
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SignalBlocked {
    SigUnblocked = 0,
    SigBlocked = 1,
}

pub enum SignalHandled {
    SignalHandled,
    SignalPtraceStop,
    DeferSignal,
}

/// Handle the given signal for |t|.
/// Returns SIGNAL_HANDLED if we handled the signal, SIGNAL_PTRACE_STOP if we
/// didn't handle the signal due to an emulated ptrace-stop, and SIGNAL_DEFER
/// if we can't handle the signal right now and should try calling
/// handle_signal again later in task execution.
/// Handling the signal means we either pushed a new signal event, new
/// desched + syscall-interruption events, or no-op.
pub fn handle_signal(
    _t: &RecordTask,
    _si: &siginfo_t,
    _deterministic: SignalDeterministic,
    _signal_was_blocked: SignalBlocked,
) -> SignalHandled {
    unimplemented!()
}

fn rdtsc() -> u64 {
    unimplemented!()
}

fn restore_sighandler_if_not_default(t: &mut RecordTask, sig: Sig) {
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

/// Restore the blocked-ness and sigaction for |sig| from |t|'s local
/// copy.
fn restore_signal_state(t: &mut RecordTask, sig: Sig, signal_was_blocked: SignalBlocked) {
    restore_sighandler_if_not_default(t, sig);
    if signal_was_blocked == SignalBlocked::SigBlocked {
        log!(LogDebug, "Restoring signal blocked-ness for {}", sig);
        {
            let mut remote = AutoRemoteSyscalls::new(t);
            let sigset_size: usize = sigaction_sigset_size(remote.arch());
            let mut bytes = Vec::<u8>::new();
            bytes.resize(sigset_size, 0u8);
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

/// Return true if |t| was stopped because of a SIGSEGV resulting
/// from a disabled instruction and |t| was updated appropriately, false
/// otherwise.
fn try_handle_trapped_instruction(_t: &RecordTask, _si: &siginfo_t) -> bool {
    unimplemented!()
}

/// Return true if |t| was stopped because of a SIGSEGV and we want to retry
/// the instruction after emulating MAP_GROWSDOWN.
fn try_grow_map(t: &mut RecordTask, si: &mut siginfo_t) -> bool {
    ed_assert_eq!(t, si.si_signo, SIGSEGV);

    // Use kernel_abi to avoid odd inconsistencies between distros
    let arch_si = unsafe { mem::transmute::<&siginfo_t, &native_arch::siginfo_t>(si) };
    let addr = unsafe { arch_si._sifields._sigfault.si_addr_ }.rptr();

    if t.vm().mapping_of(addr).is_some() {
        log!(LogDebug, "try_grow_map {}: address already mapped", addr);
        return false;
    }

    let it: KernelMapping;
    let mut new_start = floor_page_size(addr);
    {
        let maps = t.vm().maps_starting_at(floor_page_size(addr));
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
        let ret = unsafe { prlimit(t.tid, RLIMIT_STACK, ptr::null(), &mut stack_limit) };
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

    let km: KernelMapping = t.vm_shr_ptr().map(
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

fn get_stub_scratch_1_arch<Arch: Architecture>(t: &mut RecordTask) -> RemoteCodePtr {
    let locals = read_val_mem(
        t,
        RemotePtr::<preload_thread_locals<Arch>>::cast(AddressSpace::preload_thread_locals_start()),
        None,
    );

    Arch::as_rptr(locals.stub_scratch_1).into()
}

fn get_stub_scratch_1(t: &mut RecordTask) -> RemoteCodePtr {
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
fn handle_syscallbuf_breakpoint(_t: &RecordTask) -> bool {
    unimplemented!()
}

/// Return the event needing to be processed after this desched of |t|.
/// The tracee's execution may be advanced, and if so |regs| is updated
/// to the tracee's latest state.
fn handle_desched_event(_t: &RecordTask, _si: &siginfo_t) {
    unimplemented!()
}

fn is_safe_to_deliver_signal(_t: &RecordTask, _si: &siginfo_t) -> bool {
    unimplemented!()
}
