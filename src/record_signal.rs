use crate::{
    arch::Architecture,
    auto_remote_syscalls::{AutoRemoteSyscalls, AutoRestoreMem},
    bindings::{
        perf_event::{PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE},
        signal::siginfo_t,
    },
    event::SignalDeterministic,
    kernel_abi::{sigaction_sigset_size, syscall_number_for_rt_sigprocmask},
    kernel_supplement::sig_set_t,
    log::LogDebug,
    preload_interface_arch::preload_thread_locals,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::RemotePtr,
    session::{
        address_space::address_space::AddressSpace,
        task::{record_task::RecordTask, task_common::read_val_mem},
    },
    sig::Sig,
    util::signal_bit,
};
use libc::{ioctl, SIG_BLOCK};
use std::{intrinsics::copy_nonoverlapping, mem::size_of};

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

fn restore_sighandler_if_not_default(_t: &RecordTask, _sig: Sig) {
    unimplemented!()
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
fn try_grow_map(_t: &RecordTask, _si: &siginfo_t) -> bool {
    unimplemented!()
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
