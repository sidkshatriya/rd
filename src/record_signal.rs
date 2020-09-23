use crate::{
    arch::Architecture,
    bindings::{
        perf_event::{PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE},
        signal::siginfo_t,
    },
    event::SignalDeterministic,
    preload_interface_arch::preload_thread_locals,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::RemotePtr,
    session::{
        address_space::address_space::AddressSpace,
        task::{record_task::RecordTask, task_common::read_val_mem},
    },
    sig::Sig,
};
use libc::ioctl;

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
fn restore_signal_state(_t: &RecordTask, _sig: Sig, _signal_was_blocked: SignalBlocked) {
    unimplemented!()
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
