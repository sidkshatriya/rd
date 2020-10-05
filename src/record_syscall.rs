use crate::{
    event::Switchable,
    registers::Registers,
    remote_ptr::{RemotePtr, Void},
    session::task::{record_task::RecordTask, TaskSharedWeakPtr},
    trace::trace_task_event::TraceTaskEvent,
};

pub fn rec_prepare_syscall(_t: &RecordTask) -> Switchable {
    unimplemented!()
}

pub fn rec_prepare_restart_syscall(_t: &RecordTask) {
    unimplemented!()
}

pub fn rec_process_syscall(_t: &RecordTask) {
    unimplemented!()
}

type AfterSyscallAction = Box<dyn Fn(&RecordTask) -> ()>;
type ArgMutator = Box<dyn Fn(&RecordTask, RemotePtr<Void>, *const u8) -> ()>;

/// When tasks enter syscalls that may block and so must be
/// prepared for a context-switch, and the syscall params
/// include (in)outparams that point to buffers, we need to
/// redirect those arguments to scratch memory.  This allows rr
/// to serialize execution of what may be multiple blocked
/// syscalls completing "simultaneously" (from rr's
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
struct TaskSyscallState {
    t: TaskSharedWeakPtr,

    param_list: Vec<MemoryParam>,
    /// Tracks the position in t's scratch_ptr buffer where we should allocate
    /// the next scratch area.
    scratch: RemotePtr<Void>,

    after_syscall_actions: Vec<AfterSyscallAction>,

    exec_saved_event: Box<TraceTaskEvent>,

    emulate_wait_for_child: TaskSharedWeakPtr,

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
    emulated_result: u64,

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

    /// Miscellaneous saved data that can be used by particular syscalls */
    saved_data: Vec<u8>,
}

/// Upon successful syscall completion, each RestoreAndRecordScratch record
/// in param_list consumes num_bytes from the t->scratch_ptr
/// buffer, copying the data to remote_dest and recording the data at
/// remote_dest. If ptr_in_reg is greater than zero, updates the task's
/// ptr_in_reg register with 'remote_dest'. If ptr_in_memory is non-null,
/// updates the ptr_in_memory location with the value 'remote_dest'.
struct MemoryParam {
    dest: RemotePtr<Void>,
    scratch: RemotePtr<Void>,
    num_bytes: ParamSize,
    ptr_in_memory: RemotePtr<Void>,
    ptr_in_reg: i32,
    mode: ArgMode,
    mutator: ArgMutator,
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
struct ParamSize {
    incoming_size: usize,
    /// If non-null, the size is limited by the value at this location after
    /// the syscall.
    mem_ptr: RemotePtr<Void>,
    /// Size of the value at mem_ptr or in the syscall result register. */
    read_size: usize,
    /// If true, the size is limited by the value of the syscall result. */
    from_syscall: bool,
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
