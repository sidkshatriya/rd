use crate::{
    arch::Architecture,
    event::Switchable,
    registers::Registers,
    remote_ptr::{RemotePtr, Void},
    session::task::{
        record_task::RecordTask,
        task_common::read_val_mem,
        Task,
        TaskSharedPtr,
        TaskSharedWeakPtr,
    },
    trace::trace_task_event::TraceTaskEvent,
};
use std::{cmp::min, convert::TryInto, mem::size_of};

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

impl TaskSyscallState {
    fn task(&self) -> TaskSharedPtr {
        self.t.upgrade().unwrap()
    }

    pub fn init(_t: &RecordTask) {
        unimplemented!()
    }

    /// Identify a syscall memory parameter whose address is in register 'arg'
    /// with type T.
    /// Returns a RemotePtr to the data in the child (before scratch relocation)
    /// or null if parameters have already been prepared (the syscall is
    /// resuming).
    pub fn reg_parameter<T>(
        &mut self,
        arg: i32,
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
    pub fn reg_parameter_with_size(
        &mut self,
        arg: i32,
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
        {
            let t = self.task();
            ed_assert!(
                &t.borrow(),
                param.maybe_mutator.is_none() || mode == ArgMode::In
            );
        }
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
    pub fn mem_ptr_parameter<T>(
        &mut self,
        addr_of_buf_ptr: RemotePtr<Void>,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<T> {
        RemotePtr::<T>::cast(self.mem_ptr_parameter_with_size(
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
    pub fn mem_ptr_parameter_inferred<Arch: Architecture, T>(
        &mut self,
        addr_of_buf_ptr: RemotePtr<Arch::ptr<T>>,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<T> {
        RemotePtr::<T>::cast(self.mem_ptr_parameter_with_size(
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
    pub fn mem_ptr_parameter_with_size(
        &mut self,
        addr_of_buf_ptr: RemotePtr<Void>,
        param_size: ParamSize,
        maybe_mode: Option<ArgMode>,
        maybe_mutator: Option<ArgMutator>,
    ) -> RemotePtr<Void> {
        let mode = maybe_mode.unwrap_or(ArgMode::Out);
        if self.preparation_done || addr_of_buf_ptr.is_null() {
            return RemotePtr::null();
        }

        let mut param = MemoryParam::default();
        let t = self.task();
        let dest = get_remote_ptr(t.borrow_mut().as_mut(), addr_of_buf_ptr);
        if dest.is_null() {
            return RemotePtr::null();
        }
        param.dest = dest;
        param.num_bytes = param_size;
        param.mode = mode;
        param.maybe_mutator = maybe_mutator;
        ed_assert!(
            &t.borrow(),
            param.maybe_mutator.is_none() || mode == ArgMode::In
        );
        if mode != ArgMode::InOutNoScratch {
            param.scratch = self.scratch;
            self.scratch += param.num_bytes.incoming_size;
            align_scratch(&mut self.scratch, None);
            param.ptr_in_memory = addr_of_buf_ptr;
        }
        self.param_list.push(param);

        dest
    }

    pub fn after_syscall_action(&mut self, action: AfterSyscallAction) {
        self.after_syscall_actions.push(action)
    }

    pub fn emulate_result(&mut self, result: u64) {
        let t = self.task();
        ed_assert!(&t.borrow(), !self.preparation_done);
        ed_assert!(&t.borrow(), !self.should_emulate_result);
        self.should_emulate_result = true;
        self.emulated_result = result;
    }

    /// Internal method that takes 'ptr', an address within some memory parameter,
    /// and relocates it to the parameter's location in scratch memory.
    pub fn relocate_pointer_to_scratch(&self, ptr: RemotePtr<Void>) -> RemotePtr<Void> {
        let mut num_relocations: usize = 0;
        let mut result: = RemotePtr::<Void>::null();
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
    /// containing the actual sizes assigned to each param < param_index, and
    /// computes the actual size to use for parameter param_index.
    pub fn eval_param_size(_param_index: usize, _actual_sizes: &[usize]) -> usize {
        unimplemented!()
    }

    /// Called when all memory parameters have been identified. If 'sw' is
    /// Switchable::AllowSwitch, sets up scratch memory and updates registers etc as
    /// necessary.
    /// If scratch can't be used for some reason, returns Switchable::PreventSwitch,
    /// otherwise returns 'sw'.
    pub fn done_preparing(_sw: Switchable) -> Switchable {
        unimplemented!()
    }

    pub fn done_preparing_internal(_sw: Switchable) -> Switchable {
        unimplemented!()
    }

    /// Called when a syscall exits to copy results from scratch memory to their
    /// original destinations, update registers, etc.
    pub fn process_syscall_results() {
        unimplemented!()
    }

    /// Called when a syscall has been completely aborted to undo any changes we
    /// made.
    pub fn abort_syscall_results() {
        unimplemented!()
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
    ptr_in_reg: i32,
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
    /// Size of the value at mem_ptr or in the syscall result register. */
    read_size: usize,
    /// If true, the size is limited by the value of the syscall result. */
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
