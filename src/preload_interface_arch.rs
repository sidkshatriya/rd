use crate::{
    arch::Architecture,
    arch_structs::msghdr,
    kernel_abi::Ptr,
    preload_interface::{preload_globals, syscall_patch_hook},
};

/// Represents syscall params.  Makes it simpler to pass them around,
/// and avoids pushing/popping all the data for calls.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct syscall_info<Arch: Architecture> {
    pub no: Arch::signed_long,
    pub args: [Arch::signed_long; 6],
}

/// Can be architecture dependent. The rd process does not manipulate
/// these except to save and restore the values on task switches so that
/// the values are always effectively local to the current task. rd also
/// sets the `syscallbuf_stub_alt_stack` field.
/// We use this instead of regular libc TLS because sometimes buggy application
/// code breaks libc TLS for some tasks. With this approach we can be sure
/// thread-locals are usable for any task in any state.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct preload_thread_locals<Arch: Architecture> {
    /// The offset of this field MUST NOT CHANGE, it is part of the preload ABI
    /// rd depends on.
    /// Offset of this field is hardcoded in syscall_hook.S and
    /// assembly_templates.py.
    /// Pointer to alt-stack used by syscallbuf stubs (allocated at the end of
    /// the scratch buffer.
    pub syscallbuf_stub_alt_stack: Ptr<Arch::unsigned_word, u8>,
    /// The offset of this field MUST NOT CHANGE, it is part of the preload ABI
    /// tools can depend on.
    /// Where syscall result will be (or during replay, has been) saved.
    pub pending_untraced_syscall_result: Ptr<Arch::unsigned_word, i64>,
    /// The offset of this field MUST NOT CHANGE, it is part of the preload ABI
    /// rd depends on.
    /// Scratch space used by stub code.
    pub stub_scratch_1: Ptr<Arch::unsigned_word, u8>,
    /// The offset of this field MUST NOT CHANGE, it is part of the preload ABI
    /// rd depends on.
    pub alt_stack_nesting_level: i32,
    /// We could use this later.
    pub unused_padding: i32,
    /// The offset of this field MUST NOT CHANGE, it is part of the preload ABI
    /// rd depends on. It contains the parameters to the patched syscall, or
    /// zero if we're not processing a buffered syscall. Do not depend on this
    /// existing during replay, some traces with SYSCALLBUF_PROTOCOL_VERSION 0
    /// don't have it.
    pub original_syscall_parameters: Ptr<Arch::unsigned_word, syscall_info<Arch>>,

    /// Nonzero when thread-local state like the syscallbuf has been
    /// initialized.
    pub thread_inited: i32,
    /// The offset of this field MUST NOT CHANGE, it is part of the ABI tools
    /// depend on. When buffering is enabled, points at the thread's mapped buffer
    /// segment.  At the start of the segment is an object of type `struct
    /// syscallbuf_hdr`, so `buffer` is also a pointer to the buffer
    /// header.
    pub buffer: Ptr<Arch::unsigned_word, u8>,
    pub buffer_size: Arch::size_t,
    /// This is used to support the buffering of "may-block" system calls.
    /// The problem that needs to be addressed can be introduced with a
    /// simple example; assume that we're buffering the "read" and "write"
    /// syscalls.
    ///
    ///  o (Tasks W and R set up a synchronous-IO pipe open between them; W
    ///    "owns" the write end of the pipe; R owns the read end; the pipe
    ///    buffer is full)
    ///  o Task W invokes the write syscall on the pipe
    ///  o Since write is a buffered syscall, the seccomp filter traps W
    ///    directly to the kernel; there's no trace event for W delivered
    ///    to rd.
    ///  o The pipe is full, so W is descheduled by the kernel because W
    ///    can't make progress.
    ///  o rd thinks W is still running and doesn't schedule R.
    ///
    /// At this point, progress in the recorded application can only be
    /// made by scheduling R, but no one tells rd to do that.  Oops!
    ///
    /// Thus enter the "desched counter".  It's a perf_event for the "sw t
    /// switches" event (which, more precisely, is "sw deschedule"; it
    /// counts schedule-out, not schedule-in).  We program the counter to
    /// deliver a signal to this task when there's new counter data
    /// available.  And we set up the "sample period", how many descheds
    /// are triggered before the signal is delivered, to be "1".  This
    /// means that when the counter is armed, the next desched (i.e., the
    /// next time the desched counter is bumped up) of this task will
    /// deliver the signal to it.  And signal delivery always generates a
    /// ptrace trap, so rd can deduce that this task was descheduled and
    /// schedule another.
    ///
    /// The description above is sort of an idealized view; there are
    /// numerous implementation details that are documented in
    /// handle_signal.c, where they're dealt with.
    pub desched_counter_fd: i32,
    pub cloned_file_data_fd: i32,
    pub cloned_file_data_offset: Arch::off_t,
    pub scratch_buf: Ptr<Arch::unsigned_word, u8>,
    pub usable_scratch_size: Arch::size_t,

    pub notify_control_msg: Ptr<Arch::unsigned_word, msghdr<Arch>>,
}

/// Packs up the parameters passed to `SYS_rdcall_init_preload`.
/// We use this struct because it's a little cleaner.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct rdcall_init_preload_params<Arch: Architecture> {
    /// All "In" params.
    /// The syscallbuf lib's idea of whether buffering is enabled.
    /// We let the syscallbuf code decide in order to more simply
    /// replay the same decision that was recorded.
    pub syscallbuf_enabled: i32,
    pub syscall_patch_hook_count: i32,
    pub syscall_patch_hooks: Ptr<Arch::unsigned_word, syscall_patch_hook>,
    pub syscallhook_vsyscall_entry: Ptr<Arch::unsigned_word, u8>,
    pub syscallbuf_code_start: Ptr<Arch::unsigned_word, u8>,
    pub syscallbuf_code_end: Ptr<Arch::unsigned_word, u8>,
    pub get_pc_thunks_start: Ptr<Arch::unsigned_word, u8>,
    pub get_pc_thunks_end: Ptr<Arch::unsigned_word, u8>,
    pub syscallbuf_final_exit_instruction: Ptr<Arch::unsigned_word, u8>,
    pub globals: Ptr<Arch::unsigned_word, preload_globals>,
    /// Address of the first entry of the breakpoint table.
    /// After processing a sycallbuf record (and unlocking the syscallbuf),
    /// we call a function in this table corresponding to the record processed.
    /// rd can set a breakpoint in this table to break on the completion of a
    /// particular syscallbuf record.
    pub breakpoint_table: Ptr<Arch::unsigned_word, u8>,
    pub breakpoint_table_entry_size: i32,
}

/// Packs up the inout parameters passed to `SYS_rdcall_init_buffers`.
/// We use this struct because there are too many params to pass
/// through registers on at least x86.  (It's also a little cleaner.)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct rdcall_init_buffers_params<Arch: Architecture> {
    /// The fd we're using to track desched events.
    pub desched_counter_fd: i32,
    /// "Out" params.
    pub cloned_file_data_fd: i32,
    /// Returned pointer to and size of the shared syscallbuf
    /// segment.
    pub syscallbuf_ptr: Ptr<Arch::unsigned_word, u8>,
    /// Returned pointer to rd's syscall scratch buffer
    pub scratch_buf: Ptr<Arch::unsigned_word, u8>,
    pub syscallbuf_size: u32,
    pub usable_scratch_size: u32,
}
