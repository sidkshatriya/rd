#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::bindings::kernel::PAGE_SIZE;

/// Bump this whenever the interface between syscallbuf and rd changes in a way
/// that would require changes to replay. So be very careful making changes to
/// this file! Many changes would require a bump in this value, and support
/// code in rd to handle old protocol versions. And when we bump it we'll need
/// to figure out a way to test the old protocol versions.
/// To be clear, changes that only affect recording and not replay, such as
/// changes to the layout of syscall_patch_hook, do not need to bump this.
/// Note also that SYSCALLBUF_PROTOCOL_VERSION is stored in the trace header, so
/// replay always has access to the SYSCALLBUF_PROTOCOL_VERSION used during
/// recording, even before the preload library is ever loaded.
///
/// Version 0

pub const SYSCALLBUF_PROTOCOL_VERSION: u16 = 0;

pub const SYSCALLBUF_LIB_FILENAME_BASE: &'static str = "librrpreload";
pub const SYSCALLBUF_LIB_FILENAME: &'static str = "librrpreload.so";
pub const SYSCALLBUF_LIB_FILENAME_PADDED: &'static str = "librrpreload.so:::";
pub const SYSCALLBUF_LIB_FILENAME_32: &'static str = "librrpreload_32.so";

/// Set this env var to enable syscall buffering.
pub const SYSCALLBUF_ENABLED_ENV_VAR: &'static str = "_RD_USE_SYSCALLBUF";

/// Size of table mapping fd numbers to syscallbuf-disabled flag.
/// Most Linux kernels limit fds to 1024 so it probably doesn't make sense
/// to raise this value...
pub const SYSCALLBUF_FDS_DISABLED_SIZE: i32 = 1024;

pub const MPROTECT_RECORD_COUNT: u32 = 1000;

/// Must match generate_rr_page.py
pub const RD_PAGE_ADDR: usize = 0x70000000;
pub const RD_PAGE_SYSCALL_STUB_SIZE: usize = 3;
pub const RD_PAGE_SYSCALL_INSTRUCTION_END: usize = 2;

pub const fn RD_PAGE_SYSCALL_ADDR(index: usize) -> usize {
    RD_PAGE_ADDR + RD_PAGE_SYSCALL_STUB_SIZE * index
}

pub const RD_PAGE_SYSCALL_TRACED: usize = RD_PAGE_SYSCALL_ADDR(0);
pub const RD_PAGE_SYSCALL_PRIVILEGED_TRACED: usize = RD_PAGE_SYSCALL_ADDR(1);
pub const RD_PAGE_SYSCALL_UNTRACED: usize = RD_PAGE_SYSCALL_ADDR(2);
pub const RD_PAGE_SYSCALL_UNTRACED_REPLAY_ONLY: usize = RD_PAGE_SYSCALL_ADDR(3);
pub const RD_PAGE_SYSCALL_UNTRACED_RECORDING_ONLY: usize = RD_PAGE_SYSCALL_ADDR(4);
pub const RD_PAGE_SYSCALL_PRIVILEGED_UNTRACED: usize = RD_PAGE_SYSCALL_ADDR(5);
pub const RD_PAGE_SYSCALL_PRIVILEGED_UNTRACED_REPLAY_ONLY: usize = RD_PAGE_SYSCALL_ADDR(6);
pub const RD_PAGE_SYSCALL_PRIVILEGED_UNTRACED_RECORDING_ONLY: usize = RD_PAGE_SYSCALL_ADDR(7);
pub const RD_PAGE_FF_BYTES: usize = RD_PAGE_ADDR + RD_PAGE_SYSCALL_STUB_SIZE * 8;

/// PRELOAD_THREAD_LOCALS_ADDR should not change.
/// Tools depend on this address.
pub const PRELOAD_THREAD_LOCALS_ADDR: usize = RD_PAGE_ADDR + PAGE_SIZE as usize;
pub const PRELOAD_THREAD_LOCALS_SIZE: usize = 104;

/// "Magic" (rr-implemented) syscalls that we use to initialize the
/// syscallbuf.
///
/// NB: magic syscalls must be positive, because with at least linux
/// 3.8.0 / eglibc 2.17, rd only gets a trap for the *entry* of invalid
/// syscalls, not the exit.  rd can't handle that yet.

/// The preload library calls SYS_rdcall_init_preload during its
/// initialization.
pub const SYS_rdcall_init_preload: u32 = 442;

/// The preload library calls SYS_rdcall_init_buffers in each thread that
/// gets created (including the initial main thread).
pub const SYS_rdcall_init_buffers: u32 = 443;

/// The preload library calls SYS_rdcall_notify_syscall_hook_exit when
/// unlocking the syscallbuf and notify_after_syscall_hook_exit has been set.
/// The word at 4/8(sp) is returned in the syscall result and the word at
/// 8/16(sp) is stored in original_syscallno.
pub const SYS_rdcall_notify_syscall_hook_exit: u32 = 444;

/// When the preload library detects that control data has been received in a
/// syscallbuf'ed recvmsg, it calls this syscall with a pointer to the
/// 'struct msg' returned.
pub const SYS_rdcall_notify_control_msg: u32 = 445;

/// When rd replay has restored the auxv vectors for a new process (completing
/// emulation of exec), it calls this syscall. It takes one parameter, the tid
/// of the task that it has restored auxv vectors for.
pub const SYS_rdcall_reload_auxv: u32 = 446;

/// When rd replay has flushed a syscallbuf 'mprotect' record, notify any outer
/// rd of that flush. The first parameter is the tid of the task, the second
/// parameter is the address, the third parameter is the length, and the
/// fourth parameter is the prot.
pub const SYS_rdcall_mprotect_record: u32 = 447;

/// To support syscall buffering, we replace syscall instructions with a "call"
/// instruction that calls a hook in the preload library to handle the syscall.
/// Since the call instruction takes more space than the syscall instruction,
/// the patch replaces one or more instructions after the syscall instruction as
/// well; those instructions are folded into the tail of the hook function
/// and we have multiple hook functions, each one corresponding to an
/// instruction that follows a syscall instruction.
/// Each instance of this struct describes an instruction that can follow a
/// syscall and a hook function to patch with.
///
/// This is not (and must not ever be) used during replay so we can change it
/// without bumping SYSCALLBUF_PROTOCOL_VERSION.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct syscall_patch_hook {
    pub is_multi_instruction: u8,
    pub next_instruction_length: u8,
    /// Avoid any padding or anything that would make the layout arch-specific.
    pub next_instruction_bytes: [u8; 14],
    pub hook_address: u64,
}

/// IMPORTANT! This needs to be kept in sync with the syscall_patch_hook struct
pub const NEXT_INSTRUCTION_BYTES_LEN: usize = 14;

/// We buffer mprotect syscalls. Their effects need to be noted so we can
/// update AddressSpace's cache of memory layout, which stores prot bits. So,
/// the preload code builds a list of mprotect_records corresponding to the
/// mprotect syscalls that have been buffered. This list is read by rd whenever
/// we flush the syscallbuf, and its effects performed. The actual mprotect
/// syscalls are performed during recording and replay.
///
/// We simplify things by making this arch-independent.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct mprotect_record {
    pub start: u64,
    pub size: u64,
    pub prot: i32,
    pub padding: i32,
}

/// Must be arch-independent.
/// Variables used to communicate between preload and rd.
/// We package these up into a single struct to simplify the preload/rr
/// interface.
/// You can add to the end of this struct without breaking trace compatibility,
/// but don't move existing fields. Do not write to it during replay except for
/// the 'in_replay' field. Be careful reading fields during replay as noted
/// below, since they don't all exist in all trace versions.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct preload_globals {
    /// 0 during recording, 1 during replay. Set by rd.
    /// This MUST NOT be used in conditional branches. It should only be used
    /// as the condition for conditional moves so that control flow during replay
    /// does not diverge from control flow during recording.
    /// We also have to be careful that values different between record and replay
    /// don't accidentally leak into other memory locations or registers.
    /// USE WITH CAUTION.
    pub in_replay: u8,
    /// 0 during recording and replay, 1 during diversion. Set by rd.
    pub in_diversion: u8,
    /// 1 if chaos mode is enabled. DO NOT READ from rd during replay, because
    /// this field is not initialized in old traces.
    pub in_chaos: u8,
    /// The signal to use for desched events
    pub desched_sig: u8,
    /// Number of cores to pretend we have. 0 means 1. rd sets this when
    /// the preload library is initialized.
    pub pretend_num_cores: i32,
    /// Set by rd.
    /// If `syscallbuf_fds_disabled[fd]` is nonzero, then operations on that fd
    /// must be performed through traced syscalls, not the syscallbuf.
    /// The rd supervisor modifies this array directly to dynamically turn
    /// syscallbuf on and off for particular fds. fds outside the array range must
    /// never use the syscallbuf.
    /// The last entry is set if *any* fd >= SYSCALLBUF_FDS_DISABLED_SIZE - 1
    /// has had buffering disabled.
    pub syscallbuf_fds_disabled: [u8; 1024],
    /// mprotect records. Set by preload.
    pub mprotect_records: [mprotect_record; 1000],
    /// Random seed that can be used for various purposes. DO NOT READ from rd
    /// during replay, because this field does not exist in old traces.
    pub random_seed: u64,
}

/// The syscall buffer comprises an array of these variable-length
/// records, along with the header below.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct syscallbuf_record {
    /// Return value from the syscall.  This can be a memory
    /// address, so must be as big as a memory address can be.
    /// We use 64 bits rather than make syscallbuf_record Arch-specific as that
    /// gets cumbersome.
    pub ret: i64,
    /// Syscall number.
    ///
    /// NB: the x86 linux ABI has 350 syscalls as of 3.9.6 and
    /// x86-64 defines 313, so this is a pretty safe storage
    /// allocation.  It would be an earth-shattering event if the
    /// syscall surface were doubled in a short period of time, and
    /// even then we would have a comfortable cushion.  Still,
    ///
    /// TODO: static_assert this can hold largest syscall num
    pub syscallno: u16,
    /// Did the tracee arm/disarm the desched notification for this
    /// syscall?
    pub desched: u8,
    pub _padding: u8,
    /// Size of entire record in bytes: this struct plus extra
    /// recorded data stored inline after the last field, not
    /// including padding.
    ///
    /// TODO: static_assert this can repr >= buffer size
    pub size: u32,
    /// Extra recorded outparam data starts here.
    /// @TODO how to deal with this?
    pub extra_data: [u8; 0],
}

/// This struct summarizes the state of the syscall buffer.  It happens
/// to be located at the start of the buffer.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct syscallbuf_hdr {
    /// The number of valid syscallbuf_record bytes in the buffer,
    /// not counting this header.
    /// Make this volatile so that memory writes aren't reordered around
    /// updates to this field.
    pub num_rec_bytes: u32,
    /// Number of mprotect calls since last syscallbuf flush. The last record in
    /// the list may not have been applied yet.
    pub mprotect_record_count: u32,
    /// Number of records whose syscalls have definitely completed.
    /// May be one less than mprotect_record_count.
    pub mprotect_record_count_completed: u32,
    /// True if the current syscall should not be committed to the
    /// buffer, for whatever reason; likely interrupted by
    /// desched. Set by rd.
    pub abort_commit: u8,
    /// True if, next time we exit the syscall buffer hook, libpreload should
    /// execute SYS_rdcall_notify_syscall_hook_exit to give rd the opportunity to
    /// deliver a signal and/or reset the syscallbuf.
    pub notify_on_syscall_hook_exit: u8,
    /// This tracks whether the buffer is currently in use for a
    /// system call or otherwise unavailable. This is helpful when
    /// a signal handler runs during a wrapped system call; we don't want
    /// it to use the buffer for its system calls. The different reasons why the
    /// buffer could be locked, use different bits of this field and the buffer
    /// may be used only if all are clear. See enum syscallbuf_locked_why for
    /// used bits.
    pub locked: syscallbuf_locked_why,
    /// Nonzero when rd needs to worry about the desched signal.
    /// When it's zero, the desched signal can safely be
    /// discarded.
    pub desched_signal_may_be_relevant: u8,
    /// A copy of the tasks's signal mask. Updated by preload when a buffered
    /// rt_sigprocmask executes.
    pub blocked_sigs: u64,
    /// Incremented by preload every time a buffered rt_sigprocmask executes.
    /// Cleared during syscallbuf reset.
    pub blocked_sigs_generation: u32,
    /// Nonzero when preload is in the process of calling an untraced
    /// sigprocmask; the real sigprocmask may or may not match blocked_sigs.
    pub in_sigprocmask_critical_section: u8,
    /// Nonzero when the syscall was aborted during preparation without doing
    /// anything. This is set when a user seccomp filter forces a SIGSYS.
    pub failed_during_preparation: u8,

    pub recs: [syscallbuf_record; 0],
}

bitflags! {
    /// Each bit of of syscallbuf_hdr->locked indicates a reason why the syscallbuf
    /// is locked. These are all the bits that are currently defined.
    #[derive(Default)]
    pub struct syscallbuf_locked_why: u8 {
        /// Used by the tracee, during interruptible syscalls to avoid recursion
        const SYSCALLBUF_LOCKED_TRACEE = 0x1;
        /// Used by the tracer to prevent syscall buffering when necessary to preserve
        /// semantics (e.g. for ptracees whose syscalls are being observed)
        const SYSCALLBUF_LOCKED_TRACER = 0x2;
    }
}

/// Return the amount of space that a record of `length` will occupy in
/// the buffer if committed, including padding.
pub fn stored_record_size(length: u32) -> u32 {
    // Round up to a whole number of 64-bit words.
    (length + 7) & !7u32
}
