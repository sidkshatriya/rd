use crate::{
    arch::Architecture,
    kernel_abi::common::preload_interface::syscall_patch_hook,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    session::task::record_task::RecordTask,
};
use std::collections::{HashMap, HashSet};

const MAX_VDSO_SIZE: usize = 16384;
const VDSO_ABSOLUTE_ADDRESS: usize = 0xffffe000;

#[derive(Clone)]
pub struct MonkeyPatcher {
    pub x86_vsyscall: RemotePtr<Void>,

    /// The list of pages we've allocated to hold our extended jumps.
    pub extended_jump_pages: Vec<ExtendedJumpPage>,

    /// Syscalls in the VDSO that we patched to be direct syscalls. These can
    /// always be safely patched to jump to the syscallbuf.  
    pub patched_vdso_syscalls: HashSet<RemoteCodePtr>,

    /// Addresses/lengths of syscallbuf stubs.
    pub syscallbuf_stubs: HashMap<RemotePtr<u8>, usize>,

    /// The list of supported syscall patches obtained from the preload
    /// library. Each one matches a specific byte signature for the instruction(s)
    /// after a syscall instruction.    
    syscall_hooks: Vec<syscall_patch_hook>,

    /// The addresses of the instructions following syscalls that we've tried
    /// (or are currently trying) to patch.
    tried_to_patch_syscall_addresses: HashSet<RemoteCodePtr>,
}

pub enum MmapMode {
    MmapExec,
    MmapSyscall,
}

#[derive(Clone)]
pub struct ExtendedJumpPage {
    pub addr: RemotePtr<u8>,
    pub allocated: usize,
}

impl ExtendedJumpPage {
    pub fn new(addr: RemotePtr<u8>) -> Self {
        Self { addr, allocated: 0 }
    }
}

/// A class encapsulating patching state. There is one instance of this
/// class per tracee address space. Currently this class performs the following
/// tasks:
///
/// 1) Patch the VDSO's user-space-only implementation of certain system calls
/// (e.g. gettimeofday) to do a proper kernel system call instead, so rr can
/// trap and record it (x86-64 only).
///
/// 2) Patch the VDSO __kernel_vsyscall fast-system-call stub to redirect to
/// our syscall hook in the preload library (x86 only).
///
/// 3) Patch syscall instructions whose following instructions match a known
/// pattern to call the syscall hook.
///
/// Monkeypatcher only runs during recording, never replay.
impl MonkeyPatcher {
    pub fn new() -> MonkeyPatcher {
        unimplemented!()
    }

    /// Apply any necessary patching immediately after exec.
    /// In this hook we patch everything that doesn't depend on the preload
    /// library being loaded.
    pub fn patch_after_exec(_t: &RecordTask) {
        unimplemented!()
    }

    pub fn patch_at_preload_init(&self, t: &RecordTask) {
        // NB: the tracee can't be interrupted with a signal while
        // we're processing the rdcall, because it's masked off all
        // signals.
        rd_arch_function_selfless!(patch_at_preload_init_arch, t.arch(), t, self);
    }

    /// Try to patch the syscall instruction that |t| just entered. If this
    /// returns false, patching failed and the syscall should be processed
    /// as normal. If this returns true, patching succeeded and the syscall
    /// was aborted; ip() has been reset to the start of the patched syscall,
    /// and execution should resume normally to execute the patched code.
    /// Zero or more mapping operations are also recorded to the trace and must
    /// be replayed.
    pub fn try_patch_syscall(_t: &RecordTask) -> bool {
        unimplemented!()
    }

    pub fn init_dynamic_syscall_patching(
        _t: &RecordTask,
        _syscall_patch_hook_count: usize,
        _syscall_patch_hooks: RemotePtr<syscall_patch_hook>,
    ) {
        unimplemented!()
    }

    /// Try to allocate a stub from the sycall patching stub buffer. Returns null
    /// if there's no buffer or we've run out of free stubs.

    pub fn allocate_stub(_t: &RecordTask, _bytes: usize) -> RemotePtr<u8> {
        unimplemented!()
    }

    /// Apply any necessary patching immediately after an mmap. We use this to
    /// patch libpthread.so.
    pub fn patch_after_mmap(
        _t: &RecordTask,
        _start: RemotePtr<Void>,
        _size: usize,
        _offset_pages: usize,
        _child_fd: i32,
        _mode: MmapMode,
    ) {
        unimplemented!()
    }

    pub fn is_jump_stub_instruction(_p: RemoteCodePtr) -> bool {
        unimplemented!()
    }
}

fn patch_at_preload_init_arch<Arch: Architecture>(_t: &RecordTask, _patcher: &MonkeyPatcher) {
    unimplemented!()
}
