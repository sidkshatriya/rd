use crate::{
    arch::Architecture,
    preload_interface::syscall_patch_hook,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    session::{address_space::address_space, task::record_task::RecordTask},
};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
};

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
/// MonkeyPatcher only runs during recording, never replay.
impl MonkeyPatcher {
    pub fn new() -> MonkeyPatcher {
        MonkeyPatcher {
            x86_vsyscall: Default::default(),
            extended_jump_pages: vec![],
            patched_vdso_syscalls: Default::default(),
            syscallbuf_stubs: Default::default(),
            syscall_hooks: vec![],
            tried_to_patch_syscall_addresses: Default::default(),
        }
    }

    /// Apply any necessary patching immediately after exec.
    /// In this hook we patch everything that doesn't depend on the preload
    /// library being loaded.
    pub fn patch_after_exec(&self, _t: &RecordTask) {
        // @TODO PENDING!
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
    pub fn try_patch_syscall(&self, t: &RecordTask) -> bool {
        if self.syscall_hooks.is_empty() {
            // Syscall hooks not set up yet. Don't spew warnings, and don't
            // fill tried_to_patch_syscall_addresses with addresses that we might be
            // able to patch later.
            return false;
        }

        if t.emulated_ptracer.is_some() {
            // Syscall patching can confuse ptracers, which may be surprised to see
            // a syscall instruction at the current IP but then when running
            // forwards, that the syscall occurs deep in the preload library instead.
            return false;
        }

        if t.is_in_traced_syscall() {
            // Never try to patch the traced-syscall in our preload library!
            return false;
        }

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
        &self,
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

struct VdsoReader;
/// @TODO Remove
struct ElfReader;
/// @TODO Remove
struct SymbolTable;

fn write_and_record_bytes(_t: &RecordTask, _child_addr: RemotePtr<Void>, _buf: &[u8]) {
    unimplemented!()
}

fn write_and_record_mem<T>(_t: &RecordTask, _child_addr: RemotePtr<T>, _vals: &[T]) {
    unimplemented!()
}

/// RecordSession sets up an LD_PRELOAD environment variable with an entry
/// SYSCALLBUF_LIB_FILENAME_PADDED (and, if enabled, an LD_AUDIT environment
/// variable with an entry RTLDAUDIT_LIB_FILENAME_PADDED) which is big enough to
/// hold either the 32-bit or 64-bit preload/audit library file names.
/// Immediately after exec we enter this function, which patches the environment
/// variable value with the correct library name for the task's architecture.
///
/// It's possible for this to fail if a tracee alters the LD_PRELOAD value
/// and then does an exec. That's just too bad. If we ever have to handle that,
/// we should modify the environment passed to the exec call. This function
/// failing isn't necessarily fatal; a tracee might not rely on the functions
/// overridden by the preload library, or might override them itself (e.g.
/// because we're recording an rr replay).
////
fn setup_library_path_arch<Arch: Architecture>(
    _t: &RecordTask,
    _env_var: &OsStr,
    _soname_base: &OsStr,
    _soname_padded: &OsStr,
    _soname_32: &OsStr,
) {
    unimplemented!()
}

fn setup_preload_library_path<Arch: Architecture>(_t: &RecordTask) {
    unimplemented!()
}

fn setup_audit_library_path<Arch: Architecture>(_t: &RecordTask) {
    unimplemented!()
}

fn patch_syscall_with_hook_arch<Arch: Architecture>(
    _patcher: &MonkeyPatcher,
    _t: &RecordTask,
    _hook: &syscall_patch_hook,
) -> bool {
    unimplemented!()
}

fn substitute<Arch: Architecture>(
    _buffer: &[u8],
    _return_addr: u64,
    _trampoline_relative_addr: u64,
) {
    unimplemented!()
}

fn substitute_extended_jump<Arch: Architecture>(
    _buffer: &[u8],
    _patch_addr: u64,
    _return_addr: u64,
    _target_addr: u64,
) {
    unimplemented!()
}

/// Allocate an extended jump in an extended jump page and return its address.
/// The resulting address must be within 2G of from_end, and the instruction
/// there must jump to to_start.
fn allocate_extended_jump(
    _t: &RecordTask,
    _pages: Vec<ExtendedJumpPage>,
    _from_end: RemotePtr<u8>,
) -> RemotePtr<u8> {
    unimplemented!()
}

/// Some functions make system calls while storing local variables in memory
/// below the stack pointer. We need to decrement the stack pointer by
/// some "safety zone" amount to get clear of those variables before we make
/// a call instruction. So, we allocate a stub per patched callsite, and jump
/// from the callsite to the stub. The stub decrements the stack pointer,
/// calls the appropriate syscall hook function, reincrements the stack pointer,
/// and jumps back to immediately after the patched callsite.
///
/// It's important that gdb stack traces work while a thread is stopped in the
/// syscallbuf code. To ensure that the above manipulations don't foil gdb's
/// stack walking code, we add CFI data to all the stubs. To ease that, the
/// stubs are written in assembly and linked into the preload library.
///
/// On x86-64 with ASLR, we need to be able to patch a call to a stub from
/// sites more than 2^31 bytes away. We only have space for a 5-byte jump
/// instruction. So, we allocate "extender pages" --- pages of memory within
/// 2GB of the patch site, that contain the stub code. We don't really need this
/// on x86, but we do it there too for consistency.
fn patch_syscall_with_hook_x86ish(
    _patcher: &MonkeyPatcher,
    _t: &RecordTask,
    _hook: syscall_patch_hook,
) -> bool {
    unimplemented!()
}

fn patch_syscall_with_hook(
    _patcher: &MonkeyPatcher,
    _t: &RecordTask,
    _hook: &syscall_patch_hook,
) -> bool {
    unimplemented!()
}

fn task_safe_for_syscall_patching(
    _t: &RecordTask,
    _start: RemoteCodePtr,
    _end: RemoteCodePtr,
) -> bool {
    unimplemented!()
}

fn safe_for_syscall_patching(_start: RemoteCodePtr, _end: RemoteCodePtr, _exclude: &RecordTask) {
    unimplemented!()
}

/// Return true iff |addr| points to a known |__kernel_vsyscall()|
/// implementation.
fn is_kernel_vsyscall(_t: &RecordTask, _addr: RemotePtr<Void>) -> bool {
    unimplemented!()
}

/// Return the address of a recognized |__kernel_vsyscall()|
/// implementation in |t|'s address space.
fn locate_and_verify_kernel_vsyscall(
    _t: &RecordTask,
    _reader: &ElfReader,
    _syms: &SymbolTable,
) -> RemotePtr<Void> {
    unimplemented!()
}

/// VDSOs are filled with overhead critical functions related to getting the
/// time and current CPU.  We need to ensure that these syscalls get redirected
/// into actual trap-into-the-kernel syscalls so rr can intercept them.
fn patch_after_exec_arch<Arch: Architecture>(_t: &RecordTask, _patcher: &MonkeyPatcher) {
    unimplemented!()
}

struct NamedSyscall<'a> {
    pub name: &'a OsStr,
    pub syscall_number: i32,
}

fn erase_section(_t: &RecordTask, _reader: &VdsoReader, _name: &OsStr) {
    unimplemented!()
}

fn obliterate_debug_info(_t: &RecordTask, _reader: &VdsoReader) {
    unimplemented!()
}

fn resolve_address(
    _reader: &ElfReader,
    _elf_addr: usize,
    _map_start: RemotePtr<Void>,
    _map_size: usize,
    _map_offset_pages: usize,
) -> RemotePtr<Void> {
    unimplemented!()
}

fn set_and_record_bytes(
    _t: &RecordTask,
    _reader: &ElfReader,
    _elf_addr: usize,
    _bytes: &[u8],
    _map_start: RemotePtr<Void>,
    _map_size: usize,
    _map_offset_pages: usize,
) {
    unimplemented!()
}

/// Patch _dl_runtime_resolve_(fxsave,xsave,xsavec) to clear "FDP Data Pointer"
/// register so that CPU-specific behaviors involving that register don't leak
/// into stack memory.
fn patch_dl_runtime_resolve(
    _patcher: &MonkeyPatcher,
    _t: &RecordTask,
    _reader: &ElfReader,
    _elf_addr: usize,
    _bytes: &[u8],
    _map_start: RemotePtr<Void>,
    _map_size: usize,
    _map_offset_pages: usize,
) {
    unimplemented!()
}

fn file_may_need_instrumentation(_map: &address_space::Mapping) -> bool {
    unimplemented!()
}
