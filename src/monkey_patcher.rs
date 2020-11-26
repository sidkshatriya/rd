use crate::{
    arch::{Architecture, X64Arch, X86Arch},
    kernel_abi::SupportedArch,
    log::{LogDebug, LogWarn},
    preload_interface::{
        syscall_patch_hook,
        SYSCALLBUF_LIB_FILENAME_32,
        SYSCALLBUF_LIB_FILENAME_BASE,
        SYSCALLBUF_LIB_FILENAME_PADDED,
    },
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::address_space,
        task::{record_task::RecordTask, task_common::read_val_mem, task_inner::WriteFlags, Task},
    },
    util::{find, page_size},
};
use goblin::{
    elf::Elf,
    elf64::section_header::{SHF_ALLOC, SHT_NOBITS},
    strtab::Strtab,
};
use nix::{
    fcntl::{readlink, OFlag},
    sys::{
        mman::{mmap, munmap, MapFlags, ProtFlags},
        stat::fstat,
    },
};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    ffi::OsStr,
    mem::size_of,
    ops::Range,
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr,
    slice,
};

const MAX_VDSO_SIZE: usize = 16384;
const VDSO_ABSOLUTE_ADDRESS: usize = 0xffffe000;

include!(concat!(env!("OUT_DIR"), "/assembly_templates_generated.rs"));

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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
/// (e.g. gettimeofday) to do a proper kernel system call instead, so rd can
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
    pub fn patch_after_exec(&mut self, t: &mut RecordTask) {
        let arch = t.arch();
        match arch {
            SupportedArch::X86 => patch_after_exec_arch_x86arch(t, self),
            SupportedArch::X64 => patch_after_exec_arch_x64arch(t, self),
        }
    }

    pub fn patch_at_preload_init(&self, t: &RecordTask) {
        // NB: the tracee can't be interrupted with a signal while
        // we're processing the rdcall, because it's masked off all
        // signals.
        rd_arch_function_selfless!(patch_at_preload_init_arch, t.arch(), t, self);
    }

    /// Try to patch the syscall instruction that `t` just entered. If this
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
        t: &mut RecordTask,
        start: RemotePtr<Void>,
        size: usize,
        offset_pages: usize,
        child_fd: i32,
        mode: MmapMode,
    ) {
        if file_may_need_instrumentation(&t.vm().mapping_of(start).unwrap())
            && (t.arch() == SupportedArch::X86 || t.arch() == SupportedArch::X64)
        {
            let open_fd: ScopedFd;
            if child_fd >= 0 {
                open_fd = t.open_fd(child_fd, OFlag::O_RDONLY);
                ed_assert!(t, open_fd.is_open(), "Failed to open child fd {}", child_fd);
            } else {
                let buf = format!(
                    "/proc/{}/map_files/{:x}-{:x}",
                    t.tid,
                    start.as_usize(),
                    start.as_usize() + size
                );
                // Reading these directly requires CAP_SYS_ADMIN, so open the link target
                // instead.
                match readlink(buf.as_str()) {
                    Ok(link) => {
                        open_fd = ScopedFd::open_path(link.as_os_str(), OFlag::O_RDONLY);
                        if !open_fd.is_open() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
            let elf_map = ElfMap::new(&open_fd);
            // Check for symbols first in the library itself, regardless of whether
            // there is a debuglink.  For example, on Fedora 26, the .symtab and
            // .strtab sections are stripped from the debuginfo file for
            // libpthread.so.
            let elf_obj = match Elf::parse(elf_map.map) {
                Ok(elfo) => elfo,
                Err(_) => return,
            };

            if elf_obj.syms.len() == 0 {
                log!(
                    LogWarn,
                    "@TODO PENDING try to get symbols for patch_after_mmap() from debug"
                )
            }
            for sym in &elf_obj.syms {
                if has_name(&elf_obj.strtab, sym.st_name, "__elision_aconf") {
                    log!(
                        LogDebug,
                        "Found __elision_conf for possible patching in memory"
                    );
                    const ZERO: i32 = 0;
                    // Setting __elision_aconf.retry_try_xbegin to zero means that
                    // pthread rwlocks don't try to use elision at all. See ELIDE_LOCK
                    // in glibc's elide.h.
                    set_and_record_bytes(
                        t,
                        &elf_obj,
                        sym.st_value as usize + 8,
                        &ZERO.to_le_bytes(),
                        start,
                        size,
                        offset_pages,
                    );
                }
                if has_name(&elf_obj.strtab, sym.st_name, "elision_init") {
                    log!(
                        LogDebug,
                        "Found elision_init for possible patching in memory"
                    );
                    // Make elision_init return without doing anything. This means
                    // the __elision_available and __pthread_force_elision flags will
                    // remain zero, disabling elision for mutexes. See glibc's
                    // elision-conf.c.
                    const RET: [u8; 1] = [0xC3];
                    set_and_record_bytes(
                        t,
                        &elf_obj,
                        sym.st_value as usize,
                        &RET,
                        start,
                        size,
                        offset_pages,
                    );
                }
                // The following operations can only be applied once because after the
                // patch is applied the code no longer matches the expected template.
                // For replaying a replay to work, we need to only apply these changes
                // during a real exec, not during the mmap operations performed when rr
                // replays an exec.
                if mode == MmapMode::MmapExec
                    && (has_name(&elf_obj.strtab, sym.st_name, "_dl_runtime_resolve_fxsave")
                        || has_name(&elf_obj.strtab, sym.st_name, "_dl_runtime_resolve_xsave")
                        || has_name(&elf_obj.strtab, sym.st_name, "_dl_runtime_resolve_xsavec"))
                {
                    log!(LogWarn, "@TODO PENDING patch_dl_runtime_resolve()");
                }
            }
        }
    }

    pub fn is_jump_stub_instruction(_p: RemoteCodePtr) -> bool {
        unimplemented!()
    }
}

fn has_name(tab: &Strtab, index: usize, name: &str) -> bool {
    match tab.get(index) {
        Some(Ok(found_name)) if found_name == name => true,
        _ => false,
    }
}

fn patch_at_preload_init_arch<Arch: Architecture>(_t: &RecordTask, _patcher: &MonkeyPatcher) {
    unimplemented!()
}

/// @TODO Remove
struct ElfReader;
/// @TODO Remove
struct SymbolTable;

fn write_and_record_bytes(t: &mut RecordTask, child_addr: RemotePtr<Void>, buf: &[u8]) {
    t.write_bytes_helper(child_addr, buf, None, WriteFlags::empty());
    t.record_local(child_addr, buf);
}

fn write_and_record_mem<T>(t: &mut RecordTask, child_addr: RemotePtr<T>, vals: &[T]) {
    let vals_u8 =
        unsafe { slice::from_raw_parts(vals.as_ptr() as *const u8, vals.len() * size_of::<T>()) };
    write_and_record_bytes(t, RemotePtr::cast(child_addr), vals_u8);
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
fn setup_library_path_arch<Arch: Architecture>(
    t: &mut RecordTask,
    env_var: &OsStr,
    soname_base: &OsStr,
    soname_padded: &OsStr,
    soname_32: &OsStr,
) {
    let lib_name = if size_of::<Arch::unsigned_word>() < size_of::<usize>() {
        soname_32
    } else {
        soname_padded
    };
    let mut env_assignment = Vec::<u8>::new();
    env_assignment.extend_from_slice(env_var.as_bytes());
    env_assignment.push(b'=');

    let mut p = RemotePtr::<Arch::unsigned_word>::cast(t.regs_ref().sp());
    let argc: usize = read_val_mem(t, p, None).try_into().unwrap();

    // skip argc, argc parameters, and trailing NULL
    p += 1usize + argc + 1usize;
    loop {
        let envp = read_val_mem(t, p, None);
        if envp == 0u8.into() {
            log!(LogDebug, "{:?} not found", env_var);
            return;
        }
        // NOTE: Will not contain a nul at the end of Vec<u8>
        let env = t
            .read_c_str(RemotePtr::new(envp.try_into().unwrap()))
            .into_bytes();
        if find(&env, &env_assignment) != Some(0) {
            p += 1usize;
            continue;
        }
        let lib_pos = match find(&env, soname_base.as_bytes()) {
            None => {
                log!(LogDebug, "{:?} not found in {:?}", soname_base, env_var);
                return;
            }
            Some(lib_pos) => lib_pos,
        };
        match find(&env[lib_pos..], b":") {
            Some(next) => {
                let mut next_colon = next + lib_pos;
                // DIFF NOTE: There is a env[next_colon + 1] == 0 check in rr
                // Don't need it in rd as there is no terminating nul in the `env` var
                while next_colon + 1 < env.len() && env[next_colon + 1] == b':' {
                    next_colon += 1;
                }
                if next_colon < lib_pos + soname_padded.len() - 1 {
                    log!(
                        LogDebug,
                        "Insufficient space for {:?} in {:?} before next ':'",
                        lib_name,
                        env_var
                    );
                    return;
                }
            }
            None => (),
        }
        if env.len() - 1 < lib_pos + soname_padded.len() - 1 {
            log!(
                LogDebug,
                "Insufficient space for {:?} in {:?} before end of string",
                lib_name,
                env_var
            );
            return;
        }
        let dest = envp.try_into().unwrap() + lib_pos;
        write_and_record_bytes(
            t,
            RemotePtr::<Void>::from(dest),
            &lib_name.as_bytes()[0..soname_padded.len()],
        );
        return;
    }
}

fn setup_preload_library_path<Arch: Architecture>(t: &mut RecordTask) {
    let soname_base = OsStr::new(SYSCALLBUF_LIB_FILENAME_BASE);
    let soname_padded = OsStr::new(SYSCALLBUF_LIB_FILENAME_PADDED);
    let soname_32 = OsStr::new(SYSCALLBUF_LIB_FILENAME_32);
    setup_library_path_arch::<Arch>(
        t,
        OsStr::new("LD_PRELOAD"),
        soname_base,
        soname_padded,
        soname_32,
    );
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
fn allocate_extended_jump<Patch: AssemblyTemplate>(
    _t: &RecordTask,
    _pages: &[ExtendedJumpPage],
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

/// Return true iff `addr` points to a known `__kernel_vsyscall()`
/// implementation.
fn is_kernel_vsyscall(t: &mut RecordTask, addr: RemotePtr<Void>) -> bool {
    let mut impl_buf = [0u8; X86SysenterVsyscallImplementationAMD::SIZE];
    t.read_bytes(addr, &mut impl_buf);
    X86SysenterVsyscallImplementation::matchp(&impl_buf[0..X86SysenterVsyscallImplementation::SIZE])
        || X86SysenterVsyscallImplementationAMD::matchp(&impl_buf)
}

fn find_section_file_offsets<'a>(elf_obj: &Elf<'a>, section_name: &str) -> Option<Range<usize>> {
    for section in &elf_obj.section_headers {
        match elf_obj.strtab.get(section.sh_name) {
            Some(name_res) => match name_res {
                Ok(name) if name == section_name => return Some(section.file_range()),
                _ => continue,
            },
            None => continue,
        }
    }

    None
}

fn erase_section<'a>(elf_obj: &Elf<'a>, t: &mut RecordTask, section_name: &str) {
    match find_section_file_offsets(elf_obj, section_name) {
        Some(offsets) => {
            let mut zeroes: Vec<u8> = Vec::with_capacity(offsets.end - offsets.start);
            zeroes.resize(offsets.end - offsets.start, 0);
            write_and_record_bytes(t, t.vm().vdso().start() + offsets.start, &zeroes);
        }
        None => {
            log!(LogDebug, "Could not find section {} to erase", section_name);
        }
    }
}

fn obliterate_debug_info<'a>(elf_obj: &Elf<'a>, t: &mut RecordTask) {
    erase_section(elf_obj, t, ".eh_frame");
    erase_section(elf_obj, t, ".eh_frame_hdr");
    erase_section(elf_obj, t, ".note");
}

/// Patch _dl_runtime_resolve_(fxsave,xsave,xsavec) to clear "FDP Data Pointer"
/// register so that CPU-specific behaviors involving that register don't leak
/// into stack memory.
fn patch_dl_runtime_resolve(
    patcher: &MonkeyPatcher,
    t: &mut RecordTask,
    elf_obj: &Elf,
    elf_addr: usize,
    map_start: RemotePtr<Void>,
    map_size: usize,
    map_offset_pages: usize,
) {
    if t.arch() != SupportedArch::X64 {
        return;
    }
    let addr = resolve_address(elf_obj, elf_addr, map_start, map_size, map_offset_pages);
    if addr.is_null() {
        return;
    }

    let mut impl_resolve = [0u8; X64DLRuntimeResolve::SIZE];
    t.read_bytes(addr, &mut impl_resolve);
    if !X64DLRuntimeResolve::matchp(&impl_resolve) && !X64DLRuntimeResolve2::matchp(&impl_resolve) {
        log!(
            LogWarn,
            "_dl_runtime_resolve implementation doesn't look right"
        );
        return;
    }

    let mut jump_patch = [0u8; X64JumpMonkeypatch::SIZE];
    // We're patching in a relative jump, so we need to compute the offset from
    // the end of the jump to our actual destination.
    let jump_patch_start = RemotePtr::<u8>::cast(addr);
    let jump_patch_end = jump_patch_start + jump_patch.len();

    let extended_jump_start = allocate_extended_jump::<X64DLRuntimeResolvePrelude>(
        t,
        &patcher.extended_jump_pages,
        jump_patch_end,
    );
    if extended_jump_start.is_null() {
        return;
    }
    let mut stub_patch = [0u8; X64DLRuntimeResolvePrelude::SIZE];
    let return_offset: i64 = (jump_patch_start.as_isize() as i64
        + X64DLRuntimeResolve::SIZE as i64)
        - (extended_jump_start.as_isize() as i64 + X64DLRuntimeResolvePrelude::SIZE as i64);
    if return_offset != return_offset as i32 as i64 {
        log!(LogWarn, "Return out of range");
        return;
    }
    X64DLRuntimeResolvePrelude::substitute(&mut stub_patch, return_offset as u32);
    write_and_record_bytes(t, extended_jump_start, &stub_patch);

    let jump_offset: isize = extended_jump_start.as_isize() - jump_patch_end.as_isize();
    let jump_offset32 = jump_offset as i32;
    ed_assert_eq!(
        t,
        jump_offset32 as isize,
        jump_offset,
        "allocate_extended_jump didn't work"
    );
    X64JumpMonkeypatch::substitute(&mut jump_patch, jump_offset32 as u32);
    write_and_record_bytes(t, jump_patch_start, &jump_patch);

    // pad with NOPs to the next instruction
    const NOP: u8 = 0x90;
    let nops = [NOP; X64DLRuntimeResolve::SIZE - X64JumpMonkeypatch::SIZE];
    write_and_record_bytes(t, jump_patch_start + jump_patch.len(), &nops);
}

fn file_may_need_instrumentation(map: &address_space::Mapping) -> bool {
    let file_path = Path::new(map.map.fsname());

    match file_path.file_name() {
        Some(file_name) => {
            if find(file_name.as_bytes(), b"ld").is_some()
                || find(file_name.as_bytes(), b"libpthread").is_some()
            {
                true
            } else {
                false
            }
        }
        None => false,
    }
}

struct NamedSyscall {
    name: &'static str,
    syscall_number: i32,
}

const X64_SYSCALLS_TO_MONKEYPATCH: [NamedSyscall; 5] = [
    NamedSyscall {
        name: "__vdso_clock_gettime",
        syscall_number: X64Arch::CLOCK_GETTIME,
    },
    NamedSyscall {
        name: "__vdso_clock_getres",
        syscall_number: X64Arch::CLOCK_GETRES,
    },
    NamedSyscall {
        name: "__vdso_gettimeofday",
        syscall_number: X64Arch::GETTIMEOFDAY,
    },
    NamedSyscall {
        name: "__vdso_time",
        syscall_number: X64Arch::TIME,
    },
    NamedSyscall {
        name: "__vdso_getcpu",
        syscall_number: X64Arch::GETCPU,
    },
];

const X86_SYSCALLS_TO_MONKEYPATCH: [NamedSyscall; 5] = [
    NamedSyscall {
        name: "__vdso_clock_gettime",
        syscall_number: X86Arch::CLOCK_GETTIME,
    },
    NamedSyscall {
        name: "__vdso_gettimeofday",
        syscall_number: X86Arch::GETTIMEOFDAY,
    },
    NamedSyscall {
        name: "__vdso_time",
        syscall_number: X86Arch::TIME,
    },
    NamedSyscall {
        name: "__vdso_clock_getres",
        syscall_number: X86Arch::CLOCK_GETRES,
    },
    NamedSyscall {
        name: "__vdso_clock_gettime64",
        syscall_number: X86Arch::CLOCK_GETTIME64,
    },
];

/// @TODO Could offsets need a u64? rr uses a usize like here though
fn addr_to_offset<'a>(elf_obj: &Elf<'a>, addr: usize, offset: &mut usize) -> bool {
    for section in &elf_obj.section_headers {
        // Skip the section if it either "occupies no space in the file" or
        // doesn't have a valid address because it does not "occupy memory
        // during process execution".
        if section.sh_type == SHT_NOBITS || (section.sh_flags & SHF_ALLOC as u64 == 0) {
            continue;
        }
        if addr >= (section.sh_addr as usize)
            && addr - (section.sh_addr as usize) < (section.sh_size as usize)
        {
            *offset = addr - (section.sh_addr as usize) + (section.sh_offset as usize);
            return true;
        }
    }

    false
}

/// VDSOs are filled with overhead critical functions related to getting the
/// time and current CPU.  We need to ensure that these syscalls get redirected
/// into actual trap-into-the-kernel syscalls so rr can intercept them.
///
/// Monkeypatch x86-32 vdso syscalls immediately after exec. The vdso syscalls
/// will cause replay to fail if called by the dynamic loader or some library's
/// static constructors, so we can't wait for our preload library to be
/// initialized. Fortunately we're just replacing the vdso code with real
///  syscalls so there is no dependency on the preload library at all.
fn patch_after_exec_arch_x86arch(t: &mut RecordTask, patcher: &mut MonkeyPatcher) {
    setup_preload_library_path::<X86Arch>(t);
    let vdso_start = t.vm().vdso().start();
    let vdso_size = t.vm().vdso().size();

    let mut data = Vec::new();
    data.resize(vdso_size, 0u8);
    t.read_bytes_helper(vdso_start, &mut data, None);
    let elf_obj = match Elf::parse(&data) {
        Ok(elfo) => elfo,
        Err(e) => fatal!("Error in parsing vdso: {:?}", e),
    };

    patcher.x86_vsyscall = locate_and_verify_kernel_vsyscall(t, &elf_obj);
    if patcher.x86_vsyscall.is_null() {
        fatal!(
            "Failed to monkeypatch vdso: your __kernel_vsyscall() wasn't recognized.\n\
               Syscall buffering is now effectively disabled.  If you're OK with\n\
               running rd without syscallbuf, then run the recorder passing the\n\
               --no-syscall-buffer arg.\n\
               If you're *not* OK with that, file an issue."
        );
    }
    // Patch __kernel_vsyscall to use int 80 instead of sysenter.
    // During replay we may remap the VDSO to a new address, and the sysenter
    // instruction would return to the old address, so we must make sure sysenter
    // is never used.
    let mut patch = [0u8; X86SysenterVsyscallUseInt80::SIZE];
    X86SysenterVsyscallUseInt80::substitute(&mut patch);
    write_and_record_bytes(t, patcher.x86_vsyscall, &patch);
    log!(LogDebug, "monkeypatched __kernel_vsyscall to use int $80");

    for syscall in &X86_SYSCALLS_TO_MONKEYPATCH {
        for s in elf_obj.dynsyms.iter() {
            match elf_obj.dynstrtab.get(s.st_name) {
                Some(name_res) => match name_res {
                    Ok(name) if name == syscall.name => {
                        let mut file_offset: usize = 0;
                        if !addr_to_offset(&elf_obj, s.st_value as usize, &mut file_offset) {
                            log!(LogDebug, "Can't convert address {} to offset", s.st_value);

                            continue;
                        }
                        if file_offset > MAX_VDSO_SIZE {
                            // With 4.3.3-301.fc23.x86_64, once in a while we
                            // see a VDSO symbol with a crazy file offset in it which is a
                            // duplicate of another symbol. Bizzarro. Ignore it.
                            continue;
                        }

                        let absolute_address = vdso_start + file_offset;

                        let mut patch = [0u8; X86VsyscallMonkeypatch::SIZE];
                        X86VsyscallMonkeypatch::substitute(
                            &mut patch,
                            syscall.syscall_number as u32,
                        );

                        write_and_record_bytes(t, absolute_address, &patch);
                        // Record the location of the syscall instruction, skipping the
                        // "push %ebx; mov $syscall_number,%eax".
                        patcher
                            .patched_vdso_syscalls
                            .insert(RemoteCodePtr::from(absolute_address.as_usize() + 6));
                        log!(
                            LogDebug,
                            "monkeypatched {} to syscall {}",
                            syscall.name,
                            syscall.syscall_number
                        );
                    }
                    _ => (),
                },
                None => {}
            }
        }
    }

    obliterate_debug_info(&elf_obj, t);
}

/// Return the address of a recognized `__kernel_vsyscall()`
/// implementation in `t`'s address space.
fn locate_and_verify_kernel_vsyscall(t: &mut RecordTask, elf_obj: &Elf) -> RemotePtr<Void> {
    let mut kernel_vsyscall = RemotePtr::null();
    // It is unlikely but possible that multiple, versioned __kernel_vsyscall
    // symbols will exist.  But we can't rely on setting |kernel_vsyscall| to
    // catch that case, because only one of the versioned symbols will
    // actually match what we expect to see, and the matching one might be
    // the last one.  Therefore, we have this separate flag to alert us to
    // this possibility.
    let mut seen_kernel_vsyscall = false;
    for s in elf_obj.dynsyms.iter() {
        match elf_obj.dynstrtab.get(s.st_name) {
            Some(name_res) => match name_res {
                Ok(name) if name == "__kernel_vsyscall" => {
                    let mut file_offset: usize = 0;
                    if !addr_to_offset(&elf_obj, s.st_value as usize, &mut file_offset) {
                        log!(LogDebug, "Can't convert address {} to offset", s.st_value);
                        continue;
                    }
                    // The symbol values can be absolute or relative addresses.
                    if file_offset >= VDSO_ABSOLUTE_ADDRESS {
                        file_offset -= VDSO_ABSOLUTE_ADDRESS;
                    }
                    if file_offset > MAX_VDSO_SIZE {
                        // With 4.2.8-300.fc23.x86_64, execve_loop_32 seems to once in a while
                        // see a VDSO with a crazy file offset in it which is a duplicate
                        // __kernel_vsyscall. Bizzarro. Ignore it.
                        continue;
                    }
                    ed_assert!(t, !seen_kernel_vsyscall);
                    seen_kernel_vsyscall = true;
                    // The ELF information in the VDSO assumes that the VDSO
                    // is always loaded at a particular address.  The kernel,
                    // however, subjects the VDSO to ASLR, which means that
                    // we have to adjust the offsets properly.
                    let vdso_start = t.vm().vdso().start();
                    let candidate = vdso_start + file_offset;

                    if is_kernel_vsyscall(t, candidate) {
                        kernel_vsyscall = candidate;
                    }
                }
                _ => (),
            },
            None => {}
        }
    }

    kernel_vsyscall
}

/// VDSOs are filled with overhead critical functions related to getting the
/// time and current CPU.  We need to ensure that these syscalls get redirected
/// into actual trap-into-the-kernel syscalls so rr can intercept them.
///
/// Monkeypatch x86-64 vdso syscalls immediately after exec. The vdso syscalls
/// will cause replay to fail if called by the dynamic loader or some library's
/// static constructors, so we can't wait for our preload library to be
/// initialized. Fortunately we're just replacing the vdso code with real
/// syscalls so there is no dependency on the preload library at all.
///
/// DIFF NOTE: The rr version of this x64 architecture specific function call uses u64
/// and usize in a few places. It makes sense to simply use usize consistently.
/// @TODO Need to make sure if there was any deliberate intent there.
fn patch_after_exec_arch_x64arch(t: &mut RecordTask, patcher: &mut MonkeyPatcher) {
    setup_preload_library_path::<X64Arch>(t);

    let vdso_start = t.vm().vdso().start();
    let vdso_size = t.vm().vdso().size();

    let size = t.vm().vdso().size();
    let mut data = Vec::new();
    data.resize(size, 0u8);
    t.read_bytes_helper(t.vm().vdso().start(), &mut data, None);
    let elf_obj = match Elf::parse(&data) {
        Ok(elfo) => elfo,
        Err(e) => fatal!("Error in parsing vdso: {:?}", e),
    };

    for syscall in &X64_SYSCALLS_TO_MONKEYPATCH {
        for s in elf_obj.dynsyms.iter() {
            match elf_obj.dynstrtab.get(s.st_name) {
                Some(name_res) => match name_res {
                    Ok(name) if name == syscall.name => {
                        let mut file_offset: usize = 0;
                        if !addr_to_offset(&elf_obj, s.st_value as usize, &mut file_offset) {
                            log!(LogDebug, "Can't convert address {} to offset", s.st_value);

                            continue;
                        }

                        // Absolutely-addressed symbols in the VDSO claim to start here.
                        const VDSO_STATIC_BASE: usize = 0xffffffffff700000;
                        const VDSO_MAX_SIZE: usize = 0xffff;
                        let sym_offset: usize = file_offset & VDSO_MAX_SIZE;

                        // In 4.4.6-301.fc23.x86_64 we occasionally see a grossly invalid
                        // address, se.g. 0x11c6970 for __vdso_getcpu. :-(
                        if file_offset >= VDSO_STATIC_BASE
                            && file_offset < VDSO_STATIC_BASE + vdso_size
                            || file_offset < vdso_size
                        {
                            let absolute_address: usize = vdso_start.as_usize() + sym_offset;

                            let mut patch = [0u8; X64VsyscallMonkeypatch::SIZE];
                            let syscall_number: i32 = syscall.syscall_number;
                            X64VsyscallMonkeypatch::substitute(&mut patch, syscall_number as u32);

                            write_and_record_bytes(t, absolute_address.into(), &patch);
                            // Record the location of the syscall instruction, skipping the
                            // "mov $syscall_number,%eax".
                            patcher
                                .patched_vdso_syscalls
                                .insert(RemoteCodePtr::from(absolute_address + 5));
                            log!(
                                LogDebug,
                                "monkeypatched {} to syscall {} at {:#x} ({:#x})",
                                syscall.name,
                                syscall.syscall_number,
                                absolute_address,
                                file_offset
                            );

                            // With 4.4.6-301.fc23.x86_64, once in a while we see a VDSO symbol
                            // with an incorrect file offset (a small integer) in it
                            // which is a duplicate of a previous symbol. Bizzarro. So, stop once
                            // we see a valid value for the symbol.
                            break;
                        } else {
                            log!(
                        LogDebug,
                        "Ignoring odd file offset {:#x}; vdso_static_base={:#x}, size={:#x}",
                        VDSO_STATIC_BASE,
                        file_offset,
                        vdso_size
                    );
                        }
                    }
                    _ => (),
                },
                None => {}
            }
        }
    }

    obliterate_debug_info(&elf_obj, t);

    for (_, m) in &t.vm_shr_ptr().maps() {
        let km = &m.map;
        patcher.patch_after_mmap(
            t,
            km.start(),
            km.size(),
            (km.file_offset_bytes() / page_size() as u64) as usize,
            -1,
            MmapMode::MmapExec,
        );
    }
}

struct ElfMap {
    map: &'static mut [u8],
}

impl ElfMap {
    fn new(fd: &ScopedFd) -> ElfMap {
        let st = match fstat(fd.as_raw()) {
            Err(e) => fatal!("Can't stat fd {}: {:?}", fd.as_raw(), e),
            Ok(st) => st,
        };

        assert!(st.st_size > 0);

        let map_res = unsafe {
            mmap(
                ptr::null_mut(),
                st.st_size as usize,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                fd.as_raw(),
                0,
            )
        };

        match map_res {
            Err(e) => {
                fatal!("Can't map fd {}: {:?}", fd.as_raw(), e);
            }
            Ok(addr) => ElfMap {
                map: unsafe { slice::from_raw_parts_mut(addr as *mut u8, st.st_size as usize) },
            },
        }
    }
}

impl Drop for ElfMap {
    fn drop(&mut self) {
        match unsafe { munmap(self.map.as_mut_ptr() as *mut _, self.map.len()) } {
            Ok(_) => (),
            Err(e) => fatal!(
                "Could not munmap Elfmap at {:?} (len: {}): {:?}",
                self.map.as_ptr(),
                self.map.len(),
                e
            ),
        }
    }
}

fn resolve_address<'a>(
    elf_obj: &Elf<'a>,
    elf_addr: usize,
    map_start: RemotePtr<Void>,
    map_size: usize,
    map_offset_pages: usize,
) -> RemotePtr<Void> {
    let mut file_offset: usize = 0;
    if !addr_to_offset(elf_obj, elf_addr, &mut file_offset) {
        log!(LogWarn, "ELF address {:#x} not in file", elf_addr);
    }
    let map_offset = map_offset_pages * page_size();
    if file_offset < map_offset || file_offset + 32 > map_offset + map_size {
        // The value(s) to be set are outside the mapped range. This happens
        // because code and data can be mapped in separate, partial mmaps in which
        // case some symbols will be outside the mapped range.
        return RemotePtr::null();
    }

    map_start + file_offset - map_offset
}

fn set_and_record_bytes<'a>(
    t: &mut RecordTask,
    elf_obj: &Elf<'a>,
    elf_addr: usize,
    bytes: &[u8],
    map_start: RemotePtr<Void>,
    map_size: usize,
    map_offset_pages: usize,
) {
    let addr: RemotePtr<Void> =
        resolve_address(elf_obj, elf_addr, map_start, map_size, map_offset_pages);

    if addr.is_null() {
        return;
    }

    log!(
        LogDebug,
        "  resolved at address: {:#x}. Will be patched.",
        addr.as_usize()
    );
    let mut ok = true;
    t.write_bytes_helper(addr, bytes, Some(&mut ok), WriteFlags::empty());
    // Writing can fail when the value appears to be in the mapped range, but it
    // actually is beyond the file length.
    if ok {
        t.record_local(addr, bytes);
    }
}
