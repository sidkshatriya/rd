use crate::{
    arch::{Architecture, X64Arch},
    kernel_abi::SupportedArch,
    log::{LogDebug, LogWarn},
    preload_interface::syscall_patch_hook,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::address_space,
        task::{record_task::RecordTask, task_inner::WriteFlags, Task},
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
            let elf_file = match Elf::parse(elf_map.map) {
                Ok(elf_file) => elf_file,
                Err(_) => return,
            };

            if elf_file.syms.len() == 0 {
                log!(
                    LogWarn,
                    "@TODO PENDING try to get symbols for patch_after_mmap() from debug"
                )
            }
            for sym in &elf_file.syms {
                if has_name(&elf_file.strtab, sym.st_name, "__elision_aconf") {
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
                        &elf_file,
                        sym.st_value as usize + 8,
                        &ZERO.to_le_bytes(),
                        start,
                        size,
                        offset_pages,
                    );
                }
                if has_name(&elf_file.strtab, sym.st_name, "elision_init") {
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
                        &elf_file,
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
                    && (has_name(&elf_file.strtab, sym.st_name, "_dl_runtime_resolve_fxsave")
                        || has_name(&elf_file.strtab, sym.st_name, "_dl_runtime_resolve_xsave")
                        || has_name(&elf_file.strtab, sym.st_name, "_dl_runtime_resolve_xsavec"))
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
    // @TODO PENDING
    log!(LogWarn, "@TODO PENDING setup_preload_library_path()");
    // Skip for now
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

fn find_section_file_offsets<'a>(elf_file: &Elf<'a>, section_name: &str) -> Option<Range<usize>> {
    for section in &elf_file.section_headers {
        match elf_file.strtab.get(section.sh_name) {
            Some(name_res) => match name_res {
                Ok(name) if name == section_name => return Some(section.file_range()),
                _ => continue,
            },
            None => continue,
        }
    }

    None
}

fn erase_section<'a>(elf_file: &Elf<'a>, t: &mut RecordTask, section_name: &str) {
    match find_section_file_offsets(elf_file, section_name) {
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

fn obliterate_debug_info<'a>(elf_file: &Elf<'a>, t: &mut RecordTask) {
    erase_section(elf_file, t, ".eh_frame");
    erase_section(elf_file, t, ".eh_frame_hdr");
    erase_section(elf_file, t, ".note");
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

const SYSCALLS_TO_MONKEYPATCH: [NamedSyscall; 5] = [
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

/// @TODO Could offsets need a u64? rr uses a usize like here though
fn addr_to_offset<'a>(elf_file: &Elf<'a>, addr: usize, offset: &mut usize) -> bool {
    for section in &elf_file.section_headers {
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
fn patch_after_exec_arch_x86arch(_t: &mut RecordTask, _patcher: &mut MonkeyPatcher) {
    unimplemented!()
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
    let elf_file = match Elf::parse(&data) {
        Ok(elf_file) => elf_file,
        Err(e) => fatal!("Error in parsing vdso: {:?}", e),
    };

    for syscall in &SYSCALLS_TO_MONKEYPATCH {
        for s in elf_file.dynsyms.iter() {
            match elf_file.dynstrtab.get(s.st_name) {
                Some(name_res) => match name_res {
                    Ok(name) if name == syscall.name => {
                        let mut file_offset: usize = 0;
                        if !addr_to_offset(&elf_file, s.st_value as usize, &mut file_offset) {
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
                            X64VsyscallMonkeypatch::substitute(&mut patch, syscall_number);

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

    obliterate_debug_info(&elf_file, t);

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

impl X64VsyscallMonkeypatch {
    fn matchp(buffer: &[u8], syscall_number: &mut u32) -> bool {
        if buffer[0] != X64_VSYSCALL_MONKEYPATCH_BYTES[0] {
            return false;
        }
        *syscall_number = u32::from_le_bytes(buffer[1..1 + size_of::<u32>()].try_into().unwrap());
        if buffer[Self::SYSCALL_NUMBER_END..Self::SIZE]
            != X64_VSYSCALL_MONKEYPATCH_BYTES[Self::SYSCALL_NUMBER_END..Self::SIZE]
        {
            return false;
        }

        true
    }

    fn substitute(buffer: &mut [u8], syscall_number: i32) {
        buffer[0] = X64_VSYSCALL_MONKEYPATCH_BYTES[0];
        buffer[1..1 + size_of::<i32>()].copy_from_slice(&syscall_number.to_le_bytes());
        buffer[Self::SYSCALL_NUMBER_END..Self::SIZE]
            .copy_from_slice(&X64_VSYSCALL_MONKEYPATCH_BYTES[Self::SYSCALL_NUMBER_END..Self::SIZE]);
    }

    const SYSCALL_NUMBER_END: usize = 5;

    const SIZE: usize = X64_VSYSCALL_MONKEYPATCH_BYTES.len();
}

struct X64VsyscallMonkeypatch;

const X64_VSYSCALL_MONKEYPATCH_BYTES: [u8; 11] =
    [0xb8, 0x0, 0x0, 0x0, 0x0, 0xf, 0x5, 0x90, 0x90, 0x90, 0xc3];

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
    elf_file: &Elf<'a>,
    elf_addr: usize,
    map_start: RemotePtr<Void>,
    map_size: usize,
    map_offset_pages: usize,
) -> RemotePtr<Void> {
    let mut file_offset: usize = 0;
    if !addr_to_offset(elf_file, elf_addr, &mut file_offset) {
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
    elf_file: &Elf<'a>,
    elf_addr: usize,
    bytes: &[u8],
    map_start: RemotePtr<Void>,
    map_size: usize,
    map_offset_pages: usize,
) {
    let addr: RemotePtr<Void> =
        resolve_address(elf_file, elf_addr, map_start, map_size, map_offset_pages);

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
