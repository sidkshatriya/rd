use crate::{
    arch::{Architecture, X64Arch, X86Arch},
    auto_remote_syscalls::AutoRemoteSyscalls,
    flags::Flags,
    kernel_abi::{get_syscall_instruction_arch, syscall_instruction_length, SupportedArch},
    kernel_metadata::syscall_name,
    log::{LogDebug, LogWarn},
    preload_interface::{
        syscall_patch_hook, NEXT_INSTRUCTION_BYTES_LEN, SYSCALLBUF_LIB_FILENAME_32,
        SYSCALLBUF_LIB_FILENAME_BASE, SYSCALLBUF_LIB_FILENAME_PADDED,
    },
    preload_interface_arch::rdcall_init_preload_params,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::{address_space, kernel_mapping::KernelMapping, MappingFlags},
        task::{
            record_task::RecordTask,
            task_common::{read_mem, read_val_mem},
            task_inner::WriteFlags,
            Task,
        },
    },
    trace::trace_writer::MappingOrigin,
    util::{find, page_size},
};
use crc32fast::Hasher;
use goblin::{
    elf::Elf,
    elf64::section_header::{SHF_ALLOC, SHT_NOBITS},
    strtab::Strtab,
};
use nix::{
    errno::Errno,
    fcntl::{readlink, OFlag},
    sys::{
        mman::{mmap, munmap, MapFlags, ProtFlags},
        stat::fstat,
    },
    unistd::read,
    Error,
};
use object::{self, Object};
use std::{
    cmp::min,
    collections::{BTreeMap, HashSet},
    convert::TryInto,
    ffi::{OsStr, OsString},
    mem::size_of,
    ops::{
        Bound::{Included, Unbounded},
        Range,
    },
    os::unix::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
    ptr,
    rc::Rc,
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
    pub syscallbuf_stubs: BTreeMap<RemotePtr<u8>, usize>,

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

#[derive(Copy, Clone)]
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
    pub fn patch_after_exec(&mut self, t: &RecordTask) {
        let arch = t.arch();
        match arch {
            SupportedArch::X86 => patch_after_exec_arch_x86arch(t, self),
            SupportedArch::X64 => patch_after_exec_arch_x64arch(t, self),
        }
    }

    pub fn patch_at_preload_init(&mut self, t: &RecordTask) {
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
    pub fn try_patch_syscall(&mut self, t: &RecordTask) -> bool {
        if self.syscall_hooks.is_empty() {
            // Syscall hooks not set up yet. Don't spew warnings, and don't
            // fill tried_to_patch_syscall_addresses with addresses that we might be
            // able to patch later.
            return false;
        }

        if t.emulated_ptracer.borrow().is_some() {
            // Syscall patching can confuse ptracers, which may be surprised to see
            // a syscall instruction at the current IP but then when running
            // forwards, that the syscall occurs deep in the preload library instead.
            return false;
        }

        if t.is_in_traced_syscall() {
            // Never try to patch the traced-syscall in our preload library!
            return false;
        }
        let r = t.regs_ref().clone();
        let ip = r.ip();

        if self.tried_to_patch_syscall_addresses.get(&ip).is_some() {
            return false;
        }

        // We could examine the current syscall number and if it's not one that
        // we support syscall buffering for, refuse to patch the syscall instruction.
        // This would, on the face of it, reduce overhead since patching the
        // instruction just means a useless trip through the syscall buffering logic.
        // However, it actually wouldn't help much since we'd still do a switch
        // on the syscall number in this function instead, and due to context
        // switching costs any overhead saved would be insignificant.
        // Also, implementing that would require keeping a buffered-syscalls
        // list in sync with the preload code, which is unnecessary complexity.
        let mut arch = SupportedArch::default();
        let code_ptr = ip.decrement_by_syscall_insn_length(t.arch());
        if !get_syscall_instruction_arch(t, code_ptr, &mut arch) || arch != t.arch() {
            log!(
                LogDebug,
                "Declining to patch cross-architecture syscall at {}",
                ip
            );
            self.tried_to_patch_syscall_addresses.insert(ip);
            return false;
        }

        let mut following_bytes = [0u8; 256];
        // @TODO Is it ok to unwrap here? i.e. assert that there should be no error?
        let bytes_count = t
            .read_bytes_fallible(ip.to_data_ptr::<u8>(), &mut following_bytes)
            .unwrap();

        let syscallno = r.original_syscallno();
        let mut do_patch = None;
        for hook in &self.syscall_hooks {
            if bytes_count >= hook.next_instruction_length as usize
                && following_bytes[0..hook.next_instruction_length as usize]
                    == hook.next_instruction_bytes[0..hook.next_instruction_length as usize]
            {
                // Search for a following short-jump instruction that targets an
                // instruction
                // after the syscall. False positives are OK.
                // glibc-2.23.1-8.fc24.x86_64's __clock_nanosleep needs this.
                let mut found_potential_interfering_branch = false;
                // If this was a VDSO syscall we patched, we don't have to worry about
                // this check since the function doesn't do anything except execute our
                // syscall and return.
                // Otherwise the Linux 4.12 VDSO triggers the interfering-branch check.
                if !self
                    .patched_vdso_syscalls
                    .get(&ip.decrement_by_syscall_insn_length(arch))
                    .is_some()
                {
                    let mut i = 0;
                    while i + 2 <= bytes_count {
                        let b: u8 = following_bytes[i];
                        // Check for short conditional or unconditional jump
                        if b == 0xeb || (b >= 0x70 && b < 0x80) {
                            let offset: i32 = i as i32 + 2i32 + following_bytes[i + 1] as i8 as i32;
                            let cond = if hook.is_multi_instruction != 0 {
                                offset >= 0 && (offset as u8) < hook.next_instruction_length
                            } else {
                                offset == 0
                            };
                            if cond {
                                log!(
                                    LogDebug,
                                    "Found potential interfering branch at {}",
                                    ip.to_data_ptr::<u8>() + i
                                );
                                // We can't patch this because it would jump straight back into
                                // the middle of our patch code.
                                found_potential_interfering_branch = true;
                            }
                        }
                        i += 1;
                    }
                }

                if !found_potential_interfering_branch {
                    if !safe_for_syscall_patching(ip, ip + hook.next_instruction_length as usize, t)
                    {
                        log!(LogDebug,
               "Temporarily declining to patch syscall at {} because a different task has its ip in the patched range", ip);

                        return false;
                    }

                    let sl = &following_bytes[0..min(bytes_count, NEXT_INSTRUCTION_BYTES_LEN)];
                    log!(
                        LogDebug,
                        "Patched syscall at: {} syscall: {} tid: {} bytes: {:?} at time: {}",
                        ip,
                        syscall_name(syscallno as i32, t.arch()),
                        t.tid(),
                        sl,
                        t.trace_time()
                    );

                    // Get out of executing the current syscall before we patch it.
                    if !t.exit_syscall_and_prepare_restart() {
                        return false;
                    }

                    do_patch = Some(hook.clone());
                    break;
                }
            }
        }

        let success = match do_patch {
            // DIFF NOTE: @TODO rr seems to return true unconditionally?
            Some(hook) => patch_syscall_with_hook(self, t, &hook),
            None => false,
        };

        if !success {
            let sl = &following_bytes[0..min(bytes_count, NEXT_INSTRUCTION_BYTES_LEN)];
            log!(
                LogDebug,
                "Failed to patch syscall at {} syscall {} tid {} bytes {:?}",
                ip,
                syscall_name(syscallno as i32, t.arch()),
                t.tid(),
                sl
            );
            self.tried_to_patch_syscall_addresses.insert(ip);

            false
        } else {
            true
        }
    }

    pub fn init_dynamic_syscall_patching(
        &mut self,
        t: &RecordTask,
        syscall_patch_hook_count: usize,
        syscall_patch_hooks: RemotePtr<syscall_patch_hook>,
    ) {
        if syscall_patch_hook_count != 0 {
            self.syscall_hooks = read_mem(t, syscall_patch_hooks, syscall_patch_hook_count, None);
        }
    }

    /// Try to allocate a stub from the sycall patching stub buffer. Returns null
    /// if there's no buffer or we've run out of free stubs.
    pub fn allocate_stub(_t: &RecordTask, _bytes: usize) -> RemotePtr<u8> {
        unimplemented!()
    }

    /// Apply any necessary patching immediately after an mmap. We use this to
    /// patch libpthread.so.
    pub fn patch_after_mmap(
        &mut self,
        t: &RecordTask,
        start: RemotePtr<Void>,
        size: usize,
        offset_pages: usize,
        child_fd: i32,
        mode: MmapMode,
    ) {
        if file_may_need_instrumentation(&t.vm().mapping_of(start).unwrap())
            && (t.arch() == SupportedArch::X86 || t.arch() == SupportedArch::X64)
        {
            let mut open_fd: ScopedFd;
            if child_fd >= 0 {
                open_fd = t.open_fd(child_fd, OFlag::O_RDONLY);
                ed_assert!(t, open_fd.is_open(), "Failed to open child fd {}", child_fd);
            } else {
                let buf = format!(
                    "/proc/{}/map_files/{:x}-{:x}",
                    t.tid(),
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
            let mut elf_obj = match Elf::parse(elf_map.map) {
                Ok(elfo) => elfo,
                Err(_) => return,
            };

            let debug_elf_map;
            let mut maybe_original = None;
            if elf_obj.syms.len() == 0 {
                let fsname = t
                    .vm()
                    .mapping_of(start)
                    .unwrap()
                    .map
                    .fsname()
                    .to_os_string();
                match open_debug_file(elf_map.map, fsname) {
                    Some(fd) => {
                        open_fd = fd;
                        debug_elf_map = ElfMap::new(&open_fd);
                        maybe_original = Some(elf_obj);
                        elf_obj = match Elf::parse(debug_elf_map.map) {
                            Ok(elfo) => elfo,
                            Err(_) => return,
                        };
                    }
                    None => return,
                }
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
                        match maybe_original.as_ref() {
                            Some(elf) => elf,
                            None => &elf_obj,
                        },
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
                        match maybe_original.as_ref() {
                            Some(elf) => elf,
                            None => &elf_obj,
                        },
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
                    patch_dl_runtime_resolve(
                        self,
                        t,
                        match maybe_original.as_ref() {
                            Some(elf) => elf,
                            None => &elf_obj,
                        },
                        sym.st_value as usize,
                        start,
                        size,
                        offset_pages,
                    );
                }
            }
        }
    }

    pub fn is_jump_stub_instruction(&self, ip: RemoteCodePtr) -> bool {
        let pp = ip.to_data_ptr::<u8>();
        let mut range = self.syscallbuf_stubs.range((Unbounded, Included(pp)));
        match range.next_back() {
            Some((&k, &v)) => k <= pp && pp < k + v,
            None => false,
        }
    }
}

fn open_debug_file(bytes: &[u8], fsname: OsString) -> Option<ScopedFd> {
    let path = PathBuf::from(fsname.clone());
    let dirname = path.parent()?;
    let mut debug_so_path = PathBuf::from("/usr/lib/debug");
    for component in dirname.components() {
        if component != Component::RootDir {
            debug_so_path.push(component)
        }
    }

    // @TODO This uses the object crate. Probably a good idea to _just_ use object or just goblin
    let parsed = object::read::File::parse(bytes).ok()?;
    let (debug_link, crc32) = parsed.gnu_debuglink().ok()??;
    debug_so_path.push(OsStr::from_bytes(debug_link));
    let debug_fd = ScopedFd::open_path(&debug_so_path, OFlag::O_RDONLY);
    if !debug_fd.is_open() {
        return None;
    }
    // Verify that the CRC checksum matches, in case the debuginfo and text file
    // are in separate packages that are out of sync.
    let mut hash = Hasher::new();
    loop {
        let mut buf = [0u8; 4096];
        match read(debug_fd.as_raw(), &mut buf) {
            Ok(0) => break,
            Ok(nread) => hash.update(&buf[0..nread]),
            //  Try again
            Err(Error::Sys(Errno::EINTR)) => (),
            Err(e) => {
                log!(LogDebug, "Error reading {:?}: {:?}", debug_so_path, e);
                return None;
            }
        }
    }
    if hash.finalize() == crc32 {
        Some(debug_fd)
    } else {
        None
    }
}

fn has_name(tab: &Strtab, index: usize, name: &str) -> bool {
    match tab.get(index) {
        Some(Ok(found_name)) if found_name == name => true,
        _ => false,
    }
}

fn patch_at_preload_init_arch<Arch: Architecture>(t: &RecordTask, patcher: &mut MonkeyPatcher) {
    let arch = t.arch();
    match arch {
        SupportedArch::X86 => patch_at_preload_init_arch_x86arch(t, patcher),
        SupportedArch::X64 => patch_at_preload_init_arch_x64arch(t, patcher),
    }
}

fn patch_at_preload_init_arch_x86arch(t: &RecordTask, patcher: &mut MonkeyPatcher) {
    let child_addr = RemotePtr::<rdcall_init_preload_params<X86Arch>>::from(t.regs_ref().arg1());
    let params = read_val_mem(t, child_addr, None);
    if params.syscallbuf_enabled == 0 {
        return;
    }

    let kernel_vsyscall = patcher.x86_vsyscall;

    // Luckily, linux is happy for us to scribble directly over
    // the vdso mapping's bytes without mprotecting the region, so
    // we don't need to prepare remote syscalls here.
    let syscallhook_vsyscall_entry = X86Arch::as_rptr(params.syscallhook_vsyscall_entry);

    let mut patch = Vec::<u8>::with_capacity(X86SysenterVsyscallSyscallHook::SIZE);
    patch.resize(X86SysenterVsyscallSyscallHook::SIZE, 0);

    if safe_for_syscall_patching(
        kernel_vsyscall.to_code_ptr(),
        kernel_vsyscall.to_code_ptr() + patch.len(),
        t,
    ) {
        // We're patching in a relative jump, so we need to compute the offset from
        // the end of the jump to our actual destination.
        let val = (syscallhook_vsyscall_entry.as_isize()
            - (kernel_vsyscall.as_isize() + patch.len() as isize)) as u32;
        X86SysenterVsyscallSyscallHook::substitute(&mut patch, val);
        write_and_record_bytes(t, kernel_vsyscall, &patch);
        log!(
            LogDebug,
            "monkeypatched __kernel_vsyscall to jump to {}",
            syscallhook_vsyscall_entry
        );
    } else {
        if !Flags::get().suppress_environment_warnings {
            eprintln!("Unable to patch __kernel_vsyscall because a LD_PRELOAD thread is blocked in it; recording will be slow");
        }
        log!(
            LogDebug,
            "Unable to patch __kernel_vsyscall because a LD_PRELOAD thread is blocked in it"
        );
    }

    patcher.init_dynamic_syscall_patching(
        t,
        params.syscall_patch_hook_count.try_into().unwrap(),
        X86Arch::as_rptr(params.syscall_patch_hooks),
    );
}

fn patch_at_preload_init_arch_x64arch(t: &RecordTask, patcher: &mut MonkeyPatcher) {
    let child_addr = RemotePtr::<rdcall_init_preload_params<X64Arch>>::from(t.regs_ref().arg1());
    let params: rdcall_init_preload_params<X64Arch> = read_val_mem(t, child_addr, None);
    if params.syscallbuf_enabled == 0 {
        return;
    }

    patcher.init_dynamic_syscall_patching(
        t,
        params.syscall_patch_hook_count.try_into().unwrap(),
        X64Arch::as_rptr(params.syscall_patch_hooks),
    );
}

fn write_and_record_bytes(t: &RecordTask, child_addr: RemotePtr<Void>, buf: &[u8]) {
    t.write_bytes_helper(child_addr, buf, None, WriteFlags::empty());
    t.record_local(child_addr, buf);
}

fn write_and_record_mem<T>(t: &RecordTask, child_addr: RemotePtr<T>, vals: &[T]) {
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
    t: &RecordTask,
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

fn setup_preload_library_path<Arch: Architecture>(t: &RecordTask) {
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

trait AssemblyTemplateSubstituteExtendedJump: AssemblyTemplate {
    fn substitute_extended_jump(
        buffer: &mut [u8],
        patch_addr: u64,
        return_addr: u64,
        target_addr: u64,
    );
}

impl AssemblyTemplateSubstituteExtendedJump for X86SyscallStubExtendedJump {
    fn substitute_extended_jump(
        buffer: &mut [u8],
        patch_addr: u64,
        return_addr: u64,
        target_addr: u64,
    ) {
        let offset: i64 = target_addr as i64
            - (patch_addr as i64 + X86SyscallStubExtendedJump::TRAMPOLINE_RELATIVE_ADDR_END as i64);
        // An offset that appears to be > 2GB is OK here, since EIP will just
        // wrap around.
        X86SyscallStubExtendedJump::substitute(buffer, return_addr as u32, offset as u32);
    }
}

impl AssemblyTemplateSubstituteExtendedJump for X64SyscallStubExtendedJump {
    fn substitute_extended_jump(
        buffer: &mut [u8],
        _param: u64,
        return_addr: u64,
        target_addr: u64,
    ) {
        X64SyscallStubExtendedJump::substitute(
            buffer,
            return_addr as u32,
            (return_addr >> 32) as u32,
            target_addr,
        );
    }
}

/// Allocate an extended jump in an extended jump page and return its address.
/// The resulting address must be within 2G of from_end, and the instruction
/// there must jump to to_start.
fn allocate_extended_jump<ExtendedJumpPatch: AssemblyTemplate>(
    t: &RecordTask,
    pages: &mut Vec<ExtendedJumpPage>,
    from_end: RemotePtr<u8>,
) -> RemotePtr<u8> {
    let mut maybe_page: Option<usize> = None;
    for (i, p) in pages.iter().enumerate() {
        let page_jump_start = p.addr + p.allocated;
        let offset = page_jump_start.as_isize() as i64 - from_end.as_isize() as i64;
        if offset as i32 as i64 == offset && p.allocated + ExtendedJumpPatch::SIZE <= page_size() {
            maybe_page = Some(i);
            break;
        }
    }

    match maybe_page {
        None => {
            // We're looking for a gap of three pages --- one page to allocate and
            // a page on each side as a guard page.
            let required_space = 3 * page_size();
            let free_mem = t.vm().find_free_memory(
                required_space,
                // Find free space after the patch site.
                Some(t.vm().mapping_of(from_end).unwrap().map.start()),
            );

            let addr = free_mem + page_size();
            let offset: i64 = addr.as_isize() as i64 - from_end.as_isize() as i64;
            if offset as i32 as i64 != offset {
                log!(LogDebug, "Can't find space close enough for the jump");
                return RemotePtr::null();
            }

            {
                let mut remote = AutoRemoteSyscalls::new(t);
                let prot = ProtFlags::PROT_READ | ProtFlags::PROT_EXEC;
                let flags = MapFlags::MAP_ANONYMOUS | MapFlags::MAP_FIXED | MapFlags::MAP_PRIVATE;
                remote.infallible_mmap_syscall(Some(addr), page_size(), prot, flags, -1, 0);
                let recorded = KernelMapping::new_with_opts(
                    addr,
                    addr + page_size(),
                    &OsString::new(),
                    KernelMapping::NO_DEVICE,
                    KernelMapping::NO_INODE,
                    prot,
                    flags,
                    0,
                );
                remote.task().vm().map(
                    remote.task(),
                    addr,
                    page_size(),
                    prot,
                    flags,
                    0,
                    &OsString::new(),
                    KernelMapping::NO_DEVICE,
                    KernelMapping::NO_INODE,
                    None,
                    Some(&recorded),
                    None,
                    None,
                    None,
                );
                *remote.task().vm().mapping_flags_of_mut(addr) |= MappingFlags::IS_PATCH_STUBS;
                remote
                    .task()
                    .as_rec_unwrap()
                    .trace_writer_mut()
                    .write_mapped_region(
                        remote.task().as_rec_unwrap(),
                        &recorded,
                        &recorded.fake_stat(),
                        &[],
                        Some(MappingOrigin::PatchMapping),
                        None,
                    );
            }

            let mut page = ExtendedJumpPage::new(addr);
            let jump_addr = page.addr + page.allocated;
            page.allocated += ExtendedJumpPatch::SIZE;
            pages.push(page);
            jump_addr
        }
        Some(page_i) => {
            let page = pages.get_mut(page_i).unwrap();
            let jump_addr = page.addr + page.allocated;
            page.allocated += ExtendedJumpPatch::SIZE;
            jump_addr
        }
    }
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
fn patch_syscall_with_hook_x86ish<
    JumpPatch: AssemblyTemplateSubstitute,
    ExtendedJumpPatch: AssemblyTemplateSubstituteExtendedJump,
>(
    patcher: &mut MonkeyPatcher,
    t: &RecordTask,
    hook: &syscall_patch_hook,
) -> bool {
    let mut jump_patch = Vec::<u8>::with_capacity(JumpPatch::SIZE);
    jump_patch.resize(JumpPatch::SIZE, 0);
    // We're patching in a relative jump, so we need to compute the offset from
    // the end of the jump to our actual destination.
    let jump_patch_start = t.regs_ref().ip().to_data_ptr::<u8>();
    let jump_patch_end = jump_patch_start + jump_patch.len();

    let extended_jump_start = allocate_extended_jump::<ExtendedJumpPatch>(
        t,
        &mut patcher.extended_jump_pages,
        jump_patch_end,
    );
    if extended_jump_start.is_null() {
        return false;
    }

    let mut stub_patch = Vec::<u8>::with_capacity(ExtendedJumpPatch::SIZE);
    stub_patch.resize(ExtendedJumpPatch::SIZE, 0);
    let return_addr = jump_patch_start.as_usize() as u64
        + syscall_instruction_length(SupportedArch::X64) as u64
        + hook.next_instruction_length as u64;
    ExtendedJumpPatch::substitute_extended_jump(
        &mut stub_patch,
        extended_jump_start.as_usize() as u64,
        return_addr,
        hook.hook_address,
    );
    write_and_record_bytes(t, extended_jump_start, &stub_patch);

    patcher
        .syscallbuf_stubs
        .insert(extended_jump_start, ExtendedJumpPatch::SIZE);

    let jump_offset = extended_jump_start.as_isize() - jump_patch_end.as_isize();
    let jump_offset32 = jump_offset as i32 as isize;
    ed_assert_eq!(
        t,
        jump_offset32,
        jump_offset,
        "allocate_extended_jump didn't work"
    );

    JumpPatch::substitute_template(&mut jump_patch, jump_offset32 as u32);
    write_and_record_bytes(t, jump_patch_start, &jump_patch);

    // pad with NOPs to the next instruction
    const NOP: u8 = 0x90;
    debug_assert_eq!(
        syscall_instruction_length(SupportedArch::X64),
        syscall_instruction_length(SupportedArch::X86)
    );
    let nops_bufsize: usize = syscall_instruction_length(SupportedArch::X64)
        + hook.next_instruction_length as usize
        - jump_patch.len();
    let mut nops = Vec::<u8>::with_capacity(nops_bufsize);
    nops.resize(nops_bufsize, NOP);
    write_and_record_mem(t, jump_patch_start + jump_patch.len(), &nops);

    true
}

fn patch_syscall_with_hook(
    patcher: &mut MonkeyPatcher,
    t: &RecordTask,
    hook: &syscall_patch_hook,
) -> bool {
    let arch = t.arch();
    match arch {
        SupportedArch::X86 => {
            return patch_syscall_with_hook_x86ish::<
                X86SysenterVsyscallSyscallHook,
                X86SyscallStubExtendedJump,
            >(patcher, t, hook);
        }
        SupportedArch::X64 => {
            return patch_syscall_with_hook_x86ish::<X64JumpMonkeypatch, X64SyscallStubExtendedJump>(
                patcher, t, hook,
            );
        }
    }
}

fn task_safe_for_syscall_patching(
    t: &RecordTask,
    start: RemoteCodePtr,
    end: RemoteCodePtr,
) -> bool {
    if !t.is_running() {
        let ip = t.ip();
        if start <= ip && ip < end {
            return false;
        }
    }
    for e in t.pending_events.borrow().iter() {
        if e.is_syscall_event() {
            let ip = e.syscall_event().regs.ip();
            if start <= ip && ip < end {
                return false;
            }
        }
    }

    true
}

fn safe_for_syscall_patching(
    start: RemoteCodePtr,
    end: RemoteCodePtr,
    exclude: &RecordTask,
) -> bool {
    let exclude_rc = exclude.weak_self_ptr().upgrade().unwrap();
    for (_, rt) in exclude.session().tasks().iter() {
        if Rc::ptr_eq(rt, &exclude_rc) {
            continue;
        }
        if !task_safe_for_syscall_patching(rt.as_rec_unwrap(), start, end) {
            return false;
        }
    }

    true
}

/// Return true iff `addr` points to a known `__kernel_vsyscall()`
/// implementation.
fn is_kernel_vsyscall(t: &RecordTask, addr: RemotePtr<Void>) -> bool {
    let mut impl_buf = [0u8; X86SysenterVsyscallImplementationAMD::SIZE];
    t.read_bytes(addr, &mut impl_buf);
    X86SysenterVsyscallImplementation::matchp(&impl_buf[0..X86SysenterVsyscallImplementation::SIZE])
        || X86SysenterVsyscallImplementationAMD::matchp(&impl_buf)
}

fn find_section_file_offsets<'a>(elf_obj: &Elf<'a>, section_name: &str) -> Option<Range<usize>> {
    for section in &elf_obj.section_headers {
        let res = elf_obj.shdr_strtab.get(section.sh_name);
        match res {
            Some(name_res) => match name_res {
                Ok(name) if name == section_name => return Some(section.file_range()),
                _ => continue,
            },
            None => continue,
        }
    }

    None
}

fn erase_section<'a>(elf_obj: &Elf<'a>, t: &RecordTask, section_name: &str) {
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

fn obliterate_debug_info<'a>(elf_obj: &Elf<'a>, t: &RecordTask) {
    erase_section(elf_obj, t, ".eh_frame");
    erase_section(elf_obj, t, ".eh_frame_hdr");
    erase_section(elf_obj, t, ".note");
}

/// Patch _dl_runtime_resolve_(fxsave,xsave,xsavec) to clear "FDP Data Pointer"
/// register so that CPU-specific behaviors involving that register don't leak
/// into stack memory.
fn patch_dl_runtime_resolve(
    patcher: &mut MonkeyPatcher,
    t: &RecordTask,
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

    log!(
        LogDebug,
        "Found candidate _dl_runtime_resolve implementation for patching",
    );

    let mut jump_patch = [0u8; X64JumpMonkeypatch::SIZE];
    // We're patching in a relative jump, so we need to compute the offset from
    // the end of the jump to our actual destination.
    let jump_patch_start = RemotePtr::<u8>::cast(addr);
    let jump_patch_end = jump_patch_start + jump_patch.len();

    let extended_jump_start = allocate_extended_jump::<X64DLRuntimeResolvePrelude>(
        t,
        &mut patcher.extended_jump_pages,
        jump_patch_end,
    );
    if extended_jump_start.is_null() {
        return;
    }
    log!(LogDebug, "  call to allocated_extended_jump() succeeded");
    let mut stub_patch = [0u8; X64DLRuntimeResolvePrelude::SIZE];
    let return_offset: i64 = (jump_patch_start.as_isize() as i64
        + X64DLRuntimeResolve::SIZE as i64)
        - (extended_jump_start.as_isize() as i64 + X64DLRuntimeResolvePrelude::SIZE as i64);
    if return_offset != return_offset as i32 as i64 {
        log!(LogWarn, "  Return out of range. exiting");
        return;
    }
    X64DLRuntimeResolvePrelude::substitute(&mut stub_patch, return_offset as u32);
    write_and_record_bytes(t, extended_jump_start, &stub_patch);
    log!(
        LogDebug,
        "  patched in runtime resolve prelude successfully"
    );
    let jump_offset: isize = extended_jump_start.as_isize() - jump_patch_end.as_isize();
    let jump_offset32 = jump_offset as i32;
    ed_assert_eq!(
        t,
        jump_offset32 as isize,
        jump_offset,
        "jump offset not valid. allocate_extended_jump didn't work"
    );
    X64JumpMonkeypatch::substitute(&mut jump_patch, jump_offset32 as u32);
    write_and_record_bytes(t, jump_patch_start, &jump_patch);

    // pad with NOPs to the next instruction
    const NOP: u8 = 0x90;
    let nops = [NOP; X64DLRuntimeResolve::SIZE - X64JumpMonkeypatch::SIZE];
    write_and_record_bytes(t, jump_patch_start + jump_patch.len(), &nops);
    log!(LogDebug, "  patched in jump monkey patch successfully");
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
fn patch_after_exec_arch_x86arch(t: &RecordTask, patcher: &mut MonkeyPatcher) {
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
fn locate_and_verify_kernel_vsyscall(t: &RecordTask, elf_obj: &Elf) -> RemotePtr<Void> {
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
fn patch_after_exec_arch_x64arch(t: &RecordTask, patcher: &mut MonkeyPatcher) {
    setup_preload_library_path::<X64Arch>(t);

    let vdso_start = t.vm().vdso().start();
    let vdso_size = t.vm().vdso().size();

    let mut data = Vec::new();
    data.resize(vdso_size, 0u8);
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

    let mut after_mmap_vec = Vec::new();
    for (_, m) in &t.vm().maps() {
        let km = &m.map;
        let km_start = km.start();
        let km_size = km.size();
        let km_offset = km.file_offset_bytes();
        after_mmap_vec.push((km_start, km_size, km_offset));
    }

    for (km_start, km_size, km_offset) in after_mmap_vec {
        patcher.patch_after_mmap(
            t,
            km_start,
            km_size,
            (km_offset / page_size() as u64) as usize,
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

fn resolve_address(
    elf_obj: &Elf,
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
    t: &RecordTask,
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
