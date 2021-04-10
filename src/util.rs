use crate::{
    arch::Architecture,
    bindings::{
        kernel::{timeval, _LINUX_CAPABILITY_U32S_3, _LINUX_CAPABILITY_VERSION_3},
        signal::{SI_KERNEL, TRAP_BRKPT},
    },
    event::{Event, EventType, SignalDeterministic, SyscallState},
    flags::{Checksum, DumpOn, Flags},
    kernel_abi::{native_arch, CloneParameterOrdering, SupportedArch},
    kernel_supplement::sig_set_t,
    log::LogLevel::{LogDebug, LogError, LogWarn},
    preload_interface::{preload_globals, syscallbuf_hdr, syscallbuf_record},
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    scoped_fd::ScopedFd,
    session::{
        address_space::{
            address_space::{AddressSpace, Mapping},
            kernel_map_iterator::KernelMapIterator,
            kernel_mapping::KernelMapping,
            memory_range::MemoryRange,
            MappingFlags,
        },
        session_inner::SessionInner,
        task::{
            replay_task::ReplayTask,
            task_common::{read_mem, read_val_mem, write_val_mem},
            task_inner::CloneFlags,
            Task,
        },
    },
    sig::Sig,
    trace::trace_frame::FrameTime,
};
use libc::{
    pid_t,
    pwrite64,
    siginfo_t,
    ucontext_t,
    CLONE_CHILD_CLEARTID,
    CLONE_CHILD_SETTID,
    CLONE_FILES,
    CLONE_PARENT_SETTID,
    CLONE_SETTLS,
    CLONE_SIGHAND,
    CLONE_THREAD,
    CLONE_VM,
    EEXIST,
    EINVAL,
    EIO,
    ENOENT,
    PATH_MAX,
    SIGBUS,
    SIGFPE,
    SIGILL,
    SIGSEGV,
    SIGTRAP,
    STDERR_FILENO,
    _SC_NPROCESSORS_ONLN,
};
use nix::{
    errno::errno,
    sched::{sched_setaffinity, CpuSet},
    sys::{
        mman::{MapFlags, ProtFlags},
        signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
        stat::{stat, FileStat, Mode, SFlag},
        statfs::{statfs, TMPFS_MAGIC},
        uio::pread,
    },
    unistd::{
        access,
        ftruncate,
        getpid,
        isatty,
        mkdir,
        mkstemp,
        read,
        sysconf,
        write,
        AccessFlags,
        Pid,
        SysconfVar::PAGE_SIZE,
    },
    NixPath,
};
use rand::random;
use regex::bytes::Regex;
use std::{
    cmp::{max, min},
    convert::TryInto,
    env,
    env::var_os,
    error,
    ffi::{c_void, CStr, CString, OsStr, OsString},
    fs::File,
    io,
    io::{BufRead, BufReader, BufWriter, Error, ErrorKind, Read, Write},
    mem,
    mem::{size_of, size_of_val, zeroed},
    os::{
        raw::c_long,
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::Path,
    ptr::copy_nonoverlapping,
    rc::Rc,
    slice,
    sync::Mutex,
};

#[cfg(target_arch = "x86")]
use libc::{REG_EAX, REG_EIP};

#[cfg(target_arch = "x86_64")]
use crate::kernel_supplement::ARCH_SET_CPUID;

#[cfg(target_arch = "x86_64")]
use libc::{syscall, SYS_arch_prctl, REG_RAX, REG_RIP};

const RDTSC_INSN: [u8; 2] = [0x0f, 0x31];
const RDTSCP_INSN: [u8; 3] = [0x0f, 0x01, 0xf9];
const CPUID_INSN: [u8; 2] = [0x0f, 0xa2];
const INT3_INSN: [u8; 1] = [0xcc];
const PUSHF_INSN: [u8; 1] = [0x9c];
const PUSHF16_INSN: [u8; 2] = [0x66, 0x9c];

pub const CPUID_GETVENDORSTRING: u32 = 0x0;
pub const CPUID_GETFEATURES: u32 = 0x1;
pub const CPUID_GETTLB: u32 = 0x2;
pub const CPUID_GETSERIAL: u32 = 0x3;
pub const CPUID_GETCACHEPARAMS: u32 = 0x04;
pub const CPUID_GETEXTENDEDFEATURES: u32 = 0x07;
pub const CPUID_GETEXTENDEDTOPOLOGY: u32 = 0x0B;
pub const CPUID_GETXSAVE: u32 = 0x0D;
pub const CPUID_GETRDTMONITORING: u32 = 0x0F;
pub const CPUID_GETRDTALLOCATION: u32 = 0x10;
pub const CPUID_GETSGX: u32 = 0x12;
pub const CPUID_GETPT: u32 = 0x14;
pub const CPUID_GETSOC: u32 = 0x17;
pub const CPUID_HYPERVISOR: u32 = 0x40000000;
pub const CPUID_INTELEXTENDED: u32 = 0x80000000;
pub const CPUID_INTELFEATURES: u32 = 0x80000001;
pub const CPUID_INTELBRANDSTRING: u32 = 0x80000002;
pub const CPUID_INTELBRANDSTRINGMORE: u32 = 0x80000003;
pub const CPUID_INTELBRANDSTRINGEND: u32 = 0x80000004;

pub const OSXSAVE_FEATURE_FLAG: u32 = 1 << 27;
pub const AVX_FEATURE_FLAG: u32 = 1 << 28;
pub const HLE_FEATURE_FLAG: u32 = 1 << 4;
pub const XSAVEC_FEATURE_FLAG: u32 = 1 << 1;

lazy_static! {
    static ref CPUID_FAULTING_WORKS: bool = cpuid_faulting_works_init();
    static ref XSAVE_NATIVE_LAYOUT: XSaveLayout = xsave_native_layout_init();
    static ref SYSTEM_PAGE_SIZE: usize = page_size_init();
    static ref SAVED_FD_LIMIT: Mutex<Option<libc::rlimit>> = Mutex::new(None);
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SignalAction {
    DumpCore,
    Terminate,
    Continue,
    Stop,
    Ignore,
}

pub fn word_size_arch<Arch: Architecture>() -> usize {
    size_of::<Arch::signed_long>()
}

pub fn word_size(arch: SupportedArch) -> usize {
    rd_arch_function_selfless!(word_size_arch, arch)
}

pub fn word_at(buf: &[u8]) -> u64 {
    let mut temp_buf = [0u8; 8];
    let wsize = buf.len();

    temp_buf[0..wsize].copy_from_slice(&buf);
    u64::from_le_bytes(temp_buf)
}

pub fn default_action(sig: Sig) -> SignalAction {
    if 32 <= sig.as_raw() && sig.as_raw() <= 64 {
        return SignalAction::Terminate;
    }

    match sig.as_raw() {
        // TODO: SSoT for signal defs/semantics.
        libc::SIGHUP => SignalAction::Terminate,
        libc::SIGINT => SignalAction::Terminate,
        libc::SIGQUIT => SignalAction::DumpCore,
        libc::SIGILL => SignalAction::DumpCore,
        libc::SIGABRT => SignalAction::DumpCore,
        libc::SIGFPE => SignalAction::DumpCore,
        libc::SIGKILL => SignalAction::Terminate,
        libc::SIGSEGV => SignalAction::DumpCore,
        libc::SIGPIPE => SignalAction::Terminate,
        libc::SIGALRM => SignalAction::Terminate,
        libc::SIGTERM => SignalAction::Terminate,
        libc::SIGUSR1 => SignalAction::Terminate,
        libc::SIGUSR2 => SignalAction::Terminate,
        libc::SIGCHLD => SignalAction::Ignore,
        libc::SIGCONT => SignalAction::Continue,
        libc::SIGSTOP => SignalAction::Stop,
        libc::SIGTSTP => SignalAction::Stop,
        libc::SIGTTIN => SignalAction::Stop,
        libc::SIGTTOU => SignalAction::Stop,
        libc::SIGBUS => SignalAction::DumpCore,
        // SIGPOLL => SignalAction::Terminate,
        libc::SIGPROF => SignalAction::Terminate,
        libc::SIGSYS => SignalAction::DumpCore,
        libc::SIGTRAP => SignalAction::DumpCore,
        libc::SIGURG => SignalAction::Ignore,
        libc::SIGVTALRM => SignalAction::Terminate,
        libc::SIGXCPU => SignalAction::DumpCore,
        libc::SIGXFSZ => SignalAction::DumpCore,
        // SIGIOT=>SignalAction::DumpCore,
        // SIGEMT=>SignalAction::Terminate,
        libc::SIGSTKFLT => SignalAction::Terminate,
        libc::SIGIO => SignalAction::Terminate,
        libc::SIGPWR => SignalAction::Terminate,
        // SIGLOST=>SignalAction::Terminate,
        libc::SIGWINCH => SignalAction::Ignore,
        _ => {
            fatal!("Unknown signal {}", sig);
        }
    }
}

/// 0 means XSAVE not detected
pub fn xsave_area_size() -> usize {
    xsave_native_layout().full_size
}

pub fn running_under_rd() -> bool {
    let result = var_os("RUNNING_UNDER_RD");
    match result {
        Some(var_val) if !var_val.is_empty() => true,
        _ => false,
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Completion {
    Complete,
    Incomplete,
}

#[derive(Copy, Clone, Default)]
pub struct XSaveFeatureLayout {
    pub offset: u32,
    pub size: u32,
}

#[derive(Default, Clone)]
pub struct XSaveLayout {
    pub full_size: usize,
    pub supported_feature_bits: u64,
    pub feature_layouts: Vec<XSaveFeatureLayout>,
}

pub fn xsave_native_layout() -> &'static XSaveLayout {
    &*XSAVE_NATIVE_LAYOUT
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CPUIDRecord {
    pub eax_in: u32,
    pub ecx_in: u32,
    pub out: CPUIDData,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CPUIDData {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn cpuid(code: u32, subrequest: u32) -> CPUIDData {
    let temp: raw_cpuid::CpuIdResult = cpuid!(code, subrequest);
    // We could have just used the raw_cpuid::CpuIdResult struct but
    // we avoid that just to be in full control of our data structures.
    CPUIDData {
        eax: temp.eax,
        ebx: temp.ebx,
        ecx: temp.ecx,
        edx: temp.edx,
    }
}

fn cpuid_record(eax: u32, ecx: u32) -> CPUIDRecord {
    CPUIDRecord {
        eax_in: eax,
        ecx_in: ecx,
        out: cpuid(eax, ecx),
    }
}

pub fn xsave_layout_from_trace(records: &[CPUIDRecord]) -> XSaveLayout {
    let mut layout: XSaveLayout = Default::default();

    let mut record_index: usize = 0;
    while record_index < records.len() {
        if records[record_index].eax_in == CPUID_GETXSAVE {
            break;
        }
        record_index += 1;
    }

    if record_index == records.len() {
        // XSAVE not present
        layout.full_size = 512;
        // x87/XMM always supported
        layout.supported_feature_bits = 0x3;
        return layout;
    }

    let mut cpuid_data = records[record_index];
    debug_assert_eq!(cpuid_data.ecx_in, 0);
    layout.full_size = cpuid_data.out.ebx as usize;
    layout.supported_feature_bits = cpuid_data.out.eax as u64 | ((cpuid_data.out.edx as u64) << 32);

    for i in 2usize..64usize {
        if layout.supported_feature_bits & (1u64 << i as u64) != 0 {
            loop {
                record_index += 1;
                if record_index >= records.len() || records[record_index].eax_in != CPUID_GETXSAVE {
                    fatal!("Missing CPUID record for feature {}", i);
                }

                if records[record_index].ecx_in == i as u32 {
                    break;
                }
            }
            cpuid_data = records[record_index];
            while layout.feature_layouts.len() < i {
                layout
                    .feature_layouts
                    .push(XSaveFeatureLayout { offset: 0, size: 0 });
            }
            layout.feature_layouts.push(XSaveFeatureLayout {
                offset: cpuid_data.out.ebx,
                size: cpuid_data.out.eax,
            });
        }
    }

    layout
}

fn xsave_native_layout_init() -> XSaveLayout {
    xsave_layout_from_trace(&gather_cpuid_records(CPUID_GETXSAVE))
}

fn gather_cpuid_records(up_to: u32) -> Vec<CPUIDRecord> {
    let mut results: Vec<CPUIDRecord> = Vec::new();
    let vendor_string: CPUIDRecord = cpuid_record(CPUID_GETVENDORSTRING, std::u32::MAX);
    results.push(vendor_string);
    let basic_info_max: u32 = std::cmp::min(up_to, vendor_string.out.eax);
    let mut has_sgx = false;
    let mut has_hypervisor = false;

    for base in 1..=basic_info_max {
        match base {
            CPUID_GETCACHEPARAMS => {
                for level in 0..=std::u32::MAX {
                    let rec = cpuid_record(base, level);
                    results.push(rec);
                    if rec.out.eax & 0x1f == 0 {
                        // Cache Type Field == no more caches
                        break;
                    }
                }
            }
            CPUID_GETEXTENDEDFEATURES => {
                let rec = cpuid_record(base, 0);
                results.push(rec);
                if rec.out.ebx & 0x4 != 0 {
                    has_sgx = true;
                }
                for level in 1..=rec.out.eax {
                    results.push(cpuid_record(base, level));
                }
            }
            CPUID_GETEXTENDEDTOPOLOGY => {
                for level in 0..=std::u32::MAX {
                    let rec = cpuid_record(base, level);
                    results.push(rec);
                    if rec.out.ecx & 0xff00 == 0 {
                        // Level Type == 0
                        break;
                    }
                }
            }
            CPUID_GETXSAVE => {
                for level in 0..64 {
                    results.push(cpuid_record(base, level));
                }
            }
            CPUID_GETRDTMONITORING => {
                let rec = cpuid_record(base, 0);
                results.push(rec);
                // @TODO check this.
                for level in 1..64 {
                    if rec.out.edx as u64 & (1u64 << level) != 0 {
                        results.push(cpuid_record(base, level));
                    }
                }
            }
            CPUID_GETRDTALLOCATION => {
                let rec = cpuid_record(base, 0);
                results.push(rec);
                // @TODO check this.
                for level in 1..64 {
                    if rec.out.ebx as u64 & (1u64 << level) != 0 {
                        results.push(cpuid_record(base, level));
                    }
                }
            }
            CPUID_GETSGX => {
                results.push(cpuid_record(base, 0));
                if has_sgx {
                    results.push(cpuid_record(base, 1));
                    for level in 2..=std::u32::MAX {
                        let rec = cpuid_record(base, level);
                        results.push(rec);
                        if rec.out.eax & 0x0f == 0 {
                            // Sub-leaf Type == 0
                            break;
                        }
                    }
                }
            }
            CPUID_GETPT | CPUID_GETSOC => {
                let rec = cpuid_record(base, 0);
                results.push(rec);
                for level in 1..=rec.out.eax {
                    results.push(cpuid_record(base, level));
                }
            }
            CPUID_GETFEATURES => {
                let rec = cpuid_record(base, std::u32::MAX);
                results.push(rec);
                if rec.out.ecx & (1 << 31) != 0 {
                    has_hypervisor = true;
                }
            }
            _ => {
                results.push(cpuid_record(base, std::u32::MAX));
            }
        }
    }

    if up_to < CPUID_HYPERVISOR {
        return results;
    }

    if has_hypervisor {
        let hv_info = cpuid_record(CPUID_HYPERVISOR, std::u32::MAX);
        results.push(hv_info);
        let hv_info_max = std::cmp::min(up_to, hv_info.out.eax);
        for extended in CPUID_HYPERVISOR + 1..=hv_info_max {
            results.push(cpuid_record(extended, std::u32::MAX));
        }
    }

    if up_to < CPUID_INTELEXTENDED {
        return results;
    }

    let extended_info = cpuid_record(CPUID_INTELEXTENDED, std::u32::MAX);
    results.push(extended_info);
    let extended_info_max = std::cmp::min(up_to, extended_info.out.eax);
    for extended in CPUID_INTELEXTENDED + 1..=extended_info_max {
        results.push(cpuid_record(extended, std::u32::MAX));
    }

    results
}

fn page_size_init() -> usize {
    sysconf(PAGE_SIZE).unwrap().unwrap().try_into().unwrap()
}

pub fn page_size() -> usize {
    *SYSTEM_PAGE_SIZE
}

pub fn ceil_page_size<T: Into<usize> + From<usize>>(size: T) -> T {
    ((size.into() + page_size() - 1) & !(page_size() - 1)).into()
}

pub fn ceil_page_u64(size: u64) -> u64 {
    (size + page_size() as u64 - 1) & !(page_size() as u64 - 1)
}

pub fn floor_page_size<T: Into<usize> + From<usize>>(sz: T) -> T {
    let page_mask: usize = !(page_size() - 1);
    (sz.into() & page_mask).into()
}

pub fn resize_shmem_segment(fd: &ScopedFd, num_bytes: usize) {
    match ftruncate(fd.as_raw(), num_bytes as libc::off_t) {
        // errno will be reported as part of fatal
        Err(e) => fatal!("Failed to resize shmem to {}: {:?}", num_bytes, e),
        Ok(_) => (),
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum TrappedInstruction {
    None = 0,
    Rdtsc = 1,
    Rdtscp = 2,
    CpuId = 3,
    Int3 = 4,
    Pushf = 5,
    Pushf16 = 6,
}

impl Default for TrappedInstruction {
    fn default() -> Self {
        Self::None
    }
}

pub fn is_kernel_trap(si_code: i32) -> bool {
    // XXX unable to find docs on which of these "should" be
    // right.  The SI_KERNEL code is seen in the int3 test, so we
    // at least need to handle that.
    si_code == TRAP_BRKPT as i32 || si_code == SI_KERNEL
}

/// Returns $TMPDIR or "/tmp". We call ensure_dir to make sure the directory
/// exists and is writeable.
pub fn tmp_dir() -> OsString {
    let mut maybe_dir = var_os("RD_TMPDIR");
    match maybe_dir {
        Some(dir) => {
            ensure_dir(&dir, "temporary file directory (RD_TMPDIR)", Mode::S_IRWXU);
            return dir;
        }
        None => (),
    }

    maybe_dir = var_os("TMPDIR");
    match maybe_dir {
        Some(dir) => {
            ensure_dir(&dir, "temporary file directory (TMPDIR)", Mode::S_IRWXU);
            return dir;
        }
        None => (),
    }

    // Don't try to create "/tmp", that probably won't work well.
    match access("/tmp", AccessFlags::W_OK) {
        Err(e) => fatal!("Can't write to temporary file directory /tmp: {:?}", e),
        Ok(_) => (),
    }

    OsString::from("/tmp")
}

/// Create directory `dir`, creating parent directories as needed.
/// `dir_type` is printed in error messages. Fails if the resulting directory
/// is not writeable.
pub fn ensure_dir(dir: &OsStr, dir_type: &str, mode: Mode) {
    let mut d = dir.as_bytes();
    // @TODO Better than doing this manually is there a method that will clean the dir up?
    // There might be other things that need to be done like removing repeated slashes (`/`) etc.
    //
    // Remove any trailing slashes
    while d.len() > 0 && d[d.len() - 1] == b'/' {
        d = &d[0..d.len() - 1];
    }

    let st: FileStat = match stat(d) {
        Err(e) => {
            if errno() != ENOENT {
                fatal!("Error accessing {} {:?}: {:?}", dir_type, dir, e);
            }

            let last_slash = d.iter().enumerate().rfind(|c| *c.1 == b'/');
            match last_slash {
                Some(pos) if pos.0 > 0 => {
                    ensure_dir(OsStr::from_bytes(&d[0..pos.0]), dir_type, mode);
                }
                _ => {
                    fatal!("Can't find directory {:?}", dir);
                }
            }

            // Allow for a race condition where someone else creates the directory
            match mkdir(d, mode) {
                Err(e) if errno() != EEXIST => {
                    fatal!("Can't create {} {:?}: {:?}", dir_type, dir, e)
                }
                _ => (),
            }

            match stat(d) {
                Err(e) => {
                    fatal!("Can't stat {} {:?}: {:?}", dir_type, dir, e);
                }
                Ok(st) => st,
            }
        }
        Ok(st) => st,
    };

    if !SFlag::from_bits_truncate(st.st_mode).contains(SFlag::S_IFDIR) {
        fatal!("{:?} exists but isn't a directory.", dir);
    }

    match access(d, AccessFlags::W_OK) {
        Err(e) => fatal!("Can't write to {} {:?}: {:?}", dir_type, dir, e),
        Ok(_) => (),
    }
}

/// Like pwrite64(2) but we try to write all bytes by looping on short writes.
///
/// Slightly different from rr. Employs Result.
pub fn pwrite_all_fallible(fd: i32, buf_initial: &[u8], mut offset: isize) -> Result<usize, ()> {
    let mut written: usize = 0;
    let mut cur_size = buf_initial.len();

    let mut buf = buf_initial;
    while cur_size > 0 {
        let ret: isize =
            unsafe { pwrite64(fd, buf.as_ptr().cast::<c_void>(), cur_size, offset as i64) };

        if written > 0 && ret <= 0 {
            return Ok(written);
        } else if written == 0 && ret == 0 {
            return Ok(written);
        } else if ret < 0 {
            return Err(());
        } else {
            // We know that ret > 0 by now so its safe to cast ret as usize in this block.
            buf = &buf[ret as usize..];
            written += ret as usize;
            offset += ret;
            cur_size -= ret as usize;
        }
    }

    Ok(written)
}

pub fn check_for_pax_kernel() -> bool {
    let results = read_proc_status_fields(getpid().as_raw(), &[b"PaX"]);
    match results {
        Ok(vec) => !vec.is_empty(),
        Err(e) => fatal!("Error while checking if kernel is a pax kernel: {:?}", e),
    }
}

lazy_static! {
    static ref IS_PAX_KERNEL: bool = check_for_pax_kernel();
}

pub fn uses_invisible_guard_page() -> bool {
    !*IS_PAX_KERNEL
}

#[allow(unreachable_code)]
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let haystack_len = haystack.len();
    let mut it = haystack.iter();
    let mut i = 0;
    loop {
        if i + needle.len() > haystack_len {
            return None;
        }

        let rest = it.as_slice();
        if rest.starts_with(needle) {
            return Some(i);
        }
        if let None = it.next() {
            return None;
        }
        i += 1;
    }
    unreachable!()
}

/// Get the current time from the preferred monotonic clock in units of
/// seconds, relative to an unspecific point in the past.
pub fn monotonic_now_sec() -> f64 {
    let mut tp: libc::timespec = unsafe { zeroed() };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut tp) };
    assert_eq!(ret, 0);
    tp.tv_sec as f64 + (tp.tv_nsec as f64 / 1e9)
}

pub fn should_copy_mmap_region(mapping: &KernelMapping, stat: &libc::stat) -> bool {
    let v = env::var_os("RD_COPY_ALL_FILES");
    if v.is_some() {
        return true;
    }

    let flags = mapping.flags();
    let prot = mapping.prot();
    let file_name = mapping.fsname();
    let private_mapping = flags.contains(MapFlags::MAP_PRIVATE);

    // TODO: handle mmap'd files that are unlinked during
    // recording or otherwise not available.
    if !has_fs_name(file_name) {
        // This includes files inaccessible because the tracee is using a different
        // mount namespace with its own mounts
        log!(LogDebug, "  copying unlinked/inaccessible file");
        return true;
    }
    if !SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFREG) {
        log!(LogDebug, "  copying non-regular-file");
        return true;
    }
    if is_tmp_file(file_name) {
        log!(LogDebug, "  copying file on tmpfs");
        return true;
    }
    if file_name == "/etc/ld.so.cache" {
        // This file changes on almost every system update so we should copy it.
        log!(LogDebug, "  copying {:?}", file_name);
        return true;
    }
    if private_mapping && prot.contains(ProtFlags::PROT_EXEC) {
        // Be optimistic about private executable mappings
        log!(
            LogDebug,
            "  (no copy for +x private mapping {:?})",
            file_name
        );
        return false;
    }
    if private_mapping && (0o111 & stat.st_mode != 0) {
        // A private mapping of an executable file usually
        // indicates mapping data sections of object files.
        // Since we're already assuming those change very
        // infrequently, we can avoid copying the data
        // sections too.
        log!(
            LogDebug,
            "  (no copy for private mapping of +x {:?})",
            file_name
        );
        return false;
    }
    let can_read_file = access(file_name, AccessFlags::R_OK).is_ok();
    if !can_read_file {
        // It's possible for a tracee to mmap a file it doesn't have permission
        // to read, e.g. if a daemon opened the file and passed the fd over a
        // socket. We should copy the data now because we won't be able to read
        // it later. nscd does this.
        return true;
    }

    // XXX: using "can the euid of the rd process write this
    // file" as an approximation of whether the tracee can write
    // the file.  If the tracee is messing around with
    // set*[gu]id(), the real answer may be different.
    let can_write_file = access(file_name, AccessFlags::W_OK).is_ok();

    // Inside a user namespace, the real root user may be mapped to UID 65534.
    if !can_write_file && (0 == stat.st_uid || 65534 == stat.st_uid) {
        // We would like to DEBUG_ASSERT this, but on Ubuntu 13.10,
        // the file /lib/i386-linux-gnu/libdl-2.17.so is
        // writeable by root for unknown reasons.
        // DEBUG_ASSERT(!(prot & PROT_WRITE));
        //
        // Mapping a file owned by root: we don't care if this
        // was a PRIVATE or SHARED mapping, because unless the
        // program is disastrously buggy or unlucky, the
        // mapping is effectively PRIVATE.  Bad luck can come
        // from this program running during a system update,
        // or a user being added, which is probably less
        // frequent than even system updates.
        //
        // XXX what about the fontconfig cache files? */
        log!(LogDebug, "  (no copy for root-owned {:?})", file_name);
        return false;
    }
    if private_mapping {
        // Some programs (at least Firefox) have been observed
        // to use cache files that are expected to be
        // consistent and unchanged during the bulk of
        // execution, but may be destroyed or mutated at
        // shutdown in preparation for the next session.  We
        // don't otherwise know what to do with private
        // mappings, so err on the safe side.
        //
        // XXX: could get into dirty heuristics here like
        // trying to match "cache" in the filename ...
        log!(
            LogDebug,
            "  copying private mapping of non-system -x {:?}",
            file_name
        );
        return true;
    }
    if !(0o222 & stat.st_mode != 0) {
        // We couldn't write the file because it's read only.
        // But it's not a root-owned file (therefore not a
        // system file), so it's likely that it could be
        // temporary.  Copy it.
        log!(LogDebug, "  copying read-only, non-system file");
        return true;
    }
    if !can_write_file {
        // mmap'ing another user's (non-system) files?  Highly
        // irregular ...
        let shared = if flags.contains(MapFlags::MAP_SHARED) {
            ";SHARED"
        } else {
            ""
        };

        log!(
            LogWarn,
            "Scary mmap {:?} (prot: {:#x} {}); uid:{}  mode:{}",
            file_name,
            prot,
            shared,
            stat.st_uid,
            stat.st_mode
        );
    }

    return true;
}

pub fn has_fs_name(path: &OsStr) -> bool {
    stat(path).is_ok()
}

pub fn is_tmp_file(path: &OsStr) -> bool {
    let v = env::var_os("RD_TRUST_TEMP_FILES");
    if v.is_some() {
        return false;
    }

    match statfs(path) {
        Ok(sfs) => {
            // In observed configurations of Ubuntu 13.10, /tmp is
            // a folder in the / fs, not a separate tmpfs.
            TMPFS_MAGIC == sfs.filesystem_type() || path.as_bytes().starts_with(b"/tmp/")
        }
        Err(_) => false,
    }
}

pub fn copy_file(dest_fd: i32, src_fd: i32) -> bool {
    let mut buf = [0u8; 32 * 1024];
    loop {
        let bytes_result = read(src_fd, &mut buf);
        match bytes_result {
            Err(_) => return false,
            Ok(0) => break,
            Ok(nread) => {
                write_all(dest_fd, &buf[0..nread]);
            }
        }
    }
    true
}

/// Fatally aborts if function cannot write everything in `buf` to the `fd`
pub fn write_all(fd: i32, mut buf: &[u8]) {
    let mut size = buf.len();
    while size > 0 {
        let ret = write(fd, buf);
        match ret {
            Err(e) => fatal!("Can't write {} bytes to fd {}: {:?}", size, fd, e),
            Ok(0) => fatal!("Can't write {} bytes to fd {}", size, fd),
            Ok(nwritten) => {
                buf = &buf[nwritten..];
                size -= nwritten;
            }
        }
    }
}

pub fn all_cpuid_records() -> Vec<CPUIDRecord> {
    gather_cpuid_records(std::u32::MAX)
}

pub fn probably_not_interactive(maybe_fd: Option<i32>) -> bool {
    let fd = maybe_fd.unwrap_or(STDERR_FILENO);
    // Eminently tunable heuristic, but this is guaranteed to be
    // true during unit tests, where we care most about this
    // check (to a first degree).  A failing test shouldn't
    // hang.
    match isatty(fd) {
        Ok(res) => !res,
        Err(e) => {
            fatal!("Failure in calling isatty() on fd {}: {:?}", fd, e);
        }
    }
}

pub fn xsave_enabled() -> bool {
    let features = cpuid(CPUID_GETFEATURES, 0);
    (features.ecx & OSXSAVE_FEATURE_FLAG) != 0
}

pub fn xcr0() -> u64 {
    if !xsave_enabled() {
        // Assume x87/SSE enabled.
        return 3;
    }
    let eax: u32;
    let edx: u32;
    unsafe {
        llvm_asm!("xgetbv"
            : "={eax}"(eax), "={edx}"(edx)
            : "{ecx}"(0)
            :: "volatile"
        );
    }

    ((edx as u64) << 32) | (eax as u64)
}

pub fn good_random(out: &mut [u8]) {
    for i in 0..out.len() {
        out[i] = random::<u8>();
    }
}

pub fn find_cpuid_record(records: &[CPUIDRecord], eax: u32, ecx: u32) -> Option<&CPUIDRecord> {
    for rec in records {
        if rec.eax_in == eax && (rec.ecx_in == ecx || rec.ecx_in == std::u32::MAX) {
            return Some(rec);
        }
    }

    None
}

pub fn dir_exists<P: ?Sized + NixPath>(dir: &P) -> bool {
    if dir.is_empty() {
        return false;
    }

    stat(dir).is_ok()
}

pub fn real_path(path: &OsStr) -> OsString {
    match Path::new(&path).canonicalize() {
        Ok(p) => p.as_os_str().to_os_string(),
        Err(e) => fatal!("Could not retreive path {:?}: {:?}", path, e),
    }
}

pub fn resource_path() -> &'static OsStr {
    let resource_path = Flags::get().resource_path.as_ref();
    if resource_path.is_none() {
        return RD_EXE_PATH.as_os_str();
    }

    resource_path.unwrap().as_os_str()
}

lazy_static! {
    static ref RD_EXE_PATH: OsString = rd_exe_path_init();
}

fn rd_exe_path_init() -> OsString {
    let mut exe_path = Vec::from(read_exe_dir().as_bytes());
    exe_path.extend_from_slice(b"../");
    OsString::from_vec(exe_path)
}

pub fn read_exe_dir() -> OsString {
    // Get the mapping corresponding to the `read_exe_dir` method i.e. the method we're in!
    let km: KernelMapping = AddressSpace::read_local_kernel_mapping(
        read_exe_dir as *const fn() -> OsString as *const u8,
    );
    let exe_path = Path::new(km.fsname());
    let mut final_exe_path = Vec::<u8>::new();
    final_exe_path.extend_from_slice(exe_path.parent().unwrap().as_os_str().as_bytes());
    final_exe_path.extend_from_slice(b"/");
    OsString::from_vec(final_exe_path)
}

fn env_ptr<Arch: Architecture>(t: &dyn Task) -> RemotePtr<Arch::unsigned_word> {
    let mut stack_ptr: RemotePtr<Arch::unsigned_word> = RemotePtr::cast(t.regs_ref().sp());

    let argc = read_val_mem::<Arch::unsigned_word>(t, stack_ptr, None);
    let delta: usize = (argc + 1u8.into()).try_into().unwrap();
    stack_ptr += delta;

    // Check final NULL in argv
    let null_ptr = read_val_mem::<Arch::unsigned_word>(t, stack_ptr, None);
    ed_assert_eq!(t, null_ptr, 0u8.into());
    stack_ptr += 1;
    stack_ptr
}

fn read_env_arch<Arch: Architecture>(t: &dyn Task) -> Vec<CString> {
    let mut stack_ptr = env_ptr::<Arch>(t);
    // Should now point to envp
    let mut result: Vec<CString> = Vec::new();
    loop {
        let p = read_val_mem::<Arch::unsigned_word>(t, stack_ptr, None);
        stack_ptr += 1;
        if p == 0.into() {
            break;
        }
        result.push(t.read_c_str(RemotePtr::new(p.try_into().unwrap())));
    }
    result
}

pub fn read_env(t: &dyn Task) -> Vec<CString> {
    rd_arch_function_selfless!(read_env_arch, t.arch(), t)
}

pub fn read_auxv(t: &dyn Task) -> Vec<u8> {
    rd_arch_function_selfless!(read_auxv_arch, t.arch(), t)
}

fn read_auxv_arch<Arch: Architecture>(t: &dyn Task) -> Vec<u8> {
    let mut stack_ptr = env_ptr::<Arch>(t);

    // Should now point to envp
    let zero: Arch::unsigned_word = 0u8.into();
    while zero != read_val_mem::<Arch::unsigned_word>(t, stack_ptr, None) {
        stack_ptr += 1;
    }
    stack_ptr += 1;
    // should now point to ELF Auxiliary Table

    let mut result = Vec::<u8>::new();
    loop {
        let pair_vec = read_mem::<Arch::unsigned_word>(t, stack_ptr, 2, None);
        stack_ptr += 2;
        let pair = [pair_vec[0], pair_vec[1]];
        let pair_size = size_of_val(&pair);
        result.resize(result.len() + pair_size, 0u8.into());
        unsafe {
            copy_nonoverlapping(
                pair.as_ptr() as *const u8,
                result.as_mut_ptr().add(result.len() - pair_size),
                pair_size,
            );
        }
        if pair[0] == 0u8.into() {
            break;
        }
    }
    result
}

pub fn read_to_end(fd: &ScopedFd, mut offset: u64, mut buf: &mut [u8]) -> io::Result<usize> {
    let mut size = buf.len();
    let mut ret = 0;
    while size > 0 {
        // off_t is a i32 on x86 and i64 on x86_64
        match pread(fd.as_raw(), buf, offset.try_into().unwrap()) {
            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
            // EOF
            Ok(0) => return Ok(ret),
            Ok(nread) => {
                offset += nread as u64;
                ret += nread;
                size -= nread;
                buf = &mut buf[nread..];
            }
        }
    }
    Ok(ret)
}

pub fn raise_resource_limits() {
    let mut initial_fd_limit: libc::rlimit = unsafe { mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut initial_fd_limit) } < 0 {
        fatal!("Can't get RLIMIT_NOFILE");
    }

    // Save the fd limit just obtained
    {
        let mut data = SAVED_FD_LIMIT.lock().unwrap();
        *data = Some(initial_fd_limit);
    }

    let mut new_limit = initial_fd_limit;

    // Try raising fd limit to 65536
    new_limit.rlim_cur = max(new_limit.rlim_cur, 65536);
    if new_limit.rlim_max != libc::RLIM_INFINITY {
        new_limit.rlim_cur = min(new_limit.rlim_cur, new_limit.rlim_max);
    }
    if new_limit.rlim_cur != initial_fd_limit.rlim_cur {
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const new_limit) } < 0 {
            log!(LogWarn, "Failed to raise file descriptor limit");
        }
    }
}

pub fn restore_initial_resource_limits() {
    let initial_fd_limit: libc::rlimit;
    // Obtain the fd limit saved earlier
    {
        let data = SAVED_FD_LIMIT.lock().unwrap();
        initial_fd_limit = data.unwrap();
    }

    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const initial_fd_limit) } < 0 {
        log!(LogWarn, "Failed to reset file descriptor limit");
    }
}

#[derive(Default)]
pub struct CloneParameters {
    pub stack: RemotePtr<Void>,
    pub ptid: RemotePtr<i32>,
    pub tls: RemotePtr<Void>,
    pub ctid: RemotePtr<i32>,
}

/// Extract various clone(2) parameters out of the given Task's registers.
fn extract_clone_parameters_arch<Arch: Architecture>(regs: &Registers) -> CloneParameters {
    let mut result = CloneParameters::default();
    result.stack = RemotePtr::from(regs.arg2());
    result.ptid = RemotePtr::from(regs.arg3());
    if Arch::CLONE_PARAMETER_ORDERING == CloneParameterOrdering::FlagsStackParentTLSChild {
        result.tls = RemotePtr::from(regs.arg4());
        result.ctid = RemotePtr::from(regs.arg5());
    } else if Arch::CLONE_PARAMETER_ORDERING == CloneParameterOrdering::FlagsStackParentChildTLS {
        result.tls = RemotePtr::from(regs.arg5());
        result.ctid = RemotePtr::from(regs.arg4());
    }
    let flags: i32 = regs.arg1() as i32;
    // If these flags aren't set, the corresponding clone parameters may be
    // invalid pointers, so make sure they're ignored.
    if flags & CLONE_PARENT_SETTID == 0 {
        result.ptid = RemotePtr::null();
    }
    if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) == 0 {
        result.ctid = RemotePtr::null();
    }
    if flags & CLONE_SETTLS == 0 {
        result.tls = RemotePtr::null();
    }
    result
}

pub fn extract_clone_parameters(t: &dyn Task) -> CloneParameters {
    rd_arch_function_selfless!(extract_clone_parameters_arch, t.arch(), &t.regs_ref())
}

/// Convert the flags passed to the clone() syscall, `flags_arg`, into
/// the format understood by `clone_task_common()`.
pub fn clone_flags_to_task_flags(flags_arg: i32) -> CloneFlags {
    let mut flags = CloneFlags::empty();
    // See struct CloneFlags for description of the flags.
    if CLONE_CHILD_CLEARTID & flags_arg == CLONE_CHILD_CLEARTID {
        flags |= CloneFlags::CLONE_CLEARTID
    }
    if CLONE_SETTLS & flags_arg == CLONE_SETTLS {
        flags |= CloneFlags::CLONE_SET_TLS
    }
    if CLONE_SIGHAND & flags_arg == CLONE_SIGHAND {
        flags |= CloneFlags::CLONE_SHARE_SIGHANDLERS
    }
    if CLONE_THREAD & flags_arg == CLONE_THREAD {
        flags |= CloneFlags::CLONE_SHARE_THREAD_GROUP
    }
    if CLONE_VM & flags_arg == CLONE_VM {
        flags |= CloneFlags::CLONE_SHARE_VM
    }
    if CLONE_FILES & flags_arg == CLONE_FILES {
        flags |= CloneFlags::CLONE_SHARE_FILES
    }
    flags
}

pub fn to_timeval(t: f64) -> timeval {
    let tv_sec: c_long = t.floor() as c_long;
    let tv_usec: c_long = ((t - tv_sec as f64) * 1000_000.0).floor() as c_long;
    timeval { tv_sec, tv_usec }
}

pub fn is_zombie_process(pid: pid_t) -> bool {
    // If there was an error in reading /proc/{}/status then we assume that `pid` is a Zombie
    let state = read_proc_status_fields(pid, &[b"State"]).unwrap_or(Vec::new());
    return state.is_empty() || state[0].is_empty() || state[0].as_bytes()[0] == b'Z';
}

pub fn u8_slice<D: Sized>(data: &D) -> &[u8] {
    unsafe { slice::from_raw_parts(data as *const D as *const u8, size_of::<D>()) }
}

pub fn u8_slice_mut<D: Sized>(data: &mut D) -> &mut [u8] {
    unsafe { slice::from_raw_parts_mut(data as *mut D as *mut u8, size_of::<D>()) }
}

pub fn u8_raw_slice<D: Sized>(data: &D) -> *const [u8] {
    unsafe { slice::from_raw_parts(data as *const D as *const u8, size_of::<D>()) }
}

pub fn u8_raw_slice_mut<D: Sized>(data: &mut D) -> *mut [u8] {
    unsafe { slice::from_raw_parts_mut(data as *mut D as *mut u8, size_of::<D>()) }
}

pub fn trapped_instruction_len(insn: TrappedInstruction) -> usize {
    match insn {
        TrappedInstruction::Rdtsc => RDTSC_INSN.len(),
        TrappedInstruction::Rdtscp => RDTSCP_INSN.len(),
        TrappedInstruction::CpuId => CPUID_INSN.len(),
        TrappedInstruction::Int3 => INT3_INSN.len(),
        TrappedInstruction::Pushf => PUSHF_INSN.len(),
        TrappedInstruction::Pushf16 => PUSHF16_INSN.len(),
        TrappedInstruction::None => 0,
    }
}

/// XXX this probably needs to be extended to decode ignored prefixes
pub fn trapped_instruction_at<T: Task>(t: &T, ip: RemoteCodePtr) -> TrappedInstruction {
    let mut insn: [u8; RDTSCP_INSN.len()] = Default::default();
    let ret = t.read_bytes_fallible(ip.to_data_ptr::<u8>(), &mut insn);
    if ret.is_err() {
        return TrappedInstruction::None;
    }

    let len = ret.unwrap();
    if len >= RDTSC_INSN.len() && insn[0..RDTSC_INSN.len()] == RDTSC_INSN {
        return TrappedInstruction::Rdtsc;
    }
    if len >= RDTSCP_INSN.len() && insn[0..RDTSCP_INSN.len()] == RDTSCP_INSN {
        return TrappedInstruction::Rdtscp;
    }
    if len >= CPUID_INSN.len() && insn[0..CPUID_INSN.len()] == CPUID_INSN {
        return TrappedInstruction::CpuId;
    }
    if len >= INT3_INSN.len() && insn[0..INT3_INSN.len()] == INT3_INSN {
        return TrappedInstruction::Int3;
    }
    if len >= PUSHF_INSN.len() && insn[0..PUSHF_INSN.len()] == PUSHF_INSN {
        return TrappedInstruction::Pushf;
    }
    if len >= PUSHF16_INSN.len() && insn[0..PUSHF16_INSN.len()] == PUSHF16_INSN {
        return TrappedInstruction::Pushf16;
    }

    TrappedInstruction::None
}

#[derive(Copy, Clone)]
pub enum BindCPU {
    /// `RandomCPU` means binding to a randomly chosen CPU.
    RandomCPU,
    /// `UnboundCpu` means not binding to a particular CPU.
    UnboundCPU,
    /// Bind to the specific CPU number.
    BindToCPU(u32),
}

/// Pick a CPU at random to bind to, unless --cpu-unbound has been given,
/// in which case we return -1.
pub fn choose_cpu(bind_cpu: BindCPU) -> Option<u32> {
    match bind_cpu {
        BindCPU::UnboundCPU => None,
        // Pin tracee tasks to a random logical CPU, both in
        // recording and replay.  Tracees can see which HW
        // thread they're running on by asking CPUID, and we
        // don't have a way to emulate it yet.  So if a tracee
        // happens to be scheduled on a different core in
        // recording than replay, it can diverge.  (And
        // indeed, has been observed to diverge in practice,
        // in glibc.)
        //
        // Note that we will pin both the tracee processes *and*
        // the tracer process.  This ends up being a tidy
        // performance win in certain circumstances,
        // presumably due to cheaper context switching and/or
        // better interaction with CPU frequency scaling.
        BindCPU::BindToCPU(num) => Some(num),
        BindCPU::RandomCPU => {
            let maybe_cpu = get_random_cpu_cgroup();
            match maybe_cpu {
                Ok(cpu) => Some(cpu),
                Err(e) => {
                    log!(
                        LogWarn,
                        "While trying to get a random cpu number from `cpuset.cpus`, got error: `{}`.\
                         Continuing using a simpler approach.",
                        e
                    );
                    Some(random::<u32>() % get_num_cpus())
                }
            }
        }
    }
}

pub fn get_num_cpus() -> u32 {
    let res = unsafe { libc::sysconf(_SC_NPROCESSORS_ONLN) };
    if res > 0 {
        res.try_into().unwrap()
    } else {
        1
    }
}

enum CpuParseState {
    StartOrRangeStart,
    RangeEnd,
}

/// Read and parse the available CPU list then select a random CPU from the list.
pub fn get_random_cpu_cgroup() -> io::Result<u32> {
    let self_cpuset_file = File::open("/proc/self/cpuset")?;
    let mut self_cpuset = BufReader::new(self_cpuset_file);
    let mut cpuset_path: Vec<u8> = Vec::new();
    match self_cpuset.read_until(b'\n', &mut cpuset_path) {
        Err(e) => return Err(e),
        Ok(0) => {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Unexpected EOF encountered while reading /proc/self/cpuset",
            ))
        }
        Ok(read_bytes) => {
            if cpuset_path[read_bytes - 1] == b'\n' {
                cpuset_path.truncate(read_bytes - 1);
            }
        }
    }

    drop(self_cpuset);
    if cpuset_path.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            "File /proc/self/cpuset looks empty. Not able to get relevant information from it.",
        ));
    }

    let mut cpuset_sys_path = Vec::<u8>::new();
    cpuset_sys_path.extend_from_slice(b"/sys/fs/cgroup/cpuset");
    cpuset_sys_path.extend_from_slice(&cpuset_path);
    cpuset_sys_path.extend_from_slice(b"/cpuset.cpus");
    let cpuset_file = File::open(OsString::from_vec(cpuset_sys_path))?;
    let cpuset = BufReader::new(cpuset_file);

    let mut cpus: Vec<u32> = Vec::new();
    let mut parse_state = CpuParseState::StartOrRangeStart;
    let mut buf_start = String::new();
    let mut buf_end: String = String::new();
    let mut cpu_start: u32 = 0;
    let mut it = cpuset.bytes();
    loop {
        let maybe_res = it.next();
        match parse_state {
            CpuParseState::StartOrRangeStart => match maybe_res {
                Some(res) => {
                    let c = res?;
                    if c.is_ascii_digit() {
                        buf_start.push(char::from(c))
                    } else if c == b'-' {
                        parse_state = CpuParseState::RangeEnd;
                        match buf_start.parse::<u32>() {
                            Ok(num) => cpu_start = num,
                            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
                        }
                        buf_start.clear();
                        buf_end.clear();
                    } else if c == b'\n' || c == b',' {
                        match buf_start.parse::<u32>() {
                            Ok(cpu) => cpus.push(cpu),
                            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
                        }
                    } else {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("Unexpected char `{}`", char::from(c)),
                        ));
                    }
                }
                None => {
                    if buf_start.is_empty() {
                        break;
                    }
                    match buf_start.parse::<u32>() {
                        Ok(cpu) => {
                            cpus.push(cpu);
                            break;
                        }
                        Err(e) => return Err(Error::new(ErrorKind::Other, e)),
                    }
                }
            },
            CpuParseState::RangeEnd => match maybe_res {
                Some(res) => {
                    let c = res?;
                    if c.is_ascii_digit() {
                        buf_end.push(char::from(c))
                    } else if c == b'-' {
                        return Err(Error::new(ErrorKind::Other, "Unexpected char `-`"));
                    } else if c == b'\n' || c == b',' {
                        let cpu_end: u32;
                        parse_state = CpuParseState::StartOrRangeStart;
                        match buf_end.parse::<u32>() {
                            Ok(num) => cpu_end = num,
                            Err(e) => return Err(Error::new(ErrorKind::Other, e)),
                        }
                        debug_assert!(cpu_start <= cpu_end);
                        for cpu in cpu_start..(cpu_end + 1) {
                            cpus.push(cpu);
                        }
                        buf_start.clear();
                        buf_end.clear();
                    } else {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("Unexpected char `{}`", char::from(c)),
                        ));
                    }
                }
                None => {
                    if buf_end.is_empty() {
                        break;
                    }
                    match buf_end.parse::<u32>() {
                        Ok(cpu_end) => {
                            debug_assert!(cpu_start <= cpu_end);
                            for cpu in cpu_start..(cpu_end + 1) {
                                cpus.push(cpu);
                            }
                            break;
                        }
                        Err(e) => return Err(Error::new(ErrorKind::Other, e)),
                    }
                }
            },
        };
    }

    Ok(cpus[random::<usize>() % cpus.len()])
}

/// If you are specifying multiple strings to match, they must all appear one after another
/// in `/proc/{}/status`. This is like the behavior in rr.
/// @TODO The matches are cycled in the outer loop. This approach should be revisited later.
pub fn read_proc_status_fields(tid: pid_t, matches_for: &[&[u8]]) -> io::Result<Vec<OsString>> {
    let f = File::open(format!("/proc/{}/status", tid))?;
    let mut buf = BufReader::new(f);
    // Add `:`
    let mut matches = Vec::<Vec<u8>>::new();
    for &m in matches_for {
        let mut mat = Vec::from(m);
        mat.push(b':');
        matches.push(mat);
    }

    let mut result = Vec::<OsString>::new();
    for m in &matches {
        loop {
            let mut line = Vec::<u8>::new();
            match buf.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(nread) => match find(&line[0..nread - 1], m) {
                    Some(loc) => {
                        let mut needle = &line[(loc + m.len())..(nread - 1)];
                        for &c in needle {
                            if c == b' ' || c == b'\t' {
                                needle = &needle[1..];
                            }
                        }
                        result.push(OsString::from_vec(needle.to_owned()));
                        break;
                    }
                    None => continue,
                },
                Err(e) => return Err(e),
            }
        }
    }

    Ok(result)
}

/// Returns true if we succeeded, false if we failed because the
/// requested CPU does not exist/is not available.
pub fn set_cpu_affinity(cpu: u32) -> bool {
    let mut mask = CpuSet::new();
    mask.set(cpu as usize).unwrap();
    match sched_setaffinity(Pid::from_raw(0), &mask) {
        Err(_) if errno() == EINVAL => false,
        Err(e) => fatal!("Couldn't bind to CPU `{}': {:?}", cpu, e),
        Ok(_) => true,
    }
}

pub fn to_cstring_array(ar: &[OsString]) -> Vec<CString> {
    let mut res = Vec::<CString>::new();
    for a in ar {
        res.push(CString::new(a.as_bytes()).unwrap());
    }
    res
}

pub fn to_cstr_array(ar: &[CString]) -> Vec<&CStr> {
    let mut res = Vec::<&CStr>::new();
    for a in ar {
        res.push(a.as_c_str());
    }
    res
}

const SEGV_HANDLER_MAGIC: u32 = 0x98765432;

#[cfg(target_arch = "x86")]
extern "C" fn cpuid_segv_handler(_sig: i32, _siginfo: *mut siginfo_t, user: *mut c_void) {
    let ctx = user as *mut ucontext_t;
    unsafe {
        (*ctx).uc_mcontext.gregs[REG_EIP as usize] += 2;
        (*ctx).uc_mcontext.gregs[REG_EAX as usize] = SEGV_HANDLER_MAGIC as _;
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" fn cpuid_segv_handler(_sig: i32, _siginfo: *mut siginfo_t, user: *mut c_void) {
    let ctx = user as *mut ucontext_t;
    unsafe {
        (*ctx).uc_mcontext.gregs[REG_RIP as usize] += 2;
        (*ctx).uc_mcontext.gregs[REG_RAX as usize] = SEGV_HANDLER_MAGIC as _;
    }
}

fn cpuid_faulting_works_init() -> bool {
    let mut cpuid_faulting_ok = false;

    // Test to see if CPUID faulting works.
    #[cfg(not(target_arch = "x86"))]
    if unsafe { syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0) } != 0 {
        log!(LogDebug, "CPUID faulting not supported by kernel/hardware");
        return false;
    }

    // Some versions of Xen seem to set the feature bit but the feature doesn't
    // actually work, so we need to test it.
    let sa = SigAction::new(
        SigHandler::SigAction(cpuid_segv_handler),
        SaFlags::SA_SIGINFO,
        SigSet::empty(),
    );
    let old_sa = unsafe { sigaction(Signal::SIGSEGV, &sa) }.unwrap();

    let data: CPUIDData = cpuid(CPUID_GETVENDORSTRING, 0);
    if data.eax == SEGV_HANDLER_MAGIC {
        log!(LogDebug, "CPUID faulting works");
        cpuid_faulting_ok = true;
    } else {
        log!(LogDebug, "CPUID faulting advertised but does not work");
    }

    unsafe { sigaction(Signal::SIGSEGV, &old_sa) }.unwrap();

    #[cfg(not(target_arch = "x86"))]
    if unsafe { syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1) } < 0 {
        fatal!("Can't restore ARCH_SET_CPUID");
    }

    cpuid_faulting_ok
}

pub fn cpuid_faulting_works() -> bool {
    *CPUID_FAULTING_WORKS
}

pub fn cpuid_compatible(trace_records: &[CPUIDRecord]) -> bool {
    // We could compare all CPUID records but that might be fragile (it's hard to
    // be sure the values don't change in ways applications don't care about).
    // Let's just check the microarch for now.
    let cpuid_data = cpuid(CPUID_GETFEATURES, 0);
    let cpu_type: u32 = cpuid_data.eax & 0xF0FF0;
    let maybe_trace_cpuid_data = find_cpuid_record(trace_records, CPUID_GETFEATURES, 0);
    match maybe_trace_cpuid_data {
        None => {
            fatal!("GETFEATURES missing???");
        }
        Some(trace_cpuid_data) => {
            let trace_cpu_type: u32 = trace_cpuid_data.out.eax & 0xF0FF0;
            cpu_type == trace_cpu_type
        }
    }
}

pub fn has_effective_caps(mut caps: u64) -> bool {
    let header = native_arch::cap_header {
        version: _LINUX_CAPABILITY_VERSION_3 as _,
        pid: 0,
    };
    let mut data: [native_arch::cap_data; _LINUX_CAPABILITY_U32S_3 as usize] = Default::default();
    if unsafe { libc::syscall(native_arch::CAPGET as _, &header, &mut data) != 0 } {
        fatal!("Failed to read capabilities");
    }
    for i in 0.._LINUX_CAPABILITY_U32S_3 as usize {
        if (data[i].effective & caps as u32) != caps as u32 {
            return false;
        }
        caps = caps >> 32;
    }

    true
}

/// Return true if the user requested memory be dumped at this event/time.
pub fn should_dump_memory(event: &Event, time: FrameTime) -> bool {
    let flags = Flags::get();

    flags.dump_on == Some(DumpOn::DumpOnAll)
        || (event.is_syscall_event()
            && Some(DumpOn::DumpOnSyscall(event.syscall_event().number)) == flags.dump_on)
        || (event.is_signal_event()
            && Some(DumpOn::DumpOnSignal(event.signal_event().siginfo.si_signo)) == flags.dump_on)
        || (flags.dump_on == Some(DumpOn::DumpOnRdtsc)
            && event.event_type() == EventType::EvInstructionTrap)
        || flags.dump_at == Some(time)
}

/// Dump all of the memory in `t`'s address to the file
/// "<trace_dir>/<t.tid>_<global_time>_<tag>"
pub fn dump_process_memory(_t: &dyn Task, _global_time: FrameTime, _tag: &str) {
    unimplemented!()
}

/// Return true if the user has requested `t`'s memory be
/// checksummed at this event/time
pub fn should_checksum(event: &Event, time: FrameTime) -> bool {
    if event.event_type() == EventType::EvExit {
        // Task is dead, or at least detached, and we can't read its memory safely.
        return false;
    }
    if event.has_ticks_slop() {
        // We may not be at the same point during recording and replay, so don't
        // compute checksums.
        return false;
    }

    let checksum = Flags::get().checksum;
    let is_syscall_exit = EventType::EvSyscall == event.event_type()
        && SyscallState::ExitingSyscall == event.syscall_event().state;

    match checksum {
        Checksum::ChecksumNone => false,
        Checksum::ChecksumSyscall => is_syscall_exit,
        Checksum::ChecksumAll => true,
        Checksum::ChecksumAt(at_time) => time >= at_time,
    }
}

/// Write a checksum of each mapped region in `t`'s address space to a
/// special log, where it can be read by `validate_process_memory()`
/// during replay
pub fn checksum_process_memory(t: &dyn Task, global_time: FrameTime) {
    iterate_checksums(t, ChecksumMode::StoreChecksums, global_time);
}

/// Validate the checksum of `t`'s address space that was written
/// during recording
pub fn validate_process_memory(t: &dyn Task, global_time: FrameTime) {
    iterate_checksums(t, ChecksumMode::ValidateChecksums, global_time);
}

pub fn is_proc_mem_file(filename_os: &OsStr) -> bool {
    let filename = filename_os.as_bytes();
    filename.starts_with(b"/proc/") && filename.ends_with(b"/mem")
}

pub fn is_proc_fd_dir(filename_os: &OsStr) -> bool {
    let filename = filename_os.as_bytes();
    filename.starts_with(b"/proc/") && (filename.ends_with(b"/fd") || filename.ends_with(b"/fd/"))
}

pub fn check_for_leaks() {
    // Don't do leak checking. The outer rr may have injected maps into our
    // address space that look like leaks to us.
    if running_under_rd() {
        return;
    }

    let iter = KernelMapIterator::new_from_tid(getpid().as_raw());
    for km in iter {
        if find(
            km.fsname().as_bytes(),
            SessionInner::rd_mapping_prefix().as_bytes(),
        )
        .is_some()
        {
            fatal!("Leaked {:?}", km);
        }
    }
}

pub fn signal_bit(sig: Sig) -> sig_set_t {
    (1 as sig_set_t) << (sig.as_raw() - 1)
}

pub fn is_deterministic_signal(t: &dyn Task) -> SignalDeterministic {
    let signo = t.get_siginfo().si_signo;
    match signo {
        // These signals may be delivered deterministically;
        // we'll check for sure below.
        SIGILL | SIGBUS | SIGFPE | SIGSEGV =>
        // As bits/siginfo.h documents,
        //
        //   Values for `si_code'.  Positive values are
        //   reserved for kernel-generated signals.
        //
        // So if the signal is maybe-synchronous, and the
        // kernel delivered it, then it must have been
        // delivered deterministically. */
        {
            if t.get_siginfo().si_code > 0 {
                SignalDeterministic::DeterministicSig
            } else {
                SignalDeterministic::NondeterministicSig
            }
        }
        SIGTRAP => {
            // The kernel code is wrong about this one. It treats singlestep
            // traps as deterministic, but they aren't. PTRACE_ATTACH traps aren't
            // really deterministic either.
            let reasons = t.compute_trap_reasons();
            if reasons.breakpoint || reasons.watchpoint {
                SignalDeterministic::DeterministicSig
            } else {
                SignalDeterministic::NondeterministicSig
            }
        }
        _ =>
        // All other signals can never be delivered
        // deterministically (to the approximation required by
        // rd).
        {
            SignalDeterministic::NondeterministicSig
        }
    }
}

pub fn get_fd_offset(tid: pid_t, fd: i32) -> u64 {
    // Get the offset from /proc/*/fdinfo/*
    let fdinfo_path = format!("/proc/{}/fdinfo/{}", tid, fd);
    let result = File::open(&fdinfo_path);
    let mut f = match result {
        Err(e) => {
            fatal!("Failed to open `{}`: {:?}", fdinfo_path, e);
        }
        Ok(file) => BufReader::new(file),
    };

    let mut buf = String::new();
    let mut maybe_offset: Option<u64> = None;
    // @TODO do we need to use read_until() which will give a Vec<u8> instead?
    // But buf being a String should be OK for now. The characters in fdinfo should be ASCII
    // anyways.
    while let Ok(nread) = f.read_line(&mut buf) {
        if nread == 0 {
            break;
        }

        let s = buf.trim();
        let maybe_loc = s.find("pos:\t");
        if maybe_loc.is_none() {
            buf.clear();
            continue;
        }
        // 5 is length of str "pos:\t"
        let loc = maybe_loc.unwrap() + 5;
        // @TODO This is tricky. Are we sure that a negative offset won't appear in
        // /proc/{}/fdinfo/{} ?
        let maybe_res = s[loc..].parse::<u64>();
        match maybe_res {
            Ok(res) => maybe_offset = Some(res),
            Err(e) => fatal!(
                "Unable to parse file offset from `{}'. String was '{}': {:?}",
                fdinfo_path,
                s,
                e
            ),
        }
        buf.clear();
    }

    match maybe_offset {
        None => fatal!("Failed to read position"),
        Some(offset) => offset,
    }
}

fn checksum_segment_filter(m: &Mapping) -> bool {
    let may_diverge;

    if m.map.fsname().as_bytes() == b"[vsyscall]" {
        // This can't be read/checksummed.
        return false;
    }

    let maybe_st = stat(m.map.fsname());

    if maybe_st.is_err() {
        // If there's no persistent resource backing this
        // mapping, we should expect it to change.
        log!(LogDebug, "CHECKSUMMING unlinked {:?}", m.map.fsname());
        return true;
    }

    let st = maybe_st.unwrap();

    // If we're pretty sure the backing resource is effectively
    // immutable, skip checksumming, it's a waste of time.  Except
    // if the mapping is mutable, for example the rw data segment
    // of a system library, then it's interesting.
    may_diverge = !m.map.fsname().as_bytes().starts_with(b"mmap_clone_")
        && (should_copy_mmap_region(&m.map, &st) || m.map.prot().contains(ProtFlags::PROT_WRITE));

    if may_diverge {
        log!(LogDebug, "CHECKSUMMING {:?}", m.map.fsname());
    } else {
        log!(LogDebug, "  skipping {:?}", m.map.fsname());
    }

    may_diverge
}

enum ChecksumMode {
    StoreChecksums,
    ValidateChecksums,
}

enum ChecksumData {
    ValidateChecksums(BufReader<File>),
    StoreChecksums(BufWriter<File>),
}

struct ParsedChecksumLine {
    start: RemotePtr<Void>,
    end: RemotePtr<Void>,
    checksum: u32,
}

const IGNORED_CHECKSUM: u32 = 0x98765432;
const SIGBUS_CHECKSUM: u32 = 0x23456789;

/// Either create and store checksums for each segment mapped in `t`'s
/// address space, or validate an existing computed checksum.  Behavior
/// is selected by `mode`.
fn iterate_checksums(t: &dyn Task, mode: ChecksumMode, global_time: FrameTime) {
    let mut filename_vec: Vec<u8> = t.trace_dir().into_vec();
    let append = format!("/{}_{}", global_time, t.rec_tid());
    filename_vec.extend_from_slice(append.as_bytes());
    let filename = OsString::from_vec(filename_vec);
    let mut checksum_data = match mode {
        ChecksumMode::StoreChecksums => {
            let maybe_file = File::create(filename.clone());
            match maybe_file {
                Ok(file) => ChecksumData::StoreChecksums(BufWriter::new(file)),
                Err(e) => fatal!(
                    "Failed to open checksum file {:?}: error was {:?}",
                    filename,
                    e
                ),
            }
        }
        ChecksumMode::ValidateChecksums => {
            let maybe_file = File::open(filename.clone());
            match maybe_file {
                Ok(file) => ChecksumData::ValidateChecksums(BufReader::new(file)),
                Err(e) => fatal!(
                    "Failed to open checksum file {:?}: error was {:?}",
                    filename,
                    e
                ),
            }
        }
    };

    let mut in_replay: u8 = 0;
    let mut in_replay_flag = RemotePtr::null();
    if !t.preload_globals.get().is_null() {
        in_replay_flag = remote_ptr_field!(t.preload_globals.get(), preload_globals, in_replay);
        in_replay = read_val_mem(t, in_replay_flag, None);
        write_val_mem(t, in_replay_flag, &0u8, None);
    }

    let mut checksums = Vec::<ParsedChecksumLine>::new();
    match &mut checksum_data {
        ChecksumData::ValidateChecksums(file) => loop {
            let mut buf = Vec::<u8>::new();

            let nread = match file.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(nread) => nread,
            };

            let startparen = find(&buf, b"(").unwrap();
            let endparen = find(&buf, b")").unwrap();
            let space = find(&buf, b" ").unwrap();
            let dash = find(&buf, b"-").unwrap();
            let space2 = find(&buf[dash + 1..], b" ").unwrap() + dash + 1;
            ed_assert!(t, nread > dash + 1);

            let mut dummy: &[u8] = Default::default();
            let checksum: u32 = str16_to_usize(&buf[startparen + 1..endparen], &mut dummy)
                .unwrap()
                .try_into()
                .unwrap();
            let rec_start =
                RemotePtr::from(str16_to_usize(&buf[space + 1..dash], &mut dummy).unwrap());
            let rec_end =
                RemotePtr::from(str16_to_usize(&buf[dash + 1..space2], &mut dummy).unwrap());
            checksums.push(ParsedChecksumLine {
                start: rec_start,
                end: rec_end,
                checksum,
            });

            let mem_range = MemoryRange::from_range(rec_start, rec_end);
            t.vm()
                .ensure_replay_matches_single_recorded_mapping(t, mem_range);
        },
        ChecksumData::StoreChecksums(_) => (),
    }

    {
        let mut checksum_iter = checksums.iter();
        let vm = t.vm();
        let maps = vm.maps();
        let mut maps_iter = maps.into_iter();
        while let Some((_, mp)) = maps_iter.next() {
            let mut m = mp;
            let mut raw_map_line = m.map.str(true);
            let mut rec_checksum: u32 = 0;

            match &mut checksum_data {
                ChecksumData::ValidateChecksums(_) => {
                    let parsed = checksum_iter.next().unwrap();
                    while m.map.start() != parsed.start {
                        if is_task_buffer(t, m) {
                            // This region corresponds to a task scratch or syscall buffer. We
                            // tear these down a little later during replay so just skip it for
                            // now.
                            match maps_iter.next() {
                                Some((_, mp)) => {
                                    m = mp;
                                    raw_map_line = m.map.str(true);
                                    continue;
                                }
                                None => {
                                    fatal!("Maps iterator unexpectedly came to an end");
                                }
                            }
                        } else {
                            fatal!(
                                "Segment {}-{} changed to {}??",
                                parsed.start,
                                parsed.end,
                                m.map
                            );
                        }
                    }
                    ed_assert_eq!(
                        t,
                        m.map.end(),
                        parsed.end,
                        "Segment {}-{} changed to {}??",
                        parsed.start,
                        parsed.end,
                        m.map
                    );
                    if is_start_of_scratch_region(t, parsed.start) {
                        // Replay doesn't touch scratch regions, so
                        // their contents are allowed to diverge.
                        // Tracees can't observe those segments unless
                        // they do something sneaky (or disastrously
                        // buggy).
                        log!(
                            LogDebug,
                            "Not validating scratch starting at {}",
                            parsed.start
                        );
                        continue;
                    }
                    if parsed.checksum == IGNORED_CHECKSUM {
                        log!(LogDebug, "Checksum not computed during recording");
                        continue;
                    } else if parsed.checksum == SIGBUS_CHECKSUM {
                        continue;
                    } else {
                        rec_checksum = parsed.checksum;
                    }
                }
                ChecksumData::StoreChecksums(checksums_file) => {
                    if !checksum_segment_filter(&m) {
                        write!(
                            checksums_file,
                            "({:x}) {}\n",
                            IGNORED_CHECKSUM, raw_map_line
                        )
                        .unwrap();
                        continue;
                    }
                }
            }
            let mut mem = Vec::<u8>::new();
            mem.resize(m.map.size(), 0);
            let maybe_valid_mem_len = t.read_bytes_fallible(m.map.start(), &mut mem);
            // Areas not read are treated as zero. We have to do this because
            // mappings not backed by valid file data are not readable during
            // recording but are read as 0 during replay.
            if maybe_valid_mem_len.is_err() {
                // It is possible for whole mappings to be beyond the extent of the
                // backing file, in which case read_bytes_fallible will return an error.
                ed_assert_eq!(t, errno(), EIO);
            }

            if m.flags.contains(MappingFlags::IS_SYSCALLBUF) {
                // The syscallbuf consists of a region that's written
                // deterministically wrt the trace events, and a
                // region that's written nondeterministically in the
                // same way as trace scratch buffers.  The
                // deterministic region comprises committed syscallbuf
                // records, and possibly the one pending record
                // metadata.  The nondeterministic region starts at
                // the "extra data" for the possibly one pending
                // record.
                //
                // So here, we set things up so that we only checksum
                // the deterministic region.
                let child_hdr = RemotePtr::<syscallbuf_hdr>::cast(m.map.start());
                let hdr = read_val_mem(t, child_hdr, None);
                mem.resize(
                    size_of_val(&hdr) + hdr.num_rec_bytes as usize + size_of::<syscallbuf_record>(),
                    0,
                );
            }

            let checksum = compute_checksum(&mem);

            match &mut checksum_data {
                ChecksumData::StoreChecksums(file) => {
                    write!(file, "({:x}) {}\n", checksum, raw_map_line).unwrap();
                }
                ChecksumData::ValidateChecksums(_file) => {
                    ed_assert!(t, t.session().is_replaying());

                    // Ignore checksums when valid_mem_len == 0
                    if checksum != rec_checksum {
                        notify_checksum_error(
                            t.as_replay_task().unwrap(),
                            global_time,
                            checksum,
                            rec_checksum,
                            &raw_map_line,
                        );
                    }
                }
            }
        }
    }

    if !in_replay_flag.is_null() {
        write_val_mem(t, in_replay_flag, &in_replay, None);
    }
}

fn notify_checksum_error(
    _t: &ReplayTask,
    global_time: u64,
    checksum: u32,
    rec_checksum: u32,
    raw_map_line: &str,
) {
    log!(
        LogError,
        "Checksum error at time {}: {}\nRecorded checksum: {:#x}, Replay checksum: {:#x}",
        global_time,
        raw_map_line,
        rec_checksum,
        checksum
    );
    unimplemented!()
}

/// DIFF NOTE: Takes `t` instead of the address space as param
fn is_task_buffer(t: &dyn Task, m: &Mapping) -> bool {
    if RemotePtr::cast(t.syscallbuf_child.get()) == m.map.start()
        && t.syscallbuf_size.get() == m.map.size()
    {
        return true;
    }
    if t.scratch_ptr.get() == m.map.start() && t.scratch_size.get() == m.map.size() {
        return true;
    }
    for tt in t.vm().task_set().iter_except(t.weak_self_ptr()) {
        if RemotePtr::cast(tt.syscallbuf_child.get()) == m.map.start()
            && tt.syscallbuf_size.get() == m.map.size()
        {
            return true;
        }
        if tt.scratch_ptr.get() == m.map.start() && tt.scratch_size.get() == m.map.size() {
            return true;
        }
    }

    false
}

/// FIXME this function assumes that there's only one address space.
/// Should instead only look at the address space of the task in
/// question.
fn is_start_of_scratch_region(t: &dyn Task, start_addr: RemotePtr<Void>) -> bool {
    if start_addr == t.scratch_ptr.get() {
        return true;
    }

    let t_rc = t.weak_self_ptr().upgrade().unwrap();
    for (_, tt_rc) in t.session().tasks().iter() {
        if Rc::ptr_eq(tt_rc, &t_rc) {
            continue;
        }
        if start_addr == tt_rc.scratch_ptr.get() {
            return true;
        }
    }

    false
}

fn compute_checksum(data: &[u8]) -> u32 {
    let mut checksum: u32 = data.len().try_into().unwrap();
    let words = data.len() / size_of::<u32>();
    let data_as_u32: &[u32] = unsafe { slice::from_raw_parts(data.as_ptr().cast(), words) };

    for d in data_as_u32 {
        checksum = checksum
            .overflowing_shl(4)
            .0
            .overflowing_add(checksum)
            .0
            .overflowing_add(*d)
            .0;
    }

    checksum
}

/// `pattern` is an mkstemp pattern minus any leading path. We'll choose the
/// temp directory ourselves. The file is not automatically deleted, the caller
/// must take care of that.
pub fn create_temporary_file(pattern: &[u8]) -> TempFile {
    let mut buf = tmp_dir().into_vec();
    buf.push(b'/');
    buf.extend_from_slice(pattern);
    buf.truncate(PATH_MAX as usize);
    let res = mkstemp(OsString::from_vec(buf).as_os_str()).unwrap();
    TempFile {
        name: res.1.into_os_string(),
        fd: ScopedFd::from_raw(res.0),
    }
}

pub struct TempFile {
    pub name: OsString,
    pub fd: ScopedFd,
}

pub fn str16_to_usize<'a>(
    text: &'a [u8],
    new_text: &mut &'a [u8],
) -> Result<usize, Box<dyn error::Error>> {
    lazy_static! {
        static ref RE16: Regex = Regex::new(r"^\s*([\+\-])?(?:0[xX])?([0-9a-fA-F]+)").unwrap();
    }
    match RE16.find(text) {
        Some(m) => {
            let cap = RE16.captures(text).unwrap();
            let num_str = &cap[2];
            *new_text = &text[m.end()..];
            if cap.get(1).is_some() && cap[1][0] == b'-' {
                let mut num_str_neg = vec![b'-'];
                num_str_neg.extend_from_slice(num_str);
                match isize::from_str_radix(std::str::from_utf8(&num_str_neg).unwrap(), 16) {
                    Ok(num) => Ok(num as usize),
                    Err(e) => Err(Box::new(e)),
                }
            } else {
                match usize::from_str_radix(std::str::from_utf8(num_str).unwrap(), 16) {
                    Ok(num) => Ok(num),
                    Err(e) => Err(Box::new(e)),
                }
            }
        }
        None => {
            *new_text = text;
            // This tries to mimic the behavior of strtoul where if there were no
            // digits the result of the conversion is 0
            Ok(0)
        }
    }
}

pub fn str16_to_isize<'a>(
    text: &'a [u8],
    new_text: &mut &'a [u8],
) -> Result<isize, Box<dyn error::Error>> {
    lazy_static! {
        static ref RE16: Regex = Regex::new(r"^\s*([\+\-])?(?:0[xX])?([0-9a-fA-F]+)").unwrap();
    }
    match RE16.find(text) {
        Some(m) => {
            let cap = RE16.captures(text).unwrap();
            let num_str = &cap[2];
            *new_text = &text[m.end()..];
            if cap.get(1).is_some() && cap[1][0] == b'-' {
                let mut num_str_neg = vec![b'-'];
                num_str_neg.extend_from_slice(num_str);
                match isize::from_str_radix(std::str::from_utf8(&num_str_neg).unwrap(), 16) {
                    Ok(num) => Ok(num),
                    Err(e) => Err(Box::new(e)),
                }
            } else {
                match isize::from_str_radix(std::str::from_utf8(num_str).unwrap(), 16) {
                    Ok(num) => Ok(num),
                    Err(e) => Err(Box::new(e)),
                }
            }
        }
        None => {
            *new_text = text;
            // This tries to mimic the behavior of strtol where if there were no
            // digits the result of the conversion is 0
            Ok(0)
        }
    }
}

pub fn str0_to_isize<'a>(
    text: &'a [u8],
    new_text: &mut &'a [u8],
) -> Result<isize, Box<dyn error::Error>> {
    lazy_static! {
        static ref RE016: Regex = Regex::new(r"^\s*([\+\-])?0[xX]([0-9a-fA-F]+)").unwrap();
        static ref RE010: Regex = Regex::new(r"^\s*([\+\-])?([0-9]+)").unwrap();
        static ref RE08: Regex = Regex::new(r"^\s*([\+\-])?0([0-7]+)").unwrap();
    }
    match RE016.find(text) {
        Some(m) => {
            let cap = RE016.captures(text).unwrap();
            let num_str = &cap[2];
            *new_text = &text[m.end()..];
            if cap.get(1).is_some() && cap[1][0] == b'-' {
                let mut num_str_neg = vec![b'-'];
                num_str_neg.extend_from_slice(num_str);
                match isize::from_str_radix(std::str::from_utf8(&num_str_neg).unwrap(), 16) {
                    Ok(num) => Ok(num),
                    Err(e) => Err(Box::new(e)),
                }
            } else {
                match isize::from_str_radix(std::str::from_utf8(num_str).unwrap(), 16) {
                    Ok(num) => Ok(num),
                    Err(e) => Err(Box::new(e)),
                }
            }
        }
        None => {
            match RE08.find(text) {
                Some(m) => {
                    let cap = RE08.captures(text).unwrap();
                    let num_str = &cap[2];
                    *new_text = &text[m.end()..];
                    if cap.get(1).is_some() && cap[1][0] == b'-' {
                        let mut num_str_neg = vec![b'-'];
                        num_str_neg.extend_from_slice(num_str);
                        match isize::from_str_radix(std::str::from_utf8(&num_str_neg).unwrap(), 8) {
                            Ok(num) => Ok(num),
                            Err(e) => Err(Box::new(e)),
                        }
                    } else {
                        match isize::from_str_radix(std::str::from_utf8(num_str).unwrap(), 8) {
                            Ok(num) => Ok(num),
                            Err(e) => Err(Box::new(e)),
                        }
                    }
                }
                None => {
                    match RE010.find(text) {
                        Some(m) => {
                            let cap = RE010.captures(text).unwrap();
                            let num_str = &cap[2];
                            *new_text = &text[m.end()..];
                            if cap.get(1).is_some() && cap[1][0] == b'-' {
                                let mut num_str_neg = vec![b'-'];
                                num_str_neg.extend_from_slice(num_str);
                                match isize::from_str_radix(
                                    std::str::from_utf8(&num_str_neg).unwrap(),
                                    10,
                                ) {
                                    Ok(num) => Ok(num),
                                    Err(e) => Err(Box::new(e)),
                                }
                            } else {
                                match isize::from_str_radix(
                                    std::str::from_utf8(num_str).unwrap(),
                                    10,
                                ) {
                                    Ok(num) => Ok(num),
                                    Err(e) => Err(Box::new(e)),
                                }
                            }
                        }
                        None => {
                            *new_text = text;
                            // This tries to mimic the behavior of strtol where if there were no
                            // digits the result of the conversion is 0
                            Ok(0)
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str16_to_usize_test() {
        let mut sl = b"  -ff apples".as_slice();
        let maybe_num = str16_to_usize(sl, &mut sl);
        assert_eq!(-0xffisize as usize, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  ff apples".as_slice();
        let maybe_num = str16_to_usize(sl, &mut sl);
        assert_eq!(0xff, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  0xAB apples".as_slice();
        let maybe_num = str16_to_usize(sl, &mut sl);
        assert_eq!(0xAB, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  -0xAB apples".as_slice();
        let maybe_num = str16_to_usize(sl, &mut sl);
        assert_eq!(-0xABisize as usize, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"mango".as_slice();
        let maybe_num = str16_to_usize(sl, &mut sl);
        assert_eq!(maybe_num.unwrap(), 0);
        assert_eq!(b"mango", sl);
    }

    #[test]
    fn str16_to_isize_test() {
        let mut sl = b"  -ff apples".as_slice();
        let maybe_num = str16_to_isize(sl, &mut sl);
        assert_eq!(-0xff, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  ff apples".as_slice();
        let maybe_num = str16_to_isize(sl, &mut sl);
        assert_eq!(0xff, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  0xAB apples".as_slice();
        let maybe_num = str16_to_isize(sl, &mut sl);
        assert_eq!(0xAB, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  -0xAB apples".as_slice();
        let maybe_num = str16_to_isize(sl, &mut sl);
        assert_eq!(-0xAB, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"mango".as_slice();
        let maybe_num = str16_to_isize(sl, &mut sl);
        assert_eq!(maybe_num.unwrap(), 0);
        assert_eq!(b"mango", sl);
    }

    #[test]
    fn str0_to_isize_test() {
        let mut sl = b"  0xAB apples".as_slice();
        let maybe_num = str0_to_isize(sl, &mut sl);
        assert_eq!(0xAB, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  -0xAB apples".as_slice();
        let maybe_num = str0_to_isize(sl, &mut sl);
        assert_eq!(-0xAB, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  010 apples".as_slice();
        let maybe_num = str0_to_isize(sl, &mut sl);
        assert_eq!(0o10, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  -010 apples".as_slice();
        let maybe_num = str0_to_isize(sl, &mut sl);
        assert_eq!(-0o10, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  10 apples".as_slice();
        let maybe_num = str0_to_isize(sl, &mut sl);
        assert_eq!(10, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"  -10 apples".as_slice();
        let maybe_num = str0_to_isize(sl, &mut sl);
        assert_eq!(-10, maybe_num.unwrap());
        assert_eq!(b" apples", sl);

        let mut sl = b"mango".as_slice();
        let maybe_num = str0_to_isize(sl, &mut sl);
        assert_eq!(maybe_num.unwrap(), 0);
        assert_eq!(b"mango", sl);
    }
}
