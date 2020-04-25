use crate::address_space::address_space::AddressSpace;
use crate::address_space::kernel_mapping::KernelMapping;
use crate::arch::Architecture;
use crate::bindings::signal::{SI_KERNEL, TRAP_BRKPT};
use crate::flags::Flags;
use crate::log::LogLevel::{LogDebug, LogWarn};
use crate::remote_ptr::{RemotePtr, Void};
use crate::scoped_fd::ScopedFd;
use crate::task::common::{read_mem, read_val_mem};
use crate::task::task_inner::CloneFlags;
use crate::task::Task;
use libc::pwrite64;
use libc::STDERR_FILENO;
use libc::{
    CLONE_CHILD_CLEARTID, CLONE_FILES, CLONE_SETTLS, CLONE_SIGHAND, CLONE_THREAD, CLONE_VM,
};
use libc::{S_IFDIR, S_IFREG};
use nix::errno::errno;
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::stat::FileStat;
use nix::sys::stat::{stat, Mode};
use nix::sys::statfs::{statfs, TMPFS_MAGIC};
use nix::sys::uio::pread;
use nix::unistd::SysconfVar::PAGE_SIZE;
use nix::unistd::{access, ftruncate, isatty, mkdir, read, write};
use nix::unistd::{sysconf, AccessFlags};
use nix::NixPath;
use rand::random;
use std::cmp::{max, min};
use std::convert::TryInto;
use std::env::var_os;
use std::ffi::{c_void, CString, OsStr, OsString};
use std::io::{Error, ErrorKind};
use std::mem::{size_of_val, zeroed};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::ptr::copy_nonoverlapping;
use std::sync::Mutex;
use std::{env, io, mem};

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
    static ref XSAVE_NATIVE_LAYOUT: XSaveLayout = xsave_native_layout_init();
    static ref SYSTEM_PAGE_SIZE: usize = page_size_init();
    static ref SAVED_FD_LIMIT: Mutex<Option<libc::rlimit>> = Mutex::new(None);
}

pub fn running_under_rd() -> bool {
    let result = var_os("RUNNING_UNDER_RD");
    result.is_some() && result.unwrap() != ""
}

#[derive(Copy, Clone, Default)]
pub struct XSaveFeatureLayout {
    pub offset: u32,
    pub size: u32,
}

#[derive(Default)]
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

fn cpuid(code: u32, subrequest: u32) -> CPUIDData {
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
                    if rec.out.edx & (1 << level) != 0 {
                        results.push(cpuid_record(base, level));
                    }
                }
            }
            CPUID_GETRDTALLOCATION => {
                let rec = cpuid_record(base, 0);
                results.push(rec);
                // @TODO check this.
                for level in 1..64 {
                    if rec.out.ebx & (1 << level) != 0 {
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

pub fn floor_page_size<T: Into<usize> + From<usize>>(sz: T) -> T {
    let page_mask: usize = !(page_size() - 1);
    (sz.into() & page_mask).into()
}

pub fn resize_shmem_segment(fd: &ScopedFd, num_bytes: usize) {
    if ftruncate(fd.as_raw(), num_bytes as libc::off_t).is_err() {
        // errno will be reported as part of fatal
        fatal!("Failed to resize shmem to {}", num_bytes);
    }
}

#[derive(Eq, PartialEq)]
pub enum TrappedInstruction {
    None = 0,
    Rdtsc = 1,
    Rdtscp = 2,
    CpuId = 3,
    Int3 = 4,
    Pushf = 5,
    Pushf16 = 6,
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
    let mut dir = var_os("RD_TMPDIR");
    if dir.is_some() {
        ensure_dir(
            dir.as_ref().unwrap(),
            "temporary file directory (RD_TMPDIR)",
            Mode::S_IRWXU,
        );
        return OsString::from(&dir.unwrap());
    }

    dir = var_os("TMPDIR");
    if dir.is_some() {
        ensure_dir(
            dir.as_ref().unwrap(),
            "temporary file directory (TMPDIR)",
            Mode::S_IRWXU,
        );
        return OsString::from(dir.unwrap());
    }

    // Don't try to create "/tmp", that probably won't work well.
    if access("/tmp", AccessFlags::W_OK).is_ok() {
        fatal!("Can't write to temporary file directory /tmp.");
    }

    OsString::from("/tmp")
}

/// Create directory `str`, creating parent directories as needed.
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
        Err(_) => {
            if errno() != libc::ENOENT {
                fatal!("Error accessing {} `{:?}'", dir_type, dir);
            }

            let last_slash = d.iter().enumerate().rfind(|c| *c.1 == b'/');
            match last_slash {
                Some(pos) if pos.0 > 0 => {
                    ensure_dir(OsStr::from_bytes(&d[0..pos.0]), dir_type, mode);
                }
                _ => {
                    fatal!("Can't find directory `{:?}'", dir);
                }
            }

            // Allow for a race condition where someone else creates the directory
            if mkdir(d, mode).is_err() && errno() != libc::EEXIST {
                fatal!("Can't create {} `{:?}'", dir_type, dir);
            }

            match stat(d) {
                Err(_) => {
                    fatal!("Can't stat {} `{:?}'", dir_type, dir);
                    unreachable!()
                }
                Ok(st) => st,
            }
        }
        Ok(st) => st,
    };

    if !(S_IFDIR & st.st_mode == S_IFDIR) {
        fatal!("`{:?}' exists but isn't a directory.", dir);
    }
    if access(d, AccessFlags::W_OK).is_err() {
        fatal!("Can't write to {} `{:?}'", dir_type, dir);
    }
}

/// Like pwrite64(2) but we try to write all bytes by looping on short writes.
///
/// Slightly different from rr. Employs Result.
pub fn pwrite_all_fallible(fd: i32, buf_initial: &[u8], offset: isize) -> Result<usize, ()> {
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
            cur_size -= ret as usize;
        }
    }

    Ok(written)
}

/// @TODO Hardcoded to false.
pub fn check_for_pax_kernel() -> bool {
    false
}

lazy_static! {
    static ref IS_PAX_KERNEL: bool = check_for_pax_kernel();
}

pub fn uses_invisible_guard_page() -> bool {
    !*IS_PAX_KERNEL
}

#[allow(unreachable_code)]
pub fn find(haystack: &OsStr, needle: &[u8]) -> Option<usize> {
    let haystack_len = haystack.as_bytes().len();
    let mut it = haystack.as_bytes().iter();
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
    let v = env::var("RD_COPY_ALL_FILES");
    if v.is_err() || v.unwrap().is_empty() {
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
    if !(stat.st_mode & S_IFREG != S_IFREG) {
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
            "Scary mmap {:?} (prot: {:x} {}); uid:{}  mode:{}",
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
    let v = env::var("RD_TRUST_TEMP_FILES");
    if v.is_err() || v.unwrap().is_empty() {
        return true;
    }

    // DIFF NOTE: rr assumes the call always succeeds but we dont for now.
    let sfs = statfs(path).unwrap();
    // In observed configurations of Ubuntu 13.10, /tmp is
    // a folder in the / fs, not a separate tmpfs.
    TMPFS_MAGIC == sfs.filesystem_type() || path.as_bytes().starts_with(b"/tmp/")
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
            Err(_) | Ok(0) => fatal!("Can't write {} bytes", size),
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
    // true during rr unit tests, where we care most about this
    // check (to a first degree).  A failing test shouldn't
    // hang.
    match isatty(fd) {
        Ok(res) => !res,
        Err(_) => {
            fatal!("Failure in calling isatty()");
            unreachable!()
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
    // @TODO does canonicalize do what realpath does exactly?
    Path::new(&path)
        .canonicalize()
        .expect(&format!("Could not retrieve path {:?}", path))
        .as_os_str()
        .to_os_string()
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
    exe_path.parent().unwrap().as_os_str().to_os_string()
}

fn env_ptr<Arch: Architecture>(t: &mut dyn Task) -> RemotePtr<Arch::unsigned_word> {
    let mut stack_ptr: RemotePtr<Arch::unsigned_word> = RemotePtr::cast(t.regs_ref().sp());

    let argc = read_val_mem::<Arch::unsigned_word>(t, stack_ptr, None);
    let delta: usize = (argc + 1u8.into()).try_into().unwrap();
    stack_ptr += delta;

    // Check final NULL in argv
    let null_ptr = read_val_mem::<Arch::unsigned_word>(t, stack_ptr, None);
    ed_assert!(t, null_ptr == 0u8.into());
    stack_ptr += 1;
    stack_ptr
}

fn read_env_arch<Arch: Architecture>(t: &mut dyn Task) -> Vec<CString> {
    let mut stack_ptr = env_ptr::<Arch>(t);
    // Should now point to envp
    let mut result: Vec<CString> = Vec::new();
    loop {
        let p = read_val_mem::<Arch::unsigned_word>(t, stack_ptr, None);
        stack_ptr += 1;
        if p == 0.into() {
            break;
        }
        result.push(t.read_c_str(RemotePtr::new_from_val(p.try_into().unwrap())));
    }
    result
}

pub fn read_env(t: &mut dyn Task) -> Vec<CString> {
    rd_arch_function_selfless!(read_env_arch, t.arch(), t)
}

pub fn read_auxv(t: &mut dyn Task) -> Vec<u8> {
    rd_arch_function_selfless!(read_auxv_arch, t.arch(), t)
}

fn read_auxv_arch<Arch: Architecture>(t: &mut dyn Task) -> Vec<u8> {
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
    pub stack: Option<RemotePtr<Void>>,
    pub ptid: Option<RemotePtr<i32>>,
    pub tls: Option<RemotePtr<Void>>,
    pub ctid: Option<RemotePtr<i32>>,
}

/// Extract various clone(2) parameters out of the given Task's registers.
pub fn extract_clone_parameters(_t: &dyn Task) -> CloneParameters {
    unimplemented!()
}

/// Convert the flags passed to the clone() syscall, `flags_arg`, into
/// the format understood by Task::clone_task().
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
