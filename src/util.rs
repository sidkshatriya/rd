use crate::bindings::signal::{SI_KERNEL, TRAP_BRKPT};
use crate::scoped_fd::ScopedFd;
use libc::pwrite64;
use nix::sys::stat::Mode;
use nix::unistd::SysconfVar::PAGE_SIZE;
use nix::unistd::{access, ftruncate};
use nix::unistd::{sysconf, AccessFlags};
use raw_cpuid::CpuId;
use std::convert::TryInto;
use std::env;
use std::ffi::{c_void, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

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

lazy_static! {
    static ref XSAVE_NATIVE_LAYOUT: XSaveLayout = xsave_native_layout_init();
    static ref SYSTEM_PAGE_SIZE: usize = page_size_init();
}

pub fn running_under_rd() -> bool {
    env::var("RUNNING_UNDER_RD").is_ok()
}

#[derive(Copy, Clone)]
pub struct XSaveFeatureLayout {
    pub offset: u32,
    pub size: u32,
}

pub struct XSaveLayout {
    pub full_size: usize,
    pub supported_feature_bits: u64,
    pub feature_layouts: Vec<XSaveFeatureLayout>,
}

pub fn xsave_native_layout() -> &'static XSaveLayout {
    &*XSAVE_NATIVE_LAYOUT
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CPUIDRecord {
    pub eax_in: u32,
    pub ecx_in: u32,
    pub out: CPUIDData,
}

#[repr(C)]
#[derive(Copy, Clone)]
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

fn xsave_native_layout_init() -> XSaveLayout {
    let cpuid = CpuId::new();
    let maybe_extended_state_info = cpuid.get_extended_state_info();
    let mut layout: XSaveLayout;
    if let Some(extended_state_info) = maybe_extended_state_info {
        layout = XSaveLayout {
            full_size: extended_state_info.xsave_area_size_enabled_features() as usize,
            supported_feature_bits: 0,
            feature_layouts: Vec::new(),
        };
        // The initial 2 items are always like this.
        layout
            .feature_layouts
            .push(XSaveFeatureLayout { offset: 0, size: 0 });
        layout
            .feature_layouts
            .push(XSaveFeatureLayout { offset: 0, size: 0 });
        for info in extended_state_info.iter() {
            // @TODO check this `is_in_xcr0` test again. Do we need it?
            if info.is_in_xcr0() {
                layout.supported_feature_bits = layout.supported_feature_bits | (1 << info.subleaf);
                layout.feature_layouts.push(XSaveFeatureLayout {
                    offset: info.offset(),
                    size: info.size(),
                });
            }
        }
    } else {
        // @TODO check this branch.
        layout = XSaveLayout {
            full_size: 512,
            supported_feature_bits: 0x3,
            feature_layouts: Vec::new(),
        }
    }

    layout
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
    let mut dir = env::var("RD_TMPDIR");
    if dir.is_ok() {
        ensure_dir(
            dir.as_ref().unwrap(),
            "temporary file directory (RD_TMPDIR)",
            Mode::S_IRWXU,
        );
        return OsString::from(&dir.unwrap());
    }

    dir = env::var("TMPDIR");
    if dir.is_ok() {
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
pub fn ensure_dir(dir: &str, dir_type: &str, mode: Mode) {
    unimplemented!()
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

pub fn check_for_pax_kernel() -> bool {
    unimplemented!()
}

lazy_static! {
    static ref IS_PAX_KERNEL: bool = check_for_pax_kernel();
}

pub fn uses_invisible_guard_page() -> bool {
    !*IS_PAX_KERNEL
}

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
