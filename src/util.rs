use raw_cpuid::CpuId;

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
}

pub fn running_under_rd() -> bool {
    let maybe_under = option_env!("RUNNING_UNDER_RD");
    maybe_under.is_some()
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
