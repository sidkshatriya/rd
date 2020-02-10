use raw_cpuid::CpuId;

lazy_static! {
    static ref XSAVE_NATIVE_LAYOUT: XSaveLayout = xsave_layout_from_trace();
}

pub fn running_under_rd() -> bool {
    let maybe_under = option_env!("RUNNING_UNDER_RD");
    maybe_under.is_some()
}

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

fn xsave_layout_from_trace() -> XSaveLayout {
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
