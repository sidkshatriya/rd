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
