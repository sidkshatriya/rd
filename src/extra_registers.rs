use crate::gdb_register::*;
use crate::kernel_abi::x64;
use crate::kernel_abi::x86;
use crate::kernel_abi::SupportedArch;
use crate::kernel_abi::SupportedArch::*;
use crate::kernel_metadata::xsave_feature_string;
use crate::log::LogLevel::LogError;
use crate::task::task_inner::task_inner::TaskInner;
use crate::util::{xsave_native_layout, XSaveFeatureLayout, XSaveLayout};
use std::convert::TryInto;
use std::fmt::Write;
use std::io;
use std::mem::size_of;
use std::ptr::copy_nonoverlapping;

const AVX_FEATURE_BIT: usize = 2;

const XSAVE_HEADER_OFFSET: usize = 512;
const XSAVE_HEADER_SIZE: usize = 64;
const XSAVE_HEADER_END: usize = XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE;
/// This is always at 576 since AVX is always the first optional feature,
/// if present.
const AVX_XSAVE_OFFSET: usize = 576;

/// This is the byte offset at which the ST0-7 register data begins
/// with an xsave (or fxsave) block.
const ST_REGS_OFFSET: usize = 32;
/// NB: each STx register holds 10 bytes of actual data, but each
/// occupies 16 bytes of space within (f)xsave, presumably for
/// alignment purposes.
const ST_REG_SPACE: usize = 16;

/// Byte offset at which the XMM0-15 register data begins with (f)xsave.
const XMM_REGS_OFFSET: usize = 160;
const XMM_REG_SPACE: usize = 16;

const XSAVE_FEATURE_PKRU: usize = 9;

/// The Intel documentation says that the following layout is only valid in
/// 32-bit mode, or when fxsave is executed in 64-bit mode without an
/// appropriate REX prefix.  The kernel seems to only use fxsave with the
/// REX prefix, so one would think these offsets would be different.  But
/// GDB seems happy to use these offsets, so that's what we use too.
const FXSAVE_387_CTRL_OFFSETS: [usize; 8] = [
    0,  // DREG_64_FCTRL
    2,  // DREG_64_FSTAT
    4,  // DREG_64_FTAG
    12, // DREG_64_FISEG
    8,  // DREG_64_FIOFF
    20, // DREG_64_FOSEG
    16, // DREG_64_FOOFF
    6,  // DREG_64_FOP
];

const XINUSE_OFFSET: usize = 512;

/// On a x86 64-bit kernel, these structures are initialized by an XSAVE64 or
/// FXSAVE64.
/// On a x86 32-bit kernel, they are initialized by an XSAVE or FXSAVE.
///
/// The layouts are basically the same in the first 512 bytes --- an
/// FXSAVE(64) area. The differences are:
/// -- On a 64-bit kernel, registers XMM8-XMM15 are saved, but on a 32-bit
/// kernel they are not (that space is reserved).
/// -- On a 64-bit kernel, bytes 8-15 store a 64-bit "FPU IP" address,
/// but on a 32-bit kernel they store "FPU IP/CS". Likewise,
/// bytes 16-23 store "FPU DP" or "FPU DP/DS".
/// We basically ignore these differences. If gdb requests 32-bit-specific
/// registers, we return them, assuming that the data there is valid.
///
/// XSAVE/XSAVE64 have extra information after the first 512 bytes, which we
/// currently save and restore but do not otherwise use. If the data record
/// has more than 512 bytes then it's an XSAVE(64) area, otherwise it's just
/// the FXSAVE(64) area.
///
/// The data always uses our CPU's native XSAVE layout. When reading a trace,
/// we need to convert from the trace's CPU's XSAVE layout to our layout.
#[derive(Copy, Clone, PartialEq)]
pub enum Format {
    None,
    XSave,
}

#[derive(Clone)]
pub struct ExtraRegisters {
    format_: Format,
    arch_: SupportedArch,
    data_: Vec<u8>,
}

impl ExtraRegisters {
    pub fn new(arch: SupportedArch) -> ExtraRegisters {
        ExtraRegisters {
            format_: Format::None,
            arch_: arch,
            data_: Vec::new(),
        }
    }

    /// Set values from raw data, with the given XSAVE layout. Returns false
    /// if this could not be done.
    pub fn set_to_raw_data(
        &mut self,
        a: SupportedArch,
        format: Format,
        data_from: &[u8],
        layout: XSaveLayout,
    ) -> bool {
        self.arch_ = a;
        self.format_ = format;

        if format == Format::None {
            return true;
        }

        // Now we have to convert from the input XSAVE format to our
        // native XSAVE format. Be careful to handle possibly-corrupt input data.

        let native_layout = xsave_native_layout();
        if data_from.len() != layout.full_size {
            log!(
                LogError,
                "Invalid XSAVE data length: {}, expected {}",
                data_from.len(),
                layout.full_size
            );
            return false;
        }

        self.data_.resize(native_layout.full_size, 0);
        debug_assert!(self.data_.len() >= XSAVE_HEADER_OFFSET);
        if layout.full_size < XSAVE_HEADER_OFFSET {
            log!(LogError, "Invalid XSAVE layout size: {}", layout.full_size);
            return false;
        }

        self.data_
            .get_mut(0..XSAVE_HEADER_OFFSET)
            .unwrap()
            .copy_from_slice(data_from.get(0..XSAVE_HEADER_OFFSET).unwrap());

        unsafe {
            std::ptr::write_bytes(
                self.data_.as_mut_ptr().add(XSAVE_HEADER_OFFSET),
                0,
                self.data_.len() - XSAVE_HEADER_OFFSET,
            );
        }

        // Check for unsupported features being used
        if layout.full_size >= XSAVE_HEADER_END {
            let features = features_used(data_from, &layout);
            if features & !native_layout.supported_feature_bits != 0 {
                log!(
                    LogError,
                    "Unsupported CPU features found: got {:x}\
                      ({}), supported: {:x}({});\
                      Consider using `rr cpufeatures` and \
                      `rr record --disable-cpuid-features-(ext)`",
                    features,
                    xsave_feature_string(features),
                    native_layout.supported_feature_bits,
                    xsave_feature_string(native_layout.supported_feature_bits)
                );
                return false;
            }
        }

        if native_layout.full_size < XSAVE_HEADER_END {
            // No XSAVE supported here, we're done!
            return true;
        }

        if layout.full_size < XSAVE_HEADER_END {
            // Degenerate XSAVE format without an actual XSAVE header. Assume x87+XMM
            // are in use.
            let assume_features_used: u64 = 0x3;
            self.data_
                .get_mut(XSAVE_HEADER_OFFSET..XSAVE_HEADER_OFFSET + 8)
                .unwrap()
                .copy_from_slice(&assume_features_used.to_le_bytes());
            return true;
        }

        let features: u64 = features_used(data_from, &layout);
        // OK, now both our native layout and the input layout are using the full
        // XSAVE header. Copy the header. Make sure to use our updated `features`.
        self.data_
            .get_mut(XSAVE_HEADER_OFFSET..XSAVE_HEADER_OFFSET + 8)
            .unwrap()
            .copy_from_slice(&features.to_le_bytes());

        self.data_
            .get_mut(XSAVE_HEADER_OFFSET + 8..XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE)
            .unwrap()
            .copy_from_slice(
                data_from
                    .get(XSAVE_HEADER_OFFSET + 8..XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE)
                    .unwrap(),
            );

        // Now copy each optional and present area into the right place in our struct
        for i in 2..64 {
            if features & (1 << i) != 0 {
                if i >= layout.feature_layouts.len() {
                    log!(
                        LogError,
                        "Invalid feature {} beyond max layout {}",
                        i,
                        layout.feature_layouts.len()
                    );
                    return false;
                }
                let feature = layout.feature_layouts[i];
                if feature.offset as usize + feature.size as usize > layout.full_size {
                    log!(
                        LogError,
                        "Invalid feature region: {} + {} > {}",
                        feature.offset,
                        feature.size,
                        layout.full_size
                    );
                    return false;
                }
                let native_feature = native_layout.feature_layouts[i];
                if feature.size != native_feature.size {
                    log!(
                        LogError,
                        "Feature {} has wrong size {}, expected {}",
                        i,
                        feature.size,
                        native_feature.size
                    );
                    return false;
                }
                // The CPU should guarantee these
                debug_assert!(native_feature.offset > 0);
                debug_assert!(
                    native_feature.offset as usize + native_feature.size as usize
                        <= native_layout.full_size
                );

                let native_offset = native_feature.offset as usize;
                let feature_offset = feature.offset as usize;
                let feature_size = feature.size as usize;

                self.data_
                    .get_mut(native_offset..native_offset + feature_size)
                    .unwrap()
                    .copy_from_slice(
                        data_from
                            .get(feature_offset..feature_offset + feature_size)
                            .unwrap(),
                    );
            }
        }

        return true;
    }

    pub fn format(&self) -> Format {
        self.format_
    }

    pub fn arch(&self) -> SupportedArch {
        self.arch_
    }

    /// Makes a copy of the data
    pub fn data(&self) -> Vec<u8> {
        self.data_.clone()
    }

    pub fn data_size(&self) -> usize {
        self.data_.len()
    }

    pub fn data_bytes(&self) -> &[u8] {
        self.data_.as_slice()
    }

    pub fn empty(&self) -> bool {
        self.data_.len() == 0
    }

    /// Read XSAVE `xinuse` field
    pub fn read_xinuse(&self) -> Option<u64> {
        if self.format_ != Format::XSave || self.data_.len() < 512 + size_of::<u64>() {
            return None;
        }

        let ret = u64::from_le_bytes(
            self.data_
                .get(XINUSE_OFFSET..XINUSE_OFFSET + 8)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        Some(ret)
    }

    /// Like |Registers::read_register()|, except attempts to read
    /// the value of an "extra register" (floating point / vector).
    pub fn read_register(&self, buf: &mut [u8], regno: GdbRegister) -> Option<usize> {
        if self.format_ != Format::XSave {
            return None;
        }

        let reg_data = xsave_register_data(self.arch_, regno);
        // @TODO check this. rr returns size even if offset is bad.
        if reg_data.offset.is_none() || self.empty() {
            return None;
        }

        debug_assert!(reg_data.size > 0);
        // Apparently before any AVX registers are used, the feature bit is not set
        // in the XSAVE data, so we'll just return 0 for them here.
        if reg_data.xsave_feature_bit.is_some()
            && (xsave_features(&self.data_) & (1 << reg_data.xsave_feature_bit.unwrap()) == 0)
        {
            unsafe {
                std::ptr::write_bytes(buf.as_mut_ptr(), 0, reg_data.size);
            }
        } else {
            debug_assert!(reg_data.offset.unwrap() + reg_data.size <= self.data_.len());
            let off = reg_data.offset.unwrap();
            buf.get_mut(0..reg_data.size)
                .unwrap()
                .copy_from_slice(self.data_.get(off..off + reg_data.size).unwrap());
        }

        Some(reg_data.size)
    }

    /// Get a user_fpregs_struct for a particular Arch from these ExtraRegisters.
    pub fn get_user_fpregs_struct(&self, arch: SupportedArch) -> Vec<u8> {
        debug_assert!(self.format_ == Format::XSave);
        match arch {
            X86 => {
                debug_assert!(self.data_.len() >= std::mem::size_of::<x86::user_fpxregs_struct>());
                let mut regs = x86::user_fpxregs_struct::default();
                unsafe {
                    copy_nonoverlapping(
                        self.data_.as_ptr(),
                        &mut regs as *mut _ as *mut u8,
                        size_of::<x86::user_fpxregs_struct>(),
                    );
                }

                let result = convert_fxsave_to_x86_fpregs(&regs);
                let l = std::mem::size_of::<x64::user_fpregs_struct>();
                let mut new_vec: Vec<u8> = Vec::with_capacity(l);
                // @TODO This could be made more efficient by avoiding resize and simply using set_len?
                new_vec.resize(l, 0);
                unsafe {
                    copy_nonoverlapping(&result as *const _ as *const u8, new_vec.as_mut_ptr(), l);
                }
                return new_vec;
            }
            X64 => {
                debug_assert!(self.data_.len() >= std::mem::size_of::<x64::user_fpregs_struct>());
                let l = std::mem::size_of::<x64::user_fpregs_struct>();
                let mut new_vec: Vec<u8> = Vec::with_capacity(l);
                new_vec.resize(l, 0);
                new_vec
                    .get_mut(0..l)
                    .unwrap()
                    .copy_from_slice(self.data_.get(0..l).unwrap());
                return new_vec;
            }
        }
    }

    /// Update registers from a user_fpregs_struct.
    pub fn set_user_fpregs_struct(&mut self, t: &TaskInner, arch: SupportedArch, data_from: &[u8]) {
        debug_assert!(self.format_ == Format::XSave);
        match arch {
            X86 => {
                ed_assert!(t, data_from.len() >= size_of::<x86::user_fpregs_struct>());
                ed_assert!(t, self.data_.len() >= size_of::<x86::user_fpxregs_struct>());
                let mut user_fpregs_data_from = x86::user_fpregs_struct::default();
                unsafe {
                    copy_nonoverlapping(
                        data_from.as_ptr(),
                        &mut user_fpregs_data_from as *mut _ as *mut u8,
                        size_of::<x86::user_fpregs_struct>(),
                    );
                }
                let mut result = x86::user_fpxregs_struct::default();
                convert_x86_fpregs_to_fxsave(&user_fpregs_data_from, &mut result);
                unsafe {
                    copy_nonoverlapping(
                        &result as *const _ as *const u8,
                        self.data_.as_mut_ptr(),
                        size_of::<x86::user_fpxregs_struct>(),
                    );
                }
            }
            X64 => {
                ed_assert!(t, self.data_.len() >= size_of::<x64::user_fpregs_struct>());
                ed_assert!(t, data_from.len() >= size_of::<x64::user_fpregs_struct>());
                unsafe {
                    copy_nonoverlapping(
                        data_from.as_ptr(),
                        self.data_.as_mut_ptr(),
                        size_of::<x64::user_fpregs_struct>(),
                    );
                }
            }
        }
    }

    /// Get a user_fpxregs_struct for from these ExtraRegisters.
    pub fn get_user_fpxregs_struct(&self) -> x86::user_fpxregs_struct {
        debug_assert!(self.format_ == Format::XSave);
        debug_assert!(self.arch_ == X86);
        debug_assert!(self.data_.len() >= size_of::<x86::user_fpxregs_struct>());
        let mut regs = x86::user_fpxregs_struct::default();
        unsafe {
            copy_nonoverlapping(
                self.data_.as_ptr(),
                &mut regs as *mut _ as *mut u8,
                size_of::<x86::user_fpxregs_struct>(),
            );
        }
        regs
    }

    /// Update registers from a user_fpxregs_struct.
    pub fn set_user_fpxregs_struct(&mut self, t: &TaskInner, regs: &x86::user_fpxregs_struct) {
        ed_assert!(t, self.format_ == Format::XSave);
        ed_assert!(t, self.arch_ == X86);
        ed_assert!(t, self.data_.len() >= size_of::<x86::user_fpxregs_struct>());
        unsafe {
            copy_nonoverlapping(
                regs as *const _ as *const u8,
                self.data_.as_mut_ptr(),
                size_of::<x86::user_fpxregs_struct>(),
            );
        }
    }

    pub fn write_register_file_compact(&self, f: &mut dyn io::Write) -> io::Result<()> {
        match self.arch_ {
            X86 => {
                write_regs(self, DREG_ST0, 0, 8, "st", f)?;
                write!(f, " ")?;
                write_regs(self, DREG_XMM0, DREG_YMM0H, 8, "ymm", f)?;
            }
            X64 => {
                write_regs(self, DREG_64_ST0, 0, 8, "st", f)?;
                write!(f, " ")?;
                write_regs(self, DREG_64_XMM0, DREG_64_YMM0H, 16, "ymm", f)?;
            }
        }
        Ok(())
    }

    /// Reset to post-exec initial state
    pub fn reset(&mut self) {
        debug_assert!(self.format_ == Format::XSave);
        unsafe {
            std::ptr::write_bytes(self.data_.as_mut_ptr(), 0, self.data_.len());
        }
        match self.arch() {
            X64 => {
                set_word(self.arch(), &mut self.data_, DREG_64_MXCSR, 0x1f80);
                set_word(self.arch(), &mut self.data_, DREG_64_FCTRL, 0x37f);
            }
            X86 => {
                set_word(self.arch(), &mut self.data_, DREG_MXCSR, 0x1f80);
                set_word(self.arch(), &mut self.data_, DREG_FCTRL, 0x37f);
            }
        }

        if self.data_.len() >= XINUSE_OFFSET + size_of::<u64>() {
            // We have observed (Skylake, Linux 4.10) the system setting XINUSE's 0 bit
            // to indicate x87-in-use, at times unrelated to x87 actually being used.
            // Work around this by setting the bit unconditionally after exec.
            let mut xinuse = u64::from_le_bytes(
                self.data_
                    .get(XINUSE_OFFSET..XINUSE_OFFSET + 8)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );

            xinuse = xinuse | 1;
            self.data_
                .get_mut(XINUSE_OFFSET..XINUSE_OFFSET + 8)
                .unwrap()
                .copy_from_slice(&xinuse.to_le_bytes());
        }
    }

    pub fn validate(&self, t: &TaskInner) {
        if self.format_ != Format::XSave {
            return;
        }

        ed_assert!(t, self.data_.len() >= 512);
        let mut offset: usize = 512;
        if self.data_.len() > offset {
            ed_assert!(t, self.data_.len() >= offset + 64);
            offset += 64;
            let features: u64 = xsave_features(&self.data_);
            if features & (1 << AVX_FEATURE_BIT) != 0 {
                ed_assert!(t, self.data_.len() >= offset + 256);
            }
        }
    }
}

fn features_used(data: &[u8], layout: &XSaveLayout) -> u64 {
    let mut features: u64 = u64::from_le_bytes(
        data.get(XSAVE_HEADER_OFFSET..XSAVE_HEADER_OFFSET + 8)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let pkru_bit: u64 = 1u64 << XSAVE_FEATURE_PKRU;
    if features & pkru_bit != 0 && XSAVE_FEATURE_PKRU < layout.feature_layouts.len() {
        let fl: XSaveFeatureLayout = layout.feature_layouts[XSAVE_FEATURE_PKRU];
        let fl_offset = fl.offset as usize;
        let fl_size = fl.size as usize;
        if fl_offset + fl_size as usize <= layout.full_size
            && all_zeros(data.get(fl_offset..fl_offset + fl_size).unwrap())
        {
            features = features & !pkru_bit
        }
    }

    features
}

fn all_zeros(data: &[u8]) -> bool {
    for d in data.iter() {
        if *d != 0 {
            return false;
        }
    }

    true
}

// @TODO this differs from the rr implementation a bit
// with usize instead of i32 and Options<usize> in some
// places.
struct RegData {
    offset: Option<usize>,
    size: usize,
    xsave_feature_bit: Option<usize>,
}

impl RegData {
    pub fn default() -> RegData {
        RegData {
            offset: None,
            size: 0,
            xsave_feature_bit: None,
        }
    }

    pub fn new(offset: usize, size: usize) -> RegData {
        RegData {
            offset: Some(offset),
            size: size,
            xsave_feature_bit: None,
        }
    }
}

/// Return the size and data location of register |regno|.
/// If we can't read the register, returns -1 in 'offset'.
fn xsave_register_data(arch: SupportedArch, regno_param: GdbRegister) -> RegData {
    let mut regno = regno_param;
    // Check regno is in range, and if it's 32-bit then convert it to the
    // equivalent 64-bit register.
    match arch {
        X86 => {
            // Convert regno to the equivalent 64-bit version since the XSAVE layout
            // is compatible
            if regno >= DREG_XMM0 && regno <= DREG_XMM7 {
                regno = regno - DREG_XMM0 + DREG_64_XMM0;
            } else if regno >= DREG_YMM0H && regno <= DREG_YMM7H {
                regno = regno - DREG_YMM0H + DREG_64_YMM0H;
            } else if regno < DREG_FIRST_FXSAVE_REG || regno > DREG_LAST_FXSAVE_REG {
                return RegData::default();
            } else if regno == DREG_MXCSR {
                regno = DREG_64_MXCSR;
            } else {
                regno = regno - DREG_FIRST_FXSAVE_REG + DREG_64_FIRST_FXSAVE_REG;
            }
            ()
        }
        X64 => (),
    }

    let mut result: RegData = RegData::default();
    if reg_in_range(
        regno,
        DREG_64_ST0,
        DREG_64_ST7,
        ST_REGS_OFFSET,
        ST_REG_SPACE,
        10,
        &mut result,
    ) {
        return result;
    }
    if reg_in_range(
        regno,
        DREG_64_XMM0,
        DREG_64_XMM15,
        XMM_REGS_OFFSET,
        XMM_REG_SPACE,
        16,
        &mut result,
    ) {
        return result;
    }

    if reg_in_range(
        regno,
        DREG_64_YMM0H,
        DREG_64_YMM15H,
        AVX_XSAVE_OFFSET,
        16,
        16,
        &mut result,
    ) {
        result.xsave_feature_bit = Some(AVX_FEATURE_BIT);
        return result;
    }

    if regno < DREG_64_FIRST_FXSAVE_REG || regno > DREG_64_LAST_FXSAVE_REG {
        return RegData::default();
    }
    if regno == DREG_64_MXCSR {
        return RegData::new(24, 4);
    }
    debug_assert!(regno >= DREG_64_FCTRL && regno <= DREG_64_FOP);
    // NB: most of these registers only occupy 2 bytes of space in
    // the (f)xsave region, but gdb's default x86 target
    // config expects us to send back 4 bytes of data for
    // each.
    RegData::new(
        FXSAVE_387_CTRL_OFFSETS[regno as usize - DREG_64_FCTRL as usize],
        4,
    )
}

// Note: uses usize for variables instead of i32 as in rr
fn reg_in_range(
    regno: GdbRegister,
    low: GdbRegister,
    high: GdbRegister,
    offset_base: usize,
    offset_stride: usize,
    size: usize,
    out: &mut RegData,
) -> bool {
    if regno < low || regno > high {
        return false;
    }
    out.offset = Some(offset_base + offset_stride * (regno as usize - low as usize));
    out.size = size;

    true
}

fn xsave_features(data: &[u8]) -> u64 {
    // If this is just FXSAVE(64) data then we we have no XSAVE header and no
    // XSAVE(64) features enabled.
    if data.len() < XSAVE_HEADER_OFFSET + XSAVE_HEADER_SIZE {
        0
    } else {
        let result: u64 = u64::from_le_bytes(
            data.get(XSAVE_HEADER_OFFSET..XSAVE_HEADER_OFFSET + 8)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        result
    }
}

fn convert_fxsave_to_x86_fpregs(buf: &x86::user_fpxregs_struct) -> x86::user_fpregs_struct {
    let mut result = x86::user_fpregs_struct::default();

    for i in 0..8 {
        unsafe {
            // @TODO check this. Is this correct?
            copy_nonoverlapping(
                &buf.st_space[i * 4] as *const i32 as *const u8,
                std::mem::transmute::<&[i32; 20], *mut u8>(&result.st_space).add(i * 10),
                10,
            );
        }
    }

    // @TODO check this.
    result.cwd = (buf.cwd as u32 | 0xffff0000) as i32;
    result.swd = (buf.swd as u32 | 0xffff0000) as i32;
    // XXX Computing the correct twd is a pain. It probably doesn't matter to us
    // in practice.
    result.twd = 0;
    result.fip = buf.fip;
    result.fcs = buf.fcs;
    result.foo = buf.foo;
    result.fos = buf.fos;
    result
}

fn convert_x86_fpregs_to_fxsave(
    buf: &x86::user_fpregs_struct,
    result: &mut x86::user_fpxregs_struct,
) {
    for i in 0..8 {
        unsafe {
            // @TODO check this. Is this correct?
            copy_nonoverlapping(
                std::mem::transmute::<&[i32; 20], *const u8>(&buf.st_space).add(i * 10),
                &mut result.st_space[i * 4] as *mut i32 as *mut u8,
                10,
            );
        }
    }

    // @TODO check this.
    result.cwd = buf.cwd.try_into().unwrap();
    result.swd = buf.swd.try_into().unwrap();
    // XXX Computing the correct twd is a pain. It probably doesn't matter to us
    // in practice.
    result.fip = buf.fip;
    result.fcs = buf.fcs;
    result.foo = buf.foo;
    result.fos = buf.fos;
}

fn set_word(arch: SupportedArch, v: &mut [u8], r: GdbRegister, word: i32) {
    let d: RegData = xsave_register_data(arch, r);
    debug_assert!(d.size == 4);
    debug_assert!(d.offset.is_some() && d.offset.unwrap() + d.size <= v.len());
    debug_assert!(d.xsave_feature_bit.is_none());
    let d_offset = d.offset.unwrap();
    v.get_mut(d_offset..d_offset + 4)
        .unwrap()
        .copy_from_slice(&word.to_le_bytes());
}

fn write_regs(
    r: &ExtraRegisters,
    low: GdbRegister,
    hi: GdbRegister,
    num_regs: u32,
    name_base: &str,
    f: &mut dyn io::Write,
) -> io::Result<()> {
    for i in 0..num_regs {
        let mut s = String::new();
        write!(s, "{}{}", name_base, i).unwrap();
        let hip = if hi == 0 { 0 } else { hi + i };
        write_reg(r, low + i, hip, &s, f)?;
        if i < num_regs - 1 {
            write!(f, " ")?;
        }
    }

    Ok(())
}

fn write_reg(
    r: &ExtraRegisters,
    low: GdbRegister,
    hi: GdbRegister,
    name: &str,
    f: &mut dyn io::Write,
) -> io::Result<()> {
    let mut buf: [u8; 128] = [0; 128];
    let len = r.read_register(&mut buf, low);
    debug_assert!(len.is_some() && len.unwrap() <= 64);
    let mut final_len = len.unwrap();
    if hi != 0 {
        let len2 = r.read_register(buf.get_mut(len.unwrap()..).unwrap(), hi);
        if len2.is_some() {
            debug_assert!(len.unwrap() == len2.unwrap());
            final_len += len2.unwrap();
        }
    }

    let mut out = String::new();
    let mut printed_digit = false;
    let mut i = final_len as isize - 1;
    while i >= 0 {
        if !printed_digit && buf[i as usize] == 0 && i > 0 {
            continue;
        }
        if printed_digit {
            write!(out, "{:02x}", buf[i as usize]).unwrap();
        } else {
            write!(out, "{:x}", buf[i as usize]).unwrap();
        }
        printed_digit = true;
        i = i - 1;
    }
    write!(f, "{}:0x{}", name, out)
}
