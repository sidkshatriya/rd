use crate::gdb_register::GdbRegister;
use crate::kernel_abi::x86;
use crate::kernel_abi::SupportedArch;
use crate::kernel_metadata::xsave_feature_string;
use crate::log::LogLevel::LogError;
use crate::task::Task;
use crate::util::{xsave_native_layout, XSaveFeatureLayout, XSaveLayout};
use std::io;
use std::io::Write;
use std::mem::size_of_val;
use std::ptr::copy_nonoverlapping;

const AVX_FEATURE_BIT: i32 = 2;

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

        unsafe {
            copy_nonoverlapping(
                data_from.as_ptr(),
                self.data_.as_mut_ptr(),
                XSAVE_HEADER_OFFSET,
            );

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
            unsafe {
                copy_nonoverlapping(
                    &assume_features_used as *const _ as *const u8,
                    self.data_.as_mut_ptr().add(XSAVE_HEADER_OFFSET),
                    size_of_val(&assume_features_used),
                );
            }
            return true;
        }

        let features: u64 = features_used(data_from, &layout);
        // OK, now both our native layout and the input layout are using the full
        // XSAVE header. Copy the header. Make sure to use our updated `features`.
        unsafe {
            copy_nonoverlapping(
                &features as *const _ as *const u8,
                self.data_.as_mut_ptr().add(XSAVE_HEADER_OFFSET),
                size_of_val(&features),
            );

            copy_nonoverlapping(
                data_from
                    .as_ptr()
                    .add(XSAVE_HEADER_OFFSET + size_of_val(&features)),
                self.data_
                    .as_mut_ptr()
                    .add(XSAVE_HEADER_OFFSET + size_of_val(&features)),
                XSAVE_HEADER_SIZE - size_of_val(&features),
            );
        }

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
                unsafe {
                    copy_nonoverlapping(
                        data_from.as_ptr().add(feature.offset as usize),
                        self.data_.as_mut_ptr().add(native_feature.offset as usize),
                        feature.size as usize,
                    );
                }
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
        unimplemented!()
    }

    /// Like |Registers::read_register()|, except attempts to read
    /// the value of an "extra register" (floating point / vector).
    pub fn read_register(&self, buf: &mut [u8], regno: GdbRegister) -> Option<usize> {
        unimplemented!()
    }

    /// Get a user_fpregs_struct for a particular Arch from these ExtraRegisters.
    pub fn get_user_fpregs_struct(&self, arch: SupportedArch) -> Vec<u8> {
        unimplemented!()
    }

    /// Update registers from a user_fpregs_struct.
    pub fn set_user_fpregs_struct(&mut self, t: &Task, arch: SupportedArch, data: &[u8]) {
        unimplemented!()
    }

    /// Get a user_fpxregs_struct for from these ExtraRegisters.
    pub fn get_user_fpxregs_struct(&self) -> x86::user_fpxregs_struct {
        unimplemented!()
    }

    /// Update registers from a user_fpxregs_struct.
    pub fn set_user_fpxregs_struct(&mut self, t: &Task, regs: &x86::user_fpxregs_struct) {
        unimplemented!()
    }

    pub fn write_register_file_compact(&self, f: &mut dyn Write) -> io::Result<()> {
        unimplemented!()
    }

    /// Reset to post-exec initial state
    pub fn reset(&mut self) {
        unimplemented!()
    }

    pub fn validate(&self, t: &Task) {
        unimplemented!()
    }
}

fn features_used(data: &[u8], layout: &XSaveLayout) -> u64 {
    let mut features: u64 = 0;
    unsafe {
        copy_nonoverlapping(
            data.as_ptr(),
            &mut features as *mut _ as *mut u8,
            size_of_val(&features),
        );
    }

    let pkru_bit = 1 << XSAVE_FEATURE_PKRU;
    if features & pkru_bit != 0 && XSAVE_FEATURE_PKRU < layout.feature_layouts.len() {
        let fl: XSaveFeatureLayout = layout.feature_layouts[XSAVE_FEATURE_PKRU];
        if fl.offset as usize + fl.size as usize <= layout.full_size
            && all_zeros(unsafe {
                std::slice::from_raw_parts(data.as_ptr().add(fl.offset as usize), fl.size as usize)
            })
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
