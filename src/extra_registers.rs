use crate::gdb_register::GdbRegister;
use crate::kernel_abi::x86;
use crate::kernel_abi::SupportedArch;
use crate::task::Task;
use crate::util::XSaveLayout;
use std::io;
use std::io::Write;

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
#[derive(Copy, Clone)]
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
        data: &[u8],
        layout: XSaveLayout,
    ) -> bool {
        unimplemented!()
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
