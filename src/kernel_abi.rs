#[derive(Copy, Clone)]
pub enum SupportedArch {
    X86,
    X86_64,
    // @TODO
    // What about SupportArch_Max?
}

include!(concat!(
    env!("OUT_DIR"),
    "/syscall_helper_functions_generated.rs"
));

#[cfg(target_arch = "x86_64")]
pub const RR_NATIVE_ARCH: SupportedArch = SupportedArch::X86_64;

#[cfg(target_arch = "x86")]
pub const RR_NATIVE_ARCH: SupportedArch = SupportedArch::X86;

macro_rules! rr_arch_function {
    ($func_name:ident, $arch:expr) => {
        match $arch {
            SupportedArch::X86 => crate::x86_arch::$func_name(),
            SupportedArch::X86_64 => crate::x64_arch::$func_name(),
        }
    };
    ($func_name:ident, $arch:expr, $($exp:expr),+) => {
        match $arch {
            SupportedArch::X86 => crate::x86_arch::$func_name($($exp),+),
            SupportedArch::X86_64 => crate::x64_arch::$func_name($($exp),+),
        }
    };
}

pub fn syscall_instruction_length(arch: SupportedArch) -> usize {
    match arch {
        SupportedArch::X86 => 2,
        SupportedArch::X86_64 => 2,
    }
}
