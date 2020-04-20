#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use static_assertions::_core::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result};
use std::ops::{Add, Sub};
use std::result;

include!(concat!(
    env!("OUT_DIR"),
    "/gdb_register_bindings_generated.rs"
));

/// The inner u32 is deliberately NOT pub. We don't want others to manually construct arbitrary
/// GdbRegister structs. They need to go through the provided interfaces.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct GdbRegister(u32);

pub const DREG_EAX: GdbRegister = GdbRegister(__DREG_EAX);
pub const DREG_ECX: GdbRegister = GdbRegister(__DREG_ECX);
pub const DREG_EDX: GdbRegister = GdbRegister(__DREG_EDX);
pub const DREG_EBX: GdbRegister = GdbRegister(__DREG_EBX);
pub const DREG_ESP: GdbRegister = GdbRegister(__DREG_ESP);
pub const DREG_EBP: GdbRegister = GdbRegister(__DREG_EBP);
pub const DREG_ESI: GdbRegister = GdbRegister(__DREG_ESI);
pub const DREG_EDI: GdbRegister = GdbRegister(__DREG_EDI);
pub const DREG_EIP: GdbRegister = GdbRegister(__DREG_EIP);
pub const DREG_EFLAGS: GdbRegister = GdbRegister(__DREG_EFLAGS);
pub const DREG_CS: GdbRegister = GdbRegister(__DREG_CS);
pub const DREG_SS: GdbRegister = GdbRegister(__DREG_SS);
pub const DREG_DS: GdbRegister = GdbRegister(__DREG_DS);
pub const DREG_ES: GdbRegister = GdbRegister(__DREG_ES);
pub const DREG_FS: GdbRegister = GdbRegister(__DREG_FS);
pub const DREG_GS: GdbRegister = GdbRegister(__DREG_GS);
pub const DREG_FIRST_FXSAVE_REG: GdbRegister = GdbRegister(__DREG_FIRST_FXSAVE_REG);
pub const DREG_ST0: GdbRegister = GdbRegister(__DREG_ST0);
pub const DREG_ST1: GdbRegister = GdbRegister(__DREG_ST1);
pub const DREG_ST2: GdbRegister = GdbRegister(__DREG_ST2);
pub const DREG_ST3: GdbRegister = GdbRegister(__DREG_ST3);
pub const DREG_ST4: GdbRegister = GdbRegister(__DREG_ST4);
pub const DREG_ST5: GdbRegister = GdbRegister(__DREG_ST5);
pub const DREG_ST6: GdbRegister = GdbRegister(__DREG_ST6);
pub const DREG_ST7: GdbRegister = GdbRegister(__DREG_ST7);
pub const DREG_FCTRL: GdbRegister = GdbRegister(__DREG_FCTRL);
pub const DREG_FSTAT: GdbRegister = GdbRegister(__DREG_FSTAT);
pub const DREG_FTAG: GdbRegister = GdbRegister(__DREG_FTAG);
pub const DREG_FISEG: GdbRegister = GdbRegister(__DREG_FISEG);
pub const DREG_FIOFF: GdbRegister = GdbRegister(__DREG_FIOFF);
pub const DREG_FOSEG: GdbRegister = GdbRegister(__DREG_FOSEG);
pub const DREG_FOOFF: GdbRegister = GdbRegister(__DREG_FOOFF);
pub const DREG_FOP: GdbRegister = GdbRegister(__DREG_FOP);
pub const DREG_XMM0: GdbRegister = GdbRegister(__DREG_XMM0);
pub const DREG_XMM1: GdbRegister = GdbRegister(__DREG_XMM1);
pub const DREG_XMM2: GdbRegister = GdbRegister(__DREG_XMM2);
pub const DREG_XMM3: GdbRegister = GdbRegister(__DREG_XMM3);
pub const DREG_XMM4: GdbRegister = GdbRegister(__DREG_XMM4);
pub const DREG_XMM5: GdbRegister = GdbRegister(__DREG_XMM5);
pub const DREG_XMM6: GdbRegister = GdbRegister(__DREG_XMM6);
pub const DREG_XMM7: GdbRegister = GdbRegister(__DREG_XMM7);
pub const DREG_MXCSR: GdbRegister = GdbRegister(__DREG_MXCSR);
pub const DREG_LAST_FXSAVE_REG: GdbRegister = GdbRegister(__DREG_LAST_FXSAVE_REG);
pub const DREG_ORIG_EAX: GdbRegister = GdbRegister(__DREG_ORIG_EAX);
pub const DREG_YMM0H: GdbRegister = GdbRegister(__DREG_YMM0H);
pub const DREG_YMM1H: GdbRegister = GdbRegister(__DREG_YMM1H);
pub const DREG_YMM2H: GdbRegister = GdbRegister(__DREG_YMM2H);
pub const DREG_YMM3H: GdbRegister = GdbRegister(__DREG_YMM3H);
pub const DREG_YMM4H: GdbRegister = GdbRegister(__DREG_YMM4H);
pub const DREG_YMM5H: GdbRegister = GdbRegister(__DREG_YMM5H);
pub const DREG_YMM6H: GdbRegister = GdbRegister(__DREG_YMM6H);
pub const DREG_YMM7H: GdbRegister = GdbRegister(__DREG_YMM7H);
pub const DREG_RAX: GdbRegister = GdbRegister(__DREG_RAX);
pub const DREG_RBX: GdbRegister = GdbRegister(__DREG_RBX);
pub const DREG_RCX: GdbRegister = GdbRegister(__DREG_RCX);
pub const DREG_RDX: GdbRegister = GdbRegister(__DREG_RDX);
pub const DREG_RSI: GdbRegister = GdbRegister(__DREG_RSI);
pub const DREG_RDI: GdbRegister = GdbRegister(__DREG_RDI);
pub const DREG_RBP: GdbRegister = GdbRegister(__DREG_RBP);
pub const DREG_RSP: GdbRegister = GdbRegister(__DREG_RSP);
pub const DREG_R8: GdbRegister = GdbRegister(__DREG_R8);
pub const DREG_R9: GdbRegister = GdbRegister(__DREG_R9);
pub const DREG_R10: GdbRegister = GdbRegister(__DREG_R10);
pub const DREG_R11: GdbRegister = GdbRegister(__DREG_R11);
pub const DREG_R12: GdbRegister = GdbRegister(__DREG_R12);
pub const DREG_R13: GdbRegister = GdbRegister(__DREG_R13);
pub const DREG_R14: GdbRegister = GdbRegister(__DREG_R14);
pub const DREG_R15: GdbRegister = GdbRegister(__DREG_R15);
pub const DREG_RIP: GdbRegister = GdbRegister(__DREG_RIP);
pub const DREG_64_EFLAGS: GdbRegister = GdbRegister(__DREG_64_EFLAGS);
pub const DREG_64_CS: GdbRegister = GdbRegister(__DREG_64_CS);
pub const DREG_64_SS: GdbRegister = GdbRegister(__DREG_64_SS);
pub const DREG_64_DS: GdbRegister = GdbRegister(__DREG_64_DS);
pub const DREG_64_ES: GdbRegister = GdbRegister(__DREG_64_ES);
pub const DREG_64_FS: GdbRegister = GdbRegister(__DREG_64_FS);
pub const DREG_64_GS: GdbRegister = GdbRegister(__DREG_64_GS);
pub const DREG_64_FIRST_FXSAVE_REG: GdbRegister = GdbRegister(__DREG_64_FIRST_FXSAVE_REG);
pub const DREG_64_ST0: GdbRegister = GdbRegister(__DREG_64_ST0);
pub const DREG_64_ST1: GdbRegister = GdbRegister(__DREG_64_ST1);
pub const DREG_64_ST2: GdbRegister = GdbRegister(__DREG_64_ST2);
pub const DREG_64_ST3: GdbRegister = GdbRegister(__DREG_64_ST3);
pub const DREG_64_ST4: GdbRegister = GdbRegister(__DREG_64_ST4);
pub const DREG_64_ST5: GdbRegister = GdbRegister(__DREG_64_ST5);
pub const DREG_64_ST6: GdbRegister = GdbRegister(__DREG_64_ST6);
pub const DREG_64_ST7: GdbRegister = GdbRegister(__DREG_64_ST7);
pub const DREG_64_FCTRL: GdbRegister = GdbRegister(__DREG_64_FCTRL);
pub const DREG_64_FSTAT: GdbRegister = GdbRegister(__DREG_64_FSTAT);
pub const DREG_64_FTAG: GdbRegister = GdbRegister(__DREG_64_FTAG);
pub const DREG_64_FISEG: GdbRegister = GdbRegister(__DREG_64_FISEG);
pub const DREG_64_FIOFF: GdbRegister = GdbRegister(__DREG_64_FIOFF);
pub const DREG_64_FOSEG: GdbRegister = GdbRegister(__DREG_64_FOSEG);
pub const DREG_64_FOOFF: GdbRegister = GdbRegister(__DREG_64_FOOFF);
pub const DREG_64_FOP: GdbRegister = GdbRegister(__DREG_64_FOP);
pub const DREG_64_XMM0: GdbRegister = GdbRegister(__DREG_64_XMM0);
pub const DREG_64_XMM1: GdbRegister = GdbRegister(__DREG_64_XMM1);
pub const DREG_64_XMM2: GdbRegister = GdbRegister(__DREG_64_XMM2);
pub const DREG_64_XMM3: GdbRegister = GdbRegister(__DREG_64_XMM3);
pub const DREG_64_XMM4: GdbRegister = GdbRegister(__DREG_64_XMM4);
pub const DREG_64_XMM5: GdbRegister = GdbRegister(__DREG_64_XMM5);
pub const DREG_64_XMM6: GdbRegister = GdbRegister(__DREG_64_XMM6);
pub const DREG_64_XMM7: GdbRegister = GdbRegister(__DREG_64_XMM7);
pub const DREG_64_XMM8: GdbRegister = GdbRegister(__DREG_64_XMM8);
pub const DREG_64_XMM9: GdbRegister = GdbRegister(__DREG_64_XMM9);
pub const DREG_64_XMM10: GdbRegister = GdbRegister(__DREG_64_XMM10);
pub const DREG_64_XMM11: GdbRegister = GdbRegister(__DREG_64_XMM11);
pub const DREG_64_XMM12: GdbRegister = GdbRegister(__DREG_64_XMM12);
pub const DREG_64_XMM13: GdbRegister = GdbRegister(__DREG_64_XMM13);
pub const DREG_64_XMM14: GdbRegister = GdbRegister(__DREG_64_XMM14);
pub const DREG_64_XMM15: GdbRegister = GdbRegister(__DREG_64_XMM15);
pub const DREG_64_MXCSR: GdbRegister = GdbRegister(__DREG_64_MXCSR);
pub const DREG_64_LAST_FXSAVE_REG: GdbRegister = GdbRegister(__DREG_64_LAST_FXSAVE_REG);
pub const DREG_ORIG_RAX: GdbRegister = GdbRegister(__DREG_ORIG_RAX);
pub const DREG_FS_BASE: GdbRegister = GdbRegister(__DREG_FS_BASE);
pub const DREG_GS_BASE: GdbRegister = GdbRegister(__DREG_GS_BASE);
pub const DREG_64_YMM0H: GdbRegister = GdbRegister(__DREG_64_YMM0H);
pub const DREG_64_YMM1H: GdbRegister = GdbRegister(__DREG_64_YMM1H);
pub const DREG_64_YMM2H: GdbRegister = GdbRegister(__DREG_64_YMM2H);
pub const DREG_64_YMM3H: GdbRegister = GdbRegister(__DREG_64_YMM3H);
pub const DREG_64_YMM4H: GdbRegister = GdbRegister(__DREG_64_YMM4H);
pub const DREG_64_YMM5H: GdbRegister = GdbRegister(__DREG_64_YMM5H);
pub const DREG_64_YMM6H: GdbRegister = GdbRegister(__DREG_64_YMM6H);
pub const DREG_64_YMM7H: GdbRegister = GdbRegister(__DREG_64_YMM7H);
pub const DREG_64_YMM8H: GdbRegister = GdbRegister(__DREG_64_YMM8H);
pub const DREG_64_YMM9H: GdbRegister = GdbRegister(__DREG_64_YMM9H);
pub const DREG_64_YMM10H: GdbRegister = GdbRegister(__DREG_64_YMM10H);
pub const DREG_64_YMM11H: GdbRegister = GdbRegister(__DREG_64_YMM11H);
pub const DREG_64_YMM12H: GdbRegister = GdbRegister(__DREG_64_YMM12H);
pub const DREG_64_YMM13H: GdbRegister = GdbRegister(__DREG_64_YMM13H);
pub const DREG_64_YMM14H: GdbRegister = GdbRegister(__DREG_64_YMM14H);
pub const DREG_64_YMM15H: GdbRegister = GdbRegister(__DREG_64_YMM15H);

impl Display for GdbRegister {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.0)
    }
}

impl GdbRegister {
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<u32> for GdbRegister {
    type Error = ();

    fn try_from(regno: u32) -> result::Result<Self, Self::Error> {
        if regno < __DREG_NUM_LINUX_X86_64 {
            Ok(Self(regno))
        } else {
            Err(())
        }
    }
}

impl Into<usize> for GdbRegister {
    fn into(self) -> usize {
        self.as_usize()
    }
}

impl Add<Self> for GdbRegister {
    type Output = result::Result<GdbRegister, <GdbRegister as TryFrom<u32>>::Error>;

    fn add(self, rhs: Self) -> Self::Output {
        GdbRegister::try_from(self.0 + rhs.0)
    }
}

impl Sub<Self> for GdbRegister {
    type Output = result::Result<GdbRegister, <GdbRegister as TryFrom<u32>>::Error>;

    fn sub(self, rhs: Self) -> Self::Output {
        GdbRegister::try_from(self.0 - rhs.0)
    }
}

impl Add<u32> for GdbRegister {
    type Output = result::Result<GdbRegister, <GdbRegister as TryFrom<u32>>::Error>;

    fn add(self, rhs: u32) -> Self::Output {
        GdbRegister::try_from(self.0 + rhs)
    }
}

impl Sub<u32> for GdbRegister {
    type Output = result::Result<GdbRegister, <GdbRegister as TryFrom<u32>>::Error>;

    fn sub(self, rhs: u32) -> Self::Output {
        GdbRegister::try_from(self.0 - rhs)
    }
}

impl PartialOrd<u32> for GdbRegister {
    fn partial_cmp(&self, other: &u32) -> Option<Ordering> {
        if self.0 < *other {
            Some(Ordering::Less)
        } else if self.0 == *other {
            Some(Ordering::Equal)
        } else {
            Some(Ordering::Greater)
        }
    }
}

impl PartialEq<u32> for GdbRegister {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}
