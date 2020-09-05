use crate::{gdb_register::GdbRegister, registers::MAX_REG_SIZE_BYTES};

/// Represents a possibly-undefined register `name`.  `size` indicates how
/// many bytes of `value` are valid, if any.
#[derive(Clone, Debug)]
pub struct GdbRegisterValue {
    pub name: GdbRegister,
    pub value: GdbRegisterValueData,
    pub defined: bool,
    pub size: usize,
}

#[derive(Clone, Debug)]
pub enum GdbRegisterValueData {
    Value([u8; MAX_REG_SIZE_BYTES]),
    Value1(u8),
    Value2(u16),
    Value4(u32),
    Value8(u64),
}

impl GdbRegisterValue {
    pub fn value1(&self) -> u8 {
        match self.value {
            GdbRegisterValueData::Value1(v) => v,
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
    pub fn value2(&self) -> u16 {
        match self.value {
            GdbRegisterValueData::Value2(v) => v,
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
    pub fn value4(&self) -> u32 {
        match self.value {
            GdbRegisterValueData::Value4(v) => v,
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
    pub fn value8(&self) -> u64 {
        match self.value {
            GdbRegisterValueData::Value8(v) => v,
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
    pub fn value(&self) -> Vec<u8> {
        match self.value {
            GdbRegisterValueData::Value(v) => v[0..self.size].to_owned(),
            _ => panic!("Unexpected GdbRegisterValue: {:?}", self),
        }
    }
}
