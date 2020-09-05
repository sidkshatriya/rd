use crate::{remote_ptr::RemotePtr, session::task::Task};

/// Extracted from
/// https://sourceware.org/gdb/current/onlinedocs/gdb/Bytecode-Descriptions.html
#[allow(non_camel_case_types)]
#[repr(u8)]
enum Opcode {
    OP_float = 0x01,
    OP_add = 0x02,
    OP_sub = 0x03,
    OP_mul = 0x04,
    OP_div_signed = 0x05,
    OP_div_unsigned = 0x06,
    OP_rem_signed = 0x07,
    OP_rem_unsigned = 0x08,
    OP_lsh = 0x09,
    OP_rsh_signed = 0x0a,
    OP_rsh_unsigned = 0x0b,
    OP_trace = 0x0c,
    OP_trace_quick = 0x0d,
    OP_log_not = 0x0e,
    OP_bit_and = 0x0f,
    OP_bit_or = 0x10,
    OP_bit_xor = 0x11,
    OP_bit_not = 0x12,
    OP_equal = 0x13,
    OP_less_signed = 0x14,
    OP_less_unsigned = 0x15,
    OP_ext = 0x16,
    OP_ref8 = 0x17,
    OP_ref16 = 0x18,
    OP_ref32 = 0x19,
    OP_ref64 = 0x1a,
    OP_ref_float = 0x1b,
    OP_ref_double = 0x1c,
    OP_ref_long_double = 0x1d,
    OP_l_to_d = 0x1e,
    OP_d_to_l = 0x1f,
    OP_if_goto = 0x20,
    OP_goto = 0x21,
    OP_const8 = 0x22,
    OP_const16 = 0x23,
    OP_const32 = 0x24,
    OP_const64 = 0x25,
    OP_reg = 0x26,
    OP_end = 0x27,
    OP_dup = 0x28,
    OP_pop = 0x29,
    OP_zero_ext = 0x2a,
    OP_swap = 0x2b,
    OP_getv = 0x2c,
    OP_setv = 0x2d,
    OP_tracev = 0x2e,
    OP_tracenz = 0x2f,
    OP_trace16 = 0x30,
    OP_pick = 0x32,
    OP_rot = 0x33,
    OP_printf = 0x34,
}

use crate::{
    gdb_connection::GdbRegisterValue,
    gdb_register::GdbRegister,
    gdb_server::GdbServer,
    session::task::task_common::read_val_mem,
};
use std::{
    convert::TryFrom,
    intrinsics::transmute,
    mem::size_of,
    ops::{BitOr, Shl},
};
use Opcode::*;

/// DIFF NOTE: Simply called Value in rr
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct GdbExpressionValue {
    i: i64,
}

impl GdbExpressionValue {
    pub fn new(i: i64) -> GdbExpressionValue {
        GdbExpressionValue { i }
    }
}

/// gdb has a simple bytecode language for writing expressions to be evaluated
/// in a remote target. This class implements evaluation of such expressions.
/// See https://sourceware.org/gdb/current/onlinedocs/gdb/Agent-Expressions.html
pub struct GdbExpression {
    /// To work around gdb bugs, we may generate and evaluate multiple versions of
    /// the same expression program.
    bytecode_variants: Vec<Vec<u8>>,
}

impl GdbExpression {
    /// @TODO There is a more complicated version of this method in rr that takes
    /// into account gdb bugs i.e. #ifdef WORKAROUND_GDB_BUGS. We omit that.
    pub fn new(data: &[u8]) -> GdbExpression {
        let bv = vec![data.to_owned()];
        GdbExpression {
            bytecode_variants: bv,
        }
    }

    /// If evaluation succeeds, store the final result in result and return true.
    /// Otherwise return false.
    pub fn evaluate(&self, t: &mut dyn Task, result: &mut GdbExpressionValue) -> bool {
        if self.bytecode_variants.is_empty() {
            return false;
        }

        let mut first = true;
        for b in &self.bytecode_variants {
            let mut state = ExpressionState::new(b);
            let mut steps = 0usize;
            while !state.end {
                if steps >= 10000 || state.error {
                    return false;
                }
                state.step(t);

                let v: Value = state.pop();
                if state.error {
                    return false;
                }
                if first {
                    *result = v;
                    first = false;
                } else if *result != v {
                    return false;
                }
                steps += 1;
            }
        }

        true
    }
}

type Value = GdbExpressionValue;

struct ExpressionState<'a> {
    bytecode: &'a [u8],
    stack: Vec<Value>,
    pc: usize,
    error: bool,
    end: bool,
}

struct BinaryOperands {
    a: i64,
    b: i64,
}

impl BinaryOperands {
    pub fn new(a: i64, b: i64) -> BinaryOperands {
        BinaryOperands { a, b }
    }
}

impl<'a> ExpressionState<'a> {
    pub fn new(bytecode: &[u8]) -> ExpressionState {
        ExpressionState {
            stack: Vec::new(),
            bytecode,
            pc: 0,
            error: false,
            end: false,
        }
    }

    pub fn set_error(&mut self) {
        self.error = true;
    }

    /// Methods set error to true if there's an error and return some sentinel
    /// Value.
    pub fn pop(&mut self) -> Value {
        if self.stack.is_empty() {
            self.set_error();
            return Value::new(-1);
        }
        self.stack.pop().unwrap()
    }

    pub fn pop_a_b(&mut self) -> BinaryOperands {
        let b: i64 = self.pop().i;
        BinaryOperands::new(self.pop().i, b)
    }

    pub fn nonzero(&mut self, v: i64) -> i64 {
        if v != 0 {
            self.set_error();
            return 1;
        }
        v
    }
    pub fn pop_a(&mut self) -> i64 {
        self.pop().i
    }
    pub fn push(&mut self, i: i64) {
        self.stack.push(Value::new(i));
    }

    pub fn fetch<T>(&mut self) -> T
    where
        T: Default + BitOr<T, Output = T> + From<u8> + Shl<usize, Output = T>,
    {
        if self.pc + size_of::<T>() > self.bytecode.len() {
            self.set_error();
            // DIFF NOTE: rr returns -1 which not be available for all types.
            return T::default();
        }
        let mut v = T::default();
        for i in 0..size_of::<T>() {
            v = (v << 8usize) | T::from(self.bytecode[self.pc + i]);
        }
        self.pc += size_of::<T>();
        v
    }

    pub fn load<T: Into<u64>>(&mut self, t: &mut dyn Task) {
        let addr = self.pop().i as usize;
        if self.error {
            // Don't do unnecessary syscalls if we're already in an error state.
            return;
        }
        let mut ok = true;
        let v: T = read_val_mem(t, RemotePtr::from(addr), Some(&mut ok));
        if !ok {
            self.set_error();
            return;
        }
        self.push(v.into() as i64);
    }

    pub fn pick(&mut self, offset: usize) {
        if offset >= self.stack.len() {
            self.set_error();
            return;
        }
        self.push(self.stack[self.stack.len() - 1 - offset].i);
    }

    pub fn step(&mut self, t: &mut dyn Task) {
        debug_assert!(!self.error);
        let operands: BinaryOperands;
        // @TODO Will the catch all case `_` deal with even invalid enum values?
        match unsafe { transmute(self.fetch::<u8>()) } {
            OP_add => {
                operands = self.pop_a_b();
                return self.push(operands.a + operands.b);
            }

            OP_sub => {
                operands = self.pop_a_b();
                return self.push(operands.a - operands.b);
            }

            OP_mul => {
                operands = self.pop_a_b();
                return self.push(operands.a * operands.b);
            }

            OP_div_signed => {
                operands = self.pop_a_b();
                let d = self.nonzero(operands.b);
                return self.push(operands.a / d);
            }

            OP_div_unsigned => {
                operands = self.pop_a_b();
                let d = self.nonzero(operands.b) as u64;
                return self.push((operands.a as u64 / d) as i64);
            }

            OP_rem_signed => {
                operands = self.pop_a_b();
                let b = self.nonzero(operands.b);
                return self.push(operands.a % b);
            }

            OP_rem_unsigned => {
                operands = self.pop_a_b();
                let b = self.nonzero(operands.b) as u64;
                return self.push((operands.a as u64 % b) as i64);
            }

            OP_lsh => {
                operands = self.pop_a_b();
                return self.push(operands.a << operands.b);
            }

            OP_rsh_signed => {
                operands = self.pop_a_b();
                return self.push(operands.a >> operands.b);
            }

            OP_rsh_unsigned => {
                operands = self.pop_a_b();
                return self.push((operands.a as u64 >> operands.b as u64) as i64);
            }

            OP_log_not => {
                let a = self.pop_a();
                return self.push(!a);
            }

            OP_bit_and => {
                operands = self.pop_a_b();
                return self.push(operands.a & operands.b);
            }

            OP_bit_or => {
                operands = self.pop_a_b();
                return self.push(operands.a | operands.b);
            }

            OP_bit_xor => {
                operands = self.pop_a_b();
                return self.push(operands.a ^ operands.b);
            }

            OP_bit_not => {
                let a = self.pop_a();
                return self.push(!a);
            }

            OP_equal => {
                operands = self.pop_a_b();
                return self.push(if operands.a == operands.b { 1 } else { 0 });
            }

            OP_less_signed => {
                operands = self.pop_a_b();
                return self.push(if operands.a < operands.b { 1 } else { 0 });
            }

            OP_less_unsigned => {
                operands = self.pop_a_b();
                return self.push(if (operands.a as u64) < (operands.b as u64) {
                    1
                } else {
                    0
                });
            }

            OP_ext => {
                let x = self.fetch::<u8>() as i64;
                let n = self.nonzero(x);
                if n >= 64 {
                    return;
                }
                let a = self.pop_a();
                let n_mask = (1i64 << n) - 1;
                let sign_bit = (a >> (n - 1)) & 1;
                return self.push((sign_bit * !n_mask) | (a & n_mask));
            }

            OP_zero_ext => {
                let n = self.fetch::<u8>();
                if n >= 64 {
                    return;
                }
                let a = self.pop_a();
                let n_mask: i64 = (1i64 << n as i64) - 1;
                return self.push(a & n_mask);
            }

            OP_ref8 => {
                return self.load::<u8>(t);
            }

            OP_ref16 => {
                return self.load::<u16>(t);
            }

            OP_ref32 => {
                return self.load::<u32>(t);
            }

            OP_ref64 => {
                return self.load::<u64>(t);
            }

            OP_dup => {
                return self.pick(0);
            }

            OP_swap => {
                operands = self.pop_a_b();
                self.push(operands.b);
                return self.push(operands.a);
            }

            OP_pop => {
                self.pop_a();
                return;
            }

            OP_pick => {
                let offset = self.fetch::<u8>() as usize;
                return self.pick(offset);
            }

            OP_rot => {
                let c = self.pop_a();
                let b = self.pop_a();
                let a = self.pop_a();
                self.push(c);
                self.push(b);
                return self.push(a);
            }
            OP_if_goto => {
                let offset = self.fetch::<u16>();
                if self.pop_a() != 0 {
                    self.pc = offset as usize;
                }
                return;
            }
            OP_goto => {
                self.pc = self.fetch::<u16>() as usize;
                return;
            }

            OP_const8 => {
                let a = self.fetch::<u8>() as i64;
                return self.push(a);
            }

            OP_const16 => {
                let a = self.fetch::<u16>() as i64;
                return self.push(a);
            }

            OP_const32 => {
                let a = self.fetch::<u32>() as i64;
                return self.push(a);
            }

            OP_const64 => {
                let a = self.fetch::<u64>() as i64;
                return self.push(a);
            }

            OP_reg => {
                let r = match GdbRegister::try_from(self.fetch::<u16>() as u32) {
                    Ok(r) => r,
                    Err(_e) => {
                        self.set_error();
                        return;
                    }
                };
                let extra_regs = t.extra_regs_ref().clone();
                let v: GdbRegisterValue = GdbServer::get_reg(t.regs_ref(), &extra_regs, r);

                if !v.defined {
                    self.set_error();
                    return;
                }

                return match v.size {
                    1 => self.push(v.value1() as i64),
                    2 => self.push(v.value2() as i64),
                    4 => self.push(v.value4() as i64),
                    8 => self.push(v.value8() as i64),
                    _ => {
                        self.set_error();
                        return;
                    }
                };
            }

            OP_end => {
                self.end = true;
                return;
            }
            // @TODO Does the transmute play well with this?
            _ => {
                self.set_error();
                return;
            }
        }
    }
}
