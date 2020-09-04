use crate::session::task::Task;

/// DIFF NOTE: Simply called Value in rr
pub struct GdbExpressionValue {
    i: i64,
}

impl GdbExpressionValue {
    pub fn new(_i: i64) -> GdbExpressionValue {
        unimplemented!()
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
    pub fn new(_data: &[u8]) -> GdbExpression {
        unimplemented!()
    }

    /// If evaluation succeeds, store the final result in result and return true.
    /// Otherwise return false.
    pub fn evaluate(_t: &dyn Task, _result: &mut GdbExpressionValue) -> bool {
        unimplemented!()
    }
}
