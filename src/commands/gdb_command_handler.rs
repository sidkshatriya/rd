use crate::{gdb_server::GdbServer, session::task::Task};
use std::rc::Rc;

use super::gdb_command::BaseGdbCommand;

pub struct GdbCommandHandler;

impl GdbCommandHandler {
    /// Declare any registered command with supporting
    /// wrapper code.
    pub fn gdb_macros() -> String {
        unimplemented!()
    }

    pub fn register_command(_cmd: &BaseGdbCommand) {
        unimplemented!()
    }

    /// Process an incoming GDB payload of the following form:
    ///   <command name>:<arg1>:<arg2>:...
    ///
    /// NOTE: RD Commands are typically sent with the qRDCmd: prefix which
    /// should have been stripped already.
    pub fn process_command(_gdb_server: &GdbServer, _t: &dyn Task, _payload: &str) -> String {
        unimplemented!()
    }

    /// @TODO Are we sure we want Rc<> here?
    pub fn command_for_name(_name: &str) -> Rc<BaseGdbCommand> {
        unimplemented!()
    }

    /// Special return value for commands that immediatly end a diversion session
    pub fn cmd_end_diversion() -> &'static str {
        "RDCmd_EndDiversion"
    }
}
