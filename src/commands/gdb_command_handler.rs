use crate::{gdb_server::GdbServer, session::task::Task};
use std::rc::Rc;

use super::gdb_command::BaseGdbCommand;

pub struct GdbCommandHandler;

impl GdbCommandHandler {
    /// Declare any registered command with supporting
    /// wrapper code.
    pub fn gdb_macros() -> String {
        BaseGdbCommand::init_auto_args();
        let _s = r##"Delimiter(

set python print-stack full
python

import re

def gdb_unescape(string):
    result = ""
    pos = 0
    while pos < len(string):
        result += chr(int(string[pos:pos+2], 16))
        pos += 2
    return result

def gdb_escape(string):
    result = ""
    pos = 0
    for curr_char in string:
        result += format(ord(curr_char), '02x')
    return result

class RDWhere(gdb.Command):
    """Helper to get the location for checkpoints/history. Used by auto-args"""
    def __init__(self):
        gdb.Command.__init__(self, 'rd-where',
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)

    def invoke(self, arg, from_tty):
#Get the symbol name from 'frame 0' in the format:
# '#0  0x00007f9d81a04c46 in _dl_start (arg=0x7ffee1f1c740) at rtld.c:356
# 356 in rtld.c'
        try:
            rv = gdb.execute('frame 0', to_string=True)
        except:
            rv = "???" # This may occurs if we're not running
        m = re.match("#0\w*(.*)", rv);
        if m:
            rv = m.group(1)
        else:
            rv = rv + "???"
        gdb.write(rv)

RDWhere()

class RDCmd(gdb.Command):
    def __init__(self, name, auto_args):
        gdb.Command.__init__(self, name,
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)
        self.cmd_name = name
        self.auto_args = auto_args

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        self.rd_cmd(args)

    def rd_cmd(self, args):
        cmd_prefix = "maint packet qRDCmd:" + gdb_escape(self.cmd_name)
        argStr = ""
        for auto_arg in self.auto_args:
            argStr += ":" + gdb_escape(gdb.execute(auto_arg, to_string=True))
        for arg in args:
            argStr += ":" + gdb_escape(arg)
        rv = gdb.execute(cmd_prefix + argStr, to_string=True);
        rv_match = re.search('received: "(.*)"', rv, re.MULTILINE);
        if not rv_match:
            gdb.write("Response error: " + rv)
            return
        response = gdb_unescape(rv_match.group(1))
        gdb.write(response)

def history_push(p):
    gdb.execute("rd-history-push", to_string=True)

rd_suppress_run_hook = False

class RDHookRun(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'rd-hook-run',
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)

    def invoke(self, arg, from_tty):
      thread = int(gdb.parse_and_eval("$_thread"))
      if thread != 0 and not rd_suppress_run_hook:
        gdb.execute("stepi")

class RDSetSuppressRunHook(gdb.Command):
    def __init__(self):
        gdb.Command.__init__(self, 'rd-set-suppress-run-hook',
                             gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)

    def invoke(self, arg, from_tty):
      rd_suppress_run_hook = arg == '1'

RDHookRun()
RDSetSuppressRunHook()

#Automatically push an history entry when the program execution stops
#(signal, breakpoint).This is fired before an interactive prompt is shown.
#Disabled for now since it's not fully working.
#gdb.events.stop.connect(history_push)

end
)Delimiter"##;

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
