use crate::{
    commands::{
        gdb_command::{gdb_command_map, BaseGdbCommand, GdbCommand},
        gdb_server::GdbServer,
    },
    log::LogDebug,
    session::task::Task,
    util::{find, str16_to_usize},
};
use std::{ffi::OsString, io::Write, os::unix::ffi::OsStringExt};

pub struct GdbCommandHandler;

impl GdbCommandHandler {
    /// Declare any registered command with supporting
    /// wrapper code.
    pub fn gdb_macros() -> String {
        BaseGdbCommand::init_auto_args();
        let mut ss = String::new();
        let s = r##"set python print-stack full
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
"##;

        ss.push_str(s);

        for it in gdb_command_map().values() {
            ss.push_str(&gdb_macro_binding(it));
        }

        ss.push_str(
            r##"define hookpost-back
frame
end

define hookpost-forward
frame
end
"##,
        );
        ss
    }

    /// Process an incoming GDB payload of the following form:
    ///   <command name>:<arg1>:<arg2>:...
    ///
    /// NOTE: RD Commands are typically sent with the qRDCmd: prefix which
    /// should have been stripped already.
    pub fn process_command(gdb_server: &mut GdbServer, t: &dyn Task, payload: &[u8]) -> Vec<u8> {
        let args = parse_cmd(payload);
        let name = args[0].clone().into_string().unwrap();
        let maybe_cmd = Self::command_for_name(&name);
        match maybe_cmd {
            None => {
                let mut msg: Vec<u8> = Vec::new();
                writeln!(msg, "Command {:?} not found.", args[0]).unwrap();
                gdb_escape(&msg)
            }
            Some(cmd) => {
                log!(LogDebug, "invoking command: {:?}", cmd.name());
                let resp = cmd.invoke(gdb_server, t, &args);

                if resp == GdbCommandHandler::cmd_end_diversion() {
                    log!(LogDebug, "cmd must run outside of diversion ({:?})", resp);
                    return OsString::into_vec(resp);
                }

                log!(LogDebug, "cmd response: {:?}", resp);
                let mut res = OsString::into_vec(resp);
                res.push(b'\n');
                gdb_escape(&res)
            }
        }
    }

    pub fn command_for_name(name: &str) -> Option<&dyn GdbCommand> {
        if let Some(v) = gdb_command_map().get(name) {
            Some(&**v)
        } else {
            None
        }
    }

    /// Special return value for commands that immediately ends a diversion session
    pub fn cmd_end_diversion() -> OsString {
        OsString::from("RDCmd_EndDiversion")
    }
}

/// Use the simplest two hex character by byte encoding
fn gdb_escape(s: &[u8]) -> Vec<u8> {
    let mut ss = Vec::new();
    for &b in s {
        write!(ss, "{:02x}", b).unwrap();
    }
    ss
}

fn gdb_unescape(mut s: &[u8]) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    let mut ss = Vec::new();
    while s.len() >= 2 {
        let mut ignore = Default::default();
        let val: u8 = str16_to_usize(&s[0..2], &mut ignore).unwrap() as u8;
        assert_eq!(ignore.len(), 0);
        ss.push(val);
        s = &s[2..];
    }
    ss
}

fn parse_cmd(mut s: &[u8]) -> Vec<OsString> {
    let mut args: Vec<OsString> = Vec::new();
    while let Some(pos) = find(s, b":") {
        args.push(OsString::from_vec(gdb_unescape(&s[0..pos])));
        s = &s[pos + 1..];
    }
    if !s.is_empty() {
        args.push(OsString::from_vec(gdb_unescape(s)));
    }
    args
}

fn gdb_macro_binding(cmd: &Box<dyn GdbCommand>) -> String {
    let mut auto_args_str = String::from("[");
    for (i, arg) in cmd.auto_args().iter().enumerate() {
        if i > 0 {
            auto_args_str.push_str(", ");
        }
        auto_args_str.push_str(&format!("{:?}", arg));
    }
    auto_args_str.push(']');
    let mut ret = format!("python RDCmd('{}', {})\n", cmd.name(), auto_args_str);
    if !cmd.docs().is_empty() {
        ret.push_str(&format!("document {}\n{}\nend\n", cmd.name(), cmd.docs()));
    }

    ret
}
