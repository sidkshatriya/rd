use super::{exit_result::ExitResult, gdb_command_handler::GdbCommandHandler, RdCommand};
use crate::{gdb_server::GdbServer, replay_timeline::Mark, session::task::Task};
use std::{
    fmt::Write,
    ops::{Deref, DerefMut},
};

/// DIFF NOTE: Simply called GdbCommand in rr
pub struct BaseGdbCommand {
    /// @TODO Do we want a OsString here?
    cmd_name: String,
    /// @TODO Do we want a OsString here?
    documentation: String,
    /// @TODO Do we want a OsString here?
    cmd_auto_args: Vec<String>,
}

impl BaseGdbCommand {
    pub fn name(&self) -> &str {
        &self.cmd_name
    }
    pub fn docs(&self) -> &str {
        &self.documentation
    }

    /// When called, gdb will automatically run gdb.execute() on this string and
    /// pass it as an argument to the rr command. This is useful to pass gdb
    /// state alongside the command invocation.
    pub fn add_auto_arg(&mut self, auto_arg: &str) {
        self.cmd_auto_args.push(auto_arg.to_owned());
    }

    pub fn auto_args(&self) -> &[String] {
        &self.cmd_auto_args
    }

    /// Setup all the automatic auto_args for our commands.
    pub fn init_auto_args() {
        unimplemented!()
    }
}

trait GdbCommand: DerefMut<Target = BaseGdbCommand> {
    /// Handle the RD Cmd and return a string response to be echo'd
    /// to the user.
    ///
    /// NOTE: args[0] is the command name
    fn invoke(&self, gdb_server: &GdbServer, t: &dyn Task, args: &[String]) -> String;
}

impl RdCommand for BaseGdbCommand {
    fn run(&mut self) -> ExitResult<()> {
        unimplemented!()
    }
}

type InvokerFn = dyn Fn(&GdbServer, &dyn Task, &[String]) -> String;

struct SimpleGdbCommand {
    base_gdb_command: BaseGdbCommand,
    invoker: &'static InvokerFn,
}

/// @TODO Check if this causes any problems
unsafe impl Sync for SimpleGdbCommand {}

impl SimpleGdbCommand {
    pub fn new(
        cmd_name: &str,
        documentation: &str,
        invoker: &'static InvokerFn,
    ) -> SimpleGdbCommand {
        SimpleGdbCommand {
            base_gdb_command: BaseGdbCommand {
                cmd_name: cmd_name.to_owned(),
                documentation: documentation.to_owned(),
                cmd_auto_args: Default::default(),
            },
            invoker,
        }
    }
}

impl Deref for SimpleGdbCommand {
    type Target = BaseGdbCommand;

    fn deref(&self) -> &Self::Target {
        &self.base_gdb_command
    }
}

impl DerefMut for SimpleGdbCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base_gdb_command
    }
}

impl GdbCommand for SimpleGdbCommand {
    fn invoke(&self, gdb_server: &GdbServer, t: &dyn Task, args: &[String]) -> String {
        (self.invoker)(gdb_server, t, args)
    }
}

lazy_static! {
    static ref ELAPSED_TIME: SimpleGdbCommand = SimpleGdbCommand::new(
        "elapsed-time",
        "Print elapsed time (in seconds) since the start of the trace, in the 'record' timeline.",
        &elapsed_time,
    );
    static ref WHEN: SimpleGdbCommand =
        SimpleGdbCommand::new("when", "Print the current rd event number.", &when_fn);
    static ref WHEN_TICKS: SimpleGdbCommand = SimpleGdbCommand::new(
        "when-ticks",
        "Print the current rd tick count for the current thread.",
        &when_ticks,
    );
    static ref WHEN_TID: SimpleGdbCommand = SimpleGdbCommand::new(
        "when-tid",
        "Print the real tid for the current thread.",
        &when_tid,
    );
    static ref RD_HISTORY_PUSH: SimpleGdbCommand = SimpleGdbCommand::new(
        "rd-history-push",
        "Push an entry into the rd history.",
        &rd_history_push,
    );
    static ref BACK: SimpleGdbCommand =
        SimpleGdbCommand::new("back", "Go back one entry in the rd history.", &back,);
    static ref FORWARD: SimpleGdbCommand = SimpleGdbCommand::new(
        "forward",
        "Go forward one entry in the rd history.",
        &forward
    );
}

fn elapsed_time(_: &GdbServer, t: &dyn Task, _: &[String]) -> String {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion().to_owned();
    }

    let replay_t = t.as_replay_task().unwrap();
    let elapsed_time: f64 = replay_t.current_trace_frame().monotonic_time()
        - replay_t
            .session()
            .as_replay()
            .unwrap()
            .get_trace_start_time();

    let mut rets = String::new();
    write!(rets, "Elapsed Time (s): {}", elapsed_time).unwrap();
    rets
}

fn when_fn(_: &GdbServer, t: &dyn Task, _: &[String]) -> String {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion().to_owned();
    }
    let mut rets = String::new();
    write!(
        rets,
        "Current event: {}",
        t.as_replay_task().unwrap().current_trace_frame().time()
    )
    .unwrap();
    rets
}

fn when_ticks(_: &GdbServer, t: &dyn Task, _: &[String]) -> String {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion().to_owned();
    }

    let mut rets = String::new();
    write!(rets, "Current ticks: {}", t.tick_count()).unwrap();
    rets
}

fn when_tid(_: &GdbServer, t: &dyn Task, _: &[String]) -> String {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion().to_owned();
    }

    let mut rets = String::new();
    write!(rets, "Current tid: {}", t.tid).unwrap();
    rets
}

static mut BACK_STACK: Vec<Mark> = Vec::new();
static mut CURRENT_HISTORY_CP: Option<Mark> = None;
static mut FORWARD_STACK: Vec<Mark> = Vec::new();

fn rd_history_push(gdb_server: &GdbServer, t: &dyn Task, _: &[String]) -> String {
    if !t.session().is_replaying() {
        // Don't create new history state inside a diversion
        return String::new();
    }

    // @TODO Avoid unsafe?
    unsafe {
        if CURRENT_HISTORY_CP.is_some() {
            BACK_STACK.push(CURRENT_HISTORY_CP.as_ref().unwrap().clone());
        }

        CURRENT_HISTORY_CP = Some(gdb_server.get_timeline_mut().mark());
        FORWARD_STACK.clear();
    }

    String::new()
}

fn back(gdb_server: &GdbServer, t: &dyn Task, _: &[String]) -> String {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion().to_owned();
    }
    // @TODO Avoid unsafe?
    unsafe {
        if BACK_STACK.len() == 0 {
            return "Can't go back. No more history entries.".to_owned();
        }
        FORWARD_STACK.push(CURRENT_HISTORY_CP.as_ref().unwrap().clone());
        CURRENT_HISTORY_CP = Some(BACK_STACK.pop().unwrap());

        gdb_server
            .get_timeline_mut()
            .seek_to_mark(CURRENT_HISTORY_CP.as_ref().unwrap());
    }
    String::new()
}

fn forward(gdb_server: &GdbServer, t: &dyn Task, _: &[String]) -> String {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion().to_owned();
    }
    // @TODO Avoid unsafe?
    unsafe {
        if FORWARD_STACK.len() == 0 {
            return "Can't go forward. No more history entries.".to_owned();
        }
        BACK_STACK.push(CURRENT_HISTORY_CP.as_ref().unwrap().clone());
        CURRENT_HISTORY_CP = Some(FORWARD_STACK.pop().unwrap());
        gdb_server
            .get_timeline_mut()
            .seek_to_mark(CURRENT_HISTORY_CP.as_ref().unwrap());
    }

    String::new()
}
