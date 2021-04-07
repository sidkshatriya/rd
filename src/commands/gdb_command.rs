use super::{exit_result::ExitResult, gdb_command_handler::GdbCommandHandler, RdCommand};
use crate::{
    commands::gdb_server::{Checkpoint, ExplicitCheckpoint, GdbServer},
    replay_timeline::Mark,
    session::task::Task,
};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::Write,
    ops::{Deref, DerefMut},
    os::unix::ffi::OsStringExt,
    sync::atomic::{AtomicUsize, Ordering},
};

/// DIFF NOTE: Simply called GdbCommand in rr
pub struct BaseGdbCommand {
    cmd_name: String,
    documentation: String,
    cmd_auto_args: Vec<OsString>,
}

impl BaseGdbCommand {
    pub fn name(&self) -> &str {
        &self.cmd_name
    }

    pub fn docs(&self) -> &str {
        &self.documentation
    }

    /// When called, gdb will automatically run gdb.execute() on this string and
    /// pass it as an argument to the rd command. This is useful to pass gdb
    /// state alongside the command invocation.
    pub fn add_auto_arg(&mut self, auto_arg: &OsStr) {
        self.cmd_auto_args.push(auto_arg.to_owned());
    }

    pub fn auto_args(&self) -> &[OsString] {
        &self.cmd_auto_args
    }

    /// Setup all the automatic auto_args for our commands.
    pub fn init_auto_args() {
        unimplemented!()
    }
}

pub trait GdbCommand: DerefMut<Target = BaseGdbCommand> {
    /// Handle the RD Cmd and return a string response to be echo'd
    /// to the user.
    ///
    /// NOTE: args[0] is the command name
    fn invoke(&self, gdb_server: &mut GdbServer, t: &dyn Task, args: &[OsString]) -> OsString;
}

impl RdCommand for BaseGdbCommand {
    fn run(&mut self) -> ExitResult<()> {
        unimplemented!()
    }
}

type InvokerFn = dyn Fn(&mut GdbServer, &dyn Task, &[OsString]) -> OsString;

struct SimpleGdbCommand {
    base_gdb_command: BaseGdbCommand,
    invoker: &'static InvokerFn,
}

/// @TODO Check if this causes any problems
unsafe impl Sync for SimpleGdbCommand {}

impl SimpleGdbCommand {
    pub fn new(
        cmd_name: String,
        documentation: &str,
        invoker: &'static InvokerFn,
    ) -> SimpleGdbCommand {
        SimpleGdbCommand {
            base_gdb_command: BaseGdbCommand {
                cmd_name,
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
    fn invoke(&self, gdb_server: &mut GdbServer, t: &dyn Task, args: &[OsString]) -> OsString {
        (self.invoker)(gdb_server, t, args)
    }
}

lazy_static! {
    static ref GDB_COMMAND_LIST: GdbCommandListWrapper =
        GdbCommandListWrapper(gdb_command_list_init());
}

struct GdbCommandListWrapper(HashMap<String, Box<dyn GdbCommand>>);

/// Done to satisfy error in lazy_static!()
/// Should be OK since everything should be one thread
unsafe impl Sync for GdbCommandListWrapper {}

impl Deref for GdbCommandListWrapper {
    type Target = HashMap<String, Box<dyn GdbCommand>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for GdbCommandListWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(super) fn gdb_command_list() -> &'static HashMap<String, Box<dyn GdbCommand>> {
    GDB_COMMAND_LIST.deref()
}

fn gdb_command_list_init() -> HashMap<String, Box<dyn GdbCommand>> {
    let mut command_list: HashMap<String, Box<dyn GdbCommand>> = HashMap::new();

    command_list.insert(String::from("elapsed-time"), Box::new(SimpleGdbCommand::new(
        String::from("elapsed-time"),
        "Print elapsed time (in seconds) since the start of the trace, in the 'record' timeline.",
        &elapsed_time,
    )));

    command_list.insert(
        String::from("when"),
        Box::new(SimpleGdbCommand::new(
            String::from("when"),
            "Print the current rd event number.",
            &when_fn,
        )),
    );

    command_list.insert(
        String::from("when-ticks"),
        Box::new(SimpleGdbCommand::new(
            String::from("when-ticks"),
            "Print the current rd tick count for the current thread.",
            &when_ticks,
        )),
    );

    command_list.insert(
        String::from("when-tid"),
        Box::new(SimpleGdbCommand::new(
            String::from("when-tid"),
            "Print the real tid for the current thread.",
            &when_tid,
        )),
    );

    command_list.insert(
        String::from("rd-history-push"),
        Box::new(SimpleGdbCommand::new(
            String::from("rd-history-push"),
            "Push an entry into the rd history.",
            &rd_history_push,
        )),
    );

    command_list.insert(
        String::from("back"),
        Box::new(SimpleGdbCommand::new(
            String::from("back"),
            "Go back one entry in the rd history.",
            &back,
        )),
    );

    command_list.insert(
        String::from("forward"),
        Box::new(SimpleGdbCommand::new(
            String::from("forward"),
            "Go forward one entry in the rd history.",
            &forward,
        )),
    );

    command_list.insert(
        String::from("checkpoint"),
        Box::new(SimpleGdbCommand::new(
            String::from("checkpoint"),
            "create a checkpoint representing a point in the execution\n",
            &invoke_checkpoint,
        )),
    );

    command_list
}

fn elapsed_time(_: &mut GdbServer, t: &dyn Task, _: &[OsString]) -> OsString {
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

    let mut rets = Vec::<u8>::new();
    write!(rets, "Elapsed Time (s): {}", elapsed_time).unwrap();
    OsString::from_vec(rets)
}

fn when_fn(_: &mut GdbServer, t: &dyn Task, _: &[OsString]) -> OsString {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion();
    }
    let mut rets = Vec::<u8>::new();
    write!(
        rets,
        "Current event: {}",
        t.as_replay_task().unwrap().current_trace_frame().time()
    )
    .unwrap();
    OsString::from_vec(rets)
}

fn when_ticks(_: &mut GdbServer, t: &dyn Task, _: &[OsString]) -> OsString {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion();
    }

    let mut rets = Vec::<u8>::new();
    write!(rets, "Current ticks: {}", t.tick_count()).unwrap();
    OsString::from_vec(rets)
}

fn when_tid(_: &mut GdbServer, t: &dyn Task, _: &[OsString]) -> OsString {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion();
    }

    let mut rets = Vec::<u8>::new();
    write!(rets, "Current tid: {}", t.tid).unwrap();
    OsString::from_vec(rets)
}

static mut BACK_STACK: Vec<Mark> = Vec::new();
static mut CURRENT_HISTORY_CP: Option<Mark> = None;
static mut FORWARD_STACK: Vec<Mark> = Vec::new();

fn rd_history_push(gdb_server: &mut GdbServer, t: &dyn Task, _: &[OsString]) -> OsString {
    if !t.session().is_replaying() {
        // Don't create new history state inside a diversion
        return OsString::new();
    }

    // @TODO Avoid unsafe?
    unsafe {
        if CURRENT_HISTORY_CP.is_some() {
            BACK_STACK.push(CURRENT_HISTORY_CP.as_ref().unwrap().clone());
        }

        CURRENT_HISTORY_CP = Some(gdb_server.get_timeline_mut().mark());
        FORWARD_STACK.clear();
    }

    OsString::new()
}

fn back(gdb_server: &mut GdbServer, t: &dyn Task, _: &[OsString]) -> OsString {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion();
    }
    // @TODO Avoid unsafe?
    unsafe {
        if BACK_STACK.len() == 0 {
            return OsString::from("Can't go back. No more history entries.");
        }
        FORWARD_STACK.push(CURRENT_HISTORY_CP.as_ref().unwrap().clone());
        CURRENT_HISTORY_CP = Some(BACK_STACK.pop().unwrap());

        gdb_server
            .get_timeline_mut()
            .seek_to_mark(CURRENT_HISTORY_CP.as_ref().unwrap());
    }
    OsString::new()
}

fn forward(gdb_server: &mut GdbServer, t: &dyn Task, _: &[OsString]) -> OsString {
    if !t.session().is_replaying() {
        return GdbCommandHandler::cmd_end_diversion();
    }
    // @TODO Avoid unsafe?
    unsafe {
        if FORWARD_STACK.len() == 0 {
            return OsString::from("Can't go forward. No more history entries.");
        }
        BACK_STACK.push(CURRENT_HISTORY_CP.as_ref().unwrap().clone());
        CURRENT_HISTORY_CP = Some(FORWARD_STACK.pop().unwrap());
        gdb_server
            .get_timeline_mut()
            .seek_to_mark(CURRENT_HISTORY_CP.as_ref().unwrap());
    }

    OsString::new()
}

fn invoke_checkpoint(gdb_server: &mut GdbServer, _t: &dyn Task, args: &[OsString]) -> OsString {
    static NEXT_CHECKPOINT_ID: AtomicUsize = AtomicUsize::new(0);
    let where_ = &args[1];
    let checkpoint_id = NEXT_CHECKPOINT_ID.fetch_add(1, Ordering::SeqCst);

    let e = if gdb_server.get_timeline().can_add_checkpoint() {
        ExplicitCheckpoint::Explicit
    } else {
        ExplicitCheckpoint::NotExplicit
    };
    let checkpoint = Checkpoint::new(
        &mut gdb_server.get_timeline_mut(),
        gdb_server.last_continue_tuid,
        e,
        where_,
    );
    gdb_server.checkpoints.insert(checkpoint_id, checkpoint);
    let mut rets = Vec::<u8>::new();
    write!(rets, "Checkpoint {} at {:?}", checkpoint_id, where_).unwrap();
    OsString::from_vec(rets)
}
