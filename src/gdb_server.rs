use crate::{
    bindings::signal::siginfo_t,
    extra_registers::ExtraRegisters,
    gdb_connection::{GdbConnection, GdbRegisterValue},
    gdb_register::GdbRegister,
    registers::Registers,
    replay_timeline::{self, ReplayTimeline},
    scoped_fd::ScopedFd,
    session::{task::Task, SessionSharedWeakPtr},
    taskish_uid::{TaskUid, ThreadGroupUid},
    thread_db::ThreadDb,
    trace::trace_frame::FrameTime,
};
use libc::pid_t;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    rc::Weak,
};

#[derive(Clone)]
pub struct Target {
    /// Target process to debug, or `None` to just debug the first process
    pub pid: Option<pid_t>,
    /// If true, wait for the target process to exec() before attaching debugger
    pub require_exec: bool,
    /// Wait until at least 'event' has elapsed before attaching
    pub event: FrameTime,
}

impl Target {
    pub fn new() -> Self {
        Self {
            pid: None,
            require_exec: false,
            event: 0,
        }
    }
}

impl Default for Target {
    fn default() -> Target {
        Target::new()
    }
}

pub struct ConnectionFlags {
    /// `None` to let GdbServer choose the port, a positive integer to select a
    /// specific port to listen on. If keep_listening is on, wait for another
    /// debugger connection after the first one is terminated.
    pub dbg_port: Option<usize>,
    pub dbg_host: OsString,
    pub keep_listening: bool,
    /// If non-null, then when the gdbserver is set up, we write its connection
    /// parameters through this pipe. GdbServer::launch_gdb is passed the
    /// other end of this pipe to exec gdb with the parameters.
    pub debugger_params_write_pipe: Weak<RefCell<ScopedFd>>,
    // Name of the debugger to suggest. Only used if debugger_params_write_pipe
    // is null.
    pub debugger_name: OsString,
}

impl Default for ConnectionFlags {
    fn default() -> ConnectionFlags {
        ConnectionFlags {
            dbg_port: None,
            dbg_host: OsString::new(),
            keep_listening: false,
            debugger_params_write_pipe: Weak::new(),
            debugger_name: OsString::new(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ExplicitCheckpoint {
    Explicit,
    NotExplicit,
}

struct Checkpoint {
    mark: replay_timeline::Mark,
    last_continue_tuid: TaskUid,
    is_explicit: ExplicitCheckpoint,
    where_: OsString,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Checkpoint {
            mark: Default::default(),
            last_continue_tuid: Default::default(),
            is_explicit: ExplicitCheckpoint::NotExplicit,
            where_: Default::default(),
        }
    }
}

impl Checkpoint {
    fn new(
        timeline: &ReplayTimeline,
        last_continue_tuid: TaskUid,
        e: ExplicitCheckpoint,
        where_: &OsStr,
    ) -> Checkpoint {
        let mark = if e == ExplicitCheckpoint::Explicit {
            timeline.add_explicit_checkpoint()
        } else {
            timeline.mark()
        };
        Checkpoint {
            mark,
            last_continue_tuid,
            is_explicit: e,
            where_: where_.to_owned(),
        }
    }
}

pub struct GdbServer {
    target: Target,
    /// dbg is initially null. Once the debugger connection is established, it
    /// never changes.
    /// @TODO Avoid Option<Box<>> ?
    dbg: Option<Box<GdbConnection>>,
    /// When dbg is non-null, the ThreadGroupUid of the task being debugged. Never
    /// changes once the connection is established --- we don't currently
    /// support switching gdb between debuggee processes.
    debuggee_tguid: ThreadGroupUid,
    /// ThreadDb for debuggee ThreadGroup
    thread_db: Box<ThreadDb>,
    /// The TaskUid of the last continued task.
    last_continue_tuid: TaskUid,
    /// The TaskUid of the last queried task.
    last_query_tuid: TaskUid,
    final_event: FrameTime,
    /// siginfo for last notified stop.
    stop_siginfo: siginfo_t,
    in_debuggee_end_state: bool,
    /// True when the user has interrupted replaying to a target event.
    /// @TODO This is volatile in rr
    stop_replaying_to_target: bool,
    /// True when a DREQ_INTERRUPT has been received but not handled, or when
    /// we've restarted and want the first continue to be interrupted immediately.
    interrupt_pending: bool,
    timeline: ReplayTimeline,
    emergency_debug_session: SessionSharedWeakPtr,
    debugger_restart_checkpoint: Checkpoint,
    /// gdb checkpoints, indexed by ID
    checkpoints: HashMap<usize, Checkpoint>,
    /// Set of symbols to look for, for qSymbol
    symbols: HashSet<String>,
    files: HashMap<i32, ScopedFd>,
    /// The pid for gdb's last vFile:setfs
    file_scope_pid: pid_t,
}

impl GdbServer {
    /// Return the register `which`, which may not have a defined value.
    pub fn get_reg(
        _regs: &Registers,
        _extra_regs: &ExtraRegisters,
        _which: GdbRegister,
    ) -> GdbRegisterValue {
        unimplemented!()
    }

    /// Actually run the server. Returns only when the debugger disconnects.
    fn serve_replay(&self, _flags: &ConnectionFlags) {
        unimplemented!()
    }

    /// exec()'s gdb using parameters read from params_pipe_fd (and sent through
    /// the pipe passed to serve_replay_with_debugger).
    fn launch_gdb(
        _params_pipe_fd: &ScopedFd,
        _gdb_binary_file_path: &OsString,
        _gdb_options: Vec<OsString>,
    ) {
        unimplemented!()
    }

    /// Start a debugging connection for |t| and return when there are no
    /// more requests to process (usually because the debugger detaches).
    ///
    /// This helper doesn't attempt to determine whether blocking rr on a
    /// debugger connection might be a bad idea.  It will always open the debug
    /// socket and block awaiting a connection.
    fn emergency_debug(_t: &dyn Task) {
        unimplemented!()
    }

    // A string containing the default gdbinit script that we load into gdb.
    fn init_script() -> &'static str {
        unimplemented!()
    }

    /// Called from a signal handler (or other thread) during serve_replay,
    /// this will cause the replay-to-target phase to be interrupted and
    /// debugging started wherever the replay happens to be.
    fn interrupt_replay_to_target(&mut self) {
        self.stop_replaying_to_target = true;
    }
}
