use crate::{
    bindings::signal::siginfo_t,
    extra_registers::ExtraRegisters,
    gdb_connection::{GdbConnection, GdbRegisterValue, GdbRequest},
    gdb_register::GdbRegister,
    registers::Registers,
    replay_timeline::{self, ReplayTimeline},
    scoped_fd::ScopedFd,
    session::{
        diversion_session::DiversionSession,
        replay_session::ReplaySession,
        session_inner::BreakStatus,
        task::Task,
        Session,
        SessionSharedPtr,
        SessionSharedWeakPtr,
    },
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
    /// Create a gdbserver serving the replay of `session`
    pub fn new(_session: SessionSharedPtr, _target: &Target) -> GdbServer {
        unimplemented!()
    }

    fn new_from(_dbg: Box<GdbConnection>, _t: &dyn Task) -> GdbServer {
        unimplemented!()
    }

    /// Return the register `which`, which may not have a defined value.
    pub fn get_reg(
        _regs: &Registers,
        _extra_regs: &ExtraRegisters,
        _which: GdbRegister,
    ) -> GdbRegisterValue {
        unimplemented!()
    }

    /// Actually run the server. Returns only when the debugger disconnects.
    pub fn serve_replay(&self, _flags: &ConnectionFlags) {
        unimplemented!()
    }

    /// exec()'s gdb using parameters read from params_pipe_fd (and sent through
    /// the pipe passed to serve_replay_with_debugger).
    pub fn launch_gdb(
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
    pub fn emergency_debug(_t: &dyn Task) {
        unimplemented!()
    }

    // A string containing the default gdbinit script that we load into gdb.
    pub fn init_script() -> &'static str {
        unimplemented!()
    }

    /// Called from a signal handler (or other thread) during serve_replay,
    /// this will cause the replay-to-target phase to be interrupted and
    /// debugging started wherever the replay happens to be.
    pub fn interrupt_replay_to_target(&mut self) {
        self.stop_replaying_to_target = true;
    }

    pub fn get_timeline(&self) -> &ReplayTimeline {
        &self.timeline
    }

    fn current_session() -> SessionSharedPtr {
        unimplemented!()
    }

    fn dispatch_regs_request(_regs: &Registers, _extra_regs: &ExtraRegisters) {
        unimplemented!()
    }

    fn maybe_intercept_mem_request(_target: &dyn Task, _req: &GdbRequest, _result: &[u8]) {
        unimplemented!()
    }

    /// Process the single debugger request |req| inside the session |session|.
    ///
    /// Callers should implement any special semantics they want for
    /// particular debugger requests before calling this helper, to do
    /// generic processing.
    fn dispatch_debugger_request(_session: &dyn Session, _req: &GdbRequest, _state: ReportState) {
        unimplemented!();
    }

    fn at_target() -> bool {
        unimplemented!();
    }

    fn activate_debugger() {
        unimplemented!();
    }

    fn restart_session(_req: &GdbRequest) {
        unimplemented!();
    }

    fn process_debugger_requests(_state: Option<ReportState>) -> GdbRequest {
        unimplemented!();
    }

    fn detach_or_restart(_req: &GdbRequest, _s: &mut ContinueOrStop) -> bool {
        unimplemented!();
    }

    fn handle_exited_state(_last_resume_request: &GdbRequest) -> ContinueOrStop {
        unimplemented!();
    }

    fn debug_one_step(_last_resume_request: &GdbRequest) -> ContinueOrStop {
        unimplemented!();
    }

    /// If 'req' is a reverse-singlestep, try to obtain the resulting state
    /// directly from ReplayTimeline's mark database. If that succeeds,
    /// report the singlestep break status to gdb and process any get-registers
    /// requests. Repeat until we get a request that isn't reverse-singlestep
    /// or get-registers, returning that request in 'req'.
    /// During reverse-next commands, gdb tends to issue a series of
    /// reverse-singlestep/get-registers pairs, and this makes those much
    /// more efficient by avoiding having to actually reverse-singlestep the
    /// session.
    fn try_lazy_reverse_singlesteps(_req: &GdbRequest) {
        unimplemented!();
    }

    /// Process debugger requests made in |diversion_session| until action needs
    /// to be taken by the caller (a resume-execution request is received).
    /// The received request is returned through |req|.
    /// Returns true if diversion should continue, false if it should end.
    fn diverter_process_debugger_requests(
        _diversion_session: &DiversionSession,
        _diversion_refcount: &mut u32,
        _req: &GdbRequest,
    ) -> bool {
        unimplemented!()
    }

    /// Create a new diversion session using |replay| session as the
    /// template.  The |replay| session isn't mutated.
    ///
    /// Execution begins in the new diversion session under the control of
    /// |dbg| starting with initial thread target |task|.  The diversion
    /// session ends at the request of |dbg|, and |divert| returns the first
    /// request made that wasn't handled by the diversion session.  That
    /// is, the first request that should be handled by |replay| upon
    /// resuming execution in that session.
    fn divert(_replay: &ReplaySession) -> GdbRequest {
        unimplemented!();
    }

    /// If |break_status| indicates a stop that we should report to gdb,
    /// report it. |req| is the resume request that generated the stop.
    fn maybe_notify_stop(_req: &GdbRequest, _break_status: &BreakStatus) {
        unimplemented!();
    }

    /// Return the checkpoint stored as |checkpoint_id| or nullptr if there
    /// isn't one.
    fn get_checkpoint(_checkpoint_id: u32) -> SessionSharedPtr {
        unimplemented!()
    }

    /// Delete the checkpoint stored as |checkpoint_id| if it exists, or do
    /// nothing if it doesn't exist.
    fn delete_checkpoint(_checkpoint_id: u32) {
        unimplemented!()
    }

    /// Handle GDB file open requests. If we can serve this read request, add
    /// an entry to `files` with the file contents and return our internal
    /// file descriptor.
    fn open_file(_session: &dyn Session, _file_name: &OsStr) -> i32 {
        unimplemented!()
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ReportState {
    ReportNormal,
    ReportThreadsDead,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ContinueOrStop {
    ContinueDebugging,
    StopDebugging,
}
