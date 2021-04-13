use crate::{
    bindings::signal::siginfo_t,
    commands::gdb_command_handler::GdbCommandHandler,
    extra_registers::ExtraRegisters,
    gdb_connection::{GdbConnection, GdbRegisterValue, GdbRegisterValueData, GdbRequest},
    gdb_register::{GdbRegister, DREG_64_YMM15H, DREG_ORIG_EAX, DREG_ORIG_RAX, DREG_YMM7H},
    kernel_abi::SupportedArch,
    registers::Registers,
    replay_timeline::{self, ReplayTimeline, ReplayTimelineSharedPtr},
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
    cell::{Ref, RefCell, RefMut},
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    ffi::{OsStr, OsString},
    rc::{Rc, Weak},
};

const LOCALHOST_ADDR: &'static str = "127.0.0.1";

#[derive(Default, Clone)]
pub struct Target {
    /// Target process to debug, or `None` to just debug the first process
    pub pid: Option<pid_t>,
    /// If true, wait for the target process to exec() before attaching debugger
    pub require_exec: bool,
    /// Wait until at least 'event' has elapsed before attaching
    pub event: FrameTime,
}

pub struct ConnectionFlags {
    /// `None` to let GdbServer choose the port, a positive integer to select a
    /// specific port to listen on.
    pub dbg_port: Option<usize>,
    pub dbg_host: OsString,
    /// If keep_listening is true, wait for another
    /// debugger connection after the first one is terminated.
    pub keep_listening: bool,
    /// If not Weak::new(), then when the gdbserver is set up, we write its connection
    /// parameters through this pipe. GdbServer::launch_gdb is passed the
    /// other end of this pipe to exec gdb with the parameters.
    pub debugger_params_write_pipe: Weak<RefCell<ScopedFd>>,
    // Name of the debugger to suggest. Only used if debugger_params_write_pipe
    // is Weak::new().
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
pub(super) enum ExplicitCheckpoint {
    Explicit,
    NotExplicit,
}

#[derive(Clone)]
pub(super) struct Checkpoint {
    pub mark: replay_timeline::Mark,
    pub last_continue_tuid: TaskUid,
    pub is_explicit: ExplicitCheckpoint,
    pub where_: OsString,
}

impl Checkpoint {
    pub fn new(
        timeline: &mut ReplayTimeline,
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
    dbg: Option<Box<GdbConnection>>,
    /// When dbg is non-null, the ThreadGroupUid of the task being debugged. Never
    /// changes once the connection is established --- we don't currently
    /// support switching gdb between debuggee processes.
    /// NOTE: @TODO Zero if not set. Change to option?
    debuggee_tguid: ThreadGroupUid,
    /// ThreadDb for debuggee ThreadGroup
    thread_db: Box<ThreadDb>,
    /// The TaskUid of the last continued task.
    /// NOTE: @TODO Zero if not set. Change to option?
    pub(super) last_continue_tuid: TaskUid,
    /// The TaskUid of the last queried task.
    /// NOTE: @TODO Zero if not set. Change to option?
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
    timeline: Option<ReplayTimelineSharedPtr>,
    emergency_debug_session: SessionSharedWeakPtr,
    /// DIFF NOTE: This get simply initialized to the default Checkpoint constructor
    /// in rr. We have an more explicit Option<>
    debugger_restart_checkpoint: Option<Checkpoint>,
    /// gdb checkpoints, indexed by ID
    pub(super) checkpoints: HashMap<usize, Checkpoint>,
    /// Set of symbols to look for, for qSymbol
    symbols: HashSet<String>,
    files: HashMap<i32, ScopedFd>,
    /// The pid for gdb's last vFile:setfs
    /// NOTE: @TODO Zero if not set. Change to option?
    file_scope_pid: pid_t,
}

impl GdbServer {
    fn dbg(&self) -> &GdbConnection {
        &*self.dbg.as_ref().unwrap()
    }

    fn dbg_mut(&mut self) -> &mut GdbConnection {
        &mut *self.dbg.as_mut().unwrap()
    }

    pub fn get_timeline(&self) -> Ref<ReplayTimeline> {
        self.timeline.as_ref().unwrap().borrow()
    }

    pub fn get_timeline_mut(&self) -> RefMut<ReplayTimeline> {
        self.timeline.as_ref().unwrap().borrow_mut()
    }

    /// Create a gdbserver serving the replay of `session`
    pub fn new(session: SessionSharedPtr, target: &Target) -> GdbServer {
        GdbServer {
            target: target.clone(),
            dbg: Default::default(),
            debuggee_tguid: Default::default(),
            thread_db: Default::default(),
            last_continue_tuid: Default::default(),
            last_query_tuid: Default::default(),
            final_event: u64::MAX,
            stop_siginfo: Default::default(),
            in_debuggee_end_state: Default::default(),
            stop_replaying_to_target: Default::default(),
            interrupt_pending: Default::default(),
            timeline: Some(ReplayTimeline::new(session)),
            emergency_debug_session: Default::default(),
            debugger_restart_checkpoint: Default::default(),
            checkpoints: Default::default(),
            symbols: Default::default(),
            files: Default::default(),
            file_scope_pid: Default::default(),
        }
    }

    fn new_from(dbg: Box<GdbConnection>, t: &dyn Task) -> GdbServer {
        GdbServer {
            dbg: Some(dbg),
            debuggee_tguid: t.thread_group().borrow().tguid(),
            last_continue_tuid: t.tuid(),
            last_query_tuid: Default::default(),
            final_event: u64::MAX,
            stop_replaying_to_target: false,
            interrupt_pending: false,
            emergency_debug_session: Rc::downgrade(&t.session()),
            file_scope_pid: 0,
            target: Default::default(),
            thread_db: Default::default(),
            stop_siginfo: Default::default(),
            in_debuggee_end_state: Default::default(),
            timeline: Default::default(),
            debugger_restart_checkpoint: Default::default(),
            checkpoints: Default::default(),
            symbols: Default::default(),
            files: Default::default(),
        }
    }

    /// Return the register `which`, which may not have a defined value.
    pub fn get_reg(
        regs: &Registers,
        extra_regs: &ExtraRegisters,
        which: GdbRegister,
    ) -> GdbRegisterValue {
        let mut buf = [0u8; GdbRegisterValue::MAX_SIZE];
        let maybe_size = get_reg(regs, extra_regs, &mut buf, which);
        match maybe_size {
            Some(1) => GdbRegisterValue {
                name: which,
                value: GdbRegisterValueData::Value1(buf[0]),
                defined: true,
                size: 1,
            },
            Some(2) => GdbRegisterValue {
                name: which,
                value: GdbRegisterValueData::Value2(u16::from_le_bytes(
                    buf[0..2].try_into().unwrap(),
                )),
                defined: true,
                size: 2,
            },
            Some(4) => GdbRegisterValue {
                name: which,
                value: GdbRegisterValueData::Value4(u32::from_le_bytes(
                    buf[0..4].try_into().unwrap(),
                )),
                defined: true,
                size: 4,
            },
            Some(8) => GdbRegisterValue {
                name: which,
                value: GdbRegisterValueData::Value8(u64::from_le_bytes(
                    buf[0..8].try_into().unwrap(),
                )),
                defined: true,
                size: 8,
            },
            Some(siz) if siz <= GdbRegisterValue::MAX_SIZE => GdbRegisterValue {
                name: which,
                value: GdbRegisterValueData::ValueGeneric(buf.try_into().unwrap()),
                defined: true,
                size: siz,
            },
            Some(siz) => {
                panic!("Unexpected GdbRegister size: {}", siz);
            }
            None => GdbRegisterValue {
                name: which,
                value: GdbRegisterValueData::ValueGeneric(Default::default()),
                defined: false,
                size: 0,
            },
        }
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

    fn current_session(&self) -> SessionSharedPtr {
        if self.get_timeline().is_running() {
            self.get_timeline().current_session_shr_ptr()
        } else {
            self.emergency_debug_session.upgrade().unwrap()
        }
    }

    fn dispatch_regs_request(&mut self, regs: &Registers, extra_regs: &ExtraRegisters) {
        // Send values for all the registers we sent XML register descriptions for.
        // Those descriptions are controlled by GdbConnection::cpu_features().
        let have_avx = (self.dbg().cpu_features() & GdbConnection::CPU_AVX) != 0;
        let end = match regs.arch() {
            SupportedArch::X86 => {
                if have_avx {
                    DREG_YMM7H
                } else {
                    DREG_ORIG_EAX
                }
            }
            SupportedArch::X64 => {
                if have_avx {
                    DREG_64_YMM15H
                } else {
                    DREG_ORIG_RAX
                }
            }
        };
        let mut rs: Vec<GdbRegisterValue> = Vec::new();
        let mut r = GdbRegister::try_from(0).unwrap();
        while r <= end {
            rs.push(GdbServer::get_reg(regs, extra_regs, r));
            r = (r + 1).unwrap();
        }
        self.dbg_mut().reply_get_regs(&rs);
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

lazy_static! {
    static ref GDB_RD_MACROS: String = gdb_rd_macros_init();
}

fn gdb_rd_macros() -> &'static str {
    &*GDB_RD_MACROS
}

/// Special-sauce macros defined by rd when launching the gdb client,
/// which implement functionality outside of the gdb remote protocol.
/// (Don't stare at them too long or you'll go blind ;).)
fn gdb_rd_macros_init() -> String {
    let mut ss = String::new();
    ss.push_str(&GdbCommandHandler::gdb_macros());

    // In gdb version "Fedora 7.8.1-30.fc21", a raw "run" command
    // issued before any user-generated resume-execution command
    // results in gdb hanging just after the inferior hits an internal
    // gdb breakpoint.  This happens outside of rd, with gdb
    // controlling gdbserver, as well.  We work around that by
    // ensuring *some* resume-execution command has been issued before
    // restarting the session.  But, only if the inferior hasn't
    // already finished execution ($_thread != 0).  If it has and we
    // issue the "stepi" command, then gdb refuses to restart
    // execution.
    //
    // Try both "set target-async" and "maint set target-async" since
    // that changed recently.
    let s: &'static str = r##"
define restart
  run c$arg0
end
document restart
restart at checkpoint N
checkpoints are created with the 'checkpoint' command
end
define hook-run
  rd-hook-run
end
define hookpost-continue
  rd-set-suppress-run-hook 1
end
define hookpost-step
  rd-set-suppress-run-hook 1
end
define hookpost-stepi
  rd-set-suppress-run-hook 1
end
define hookpost-next
  rd-set-suppress-run-hook 1
end
define hookpost-nexti
  rd-set-suppress-run-hook 1
end
define hookpost-finish
  rd-set-suppress-run-hook 1
end
define hookpost-reverse-continue
  rd-set-suppress-run-hook 1
end
define hookpost-reverse-step
  rd-set-suppress-run-hook 1
end
define hookpost-reverse-stepi
  rd-set-suppress-run-hook 1
end
define hookpost-reverse-finish
  rd-set-suppress-run-hook 1
end
define hookpost-run
  rd-set-suppress-run-hook 0
end
set unwindonsignal on
handle SIGURG stop
set prompt (rd)
python
import re
m = re.compile('.* ([0-9]+)\\.([0-9]+)(\\.([0-9]+))?.*').match(gdb.execute('show version', False, True))
ver = int(m.group(1))*10000 + int(m.group(2))*100
if m.group(4):
    ver = ver + int(m.group(4))

if ver == 71100:
    gdb.write('This version of gdb (7.11.0) has known bugs that break rd. Install 7.11.1 or later.\\n', gdb.STDERR)

if ver < 71101:
    gdb.execute('set target-async 0')
    gdb.execute('maint set target-async 0')
end
"##;
    ss.push_str(s);
    ss
}

/// Attempt to find the value of `regname` (a DebuggerRegister name), and if so:
/// (i) write it to `buf`;
/// (ii) return the size of written data as on Option<usize>
///
/// If None is returned, the value of `buf` is meaningless.
///
/// This helper can fetch the values of both general-purpose
/// and "extra" registers.
///
/// NB: `buf` must be large enough to hold the largest register
/// value that can be named by `regname`.
fn get_reg(
    regs: &Registers,
    extra_regs: &ExtraRegisters,
    buf: &mut [u8],
    regname: GdbRegister,
) -> Option<usize> {
    match regs.read_register(buf, regname) {
        Some(siz) => Some(siz),
        None => extra_regs.read_register(buf, regname),
    }
}
