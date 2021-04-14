use crate::{
    bindings::signal::siginfo_t,
    breakpoint_condition::BreakpointCondition,
    commands::gdb_command_handler::GdbCommandHandler,
    extra_registers::ExtraRegisters,
    gdb_connection::{
        GdbConnection, GdbConnectionFeatures, GdbRegisterValue, GdbRegisterValueData, GdbRequest,
        GdbRequestType, GdbThreadId, DREQ_REMOVE_HW_BREAK, DREQ_REMOVE_RDWR_WATCH,
        DREQ_REMOVE_RD_WATCH, DREQ_REMOVE_WR_WATCH, DREQ_SET_HW_BREAK, DREQ_SET_RDWR_WATCH,
        DREQ_SET_RD_WATCH, DREQ_SET_WR_WATCH,
    },
    gdb_expression::{GdbExpression, GdbExpressionValue},
    gdb_register::{GdbRegister, DREG_64_YMM15H, DREG_ORIG_EAX, DREG_ORIG_RAX, DREG_YMM7H},
    kernel_abi::{syscall_number_for_execve, SupportedArch},
    log::LogDebug,
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    replay_timeline::{self, ReplayTimeline, ReplayTimelineSharedPtr, RunDirection},
    scoped_fd::ScopedFd,
    session::{
        address_space::{memory_range::MemoryRange, MappingFlags, WatchType},
        diversion_session::DiversionSession,
        replay_session::ReplaySession,
        session_inner::BreakStatus,
        task::{Task, TaskSharedPtr},
        Session, SessionSharedPtr, SessionSharedWeakPtr,
    },
    sig::Sig,
    taskish_uid::{TaskUid, ThreadGroupUid},
    thread_db::ThreadDb,
    trace::trace_frame::FrameTime,
    util::{
        cpuid, find, floor_page_size, page_size, word_size, AVX_FEATURE_FLAG, CPUID_GETFEATURES,
        OSXSAVE_FEATURE_FLAG,
    },
};
use libc::{pid_t, SIGKILL, SIGTRAP};
use std::{
    cell::{Ref, RefCell, RefMut},
    cmp::min,
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

    fn maybe_intercept_mem_request(target: &dyn Task, req: &GdbRequest, result: &mut [u8]) {
        // Crazy hack!
        // When gdb tries to read the word at the top of the stack, and we're in our
        // dynamically-generated stub code, tell it the value is zero, so that gdb's
        // stack-walking code doesn't find a bogus value that it treats as a return
        // address and sets a breakpoint there, potentially corrupting program data.
        // gdb sometimes reads a whole block of memory around the stack pointer so
        // handle cases where the top-of-stack word is contained in a larger range.
        let size = word_size(target.arch());
        if target.regs_ref().sp() >= req.mem().addr
            && target.regs_ref().sp() + size <= req.mem().addr + req.mem().len
            && is_in_patch_stubs(target, target.ip())
        {
            let offset = target.regs_ref().sp().as_usize() - req.mem().addr.as_usize();
            result[offset..offset + size].fill(0);
        }
    }

    /// Process the single debugger request |req| inside the session |session|.
    ///
    /// Callers should implement any special semantics they want for
    /// particular debugger requests before calling this helper, to do
    /// generic processing.
    fn dispatch_debugger_request(_session: &dyn Session, _req: &GdbRequest, _state: ReportState) {
        unimplemented!();
    }

    fn at_target(&self) -> bool {
        // Don't launch the debugger for the initial rd fork child.
        // No one ever wants that to happen.
        if !self.get_timeline().current_session().done_initial_exec() {
            return false;
        }
        let maybe_t = self.get_timeline().current_session().current_task();
        if maybe_t.is_none() {
            return false;
        }
        let t = maybe_t.unwrap();
        if !self.get_timeline().can_add_checkpoint() {
            return false;
        }
        if self.stop_replaying_to_target {
            return true;
        }
        // When we decide to create the debugger, we may end up
        // creating a checkpoint.  In that case, we want the
        // checkpoint to retain the state it had *before* we started
        // replaying the next frame.  Otherwise, the TraceIfstream
        // will be one frame ahead of its tracee tree.
        //
        // So we make the decision to create the debugger based on the
        // frame we're *about to* replay, without modifying the
        // TraceIfstream.
        // NB: we'll happily attach to whichever task within the
        // group happens to be scheduled here.  We don't take
        // "attach to process" to mean "attach to thread-group
        // leader".
        let timeline = self.get_timeline();
        let ret = timeline.current_session().current_trace_frame().time() >
             self.target.event &&
         (self.target.pid.is_none() || t.tgid() == self.target.pid.unwrap()) &&
         (!self.target.require_exec || t.execed()) &&
         // Ensure we're at the start of processing an event. We don't
         // want to attach while we're finishing an exec() since that's a
         // slightly confusing state for ReplayTimeline's reverse execution.
         !timeline.current_session().current_step_key().in_execution();
        ret
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
    fn maybe_notify_stop(&mut self, req: &GdbRequest, break_status: &BreakStatus) {
        let mut do_stop = false;
        let mut watch_addr: RemotePtr<Void> = Default::default();
        if !break_status.watchpoints_hit.is_empty() {
            do_stop = true;
            self.stop_siginfo = Default::default();
            self.stop_siginfo.si_signo = SIGTRAP;
            watch_addr = break_status.watchpoints_hit[0].addr;
            log!(LogDebug, "Stopping for watchpoint at {}", watch_addr);
        }
        if break_status.breakpoint_hit || break_status.singlestep_complete {
            do_stop = true;
            self.stop_siginfo = Default::default();
            self.stop_siginfo.si_signo = SIGTRAP;
            if break_status.breakpoint_hit {
                log!(LogDebug, "Stopping for breakpoint");
            } else {
                log!(LogDebug, "Stopping for singlestep");
            }
        }
        if break_status.signal.is_some() {
            do_stop = true;
            self.stop_siginfo = **break_status.signal.as_ref().unwrap();
            log!(LogDebug, "Stopping for signal {}", self.stop_siginfo);
        }
        if is_last_thread_exit(break_status) && self.dbg().features().reverse_execution {
            do_stop = true;
            self.stop_siginfo = Default::default();
            if req.cont().run_direction == RunDirection::RunForward {
                // The exit of the last task in a thread group generates a fake SIGKILL,
                // when reverse-execution is enabled, because users often want to run
                // backwards from the end of the task.
                self.stop_siginfo.si_signo = SIGKILL;
                log!(LogDebug, "Stopping for synthetic SIGKILL");
            } else {
                // The start of the debuggee task-group should trigger a silent stop.
                self.stop_siginfo.si_signo = 0;
                log!(
                    LogDebug,
                    "Stopping at start of execution while running backwards"
                );
            }
        }
        let mut t = break_status.task.upgrade().unwrap();
        let in_exec_task = is_in_exec(&self.get_timeline());
        if in_exec_task.is_some() {
            do_stop = true;
            self.stop_siginfo = Default::default();
            t = in_exec_task.unwrap();
            log!(LogDebug, "Stopping at exec");
        }
        let tguid = t.thread_group().borrow().tguid();
        if do_stop && tguid == self.debuggee_tguid {
            // Notify the debugger and process any new requests
            // that might have triggered before resuming.
            let signo = self.stop_siginfo.si_signo;
            let threadid = get_threadid(&**t);
            self.dbg_mut()
                .notify_stop(threadid, Sig::try_from(signo).ok(), watch_addr);
            self.last_continue_tuid = t.tuid();
            self.last_query_tuid = t.tuid();
        }
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

fn is_in_patch_stubs(t: &dyn Task, ip: RemoteCodePtr) -> bool {
    let p = ip.to_data_ptr();
    t.vm().mapping_of(p).is_some()
        && t.vm()
            .mapping_flags_of(p)
            .contains(MappingFlags::IS_PATCH_STUBS)
}

/// Wait for exactly one gdb host to connect to this remote target on
/// the specified IP address |host|, port |port|.  If |probe| is nonzero,
/// a unique port based on |start_port| will be searched for.  Otherwise,
/// if |port| is already bound, this function will fail.
///
/// Pass the |tgid| of the task on which this debug-connection request
/// is being made.  The remaining debugging session will be limited to
/// traffic regarding |tgid|, but clients don't need to and shouldn't
/// need to assume that.
///
/// If we're opening this connection on behalf of a known client, pass
/// an fd in |client_params_fd|; we'll write the allocated port and |exe_image|
/// through the fd before waiting for a connection. |exe_image| is the
/// process that will be debugged by client, or null ptr if there isn't
/// a client.
///
/// This function is infallible: either it will return a valid
/// debugging context, or it won't return.
fn await_connection(
    t: &dyn Task,
    listen_fd: &ScopedFd,
    features: GdbConnectionFeatures,
) -> Box<GdbConnection> {
    let mut dbg = Box::new(GdbConnection::new(t.tgid(), features));
    let arch = t.arch();
    dbg.set_cpu_features(get_cpu_features(arch));
    dbg.await_debugger(listen_fd);
    dbg
}

fn get_cpu_features(arch: SupportedArch) -> u32 {
    let mut cpu_features = match arch {
        SupportedArch::X86 => 0,
        SupportedArch::X64 => GdbConnection::CPU_64BIT,
    };

    let avx_cpuid_flags = AVX_FEATURE_FLAG | OSXSAVE_FEATURE_FLAG;
    let cpuid_data = cpuid(CPUID_GETFEATURES, 0);
    // We're assuming here that AVX support on the system making the recording
    // is the same as the AVX support during replay. But if that's not true,
    // rd is totally broken anyway.
    if (cpuid_data.ecx & avx_cpuid_flags) == avx_cpuid_flags {
        cpu_features |= GdbConnection::CPU_AVX;
    }

    cpu_features
}

fn is_in_exec(timeline: &ReplayTimeline) -> Option<TaskSharedPtr> {
    let t = timeline.current_session().current_task()?;
    let arch = t.arch();
    if timeline
        .current_session()
        .next_step_is_successful_syscall_exit(syscall_number_for_execve(arch))
    {
        Some(t)
    } else {
        None
    }
}

fn get_threadid(t: &dyn Task) -> GdbThreadId {
    GdbThreadId::new(t.tgid(), t.rec_tid())
}

fn is_last_thread_exit(break_status: &BreakStatus) -> bool {
    break_status.task_exit
        && break_status
            .task
            .upgrade()
            .unwrap()
            .thread_group()
            .borrow()
            .task_set()
            .len()
            == 1
}

struct GdbBreakpointCondition {
    expressions: Vec<GdbExpression>,
}

impl GdbBreakpointCondition {
    pub fn new(bytecodes: &[Vec<u8>]) -> GdbBreakpointCondition {
        let mut expressions = Vec::new();
        for b in bytecodes {
            expressions.push(GdbExpression::new(b));
        }
        Self { expressions }
    }
}

impl BreakpointCondition for GdbBreakpointCondition {
    fn evaluate(&self, t: &dyn Task) -> bool {
        for e in &self.expressions {
            let mut v: GdbExpressionValue = Default::default();
            // Break if evaluation fails or the result is nonzero
            if !e.evaluate(t, &mut v) || v.i != 0 {
                return true;
            }
        }
        return false;
    }
}

fn breakpoint_condition(request: &GdbRequest) -> Option<Box<dyn BreakpointCondition>> {
    if request.watch().conditions.is_empty() {
        return None;
    }
    Some(Box::new(GdbBreakpointCondition::new(
        &request.watch().conditions,
    )))
}

fn search_memory(t: &dyn Task, where_: MemoryRange, find_s: &[u8]) -> Option<RemotePtr<Void>> {
    // DIFF NOTE: This assert is not present in rd
    assert!(find_s.len() > 0);
    let mut buf = Vec::<u8>::new();
    buf.resize(page_size() + find_s.len() - 1, 0);
    for (_, m) in &t.vm().maps() {
        let mut r = MemoryRange::from_range(m.map.start(), m.map.end() + (find_s.len() - 1))
            .intersect(where_);
        // We basically read page by page here, but we read past the end of the
        // page to handle the case where a found string crosses page boundaries.
        // This approach isn't great for handling long search strings but gdb's find
        // command isn't really suited to that.
        // Reading page by page lets us avoid problems where some pages in a
        // mapping aren't readable (e.g. reading beyond end of file).
        while r.size() >= find_s.len() {
            let l = min(buf.len(), r.size());
            let res = t.read_bytes_fallible(r.start(), &mut buf[0..l]);
            match res {
                Ok(nread) if nread >= find_s.len() => {
                    let maybe_offset = find(&buf[0..nread], find_s);
                    if maybe_offset.is_some() {
                        let result = Some(r.start() + maybe_offset.unwrap());
                        return result;
                    }
                }
                // @TODO Check again. This means that any Err(()) might be ignored. Is this what we want?
                _ => (),
            }
            r = MemoryRange::from_range(
                min(r.end(), floor_page_size(r.start()) + page_size()),
                r.end(),
            );
        }
    }
    None
}

fn get_threadid_from_tuid(session: &dyn Session, tuid: TaskUid) -> GdbThreadId {
    let maybe_t = session.find_task_from_task_uid(tuid);
    let pid = match maybe_t {
        Some(t) => t.tgid(),
        None => GdbThreadId::ANY.pid,
    };
    GdbThreadId::new(pid, tuid.tid())
}

fn matches_threadid(t: &dyn Task, target: GdbThreadId) -> bool {
    (target.pid <= 0 || target.pid == t.tgid()) && (target.tid <= 0 || target.tid == t.rec_tid())
}

fn watchpoint_type(req: GdbRequestType) -> WatchType {
    match req {
        DREQ_SET_HW_BREAK | DREQ_REMOVE_HW_BREAK => WatchType::WatchExec,
        DREQ_SET_WR_WATCH | DREQ_REMOVE_WR_WATCH => WatchType::WatchWrite,
        // NB| x86 doesn't support read-only watchpoints (who would
        // ever want to use one?) so we treat them as readwrite
        // watchpoints and hope that gdb can figure out what's going
        // on.  That is, if a user ever tries to set a read
        // watchpoint.
        DREQ_REMOVE_RDWR_WATCH | DREQ_SET_RDWR_WATCH | DREQ_REMOVE_RD_WATCH | DREQ_SET_RD_WATCH => {
            WatchType::WatchReadWrite
        }
        _ => fatal!("Unknown dbg request {}", req),
    }
}
