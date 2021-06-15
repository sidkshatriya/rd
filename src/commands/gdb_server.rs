#[allow(unused_imports)]
use crate::{
    bindings::signal::siginfo_t,
    breakpoint_condition::BreakpointCondition,
    commands::gdb_command_handler::GdbCommandHandler,
    extra_registers::ExtraRegisters,
    gdb_connection::{
        GdbActionType, GdbConnection, GdbConnectionFeatures, GdbContAction, GdbRegisterValue,
        GdbRegisterValueData, GdbRequest, GdbRequestType, GdbRestartType, GdbThreadId, DREQ_CONT,
        DREQ_DETACH, DREQ_FILE_CLOSE, DREQ_FILE_OPEN, DREQ_FILE_PREAD, DREQ_FILE_SETFS,
        DREQ_GET_AUXV, DREQ_GET_CURRENT_THREAD, DREQ_GET_EXEC_FILE, DREQ_GET_IS_THREAD_ALIVE,
        DREQ_GET_MEM, DREQ_GET_OFFSETS, DREQ_GET_REG, DREQ_GET_REGS, DREQ_GET_STOP_REASON,
        DREQ_GET_THREAD_EXTRA_INFO, DREQ_GET_THREAD_LIST, DREQ_INTERRUPT, DREQ_NONE, DREQ_QSYMBOL,
        DREQ_RD_CMD, DREQ_READ_SIGINFO, DREQ_REMOVE_HW_BREAK, DREQ_REMOVE_RDWR_WATCH,
        DREQ_REMOVE_RD_WATCH, DREQ_REMOVE_SW_BREAK, DREQ_REMOVE_WR_WATCH, DREQ_RESTART,
        DREQ_SEARCH_MEM, DREQ_SET_CONTINUE_THREAD, DREQ_SET_HW_BREAK, DREQ_SET_MEM,
        DREQ_SET_QUERY_THREAD, DREQ_SET_RDWR_WATCH, DREQ_SET_RD_WATCH, DREQ_SET_REG,
        DREQ_SET_SW_BREAK, DREQ_SET_WR_WATCH, DREQ_TLS, DREQ_WRITE_SIGINFO,
    },
    gdb_expression::{GdbExpression, GdbExpressionValue},
    gdb_register::{GdbRegister, DREG_64_YMM15H, DREG_ORIG_EAX, DREG_ORIG_RAX, DREG_YMM7H},
    kernel_abi::{syscall_number_for_execve, SupportedArch},
    log::dump_rd_stack,
    log::{LogDebug, LogError, LogInfo, LogWarn},
    registers::Registers,
    remote_code_ptr::RemoteCodePtr,
    remote_ptr::{RemotePtr, Void},
    replay_timeline::{self, Mark, ReplayTimeline, ReplayTimelineSharedPtr, RunDirection},
    scoped_fd::{ScopedFd, ScopedFdSharedPtr, ScopedFdSharedWeakPtr},
    session::{
        address_space::{
            memory_range::MemoryRange, BreakpointType, MappingFlags, WatchType, BREAKPOINT_INSN,
        },
        diversion_session::{DiversionSession, DiversionStatus},
        replay_session::{ReplayResult, ReplaySession, ReplayStatus},
        session_inner::{BreakStatus, RunCommand},
        task::{
            replay_task::ReplayTask,
            task_inner::{TaskInner, WriteFlags},
            Task, TaskSharedPtr,
        },
        Session, SessionSharedPtr, SessionSharedWeakPtr,
    },
    sig,
    sig::Sig,
    taskish_uid::{TaskUid, ThreadGroupUid},
    thread_db::ThreadDb,
    trace::trace_frame::FrameTime,
    util::read_to_end,
    util::write_all,
    util::{
        cpuid, create_temporary_file, find, flat_env, floor_page_size, open_socket, page_size,
        to_cstring_array, trace_instructions_up_to_event, u8_slice, u8_slice_mut, word_size,
        ProbePort, AVX_FEATURE_FLAG, CPUID_GETFEATURES, OSXSAVE_FEATURE_FLAG,
    },
};
use libc::{pid_t, SIGKILL, SIGTRAP};
use nix::{
    errno::{errno, Errno},
    sys::{
        mman::{MapFlags, ProtFlags},
        stat::{major, minor},
    },
    unistd::{dup, execvpe, getpid, read, unlink, write},
    Error,
};
use std::{
    cell::{Ref, RefCell, RefMut},
    cmp::{max, min},
    collections::{BTreeMap, HashMap},
    convert::{TryFrom, TryInto},
    env,
    ffi::{CString, OsStr, OsString},
    fs::File,
    io::{stderr, Write},
    mem,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        io::FromRawFd,
    },
    path::{Component, Path, PathBuf},
    ptr,
    ptr::copy_nonoverlapping,
    rc::Rc,
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
    pub dbg_port: Option<u16>,
    pub dbg_host: String,
    /// If keep_listening is true, wait for another
    /// debugger connection after the first one is terminated.
    pub keep_listening: bool,
    /// If not None, then when the gdbserver is set up, we write its connection
    /// parameters through this pipe. GdbServer::launch_gdb is passed the
    /// other end of this pipe to exec gdb with the parameters.
    pub debugger_params_write_pipe: Option<ScopedFdSharedWeakPtr>,
    // Name of the debugger to suggest. Only used if debugger_params_write_pipe
    // is Weak::new().
    pub debugger_name: PathBuf,
}

impl ConnectionFlags {
    pub fn debugger_params_write_pipe_unwrap(&self) -> ScopedFdSharedPtr {
        self.debugger_params_write_pipe
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap()
    }
}

impl Default for ConnectionFlags {
    fn default() -> ConnectionFlags {
        ConnectionFlags {
            dbg_port: None,
            dbg_host: String::new(),
            keep_listening: false,
            debugger_params_write_pipe: None,
            debugger_name: PathBuf::new(),
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

pub type GdbConnectionSharedPtr = Rc<RefCell<GdbConnection>>;

pub struct GdbServer {
    target: Target,
    /// dbg is initially null. Once the debugger connection is established, it
    /// never changes.
    dbg: Option<GdbConnectionSharedPtr>,
    /// When dbg is non-null, the ThreadGroupUid of the task being debugged. Never
    /// changes once the connection is established --- we don't currently
    /// support switching gdb between debuggee processes.
    /// NOTE: @TODO Zero if not set. Change to option?
    debuggee_tguid: ThreadGroupUid,
    /// ThreadDb for debuggee ThreadGroup
    thread_db: Option<Box<ThreadDb>>,
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
    /// Use a BTreeMap so that result is sorted by checkpoint id
    pub(super) checkpoints: BTreeMap<u64, Checkpoint>,
    /// Set of symbols to look for, for qSymbol
    symbols: Vec<OsString>,
    symbols_loc: Option<usize>,
    files: HashMap<i32, ScopedFd>,
    /// The pid for gdb's last vFile:setfs
    /// NOTE: @TODO Zero if not set. Change to option?
    file_scope_pid: pid_t,
}

impl GdbServer {
    fn thread_db_mut_unwrap(&mut self) -> &mut ThreadDb {
        self.thread_db.as_mut().unwrap()
    }

    fn thread_db_unwrap(&self) -> &ThreadDb {
        self.thread_db.as_ref().unwrap()
    }

    fn dbg_unwrap(&self) -> Ref<GdbConnection> {
        self.dbg.as_ref().unwrap().borrow()
    }

    fn dbg_unwrap_mut(&mut self) -> RefMut<GdbConnection> {
        self.dbg.as_ref().unwrap().borrow_mut()
    }

    /// DIFF NOTE: This method is not present in rr. We need this
    /// because our timeline is stored in an Option<>
    pub fn timeline_is_running(&self) -> bool {
        if let Some(tline) = self.timeline.as_ref() {
            tline.borrow().is_running()
        } else {
            false
        }
    }

    pub fn timeline_unwrap(&self) -> Ref<ReplayTimeline> {
        self.timeline.as_ref().unwrap().borrow()
    }

    pub fn timeline_unwrap_mut(&self) -> RefMut<ReplayTimeline> {
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
            symbols_loc: Default::default(),
            files: Default::default(),
            file_scope_pid: Default::default(),
        }
    }

    fn new_from(dbg: GdbConnection, t: &TaskInner) -> GdbServer {
        GdbServer {
            dbg: Some(Rc::new(RefCell::new(dbg))),
            debuggee_tguid: t.thread_group().borrow().tguid(),
            last_continue_tuid: t.tuid(),
            last_query_tuid: t.tuid(),
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
            symbols_loc: Default::default(),
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
                value: GdbRegisterValueData::ValueGeneric(buf),
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
    pub fn serve_replay(&mut self, flags: &ConnectionFlags) {
        loop {
            let result = self
                .timeline_unwrap_mut()
                .replay_step_forward(RunCommand::Continue, self.target.event);
            if result.status == ReplayStatus::ReplayExited {
                log!(LogInfo, "Debugger was not launched before end of trace");
                return;
            }
            if self.at_target() {
                break;
            }
        }

        let mut port: u16 = match flags.dbg_port {
            Some(port) => port,
            None => getpid().as_raw() as u16,
        };
        // Don't probe if the user specified a port.  Explicitly
        // selecting a port is usually done by scripts, which would
        // presumably break if a different port were to be selected by
        // rd (otherwise why would they specify a port in the first
        // place).  So fail with a clearer error message.
        let probe = match flags.dbg_port {
            Some(_port) => ProbePort::DontProbe,
            None => ProbePort::ProbePort,
        };

        let listen_fd: ScopedFd;
        let t_tgid: pid_t;
        let t_arch: SupportedArch;
        {
            // We MUST have a current task
            let t = self
                .timeline_unwrap()
                .current_session()
                .current_task()
                .unwrap();

            t_tgid = t.tgid();
            t_arch = t.arch();
            listen_fd = open_socket(&flags.dbg_host, &mut port, probe);

            if flags.debugger_params_write_pipe.is_some() {
                let c_exe_image = CString::new(t.vm().exe_image().as_bytes()).unwrap();
                let len = c_exe_image.as_bytes_with_nul().len();
                assert!(len <= libc::PATH_MAX as usize);
                let mut exe_image = [0u8; libc::PATH_MAX as usize];
                exe_image[0..len].copy_from_slice(c_exe_image.as_bytes_with_nul());
                let mut host = [0u8; 16];
                host[0..flags.dbg_host.len()].copy_from_slice(flags.dbg_host.as_bytes());
                let params = DebuggerParams {
                    exe_image,
                    host,
                    port,
                };
                let fd = flags.debugger_params_write_pipe_unwrap().borrow().as_raw();
                let nwritten = write(fd, u8_slice(&params)).unwrap();
                // DIFF NOTE: This is a debug_assert in rr
                assert_eq!(nwritten, mem::size_of_val(&params));
            } else {
                eprintln!("Launch gdb with");
                write_debugger_launch_command(
                    &**t,
                    &flags.dbg_host,
                    port,
                    &flags.debugger_name,
                    &mut stderr(),
                );
            }

            if flags.debugger_params_write_pipe.is_some() {
                flags
                    .debugger_params_write_pipe_unwrap()
                    .borrow_mut()
                    .close();
            }
            self.debuggee_tguid = t.thread_group().borrow().tguid();

            let first_run_event = t.vm().first_run_event();
            if first_run_event > 0 {
                self.timeline_unwrap_mut()
                    .set_reverse_execution_barrier_event(first_run_event);
            }
        }

        loop {
            log!(LogDebug, "initializing debugger connection");
            self.dbg = Some(Rc::new(RefCell::new(await_connection(
                t_tgid,
                t_arch,
                &listen_fd,
                GdbConnectionFeatures::default(),
            ))));
            self.activate_debugger();

            // @TODO Check this
            let mut last_resume_request: GdbRequest = Default::default();
            while self.debug_one_step(&mut last_resume_request) == ContinueOrStop::ContinueDebugging
            {
                // Do nothing here, but we need the side effect in debug_one_step()
            }

            self.timeline_unwrap_mut()
                .remove_breakpoints_and_watchpoints();

            if !flags.keep_listening {
                break;
            }
        }

        log!(LogDebug, "debugger server exiting ...");
    }

    /// exec()'s gdb using parameters read from params_pipe_fd (and sent through
    /// the pipe passed to serve_replay_with_debugger).
    pub fn launch_gdb(
        params_pipe_fd: &ScopedFd,
        gdb_binary_file_path: &Path,
        gdb_options: &[OsString],
    ) {
        let macros = gdb_rd_macros();
        let gdb_command_file = create_gdb_command_file(macros);

        let mut params = DebuggerParams::default();
        let mut res;
        loop {
            res = read(params_pipe_fd.as_raw(), u8_slice_mut(&mut params));
            match res {
                Ok(0) => {
                    // pipe was closed. Probably rd failed/died.
                    return;
                }
                Err(Error::Sys(Errno::EINTR)) => continue,
                _ => break,
            }
        }
        // DIFF NOTE: This is a debug_assert in rr
        assert_eq!(res.unwrap(), mem::size_of_val(&params));

        let mut args = vec![gdb_binary_file_path.into()];
        push_default_gdb_options(&mut args);
        args.push("-x".into());
        args.push(gdb_command_file);
        let mut did_set_remote = false;
        let host = OsStr::from_bytes(params.host.split(|&c| c == 0).next().unwrap())
            .to_str()
            .unwrap();
        let exe_image =
            OsStr::from_bytes(params.exe_image.split(|&c| c == 0).next().unwrap()).to_owned();
        for i in 0..gdb_options.len() {
            if !did_set_remote
                && gdb_options[i].as_bytes() == b"-ex"
                && i + 1 < gdb_options.len()
                && needs_target(&gdb_options[i + 1])
            {
                push_target_remote_cmd(&mut args, host, params.port);
                did_set_remote = true;
            }
            args.push(gdb_options[i].clone());
        }
        if !did_set_remote {
            push_target_remote_cmd(&mut args, host, params.port);
        }
        args.push(exe_image);

        // @TODO Probably more efficient to just obtain the environment without key, value pairs?
        let mut env: Vec<(OsString, OsString)> = env::vars_os().collect();
        env.push(("GDB_UNDER_RD".into(), "1".into()));

        log!(LogDebug, "launching {:?}", args);

        execvpe(
            &CString::new(gdb_binary_file_path.to_str().unwrap()).unwrap(),
            &to_cstring_array(&args),
            &to_cstring_array(&flat_env(&env)),
        )
        .unwrap_or_else(|_| fatal!("Failed to exec gdb."));
    }

    /// Start a debugging connection for |t| and return when there are no
    /// more requests to process (usually because the debugger detaches).
    ///
    /// This helper doesn't attempt to determine whether blocking rr on a
    /// debugger connection might be a bad idea.  It will always open the debug
    /// socket and block awaiting a connection.
    pub fn emergency_debug(t: &TaskInner) {
        // See the comment in |guard_overshoot()| explaining why we do
        // this.  Unlike in that context though, we don't know if |t|
        // overshot an internal breakpoint.  If it did, cover that
        // breakpoint up.
        if t.vm_exists() {
            t.vm().remove_all_breakpoints();
        }

        // Don't launch a debugger on fatal errors; the user is most
        // likely already in a debugger, and wouldn't be able to
        // control another session. Instead, launch a new GdbServer and wait for
        // the user to connect from another window.
        // Don't advertise reverse_execution to gdb becase a) it won't work and
        // b) some gdb versions will fail if the user doesn't turn off async
        // mode (and we don't want to require users to do that)
        let features: GdbConnectionFeatures = GdbConnectionFeatures {
            reverse_execution: false,
        };
        let mut port: u16 = t.tid() as u16;
        let listen_fd = open_socket(LOCALHOST_ADDR, &mut port, ProbePort::ProbePort);

        let maybe_test_monitor_pid = env::var("RUNNING_UNDER_TEST_MONITOR");
        if let Ok(test_monitor_pid) = maybe_test_monitor_pid {
            let pid = test_monitor_pid.parse::<pid_t>().unwrap();
            assert!(pid > 0);
            // Tell test-monitor to wake up and take a snapshot. It will also
            // connect the emergency debugger so let that happen.
            // DIFF NOTE: Unlike rr, we have an unwrap for File::create() i.e. The file create must succeed
            let mut gdb_cmd = File::create("gdb_cmd").unwrap();
            write_debugger_launch_command(t, LOCALHOST_ADDR, port, Path::new("gdb"), &mut gdb_cmd);
            unsafe { libc::kill(pid, libc::SIGURG) };
        } else {
            dump_rd_stack(backtrace::Backtrace::new());
            eprint!("Launch gdb with\n  ");
            write_debugger_launch_command(t, LOCALHOST_ADDR, port, Path::new("gdb"), &mut stderr());
        }
        let tgid = t.tgid();
        let arch = t.arch();
        let dbg = await_connection(tgid, arch, &listen_fd, features);

        GdbServer::new_from(dbg, t).process_debugger_requests(None);
    }

    // A string containing the default gdbinit script that we load into gdb.
    pub fn init_script() -> &'static str {
        gdb_rd_macros()
    }

    /// Called from a signal handler (or other thread) during serve_replay,
    /// this will cause the replay-to-target phase to be interrupted and
    /// debugging started wherever the replay happens to be.
    pub fn interrupt_replay_to_target(&mut self) {
        self.stop_replaying_to_target = true;
    }

    fn current_session(&self) -> SessionSharedPtr {
        if self.timeline_is_running() {
            self.timeline_unwrap().current_session_shr_ptr()
        } else {
            self.emergency_debug_session.upgrade().unwrap()
        }
    }

    fn dispatch_regs_request(&mut self, regs: &Registers, extra_regs: &ExtraRegisters) {
        // Send values for all the registers we sent XML register descriptions for.
        // Those descriptions are controlled by GdbConnection::cpu_features().
        let have_avx = (self.dbg_unwrap().cpu_features() & GdbConnection::CPU_AVX) != 0;
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
        loop {
            rs.push(GdbServer::get_reg(regs, extra_regs, r));
            if let Ok(res) = r + 1 {
                if res > end {
                    break;
                }
                r = res;
            } else {
                break;
            }
        }
        self.dbg_unwrap_mut().reply_get_regs(&rs);
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
            && target.regs_ref().sp() + size <= req.mem().addr + result.len()
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
    fn dispatch_debugger_request(
        &mut self,
        session: &dyn Session,
        req: &GdbRequest,
        state: ReportState,
    ) {
        debug_assert!(!req.is_resume_request());
        // These requests don't require a target task.
        match req.type_ {
            DREQ_RESTART => {
                // DIFF NOTE: This is a debug_assert in rr
                assert!(false);
            }
            DREQ_GET_CURRENT_THREAD => {
                let threadid = get_threadid_from_tuid(session, self.last_continue_tuid);
                self.dbg_unwrap_mut().reply_get_current_thread(threadid);
                return;
            }
            DREQ_GET_OFFSETS => {
                // TODO
                self.dbg_unwrap_mut().reply_get_offsets();
                return;
            }
            DREQ_GET_THREAD_LIST => {
                let mut tids: Vec<GdbThreadId> = Vec::new();
                if state != ReportState::ReportThreadsDead {
                    for (_, t) in session.task_map.borrow().iter() {
                        let threadid = get_threadid_from_tuid(session, t.tuid());
                        tids.push(threadid);
                    }
                }
                self.dbg_unwrap_mut().reply_get_thread_list(&tids);
                return;
            }
            DREQ_INTERRUPT => {
                let maybe_t = session.find_task_from_task_uid(self.last_continue_tuid);
                assert!(
                    session.is_diversion(),
                    "Replay interrupts should be handled at a higher level"
                );
                if let Some(t) = maybe_t {
                    debug_assert_eq!(t.thread_group().borrow().tguid(), self.debuggee_tguid);
                    let threadid = get_threadid(&**t);
                    self.dbg_unwrap_mut()
                        .notify_stop(threadid, None, RemotePtr::null());
                    self.last_query_tuid = t.tuid();
                    self.last_continue_tuid = t.tuid();
                } else {
                    self.dbg_unwrap_mut().notify_stop(
                        GdbThreadId::default(),
                        None,
                        RemotePtr::null(),
                    );
                }
                self.stop_siginfo = Default::default();
                return;
            }
            DREQ_GET_EXEC_FILE => {
                // We shouldn't normally receive this since we try to pass the exe file
                // name on gdb's command line, but the user might start gdb manually
                // and this is easy to support in some other debugger or
                // configuration needs it.
                let mut maybe_t = None;
                // DIFF NOTE: @TODO This is simply req.target.tid in rr
                // Since -1 will succeed there, a > 0 requirement has been added.
                if req.target.tid > 0 {
                    let maybe_tg = session.find_thread_group_from_pid(req.target.tid);
                    if let Some(tg) = maybe_tg {
                        maybe_t = Some(tg.borrow().task_set().iter().next().unwrap());
                    }
                } else {
                    maybe_t = session.find_task_from_task_uid(self.last_continue_tuid);
                }
                if let Some(t) = maybe_t {
                    self.dbg_unwrap_mut()
                        .reply_get_exec_file(t.vm().exe_image());
                } else {
                    self.dbg_unwrap_mut().reply_get_exec_file(OsStr::new(""));
                }
                return;
            }
            DREQ_FILE_SETFS => {
                // Only the filesystem as seen by the remote stub is supported currently
                self.file_scope_pid = req.file_setfs().pid;
                self.dbg_unwrap_mut().reply_setfs(0);
                return;
            }
            DREQ_FILE_OPEN => {
                // We only support reading files
                if req.file_open().flags == libc::O_RDONLY {
                    let fd = self.open_file(session, OsStr::new(&req.file_open().file_name));
                    self.dbg_unwrap_mut()
                        .reply_open(fd, if fd >= 0 { 0 } else { libc::ENOENT });
                } else {
                    self.dbg_unwrap_mut().reply_open(-1, libc::EACCES);
                }
                return;
            }
            DREQ_FILE_PREAD => {
                let it = self.files.get(&req.file_pread().fd);
                if let Some(sfd) = it {
                    let size = min(req.file_pread().size, 1024 * 1024);
                    let mut data = vec![0u8; size];
                    let bytes = read_to_end(sfd, req.file_pread().offset, &mut data);
                    match bytes {
                        Ok(nread) => self.dbg_unwrap_mut().reply_pread(&data[0..nread], 0),
                        Err(_) => self.dbg_unwrap_mut().reply_pread(&[], errno()),
                    }
                } else {
                    self.dbg_unwrap_mut().reply_pread(&[], libc::EBADF);
                }
                return;
            }
            DREQ_FILE_CLOSE => {
                let found = self.files.get(&req.file_close().fd).is_some();
                if found {
                    self.files.remove(&req.file_close().fd);
                    self.dbg_unwrap_mut().reply_close(0);
                } else {
                    self.dbg_unwrap_mut().reply_close(libc::EBADF);
                }
                return;
            }
            _ => (),
        }

        let is_query = req.type_ != DREQ_SET_CONTINUE_THREAD;
        let maybe_target: Option<TaskSharedPtr> = if req.target.tid > 0 {
            session.find_task_from_rec_tid(req.target.tid)
        } else {
            session.find_task_from_task_uid(if is_query {
                self.last_query_tuid
            } else {
                self.last_continue_tuid
            })
        };

        if let Some(t) = maybe_target.as_ref() {
            if is_query {
                self.last_query_tuid = t.tuid();
            } else {
                self.last_continue_tuid = t.tuid();
            }
        };
        // These requests query or manipulate which task is the
        // target, so it's OK if the task doesn't exist.
        match req.type_ {
            DREQ_GET_IS_THREAD_ALIVE => {
                self.dbg_unwrap_mut()
                    .reply_get_is_thread_alive(maybe_target.is_some());
                return;
            }
            DREQ_GET_THREAD_EXTRA_INFO => {
                self.dbg_unwrap_mut()
                    .reply_get_thread_extra_info(&maybe_target.as_ref().unwrap().name());
                return;
            }
            DREQ_SET_CONTINUE_THREAD => {
                self.dbg_unwrap_mut()
                    .reply_select_thread(maybe_target.is_some());
                return;
            }
            DREQ_SET_QUERY_THREAD => {
                self.dbg_unwrap_mut()
                    .reply_select_thread(maybe_target.is_some());
                return;
            }
            _ => (),
        }
        // These requests require a valid target task.  We don't trust
        // the debugger to use the information provided above to only
        // query valid tasks.
        if maybe_target.is_none() {
            self.dbg_unwrap_mut().notify_no_such_thread(req);
            return;
        }
        let target = maybe_target.unwrap();
        match req.type_ {
            DREQ_GET_AUXV => {
                self.dbg_unwrap_mut()
                    .reply_get_auxv(&target.vm().saved_auxv());
                return;
            }
            DREQ_GET_MEM => {
                let mut mem: Vec<u8> = vec![0u8; req.mem().len];
                let nread = target.read_bytes_fallible(req.mem().addr, &mut mem);
                mem.resize(max(0, nread.unwrap_or(0)), 0u8);
                target
                    .vm()
                    .replace_breakpoints_with_original_values(&mut mem, req.mem().addr);
                Self::maybe_intercept_mem_request(&**target, req, &mut mem);
                self.dbg_unwrap_mut().reply_get_mem(&mem);
                return;
            }
            DREQ_SET_MEM => {
                // gdb has been observed to send requests of length 0 at
                // odd times
                // (e.g. before sending the magic write to create a checkpoint)
                if req.mem().len == 0 {
                    self.dbg_unwrap_mut().reply_set_mem(true);
                    return;
                }
                // We only allow the debugger to write memory if the
                // memory will be written to an diversion session.
                // Arbitrary writes to replay sessions cause
                // divergence.
                if !session.is_diversion() {
                    log!(
                        LogError,
                        "Attempt to write memory outside diversion session"
                    );
                    self.dbg_unwrap_mut().reply_set_mem(false);
                    return;
                }
                log!(
                    LogDebug,
                    "Writing {} bytes to {}",
                    req.mem().len,
                    req.mem().addr
                );
                // TODO fallible
                target.write_bytes_helper(
                    req.mem().addr,
                    &req.mem().data,
                    None,
                    WriteFlags::empty(),
                );
                self.dbg_unwrap_mut().reply_set_mem(true);
                return;
            }
            DREQ_SEARCH_MEM => {
                let range = MemoryRange::new_range(req.mem().addr, req.mem().len);
                let found_addr = search_memory(&**target, range, &req.mem().data);
                self.dbg_unwrap_mut().reply_search_mem(
                    found_addr.is_some(),
                    found_addr.unwrap_or(RemotePtr::null()),
                );
                return;
            }
            DREQ_GET_REG => {
                let reg =
                    Self::get_reg(&target.regs_ref(), &target.extra_regs_ref(), req.reg().name);
                self.dbg_unwrap_mut().reply_get_reg(&reg);
                return;
            }
            DREQ_GET_REGS => {
                self.dispatch_regs_request(&target.regs_ref(), &target.extra_regs_ref());
                return;
            }
            DREQ_SET_REG => {
                if !session.is_diversion() {
                    // gdb sets orig_eax to -1 during a restart. For a
                    // replay session this is not correct (we might be
                    // restarting from an rr checkpoint inside a system
                    // call, and we must not tamper with replay state), so
                    // just ignore it.
                    if target.arch() == SupportedArch::X86 && req.reg().name == DREG_ORIG_EAX
                        || (target.arch() == SupportedArch::X64 && req.reg().name == DREG_ORIG_RAX)
                    {
                        self.dbg_unwrap_mut().reply_set_reg(true);
                        return;
                    }
                    log!(
                        LogError,
                        "Attempt to write register outside diversion session"
                    );
                    self.dbg_unwrap_mut().reply_set_reg(false);
                    return;
                }
                if req.reg().defined {
                    let mut regs = target.regs();
                    regs.write_register(req.reg().value(), req.reg().name);
                    target.set_regs(&regs);
                }
                self.dbg_unwrap_mut()
                    .reply_set_reg(true /*currently infallible*/);
                return;
            }
            DREQ_GET_STOP_REASON => {
                let threadid = get_threadid_from_tuid(session, self.last_continue_tuid);
                let maybe_sig = Sig::try_from(self.stop_siginfo.si_signo).ok();
                self.dbg_unwrap_mut()
                    .reply_get_stop_reason(threadid, maybe_sig);
                return;
            }
            DREQ_SET_SW_BREAK => {
                ed_assert_eq!(
                    target,
                    req.watch().kind,
                    mem::size_of_val(&BREAKPOINT_INSN),
                    "Debugger setting bad breakpoint insn"
                );
                // Mirror all breakpoint/watchpoint sets/unsets to the target process
                // if it's not part of the timeline (i.e. it's a diversion).
                let replay_task = self
                    .timeline_unwrap()
                    .current_session()
                    .find_task_from_task_uid(target.tuid())
                    .unwrap();
                let ok = self.timeline_unwrap_mut().add_breakpoint(
                    replay_task.as_replay_task().unwrap(),
                    req.watch().addr.to_code_ptr(),
                    breakpoint_condition(req),
                );
                if ok
                    && !session
                        .weak_self()
                        .ptr_eq(self.timeline_unwrap().current_session().weak_self())
                {
                    let diversion_ok = target
                        .vm()
                        .add_breakpoint(req.watch().addr.to_code_ptr(), BreakpointType::User);
                    ed_assert!(target, diversion_ok);
                }
                self.dbg_unwrap_mut().reply_watchpoint_request(ok);
                return;
            }
            DREQ_SET_HW_BREAK | DREQ_SET_RD_WATCH | DREQ_SET_WR_WATCH | DREQ_SET_RDWR_WATCH => {
                let task = self
                    .timeline_unwrap()
                    .current_session()
                    .find_task_from_task_uid(target.tuid())
                    .unwrap();
                let ok = self.timeline_unwrap_mut().add_watchpoint(
                    task.as_replay_task().unwrap(),
                    req.watch().addr,
                    req.watch().kind,
                    watchpoint_type(req.type_),
                    breakpoint_condition(req),
                );
                if ok
                    && !session
                        .weak_self()
                        .ptr_eq(self.timeline_unwrap().current_session().weak_self())
                {
                    let diversion_ok = target.vm().add_watchpoint(
                        req.watch().addr,
                        req.watch().kind,
                        watchpoint_type(req.type_),
                    );
                    ed_assert!(target, diversion_ok);
                }
                self.dbg_unwrap_mut().reply_watchpoint_request(ok);
                return;
            }
            DREQ_REMOVE_SW_BREAK => {
                let replay_task = self
                    .timeline_unwrap()
                    .current_session()
                    .find_task_from_task_uid(target.tuid())
                    .unwrap();
                self.timeline_unwrap_mut().remove_breakpoint(
                    replay_task.as_replay_task().unwrap(),
                    req.watch().addr.to_code_ptr(),
                );
                if !session
                    .weak_self()
                    .ptr_eq(self.timeline_unwrap().current_session().weak_self())
                {
                    target.vm().remove_breakpoint(
                        req.watch().addr.to_code_ptr(),
                        BreakpointType::User,
                    );
                }
                self.dbg_unwrap_mut().reply_watchpoint_request(true);
                return;
            }
            DREQ_REMOVE_HW_BREAK
            | DREQ_REMOVE_RD_WATCH
            | DREQ_REMOVE_WR_WATCH
            | DREQ_REMOVE_RDWR_WATCH => {
                let task = self
                    .timeline_unwrap()
                    .current_session()
                    .find_task_from_task_uid(target.tuid())
                    .unwrap();
                self.timeline_unwrap_mut().remove_watchpoint(
                    task.as_replay_task().unwrap(),
                    req.watch().addr,
                    req.watch().kind,
                    watchpoint_type(req.type_),
                );
                if !session
                    .weak_self()
                    .ptr_eq(self.timeline_unwrap().current_session().weak_self())
                {
                    target.vm().remove_watchpoint(
                        req.watch().addr,
                        req.watch().kind,
                        watchpoint_type(req.type_),
                    );
                }
                self.dbg_unwrap_mut().reply_watchpoint_request(true);
                return;
            }
            DREQ_READ_SIGINFO => {
                let mut si_bytes = vec![0u8; req.mem().len];
                unsafe {
                    copy_nonoverlapping(
                        &self.stop_siginfo as *const _ as *const u8,
                        si_bytes.as_mut_ptr() as *mut u8,
                        min(si_bytes.len(), mem::size_of_val(&self.stop_siginfo)),
                    )
                };
                self.dbg_unwrap_mut().reply_read_siginfo(&si_bytes);
                return;
            }
            DREQ_WRITE_SIGINFO => {
                log!(
                    LogWarn,
                    "WRITE_SIGINFO request outside of diversion session"
                );
                self.dbg_unwrap_mut().reply_write_siginfo();
                return;
            }
            DREQ_RD_CMD => {
                let text = GdbCommandHandler::process_command(self, &**target, req.text());
                self.dbg_unwrap_mut().reply_rd_cmd(&text);
                return;
            }
            DREQ_QSYMBOL => {
                // When gdb sends "qSymbol::", it means that gdb is ready to
                // respond to symbol requests.  This can be sent multiple times
                // during the course of a session -- gdb sends it whenever
                // something in the inferior has changed, making it possible
                // that previous failed symbol lookups could now succeed.  In
                // response to a qSymbol request from gdb, we either send back a
                // qSymbol response, requesting the address of a symbol; or we
                // send back OK.  We have to do this as an ordinary response and
                // maintain our own state explicitly, as opposed to simply
                // reading another packet from gdb, because when gdb looks up a
                // symbol it might send other requests that must be served.  So,
                // we keep a copy of the symbol names, and an iterator into this
                // copy.  When gdb sends a plain "qSymbol::" packet, because gdb
                // has detected some change in the inferior state that might
                // enable more symbol lookups, we restart the iterator.
                if self.thread_db.is_none() {
                    self.thread_db = Some(ThreadDb::new(self.debuggee_tguid.tid()));
                }

                let name = OsStr::from_bytes(req.sym().name.as_bytes()).to_owned();
                if req.sym().has_address {
                    // Got a response holding a previously-requested symbol's name
                    // and address.
                    self.thread_db_mut_unwrap()
                        .register_symbol(name, req.sym().address);
                } else if name.as_bytes().is_empty() {
                    // Plain "qSymbol::" request.
                    self.symbols = self.thread_db_mut_unwrap().get_symbols_and_clear_map();
                    self.symbols_loc = Some(0);
                }

                if self.symbols_loc == Some(self.symbols.len()) || self.symbols_loc == None {
                    self.dbg_unwrap_mut().qsymbols_finished();
                } else {
                    let symbol = self.symbols[self.symbols_loc.unwrap()].clone();
                    self.symbols_loc = Some(self.symbols_loc.unwrap() + 1);
                    self.dbg_unwrap_mut().send_qsymbol(symbol.as_bytes());
                }

                return;
            }
            DREQ_TLS => {
                if self.thread_db.is_none() {
                    self.thread_db = Some(ThreadDb::new(self.debuggee_tguid.tid()));
                }
                let tg_shr = target.thread_group();
                let mut tg = tg_shr.borrow_mut();
                let maybe_addr = self.thread_db.as_mut().unwrap().get_tls_address(
                    &mut tg,
                    target.rec_tid.get(),
                    req.tls().offset,
                    req.tls().load_module,
                );
                self.dbg_unwrap_mut().reply_tls_addr(maybe_addr);
                return;
            }
            _ => fatal!("Unknown debugger request {}", req.type_),
        }
    }

    fn at_target(&self) -> bool {
        // Don't launch the debugger for the initial rd fork child.
        // No one ever wants that to happen.
        if !self.timeline_unwrap().current_session().done_initial_exec() {
            return false;
        }
        let maybe_t = self.timeline_unwrap().current_session().current_task();
        if maybe_t.is_none() {
            return false;
        }
        let t = maybe_t.unwrap();
        if !self.timeline_unwrap().can_add_checkpoint() {
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
        let timeline = self.timeline_unwrap();
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

    fn activate_debugger(&mut self) {
        let event_now = self
            .timeline_unwrap()
            .current_session()
            .current_trace_frame()
            .time();
        // We MUST have a task
        let t = self
            .timeline_unwrap()
            .current_session()
            .current_task()
            .unwrap();
        if self.target.event > 0 || self.target.pid.is_some() {
            if self.stop_replaying_to_target {
                // @TODO There should be a bell in message
                eprint!(
                    "\n\
               --------------------------------------------------\n\
               ---> Interrupted; attached to NON-TARGET process {} at event {}.\n\
               --------------------------------------------------\n",
                    t.tgid(),
                    event_now
                );
            } else {
                // @TODO There should be a bell in message
                eprint!(
                    "\n\
               --------------------------------------------------\n\
               ---> Reached target process {} at event {}.\n\
               --------------------------------------------------\n",
                    t.tgid(),
                    event_now
                );
            }
        }

        // Store the current tgid and event as the "execution target"
        // for the next replay session, if we end up restarting.  This
        // allows us to determine if a later session has reached this
        // target without necessarily replaying up to this point.
        self.target.pid = Some(t.tgid());
        self.target.require_exec = false;
        self.target.event = event_now;

        self.last_query_tuid = t.tuid();
        self.last_continue_tuid = t.tuid();

        // Have the "checkpoint" be the original replay
        // session, and then switch over to using the cloned
        // session.  The cloned tasks will look like children
        // of the clonees, so this scheme prevents |pstree|
        // output from getting /too/ far out of whack.
        let where_ = OsString::from("???");
        let can_add_checkpoint = self.timeline_unwrap().can_add_checkpoint();
        let checkpoint = if can_add_checkpoint {
            Checkpoint::new(
                &mut self.timeline_unwrap_mut(),
                self.last_continue_tuid,
                ExplicitCheckpoint::Explicit,
                &where_,
            )
        } else {
            Checkpoint::new(
                &mut self.timeline_unwrap_mut(),
                self.last_continue_tuid,
                ExplicitCheckpoint::NotExplicit,
                &where_,
            )
        };
        self.debugger_restart_checkpoint = Some(checkpoint);
    }

    fn restart_session(&mut self, req: &GdbRequest) {
        debug_assert_eq!(req.type_, DREQ_RESTART);
        debug_assert!(self.dbg.is_some());

        self.in_debuggee_end_state = false;
        self.timeline_unwrap_mut()
            .remove_breakpoints_and_watchpoints();

        let mut maybe_checkpoint_to_restore = None;
        if req.restart().type_ == GdbRestartType::FromCheckpoint {
            let maybe_it = self.checkpoints.get(&req.restart().param).cloned();
            match maybe_it {
                None => {
                    println!("Checkpoint {} not found.", req.restart().param_str);
                    println!("Valid checkpoints:");
                    for &i in self.checkpoints.keys() {
                        println!(" {}", i);
                    }
                    println!();
                    self.dbg_unwrap_mut().notify_restart_failed();
                    return;
                }
                Some(c) => {
                    maybe_checkpoint_to_restore = Some(c);
                }
            }
        } else if req.restart().type_ == GdbRestartType::FromPrevious {
            maybe_checkpoint_to_restore = self.debugger_restart_checkpoint.clone();
        }

        self.interrupt_pending = true;

        if let Some(checkpoint) = maybe_checkpoint_to_restore {
            self.timeline_unwrap_mut().seek_to_mark(&checkpoint.mark);
            self.last_query_tuid = checkpoint.last_continue_tuid;
            self.last_continue_tuid = checkpoint.last_continue_tuid;
            if self
                .debugger_restart_checkpoint
                .as_ref()
                .unwrap()
                .is_explicit
                == ExplicitCheckpoint::Explicit
            {
                self.timeline_unwrap_mut().remove_explicit_checkpoint(
                    &self.debugger_restart_checkpoint.as_ref().unwrap().mark,
                );
            }
            self.debugger_restart_checkpoint = Some(checkpoint);
            let can_add_checkpoint = self.timeline_unwrap().can_add_checkpoint();
            if can_add_checkpoint {
                self.timeline_unwrap_mut().add_explicit_checkpoint();
            }
            return;
        }

        self.stop_replaying_to_target = false;

        debug_assert_eq!(req.restart().type_, GdbRestartType::FromEvent);
        // Note that we don't reset the target pid; we intentionally keep targeting
        // the same process no matter what is running when we hit the event.
        self.target.event = req.restart().param;
        self.target.event = min(self.final_event - 1, self.target.event);
        self.timeline_unwrap_mut()
            .seek_to_before_event(self.target.event);
        loop {
            let result = self
                .timeline_unwrap_mut()
                .replay_step_forward(RunCommand::Continue, self.target.event);
            // We should never reach the end of the trace without hitting the stop
            // condition below.
            debug_assert_ne!(result.status, ReplayStatus::ReplayExited);
            if is_last_thread_exit(&result.break_status)
                && result
                    .break_status
                    .task_unwrap()
                    .thread_group()
                    .borrow()
                    .tgid
                    == self.target.pid.unwrap()
            {
                // Debuggee task is about to exit. Stop here.
                self.in_debuggee_end_state = true;
                break;
            }
            if self.at_target() {
                break;
            }
        }
        self.activate_debugger();
    }

    fn process_debugger_requests(&mut self, maybe_state: Option<ReportState>) -> GdbRequest {
        loop {
            let state = maybe_state.unwrap_or(ReportState::ReportNormal);
            let mut req = self.dbg_unwrap_mut().get_request();
            req.suppress_debugger_stop = false;
            self.try_lazy_reverse_singlesteps(&mut req);

            if req.type_ == DREQ_READ_SIGINFO {
                let mut si_bytes = vec![0u8; req.mem().len];
                let num_bytes = min(si_bytes.len(), mem::size_of_val(&self.stop_siginfo));
                unsafe {
                    ptr::copy_nonoverlapping(
                        &self.stop_siginfo as *const siginfo_t as *const u8,
                        si_bytes.as_mut_ptr(),
                        num_bytes,
                    );
                }
                self.dbg_unwrap_mut().reply_read_siginfo(&si_bytes);

                // READ_SIGINFO is usually the start of a diversion. It can also be
                // triggered by "print $_siginfo" but that is rare so we just assume it's
                // a diversion start; if "print $_siginfo" happens we'll print the correct
                // siginfo and then incorrectly start a diversion and go haywire :-(.
                // Ideally we'd come up with a better way to detect diversions so that
                // "print $_siginfo" works.
                let curr_sess = self.timeline_unwrap().current_session_shr_ptr();
                req = self.divert(curr_sess.as_replay().unwrap());
                if req.type_ == DREQ_NONE {
                    continue;
                }
                // Carry on to process the request that was rejected by
                // the diversion session
            }

            if req.is_resume_request() {
                if let Some(t) = self
                    .current_session()
                    .find_task_from_task_uid(self.last_continue_tuid)
                {
                    maybe_singlestep_for_event(&**t, &mut req);
                }
                return req;
            }

            if req.type_ == DREQ_INTERRUPT {
                log!(LogDebug, "  request to interrupt");
                return req;
            }

            if req.type_ == DREQ_RESTART {
                // Debugger client requested that we restart execution
                // from the beginning.  Restart our debug session.
                log!(
                    LogDebug,
                    "  request to restart at event {}",
                    req.restart().param
                );
                return req;
            }
            if req.type_ == DREQ_DETACH {
                log!(LogDebug, "  debugger detached");
                self.dbg_unwrap_mut().reply_detach();
                return req;
            }

            let session = self.current_session();
            self.dispatch_debugger_request(&**session, &req, state);
        }
    }

    fn detach_or_restart(&mut self, req: &GdbRequest, s: &mut ContinueOrStop) -> bool {
        if DREQ_RESTART == req.type_ {
            self.restart_session(req);
            *s = ContinueOrStop::ContinueDebugging;
            true
        } else if DREQ_DETACH == req.type_ {
            *s = ContinueOrStop::StopDebugging;
            true
        } else {
            false
        }
    }

    fn handle_exited_state(&mut self, last_resume_request: &mut GdbRequest) -> ContinueOrStop {
        // TODO return real exit code, if it's useful.
        self.dbg_unwrap_mut().notify_exit_code(0);
        let final_event = self
            .timeline_unwrap()
            .current_session()
            .trace_reader()
            .time();
        self.final_event = final_event;
        let req: GdbRequest = self.process_debugger_requests(Some(ReportState::ReportThreadsDead));
        let mut s = ContinueOrStop::default();
        if self.detach_or_restart(&req, &mut s) {
            *last_resume_request = GdbRequest::new(DREQ_NONE);
            return s;
        }
        fatal!("Received continue/interrupt request after end-of-trace.");
    }

    fn debug_one_step(&mut self, last_resume_request: &mut GdbRequest) -> ContinueOrStop {
        let mut result: ReplayResult = Default::default();
        let mut req: GdbRequest;

        if self.in_debuggee_end_state {
            // Treat the state where the last thread is about to exit like
            // termination.
            req = self.process_debugger_requests(None);
            // If it's a forward execution request, fake the exited state.
            if req.is_resume_request() && req.cont().run_direction == RunDirection::RunForward {
                if self.interrupt_pending {
                    // Just process this. We're getting it after a restart.
                } else {
                    return self.handle_exited_state(last_resume_request);
                }
            } else {
                if req.type_ != DREQ_DETACH {
                    self.in_debuggee_end_state = false;
                }
            }
            // Otherwise (e.g. detach, restart, interrupt or reverse-exec) process
            // the request as normal.
        } else if !self.interrupt_pending || last_resume_request.type_ == DREQ_NONE {
            req = self.process_debugger_requests(None);
        } else {
            req = last_resume_request.clone();
        }

        let mut s: ContinueOrStop = Default::default();
        if self.detach_or_restart(&req, &mut s) {
            *last_resume_request = GdbRequest::default();
            return s;
        }

        if req.is_resume_request() {
            *last_resume_request = req.clone();
        } else {
            debug_assert_eq!(req.type_, DREQ_INTERRUPT);
            self.interrupt_pending = true;
            req = last_resume_request.clone();
            debug_assert!(req.is_resume_request());
        }

        if self.interrupt_pending {
            let t = self
                .timeline_unwrap()
                .current_session()
                .current_task()
                .unwrap();
            if t.thread_group().borrow().tguid() == self.debuggee_tguid {
                self.interrupt_pending = false;
                let threadid = get_threadid(&**t);
                let maybe_sig = if self.in_debuggee_end_state {
                    Some(sig::SIGKILL)
                } else {
                    None
                };
                self.dbg_unwrap_mut()
                    .notify_stop(threadid, maybe_sig, RemotePtr::null());
                self.stop_siginfo = Default::default();
                return ContinueOrStop::ContinueDebugging;
            }
        }

        if req.cont().run_direction == RunDirection::RunForward {
            if is_in_exec(&self.timeline_unwrap()).is_some()
                && self
                    .timeline_unwrap()
                    .current_session()
                    .current_task()
                    .unwrap()
                    .thread_group()
                    .borrow()
                    .tguid()
                    == self.debuggee_tguid
            {
                // Don't go any further forward. maybe_notify_stop will generate a
                // stop.
                result = ReplayResult::default();
            } else {
                let mut signal_to_deliver: Option<Sig> = None;
                let task = self
                    .timeline_unwrap()
                    .current_session()
                    .current_task()
                    .unwrap();
                let command: RunCommand =
                    compute_run_command_from_actions(&**task, &req, &mut signal_to_deliver);
                // Ignore gdb's |signal_to_deliver|; we just have to follow the replay.
                result = self
                    .timeline_unwrap_mut()
                    .replay_step_forward(command, self.target.event);
            }
        } else {
            let mut allowed_tasks: Vec<AllowedTasks> = Vec::new();
            // Convert the tids in GdbContActions into TaskUids to avoid issues
            // if tids get reused.
            let command: RunCommand = compute_run_command_for_reverse_exec(
                self.timeline_unwrap().current_session(),
                self.debuggee_tguid,
                &req,
                &mut allowed_tasks,
            );
            let debugee_tguid = self.debuggee_tguid;
            let stop_filter = move |t: &ReplayTask| -> bool {
                if t.thread_group().borrow().tguid() != debugee_tguid {
                    return false;
                }
                // If gdb's requested actions don't allow the task to run, we still
                // let it run (we can't do anything else, since we're replaying), but
                // we won't report stops in that task.
                for a in &allowed_tasks {
                    if a.task.tid() == 0 || a.task == t.tuid() {
                        return true;
                    }
                }
                return false;
            };
            let gdb_connection = self.dbg.as_ref().unwrap().clone();
            let interrupt_check = move || -> bool { gdb_connection.borrow_mut().sniff_packet() };
            match command {
                RunCommand::Continue => {
                    result = self
                        .timeline_unwrap_mut()
                        .reverse_continue(&stop_filter, &interrupt_check);
                }
                RunCommand::Singlestep => {
                    let tick_count = self
                        .timeline_unwrap()
                        .current_session()
                        .find_task_from_task_uid(self.last_continue_tuid)
                        .unwrap()
                        .tick_count();
                    result = self.timeline_unwrap_mut().reverse_singlestep(
                        self.last_continue_tuid,
                        tick_count,
                        &stop_filter,
                        &interrupt_check,
                    );
                }
                _ => debug_assert!(false),
            }
        }

        if result.status == ReplayStatus::ReplayExited {
            return self.handle_exited_state(last_resume_request);
        }

        if !req.suppress_debugger_stop {
            self.maybe_notify_stop(&req, &result.break_status);
        }
        if req.cont().run_direction == RunDirection::RunForward
            && is_last_thread_exit(&result.break_status)
            && result
                .break_status
                .task
                .upgrade()
                .unwrap()
                .thread_group()
                .borrow()
                .tguid()
                == self.debuggee_tguid
        {
            self.in_debuggee_end_state = true;
        }

        ContinueOrStop::ContinueDebugging
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
    fn try_lazy_reverse_singlesteps(&mut self, req: &mut GdbRequest) {
        if !self.timeline_is_running() {
            return;
        }

        let mut now: Option<Mark> = None;
        let mut need_seek = false;
        let maybe_t = self.timeline_unwrap().current_session().current_task();
        while maybe_t.is_some()
            && req.type_ == DREQ_CONT
            && req.cont().run_direction == RunDirection::RunBackward
            && req.cont().actions.len() == 1
            && req.cont().actions[0].type_ == GdbActionType::ActionStep
            && req.cont().actions[0].maybe_signal_to_deliver.is_none()
            && matches_threadid(&***maybe_t.as_ref().unwrap(), req.cont().actions[0].target)
            && !req.suppress_debugger_stop
        {
            let t = maybe_t.as_ref().unwrap();
            if now.is_none() {
                now = Some(self.timeline_unwrap_mut().mark());
            }
            let previous = self
                .timeline_unwrap_mut()
                .lazy_reverse_singlestep(now.as_ref().unwrap(), t.as_replay_task().unwrap());
            if previous.is_none() {
                break;
            }

            now = previous;
            need_seek = true;
            let break_status = BreakStatus {
                task: t.weak_self_clone(),
                singlestep_complete: true,
                ..Default::default()
            };
            log!(LogDebug, "  using lazy reverse-singlestep");
            self.maybe_notify_stop(req, &break_status);

            loop {
                *req = self.dbg_unwrap_mut().get_request();
                req.suppress_debugger_stop = false;
                if req.type_ != DREQ_GET_REGS {
                    break;
                }
                log!(LogDebug, "  using lazy reverse-singlestep registers");
                self.dispatch_regs_request(
                    &now.as_ref().unwrap().regs(),
                    &now.as_ref().unwrap().extra_regs(),
                );
            }
        }

        if need_seek {
            self.timeline_unwrap_mut()
                .seek_to_mark(now.as_ref().unwrap());
        }
    }

    /// Process debugger requests made in |diversion_session| until action needs
    /// to be taken by the caller (a resume-execution request is received).
    /// The received request is returned through |req|.
    /// Returns true if diversion should continue, false if it should end.
    fn diverter_process_debugger_requests(
        &mut self,
        diversion_session: &DiversionSession,
        diversion_refcount: &mut usize,
        req: &mut GdbRequest,
    ) -> bool {
        loop {
            *req = self.dbg_unwrap_mut().get_request();

            if req.is_resume_request() {
                return *diversion_refcount > 0;
            }

            match req.type_ {
                DREQ_RESTART | DREQ_DETACH => {
                    *diversion_refcount = 0;
                    return false;
                }
                DREQ_READ_SIGINFO => {
                    log!(LogDebug, "Adding ref to diversion session");
                    *diversion_refcount += 1;
                    // TODO: maybe share with replayer.cc?
                    let si_bytes = vec![0u8; req.mem().len];
                    self.dbg_unwrap_mut().reply_read_siginfo(&si_bytes);
                    continue;
                }

                DREQ_SET_QUERY_THREAD => {
                    if req.target.tid > 0 {
                        if let Some(next) = diversion_session.find_task_from_rec_tid(req.target.tid)
                        {
                            self.last_query_tuid = next.tuid();
                        }
                    }
                }

                DREQ_WRITE_SIGINFO => {
                    log!(LogDebug, "Removing reference to diversion session ...");
                    debug_assert!(*diversion_refcount > 0);
                    *diversion_refcount -= 1;
                    if *diversion_refcount == 0 {
                        log!(LogDebug, "  ... dying at next continue request");
                    }
                    self.dbg_unwrap_mut().reply_write_siginfo();
                    continue;
                }
                DREQ_RD_CMD => {
                    debug_assert_eq!(req.type_, DREQ_RD_CMD);
                    let maybe_task =
                        diversion_session.find_task_from_task_uid(self.last_continue_tuid);
                    if let Some(task) = maybe_task {
                        let reply = GdbCommandHandler::process_command(self, &**task, req.text());
                        // Certain commands cause the diversion to end immediately
                        // while other commands must work within a diversion.
                        if reply == GdbCommandHandler::cmd_end_diversion().as_bytes() {
                            *diversion_refcount = 0;
                            return false;
                        }
                        self.dbg_unwrap_mut().reply_rd_cmd(&reply);
                        continue;
                    } else {
                        *diversion_refcount = 0;
                        return false;
                    }
                }

                _ => (),
            };
            self.dispatch_debugger_request(diversion_session, req, ReportState::ReportNormal);
        }
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
    fn divert(&mut self, replay: &ReplaySession) -> GdbRequest {
        let mut req: GdbRequest = Default::default();
        log!(
            LogDebug,
            "Starting debugging diversion for {}",
            replay.unique_id()
        );

        if self.timeline_is_running() {
            // Ensure breakpoints and watchpoints are applied before we fork the
            // diversion, to ensure the diversion is consistent with the timeline
            // breakpoint/watchpoint state.
            self.timeline_unwrap_mut()
                .apply_breakpoints_and_watchpoints();
        }
        let diversion_session = replay.clone_diversion();
        let mut diversion_refcount: usize = 1;
        let saved_query_tuid = self.last_query_tuid;

        while self.diverter_process_debugger_requests(
            diversion_session.as_diversion().unwrap(),
            &mut diversion_refcount,
            &mut req,
        ) {
            debug_assert!(req.is_resume_request());

            if req.cont().run_direction == RunDirection::RunBackward {
                // We don't support reverse execution in a diversion. Just issue
                // an immediate stop.
                let thread_id =
                    get_threadid_from_tuid(&**diversion_session, self.last_continue_tuid);
                self.dbg_unwrap_mut()
                    .notify_stop(thread_id, None, RemotePtr::null());
                self.stop_siginfo = Default::default();
                self.last_query_tuid = self.last_continue_tuid;
                continue;
            }

            let maybe_t = diversion_session.find_task_from_task_uid(self.last_continue_tuid);
            if maybe_t.is_none() {
                diversion_refcount = 0;
                req = GdbRequest::new(DREQ_NONE);
                break;
            }
            let t = maybe_t.unwrap();
            let mut maybe_signal_to_deliver = None;
            let command =
                compute_run_command_from_actions(&**t, &req, &mut maybe_signal_to_deliver);
            let result = diversion_session.as_diversion().unwrap().diversion_step(
                &**t,
                command,
                maybe_signal_to_deliver,
            );

            if result.status == DiversionStatus::DiversionExited {
                diversion_refcount = 0;
                req = GdbRequest::new(DREQ_NONE);
                break;
            }

            debug_assert_eq!(result.status, DiversionStatus::DiversionContinue);

            self.maybe_notify_stop(&req, &result.break_status);
        }

        log!(LogDebug, "... ending debugging diversion");
        debug_assert!(diversion_refcount == 0);

        diversion_session.kill_all_tasks();

        self.last_query_tuid = saved_query_tuid;
        req
    }

    /// If `break_status` indicates a stop that we should report to gdb,
    /// report it. `req` is the resume request that generated the stop.
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
        if is_last_thread_exit(break_status) && self.dbg_unwrap().features().reverse_execution {
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
        let mut maybe_t = break_status.task.upgrade();
        let maybe_in_exec_task = is_in_exec(&self.timeline_unwrap());
        if let Some(in_exec_task) = maybe_in_exec_task {
            do_stop = true;
            self.stop_siginfo = Default::default();
            maybe_t = Some(in_exec_task);
            log!(LogDebug, "Stopping at exec");
        }
        if do_stop {
            let t = maybe_t.unwrap();
            if t.thread_group().borrow().tguid() == self.debuggee_tguid {
                // Notify the debugger and process any new requests
                // that might have triggered before resuming.
                let signo = self.stop_siginfo.si_signo;
                let threadid = get_threadid(&**t);
                self.dbg_unwrap_mut()
                    .notify_stop(threadid, Sig::try_from(signo).ok(), watch_addr);
                self.last_continue_tuid = t.tuid();
                self.last_query_tuid = t.tuid();
            }
        }
    }

    /// Handle GDB file open requests. If we can serve this read request, add
    /// an entry to `files` with the file contents and return our internal
    /// file descriptor.
    #[allow(clippy::unnecessary_unwrap)]
    fn open_file(&mut self, session: &dyn Session, pathname: &OsStr) -> i32 {
        // XXX should we require file_scope_pid == 0 here?
        log!(LogDebug, "Trying to open {:?}", pathname);

        let mut content = ScopedFd::new();
        let pathname = Path::new(pathname);
        let mut components = pathname.components();
        let maybe_rootdir = components.next();
        let maybe_proc = components.next();
        let maybe_pid_os_str = components.next();
        let maybe_task_or_maps = components.next();
        let maybe_tid_os_str = components.next();
        let maybe_maps = components.next();
        if (maybe_rootdir, maybe_proc, maybe_task_or_maps, maybe_maps)
            == (
                Some(Component::RootDir),
                Some(Component::Normal(OsStr::new("proc"))),
                Some(Component::Normal(OsStr::new("task"))),
                Some(Component::Normal(OsStr::new("maps"))),
            )
            && maybe_pid_os_str.is_some()
            && maybe_tid_os_str.is_some()
        {
            let maybe_pid_str =
                std::str::from_utf8(maybe_pid_os_str.unwrap().as_os_str().as_bytes()).ok();
            let maybe_tid_str =
                std::str::from_utf8(maybe_tid_os_str.unwrap().as_os_str().as_bytes()).ok();
            match (maybe_pid_str, maybe_tid_str) {
                (Some(pid_s), Some(tid_s)) => {
                    let maybe_pid = pid_s.parse::<pid_t>().ok();
                    let maybe_tid = tid_s.parse::<pid_t>().ok();
                    match (maybe_pid, maybe_tid) {
                        (Some(pid), Some(tid)) if pid == tid => {
                            if let Some(t) = session.find_task_from_rec_tid(tid) {
                                content = generate_fake_proc_maps(&**t)
                            } else {
                                return -1;
                            }
                        }
                        _ => return -1,
                    }
                }
                _ => return -1,
            }
        } else if (maybe_rootdir, maybe_proc, maybe_task_or_maps)
            == (
                Some(Component::RootDir),
                Some(Component::Normal(OsStr::new("proc"))),
                Some(Component::Normal(OsStr::new("maps"))),
            )
            && maybe_pid_os_str.is_some()
        {
            let maybe_pid_str =
                std::str::from_utf8(maybe_pid_os_str.unwrap().as_os_str().as_bytes()).ok();
            match maybe_pid_str {
                Some(pid_s) => {
                    let maybe_pid = pid_s.parse::<pid_t>().ok();
                    match maybe_pid {
                        Some(pid) => {
                            if let Some(t) = session.find_task_from_rec_tid(pid) {
                                content = generate_fake_proc_maps(&**t)
                            } else {
                                return -1;
                            }
                        }
                        _ => return -1,
                    }
                }
                _ => return -1,
            }
        }
        let mut ret_fd: i32 = 0;
        while self.files.get(&ret_fd).is_some() {
            ret_fd += 1;
        }
        self.files.insert(ret_fd, content);
        ret_fd
    }
}

fn generate_fake_proc_maps(t: &dyn Task) -> ScopedFd {
    let file = create_temporary_file(b"rd-fake-proc-maps-XXXXXX");
    unlink(file.name.as_os_str()).unwrap();

    let fd = match dup(file.fd.as_raw()) {
        Ok(fd) => fd,
        Err(e) => {
            fatal!("Cannot dup: {:?}", e)
        }
    };
    // @TODO : rr has fdopen(fd, "w").
    // Is this equivalent in all cases?
    let mut f = unsafe { File::from_raw_fd(fd) };

    let addr_min_width: usize = if word_size(t.arch()) == 8 { 10 } else { 8 };
    for (&_, m) in &t.vm().maps() {
        let s: String = format!(
            "{:0addr_min_width$x}-{:0addr_min_width$x} {}{}{}{} {:08x} {:02x}:{:02x} {}",
            m.recorded_map.start().as_usize(),
            m.recorded_map.end().as_usize(),
            if m.recorded_map.prot().contains(ProtFlags::PROT_READ) {
                "r"
            } else {
                "-"
            },
            if m.recorded_map.prot().contains(ProtFlags::PROT_WRITE) {
                "w"
            } else {
                "-"
            },
            if m.recorded_map.prot().contains(ProtFlags::PROT_EXEC) {
                "x"
            } else {
                "-"
            },
            if m.recorded_map.flags().contains(MapFlags::MAP_SHARED) {
                "s"
            } else {
                "p"
            },
            m.recorded_map.file_offset_bytes(),
            major(m.recorded_map.device()),
            minor(m.recorded_map.device()),
            m.recorded_map.inode()
        );
        f.write_all(s.as_bytes()).unwrap();
        let mut len = s.len();
        while len < 72 {
            f.write_all(b" ").unwrap();
            len += 1;
        }
        f.write_all(b" ").unwrap();

        let mut name = Vec::<u8>::new();
        let fsname = m.recorded_map.fsname();
        for &b in fsname.as_bytes() {
            if b == b'\n' {
                name.extend_from_slice(b"\\012");
            } else {
                name.push(b);
            }
        }
        f.write_all(&name).unwrap();
        f.write_all(b"\n").unwrap();
    }
    file.fd
}

fn maybe_singlestep_for_event(t: &dyn Task, req: &mut GdbRequest) {
    if !t.session().is_replaying() {
        return;
    }
    let rt = t.as_replay_task().unwrap();
    if trace_instructions_up_to_event(
        rt.session()
            .as_replay()
            .unwrap()
            .current_trace_frame()
            .time(),
    ) {
        eprint!("Stepping: ");
        rt.regs_ref()
            .write_register_file_compact(&mut stderr())
            .unwrap();
        eprint!(" ticks:{}", rt.tick_count());
        *req = GdbRequest::new(DREQ_CONT);
        req.suppress_debugger_stop = true;
        let thread_id = get_threadid_from_tuid(&**rt.session(), rt.tuid());
        req.cont_mut().actions.push(GdbContAction::new(
            Some(GdbActionType::ActionStep),
            Some(thread_id),
            None,
        ));
    }
}

fn compute_run_command_for_reverse_exec(
    session: &ReplaySession,
    debuggee_tguid: ThreadGroupUid,
    req: &GdbRequest,
    allowed_tasks: &mut Vec<AllowedTasks>,
) -> RunCommand {
    // Singlestep if any of the actions request singlestepping.
    let mut result: RunCommand = RunCommand::Continue;
    for action in &req.cont().actions {
        if action.target.pid > 0 && action.target.pid != debuggee_tguid.tid() {
            continue;
        }
        let mut allowed = AllowedTasks {
            command: RunCommand::Continue,
            ..Default::default()
        };
        if action.type_ == GdbActionType::ActionStep {
            result = RunCommand::Singlestep;
            allowed.command = RunCommand::Singlestep;
        }
        if action.target.tid > 0 {
            if let Some(t) = session.find_task_from_rec_tid(action.target.tid) {
                allowed.task = t.tuid();
            }
        }
        allowed_tasks.push(allowed);
    }
    result
}

fn compute_run_command_from_actions(
    t: &dyn Task,
    req: &GdbRequest,
    maybe_signal_to_deliver: &mut Option<Sig>,
) -> RunCommand {
    for action in &req.cont().actions {
        if matches_threadid(t, action.target) {
            // We can only run task |t|; neither diversion nor replay sessions
            // support running multiple threads. So even if gdb tells us to continue
            // multiple threads, we don't do that.
            *maybe_signal_to_deliver = action.maybe_signal_to_deliver;
            return if action.type_ == GdbActionType::ActionStep {
                RunCommand::Singlestep
            } else {
                RunCommand::Continue
            };
        }
    }
    // gdb told us to run (or step) some thread that's not |t|, without resuming
    // |t|. It sometimes does this even though its target thread is entering a
    // blocking syscall and |t| must run before gdb's target thread can make
    // progress. So, allow |t| to run anyway.
    *maybe_signal_to_deliver = None;
    RunCommand::Continue
}

fn needs_target(option: &OsStr) -> bool {
    option.as_bytes() == b"continue"
}

fn create_gdb_command_file(macros: &str) -> OsString {
    let mut file = create_temporary_file(b"rd-gdb-commands-XXXXXX");
    // This fd is just leaked. That's fine since we only call this once
    // per rr invocation at the moment.
    let fd = file.fd.extract();
    // DIFF NOTE: Unlike rr, we require unlink to be successful
    unlink(file.name.as_os_str()).unwrap();

    // DIFF NOTE: rr uses write in unistd.h
    write_all(fd, macros.as_bytes());

    let mut procfile = Vec::new();
    write!(procfile, "/proc/{}/fd/{}", getpid(), fd).unwrap();
    OsString::from_vec(procfile)
}

/// DIFF NOTE: Called print_debugger_launch_command() in rr
fn write_debugger_launch_command(
    t: &TaskInner,
    dbg_host: &str,
    port: u16,
    debugger_name: &Path,
    out: &mut dyn Write,
) {
    let mut options: Vec<OsString> = Vec::new();
    push_default_gdb_options(&mut options);
    push_target_remote_cmd(&mut options, dbg_host, port);
    out.write_all(debugger_name.as_os_str().as_bytes()).unwrap();
    for opt in &options {
        out.write_all(b" '").unwrap();
        out.write_all(opt.as_bytes()).unwrap();
        out.write_all(b"'").unwrap();
    }
    out.write_all(b" ").unwrap();
    out.write_all(t.vm().exe_image().as_bytes()).unwrap();
    out.write_all(b"\n").unwrap();
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

impl Default for ContinueOrStop {
    fn default() -> Self {
        // Purely arbitrary
        Self::ContinueDebugging
    }
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
///
/// DIFF NOTE: Just takes the task params it needs
fn await_connection(
    tgid: pid_t,
    arch: SupportedArch,
    listen_fd: &ScopedFd,
    features: GdbConnectionFeatures,
) -> GdbConnection {
    let mut dbg = GdbConnection::new(tgid, features);
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
        false
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
    assert_ne!(find_s.len(), 0);
    let mut buf = vec![0u8; page_size() + find_s.len() - 1];
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
                    if let Some(off) = maybe_offset {
                        let result = Some(r.start() + off);
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
        DREQ_SET_HW_BREAK | DREQ_REMOVE_HW_BREAK => WatchType::Exec,
        DREQ_SET_WR_WATCH | DREQ_REMOVE_WR_WATCH => WatchType::Write,
        // NB| x86 doesn't support read-only watchpoints (who would
        // ever want to use one?) so we treat them as readwrite
        // watchpoints and hope that gdb can figure out what's going
        // on.  That is, if a user ever tries to set a read
        // watchpoint.
        DREQ_REMOVE_RDWR_WATCH | DREQ_SET_RDWR_WATCH | DREQ_REMOVE_RD_WATCH | DREQ_SET_RD_WATCH => {
            WatchType::ReadWrite
        }
        _ => fatal!("Unknown dbg request {}", req),
    }
}

struct DebuggerParams {
    exe_image: [u8; libc::PATH_MAX as usize],
    /// INET_ADDRSTRLEN
    host: [u8; 16],
    port: u16,
}

impl Default for DebuggerParams {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

fn push_default_gdb_options(vec: &mut Vec<OsString>) {
    // The gdb protocol uses the "vRun" packet to reload
    // remote targets.  The packet is specified to be like
    // "vCont", in which gdb waits infinitely long for a
    // stop reply packet.  But in practice, gdb client
    // expects the vRun to complete within the remote-reply
    // timeout, after which it issues vCont.  The timeout
    // causes gdb<-->rd communication to go haywire.
    //
    // rd can take a very long time indeed to send the
    // stop-reply to gdb after restarting replay; the time
    // to reach a specified execution target is
    // theoretically unbounded.  Timing out on vRun is
    // technically a gdb bug, but because the rd replay and
    // the gdb reload models don't quite match up, we'll
    // work around it on the rd side by disabling the
    // remote-reply timeout.
    vec.push("-l".into());
    vec.push("10000".into());
    // For now, avoid requesting binary files through vFile. That is slow and
    // hard to make work correctly, because gdb requests files based on the
    // names it sees in memory and in ELF, and those names may be symlinks to
    // the filenames in the trace, so it's hard to match those names to files in
    // the trace.
    vec.push("-ex".into());
    vec.push("set sysroot /".into());
}

fn push_target_remote_cmd(vec: &mut Vec<OsString>, host: &str, port: u16) {
    vec.push("-ex".into());
    let mut ss = Vec::<u8>::new();
    // If we omit the address, then gdb can try to resolve "localhost" which
    // in some broken environments may not actually resolve to the local host
    write!(ss, "target extended-remote {}:{}", host, port).unwrap();
    vec.push(OsString::from_vec(ss));
}

#[derive(Default)]
struct AllowedTasks {
    /// tid 0 means 'any member of debuggee_tguid'
    task: TaskUid,
    command: RunCommand,
}
