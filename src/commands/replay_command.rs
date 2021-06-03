use crate::{
    assert_prerequisites,
    bindings::kernel::{gettimeofday, timeval},
    commands::{gdb_server, RdCommand},
    flags::Flags,
    kernel_metadata::errno_name,
    log::{LogDebug, LogInfo},
    scoped_fd::ScopedFd,
    session::{
        replay_session,
        session_inner::{RunCommand, Statistics},
        SessionSharedPtr,
    },
    trace::{
        trace_frame::FrameTime, trace_reader::TraceReader, trace_task_event::TraceTaskEventType,
    },
    util::{check_for_leaks, find, running_under_rd},
};
use io::stderr;
use libc::{pid_t, WEXITSTATUS, WIFEXITED, WIFSIGNALED};
use nix::{
    errno::errno,
    fcntl::OFlag,
    sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
    unistd::{close, fork, getpid, getppid, pipe2, ForkResult},
};
use replay_session::{ReplaySession, ReplayStatus};
use std::{
    cell::RefCell,
    ffi::{OsStr, OsString},
    io,
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    rc::Rc,
};

use super::{
    exit_result::ExitResult,
    gdb_server::{ConnectionFlags, GdbServer},
    rd_options::{PidOrCommand, RdOptions, RdSubCommand},
};

#[derive(Copy, Clone, Eq, PartialEq)]
enum CreatedHow {
    CreatedNone,
    CreatedExec,
    CreatedFork,
}

pub struct ReplayCommand {
    /// Start a debug server for the task scheduled at the first
    /// event at which reached this event AND target_process has
    /// been "created".
    goto_event: FrameTime,
    singlestep_to_event: FrameTime,
    target_process: Option<pid_t>,
    target_command: Option<OsString>,

    /// We let users specify which process should be "created" before
    /// starting a debug session for it.  Problem is, "process" in this
    /// context is ambiguous.  It could mean the "thread group", which is
    /// created at fork().  Or it could mean the "address space", which is
    /// created at exec() (after the fork).
    ///
    /// We force choosers to specify which they mean.
    process_created_how: CreatedHow,

    /// Only open a debug socket, don't launch the debugger too.
    dont_launch_debugger: bool,

    /// IP port to listen on for debug connections.
    dbg_port: Option<u16>,

    /// IP host to listen on for debug connections.
    dbg_host: String,

    /// Whether to keep listening with a new server after the existing server
    /// detaches
    keep_listening: bool,

    /// Pass these options to gdb
    gdb_options: Vec<OsString>,

    /// Specify a custom gdb binary with -d
    gdb_binary_file_path: PathBuf,

    /// When true, echo tracee stdout/stderr writes to console.
    redirect: bool,

    /// When true, do not bind to the CPU stored in the trace file.
    cpu_unbound: bool,

    /// When true make all private mappings shared with the tracee by default
    /// to test the corresponding code.
    share_private_mappings: bool,

    /// When Some(_), display statistics every N steps.
    dump_interval: Option<u32>,

    trace_dir: Option<PathBuf>,
}

impl Default for ReplayCommand {
    fn default() -> Self {
        Self {
            goto_event: 0,
            singlestep_to_event: 0,
            target_process: None,
            target_command: None,
            process_created_how: CreatedHow::CreatedNone,
            dont_launch_debugger: false,
            dbg_port: None,
            dbg_host: "127.0.0.1".into(),
            keep_listening: false,
            gdb_binary_file_path: "gdb".into(),
            redirect: true,
            cpu_unbound: false,
            share_private_mappings: false,
            dump_interval: None,
            gdb_options: vec![],
            trace_dir: None,
        }
    }
}

impl ReplayCommand {
    pub fn new(options: &RdOptions) -> ReplayCommand {
        match options.cmd.clone() {
            RdSubCommand::Replay {
                autopilot,
                onfork,
                goto_event,
                debugger_option,
                debugger_options,
                onprocess,
                fullname,
                interpreter,
                debugger_file,
                no_redirect_output,
                dbghost,
                dbgport,
                keep_listening,
                trace_event,
                cpu_unbound,
                gdb_x_file,
                stats,
                trace_dir,
                share_private_mappings,
            } => {
                let mut flags = ReplayCommand::default();

                if autopilot {
                    flags.goto_event = FrameTime::MAX;
                    flags.dont_launch_debugger = true;
                }

                if let Some(file) = debugger_file {
                    flags.gdb_binary_file_path = file;
                }

                if onfork.is_some() {
                    flags.target_process = onfork;
                    flags.process_created_how = CreatedHow::CreatedFork;
                }

                if let Some(ge) = goto_event {
                    flags.goto_event = ge;
                }

                flags.keep_listening = keep_listening;
                if let Some(opt) = debugger_option {
                    flags.gdb_options.push(opt);
                }
                flags.gdb_options.extend(debugger_options);

                match onprocess {
                    None => (),
                    Some(pid_or_command) => {
                        match pid_or_command {
                            PidOrCommand::Pid(pid) => {
                                flags.target_process = Some(pid);
                            }
                            PidOrCommand::Command(cmd) => {
                                flags.target_command = Some(cmd);
                            }
                        }
                        flags.process_created_how = CreatedHow::CreatedExec;
                    }
                }

                flags.redirect = !no_redirect_output;

                if let Some(host) = dbghost {
                    flags.dbg_host = host;
                    flags.dont_launch_debugger = true;
                }

                if dbgport.is_some() {
                    flags.dbg_port = dbgport;
                    flags.dont_launch_debugger = true;
                }

                if let Some(te) = trace_event {
                    flags.singlestep_to_event = te;
                }

                if let Some(file) = gdb_x_file {
                    flags.gdb_options.push("-x".into());
                    flags.gdb_options.push(file);
                }

                flags.share_private_mappings = share_private_mappings;

                if fullname {
                    flags.gdb_options.push("--fullname".into());
                }

                if stats.is_some() {
                    flags.dump_interval = stats;
                }

                flags.cpu_unbound = cpu_unbound;

                if let Some(inter) = interpreter {
                    flags.gdb_options.push("-i".into());
                    flags.gdb_options.push(OsString::from(inter));
                }

                flags.trace_dir = trace_dir;

                flags
            }
            _ => panic!("Unexpected RdSubCommand variant. Not a Replay variant!"),
        }
    }

    fn session_flags(&self) -> replay_session::Flags {
        replay_session::Flags {
            redirect_stdio: self.redirect,
            share_private_mappings: self.share_private_mappings,
            cpu_unbound: self.cpu_unbound,
        }
    }

    fn serve_replay_no_debugger(&self, out: &mut dyn Write) -> io::Result<()> {
        let session: SessionSharedPtr =
            ReplaySession::create(self.trace_dir.as_ref(), self.session_flags());
        let replay_session = session.as_replay().unwrap();
        let mut step_count: u32 = 0;
        let mut last_dump_time = timeval::default();
        let mut last_dump_rectime: f64 = 0.0;
        let mut last_stats = Statistics::default();
        unsafe { gettimeofday(&raw mut last_dump_time, ptr::null_mut()) };

        loop {
            let mut cmd = RunCommand::RunContinue;
            if self.singlestep_to_event > 0
                && replay_session.trace_reader().time() >= self.singlestep_to_event
            {
                cmd = RunCommand::RunSinglestep;
                write!(out, "Stepping from: ")?;
                let t = replay_session.current_task().unwrap();
                t.regs_ref().write_register_file_compact(out)?;
                write!(out, " ")?;
                t.extra_regs_ref().write_register_file_compact(out)?;
                write!(out, " ticks:{}", t.tick_count())?;
            }

            let before_time: FrameTime = replay_session.trace_reader().time();
            let result = replay_session.replay_step(cmd);
            let after_time: FrameTime = replay_session.trace_reader().time();
            debug_assert!(after_time >= before_time && after_time <= before_time + 1);
            if last_dump_rectime == 0.0 {
                last_dump_rectime = replay_session.trace_reader().recording_time();
            }
            step_count += 1;
            if self.dump_interval.is_some() && step_count % self.dump_interval.unwrap() == 0 {
                let mut now = timeval::default();
                unsafe { gettimeofday(&raw mut now, ptr::null_mut()) };
                let rectime: f64 = replay_session.trace_reader().recording_time();
                let elapsed_usec: u64 = to_microseconds(&now) - to_microseconds(&last_dump_time);
                let stats: Statistics = replay_session.statistics();
                writeln!(out,
          "[ReplayStatistics] ticks {} syscalls {} bytes_written {} microseconds {} %%realtime {:.0}%%",
          stats.ticks_processed - last_stats.ticks_processed,
          stats.syscalls_performed - last_stats.syscalls_performed,
          stats.bytes_written - last_stats.bytes_written,
          elapsed_usec,
          100.0 * ((rectime - last_dump_rectime) * 1.0e6) / (elapsed_usec as f64)
        )?;
                last_dump_time = now;
                last_stats = stats;
                last_dump_rectime = rectime;
            }

            if result.status == ReplayStatus::ReplayExited {
                break;
            }
            debug_assert_eq!(result.status, ReplayStatus::ReplayContinue);
            debug_assert!(result.break_status.watchpoints_hit.is_empty());
            debug_assert!(!result.break_status.breakpoint_hit);
            debug_assert!(
                cmd == RunCommand::RunSinglestep || !result.break_status.singlestep_complete
            );
        }

        log!(LogInfo, "Replayer successfully finished");
        Ok(())
    }

    fn replay(&self) -> ExitResult<()> {
        let mut target = gdb_server::Target::default();
        match self.process_created_how {
            CreatedHow::CreatedExec => {
                target.pid = self.target_process;
                target.require_exec = true;
            }
            CreatedHow::CreatedFork => {
                target.pid = self.target_process;
                target.require_exec = false;
            }
            CreatedHow::CreatedNone => (),
        }
        target.event = self.goto_event;

        // If we're not going to autolaunch the debugger, don't go
        // through the rigamarole to set that up.  All it does is
        // complicate the process tree and confuse users.
        if self.dont_launch_debugger {
            if target.event == FrameTime::MAX {
                if let Err(e) = self.serve_replay_no_debugger(&mut stderr()) {
                    return ExitResult::Err(Box::new(e), 1);
                }
            } else {
                let session = ReplaySession::create(self.trace_dir.as_ref(), self.session_flags());
                let conn_flags = ConnectionFlags {
                    dbg_port: self.dbg_port,
                    dbg_host: self.dbg_host.clone(),
                    keep_listening: self.keep_listening,
                    debugger_params_write_pipe: None,
                    debugger_name: self.gdb_binary_file_path.clone(),
                };
                GdbServer::new(session, &target).serve_replay(&conn_flags);
            }

            check_for_leaks();
            return ExitResult::Ok(());
        }

        let debugger_params_pipe: [i32; 2];
        match pipe2(OFlag::O_CLOEXEC) {
            Ok((fd1, fd2)) => {
                debugger_params_pipe = [fd1, fd2];
            }
            Err(e) => {
                fatal!("Couldn't open debugger params pipe: {:?}", e);
            }
        }

        let fork_result = unsafe { fork().unwrap() };
        match fork_result {
            ForkResult::Child => {
                // Ensure only the parent has the read end of the pipe open. Then if
                // the parent dies, our writes to the pipe will error out.
                // DIFF NOTE: Unlike rr we require close to be successful
                close(debugger_params_pipe[0]).unwrap();

                {
                    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };

                    let debugger_params_write_pipe =
                        Rc::new(RefCell::new(ScopedFd::from_raw(debugger_params_pipe[1])));
                    let session =
                        ReplaySession::create(self.trace_dir.as_ref(), self.session_flags());
                    let conn_flags = ConnectionFlags {
                        dbg_port: self.dbg_port,
                        dbg_host: self.dbg_host.clone(),
                        keep_listening: self.keep_listening,
                        debugger_params_write_pipe: Some(Rc::downgrade(
                            &debugger_params_write_pipe,
                        )),
                        debugger_name: self.gdb_binary_file_path.clone(),
                    };
                    let mut server = GdbServer::new(session, &target);
                    let sa = SigAction::new(
                        SigHandler::Handler(handle_sigint_in_child),
                        SaFlags::SA_RESTART,
                        SigSet::empty(),
                    );
                    unsafe { SERVER_PTR = &raw mut server };
                    if let Err(e) = unsafe { sigaction(Signal::SIGINT, &sa) } {
                        fatal!("Couldn't set sigaction for SIGINT: {:?}", e);
                    }

                    server.serve_replay(&conn_flags);
                }
                // Everything should have been cleaned up by now.
                check_for_leaks();
            }
            ForkResult::Parent { child } => {
                // Ensure only the child has the write end of the pipe open. Then if
                // the child dies, our reads from the pipe will return EOF.
                close(debugger_params_pipe[1]).unwrap();
                log!(LogDebug, "{} : forked debugger server {}", getpid(), child);
                let sa = SigAction::new(
                    SigHandler::Handler(handle_sigint_in_parent),
                    SaFlags::SA_RESTART,
                    SigSet::empty(),
                );
                if let Err(e) = unsafe { sigaction(Signal::SIGINT, &sa) } {
                    fatal!("Couldn't set sigaction for SIGINT: {:?}", e);
                }

                {
                    let params_pipe_read_fd = ScopedFd::from_raw(debugger_params_pipe[0]);
                    GdbServer::launch_gdb(
                        &params_pipe_read_fd,
                        &self.gdb_binary_file_path,
                        &self.gdb_options,
                    );
                }
                // Child must have died before we were able to get debugger parameters
                // and exec gdb. Exit with the exit status of the child.
                loop {
                    let mut status: i32 = 0;
                    let ret = unsafe { libc::waitpid(child.as_raw(), &mut status, 0) };
                    let err = errno();
                    log!(
                        LogDebug,
                        "{}: waitpid({}) returned {} ({}); status: {:x}",
                        getpid(),
                        child,
                        errno_name(err),
                        err,
                        status
                    );
                    if child.as_raw() != ret {
                        if libc::EINTR == err {
                            continue;
                        }
                        fatal!("{}: waitpid({}) failed", getpid(), child);
                    }
                    if WIFEXITED(status) || WIFSIGNALED(status) {
                        log!(LogInfo, "Debugger server died.  Exiting.");
                        if WIFEXITED(status) {
                            return ExitResult::err_from(
                                io::Error::new(
                                    io::ErrorKind::Other,
                                    "Debugger server died.  Exiting.",
                                ),
                                WEXITSTATUS(status),
                            );
                        } else {
                            return ExitResult::err_from(
                                io::Error::new(
                                    io::ErrorKind::Other,
                                    "Debugger server died.  Exiting.",
                                ),
                                1,
                            );
                        }
                    }
                }
            }
        }
        ExitResult::Ok(())
    }
}

/// Uses the same approach as rr but not very pretty!
static mut SERVER_PTR: *mut GdbServer = std::ptr::null_mut();

impl RdCommand for ReplayCommand {
    fn run(&mut self) -> ExitResult<()> {
        if let Some(ref target_command) = self.target_command {
            self.target_process = find_pid_for_command(self.trace_dir.as_ref(), target_command);
            if self.target_process.is_none() {
                return ExitResult::err_from(
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "No process {:?} found in trace. Try 'rd ps'.",
                            target_command
                        ),
                    ),
                    2,
                );
            }
        }

        if self.process_created_how != CreatedHow::CreatedNone {
            if let Some(pid) = self.target_process {
                if !pid_exists(self.trace_dir.as_ref(), pid) {
                    return ExitResult::err_from(
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("No process {} found in trace. Try 'rd ps'.", pid),
                        ),
                        2,
                    );
                }
                if self.process_created_how == CreatedHow::CreatedExec
                    && !pid_execs(self.trace_dir.as_ref(), pid)
                {
                    return ExitResult::err_from(
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("Process {} never exec()ed. Try 'rd ps', or use '-f'.", pid),
                        ),
                        2,
                    );
                }
            }
        }

        if self.dump_interval.is_some() && !self.dont_launch_debugger {
            return ExitResult::err_from(
                io::Error::new(io::ErrorKind::InvalidInput, "--stats requires -a"),
                2,
            );
        }

        assert_prerequisites(None);

        if running_under_rd() {
            if !Flags::get().suppress_environment_warnings {
                eprintln!(
                    "rd: rd pid {} running under parent {}. Good luck.",
                    getpid(),
                    getppid()
                );
            }
            if self.trace_dir.is_none() {
                return ExitResult::err_from(
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "No trace-dir supplied. You'll try to rerun the recording of this rd \
                        and have a bad time. Bailing out.",
                    ),
                    3,
                );
            }
        }

        if self.keep_listening && self.dbg_port.is_none() {
            return ExitResult::err_from(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Cannot use --keep-listening (-k) without --dbgport (-s).",
                ),
                4,
            );
        }

        self.replay()
    }
}

fn to_microseconds(tv: &timeval) -> u64 {
    (tv.tv_sec as u64) * 1000000 + (tv.tv_usec as u64)
}

extern "C" fn handle_sigint_in_child(sig: i32) {
    debug_assert_eq!(sig, libc::SIGINT);
    unsafe {
        if !SERVER_PTR.is_null() {
            (*SERVER_PTR).interrupt_replay_to_target();
        }
    }
}

/// Handling ctrl-C during replay:
/// We want the entire group of processes to remain a single process group
/// since that allows shell job control to work best.
/// We want ctrl-C to not reach tracees, because that would disturb replay.
/// That's taken care of by Task::set_up_process.
/// We allow terminal SIGINT to go directly to the parent and the child (rd).
/// rd's SIGINT handler |handle_SIGINT_in_child| just interrupts the replay
/// if we're in the process of replaying to a target event, otherwise it
/// does nothing.
/// Before the parent execs gdb, its SIGINT handler does nothing. After exec,
/// the signal handler is reset to default so gdb behaves as normal (which is
/// why we use a signal handler instead of SIG_IGN).
extern "C" fn handle_sigint_in_parent(sig: i32) {
    debug_assert_eq!(sig, libc::SIGINT);
    // Just ignore it.
}

fn pid_exists<T: AsRef<Path>>(maybe_trace_dir: Option<T>, pid: pid_t) -> bool {
    let mut trace = TraceReader::new(maybe_trace_dir);

    while let Some(e) = trace.read_task_event(None) {
        if e.tid() == pid {
            return true;
        }
    }

    false
}

fn pid_execs<T: AsRef<Path>>(maybe_trace_dir: Option<T>, pid: pid_t) -> bool {
    let mut trace = TraceReader::new(maybe_trace_dir);

    while let Some(e) = trace.read_task_event(None) {
        if e.tid() == pid && e.event_type() == TraceTaskEventType::Exec {
            return true;
        }
    }

    false
}

fn find_pid_for_command<T: AsRef<Path>>(
    maybe_trace_dir: Option<T>,
    command_os_str: &OsStr,
) -> Option<pid_t> {
    let mut trace = TraceReader::new(maybe_trace_dir);
    while let Some(e) = trace.read_task_event(None) {
        if e.event_type() != TraceTaskEventType::Exec {
            continue;
        }
        if e.exec_variant().cmd_line().is_empty() {
            continue;
        }
        let cmd: &[u8] = e.exec_variant().cmd_line()[0].as_bytes();
        let command: &[u8] = command_os_str.as_bytes();
        let mut command_with_slash = vec![b'/'];
        command_with_slash.extend_from_slice(command_os_str.as_bytes());

        if cmd == command
            || (cmd.len() > command.len()
                && find(cmd, &command_with_slash) == Some(cmd.len() - command_with_slash.len()))
        {
            return Some(e.tid());
        }
    }
    None
}
