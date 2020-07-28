use super::rd_options::{PidOrCommand, RdOptions, RdSubCommand};
use crate::{
    assert_prerequisites,
    commands::RdCommand,
    flags::Flags,
    session::replay_session,
    trace::trace_frame::FrameTime,
    util::running_under_rd,
};
use io::stderr;
use libc::pid_t;
use nix::unistd::{getpid, getppid};
use std::{ffi::OsString, io, io::Write, path::PathBuf};

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

                if debugger_file.is_some() {
                    flags.gdb_binary_file_path = debugger_file.unwrap();
                }

                if onfork.is_some() {
                    flags.target_process = onfork;
                    flags.process_created_how = CreatedHow::CreatedFork;
                }

                if goto_event.is_some() {
                    flags.goto_event = goto_event.unwrap();
                }

                flags.keep_listening = keep_listening;
                if debugger_option.is_some() {
                    flags.gdb_options.push(debugger_option.unwrap());
                }

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

                flags.redirect = no_redirect_output;

                if dbghost.is_some() {
                    flags.dbg_host = dbghost.unwrap();
                    flags.dont_launch_debugger = true;
                }

                if dbgport.is_some() {
                    flags.dbg_port = dbgport;
                    flags.dont_launch_debugger = true;
                }

                if trace_event.is_some() {
                    flags.singlestep_to_event = trace_event.unwrap();
                }

                if gdb_x_file.is_some() {
                    flags.gdb_options.push("-x".into());
                    flags.gdb_options.push(gdb_x_file.unwrap());
                }

                flags.share_private_mappings = share_private_mappings;

                if fullname {
                    flags.gdb_options.push("--fullname".into());
                }

                if stats.is_some() {
                    flags.dump_interval = stats;
                }

                flags.cpu_unbound = cpu_unbound;

                if interpreter.is_some() {
                    flags.gdb_options.push("-i".into());
                    flags.gdb_options.push(OsString::from(interpreter.unwrap()));
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

    // DIFF NOTE: In rr a result code e.g. 0 is return. We simply return Ok(()) if there is no error.
    fn replay(&self) -> io::Result<()> {
        unimplemented!()
    }
}

impl RdCommand for ReplayCommand {
    /// DIFF NOTE: In rr a result code e.g. 3 is returned. We simply return `Ok(())` in case there is
    /// no error or a `Err(_)` if there is.
    fn run(&mut self) -> io::Result<()> {
        if self.target_command.is_some() {
            unimplemented!()
        }

        if self.process_created_how != CreatedHow::CreatedNone {
            unimplemented!()
        }

        if self.dump_interval.is_some() && !self.dont_launch_debugger {
            // DIFF NOTE: We return an Err() while rr returns error code 2
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--stats requires -a",
            ));
        }

        assert_prerequisites(None);

        if running_under_rd() {
            if !Flags::get().suppress_environment_warnings {
                write!(
                    stderr(),
                    "rd: rd pid {} running under parent {}. Good luck.\n",
                    getpid(),
                    getppid()
                )?;
            }
            if self.trace_dir.is_none() {
                // DIFF NOTE: An error code of 3 is returned in rr. We return an `Err(_)`
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No trace-dir supplied. You'll try to rerun the recording of this rd \
                        and have a bad time. Bailing out.",
                ));
            }
        }
        if self.keep_listening && self.dbg_port.is_none() {
            // DIFF NOTE: An error code of 4 is returned in rr. We return an `Err(_)`
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot use --keep-listening (-k) without --dbgport (-s).",
            ));
        }

        self.replay()
    }
}
