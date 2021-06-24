use crate::{
    assert_prerequisites,
    commands::RdCommand,
    flags::Flags,
    log::LogInfo,
    session::{replay_session, session_inner::RunCommand, SessionSharedPtr},
    trace::trace_frame::FrameTime,
    util,
    util::{check_for_leaks, pid_execs, pid_exists, running_under_rd},
};
use io::stdout;
use libc::pid_t;
use nix::unistd::{getpid, getppid};
use replay_session::{ReplaySession, ReplayStatus};
use std::{io, io::Write, path::PathBuf};

use super::{
    exit_result::ExitResult,
    rd_options::{RdOptions, RdSubCommand},
};

pub struct EnvCommand {
    target_process: pid_t,
    /// When true, do not bind to the CPU stored in the trace file.
    cpu_unbound: bool,
    trace_dir: Option<PathBuf>,
}

impl EnvCommand {
    pub fn new(options: &RdOptions) -> EnvCommand {
        match options.cmd.clone() {
            RdSubCommand::Env {
                process,
                cpu_unbound,
                trace_dir,
            } => EnvCommand {
                target_process: process,
                cpu_unbound,
                trace_dir,
            },
            _ => panic!("Unexpected RdSubCommand variant. Not a Replay variant!"),
        }
    }

    fn session_flags(&self) -> replay_session::Flags {
        replay_session::Flags {
            redirect_stdio: false,
            share_private_mappings: false,
            cpu_unbound: self.cpu_unbound,
        }
    }

    fn replay_and_exit_upon_process_exec(&self, out: &mut dyn Write) -> io::Result<()> {
        let session: SessionSharedPtr =
            ReplaySession::create(self.trace_dir.as_ref(), self.session_flags());
        let replay_session = session.as_replay().unwrap();

        loop {
            let before_time: FrameTime = replay_session.trace_reader().time();
            let result = replay_session.replay_step(RunCommand::Continue);
            let after_time: FrameTime = replay_session.trace_reader().time();
            debug_assert!(after_time >= before_time && after_time <= before_time + 1);
            if result.status == ReplayStatus::ReplayExited {
                break;
            }

            if let Some(t) = replay_session.current_task() {
                if t.tgid() == self.target_process && t.execed() {
                    writeln!(out, "{:?}", util::read_env(&**t)).unwrap();
                    break;
                }
            }

            debug_assert_eq!(result.status, ReplayStatus::ReplayContinue);
            debug_assert!(result.break_status.watchpoints_hit.is_empty());
            debug_assert!(!result.break_status.breakpoint_hit);
            debug_assert!(!result.break_status.singlestep_complete);
        }

        log!(LogInfo, "Replayer successfully finished");
        Ok(())
    }

    fn replay(&self) -> ExitResult<()> {
        if let Err(e) = self.replay_and_exit_upon_process_exec(&mut stdout()) {
            return ExitResult::Err(Box::new(e), 1);
        }

        check_for_leaks();
        return ExitResult::Ok(());
    }
}

impl RdCommand for EnvCommand {
    fn run(&mut self) -> ExitResult<()> {
        if !pid_exists(self.trace_dir.as_ref(), self.target_process) {
            return ExitResult::err_from(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "No process {} found in trace. Try 'rd ps'.",
                        self.target_process
                    ),
                ),
                2,
            );
        }

        if !pid_execs(self.trace_dir.as_ref(), self.target_process) {
            return ExitResult::err_from(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "Process {} never exec()ed. Try 'rd ps', or use '-f'.",
                        self.target_process
                    ),
                ),
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

        self.replay()
    }
}
