use super::exit_result::ExitResult;
use crate::{
    assert_prerequisites,
    bindings::sysexits::EX_UNAVAILABLE,
    commands::{
        rd_options::{RdOptions, RdSubCommand},
        RdCommand,
    },
    kernel_metadata::signal_name,
    log::{notifying_abort, LogInfo, LogWarn},
    scheduler::TicksHowMany,
    session::record_session::{
        DisableCPUIDFeatures,
        RecordResult,
        RecordSession,
        SyscallBuffering,
        TraceUuid,
    },
    ticks::Ticks,
    util::{check_for_leaks, page_size, running_under_rd, write_all, BindCPU},
    wait_status::{WaitStatus, WaitType},
};
use libc::{prctl, PR_SET_DUMPABLE, SIGTERM, STDERR_FILENO};
use nix::{
    sys::signal::{kill, signal, SigHandler, Signal},
    unistd::{geteuid, getpid, Uid},
};
use rand::random;
use std::{
    convert::TryFrom,
    env::var_os,
    ffi::{OsStr, OsString},
    io,
    os::unix::ffi::{OsStrExt, OsStringExt},
    sync::atomic::{AtomicBool, Ordering},
};

/// DIFF NOTE: Many struct members are Option<> when compared to rr equivalents.
pub struct RecordCommand {
    extra_env: Vec<(OsString, OsString)>,

    /// Max counter value before the scheduler interrupts a tracee. */
    max_ticks: Ticks,

    /// Whenever `ignore_sig` is pending for a tracee, decline to deliver it.
    ignore_sig: Option<i32>,

    /// Whenever `continue_through_sig` is delivered to a tracee, if there is no
    /// user handler and the signal would terminate the program, just ignore it.
    continue_through_sig: Option<i32>,

    /// Whether to use syscall buffering optimization during recording.
    use_syscall_buffer: SyscallBuffering,

    /// If Some(_), the desired syscall buffer size in bytes. Must be a multiple of the page size.
    syscall_buffer_size: Option<usize>,

    /// CPUID features to disable
    disable_cpuid_features: DisableCPUIDFeatures,

    print_trace_dir_fd: Option<i32>,

    output_trace_dir: Option<OsString>,

    /// Whether to use file-cloning optimization during recording.
    use_file_cloning: bool,

    /// Whether to use read-cloning optimization during recording.
    use_read_cloning: bool,

    /// Whether tracee processes in record and replay are allowed to run on any logical CPU.
    bind_cpu: BindCPU,

    /// True if we should context switch after every rd event
    always_switch: bool,

    /// Whether to enable chaos mode in the scheduler
    chaos: bool,

    /// Controls number of cores reported to recorded process.
    num_cores: Option<u32>,

    /// True if we should wait for all processes to exit before finishing recording.
    wait_for_all: bool,

    /// Start child process directly if run under nested rr recording
    ignore_nested: bool,

    scarce_fds: bool,

    setuid_sudo: bool,

    trace_id: Box<TraceUuid>,

    /// Copy preload sources to trace dir
    copy_preload_src: bool,

    /// The signal to use for syscallbuf desched events
    syscallbuf_desched_sig: Option<i32>,

    // The exe and exe_args
    args: Vec<OsString>,
}

/// This can be called during debugging to close the trace so it can be used
/// later.
pub fn force_close_record_session() {
    unimplemented!()
}

static TERM_REQUEST: AtomicBool = AtomicBool::new(false);

impl RecordCommand {
    pub fn new(options: &RdOptions) -> RecordCommand {
        match options.cmd.clone() {
            RdSubCommand::Record {
                exe,
                exe_args,
                force_syscall_buffer,
                num_cpu_ticks,
                disable_cpuid_features,
                disable_cpuid_features_ext,
                disable_cpuid_features_xsave,
                chaos_mode,
                ignore_signal,
                no_syscall_buffer,
                no_file_cloning,
                no_read_cloning,
                num_cores,
                output_trace_dir,
                print_trace_dir_fd,
                syscall_buffer_size,
                syscall_buffer_sig,
                always_switch,
                continue_through_signal,
                cpu_unbound,
                bind_to_cpu,
                env,
                wait,
                ignore_error,
                scarce_fds,
                setuid_sudo,
                trace_id,
                copy_preload_src,
            } => RecordCommand {
                extra_env: env.unwrap_or(Vec::new()),
                max_ticks: num_cpu_ticks.unwrap_or(TicksHowMany::DefaultMaxTicks as u64),
                ignore_sig: ignore_signal,
                continue_through_sig: continue_through_signal,
                // Generally speaking the `force_syscall_buffer` and the `no_syscall_buffer`
                // options are contradictory and and error should result if both options were
                // used on the commandline. For now give priority for `force_syscall_buffer`.
                use_syscall_buffer: {
                    if force_syscall_buffer && no_syscall_buffer {
                        log!(LogWarn, "--force-syscall-buffer and --no-syscall-buffer are contradictory. Giving preference to --force-syscall-buffer");
                    }
                    if force_syscall_buffer {
                        SyscallBuffering::EnableSycallBuf
                    } else {
                        if no_syscall_buffer {
                            SyscallBuffering::DisableSyscallBuf
                        } else {
                            SyscallBuffering::EnableSycallBuf
                        }
                    }
                },
                syscall_buffer_size,
                disable_cpuid_features: DisableCPUIDFeatures::from(
                    disable_cpuid_features.unwrap_or((0, 0)),
                    disable_cpuid_features_ext.unwrap_or((0, 0, 0)),
                    disable_cpuid_features_xsave.unwrap_or(0),
                ),
                print_trace_dir_fd,
                output_trace_dir,
                use_file_cloning: !no_file_cloning,
                use_read_cloning: !no_read_cloning,
                // Generally speaking the `cpu_unbound` and `bind_to_cpu` options
                // are contradictory and an error should result if both options were
                // used on the commandline. For now we give priority to `bind_to_cpu`.
                bind_cpu: {
                    if bind_to_cpu.is_some() && cpu_unbound {
                        log!(LogWarn, "--bind-to-cpu and --cpu-unbound are contradictory. Giving preference to --bind-to-cpu");
                    }
                    match bind_to_cpu {
                        Some(n) => BindCPU::BindToCPU(n),
                        None => {
                            if cpu_unbound {
                                BindCPU::UnboundCPU
                            } else {
                                BindCPU::RandomCPU
                            }
                        }
                    }
                },
                always_switch,
                chaos: {
                    if chaos_mode {
                        log!(LogInfo, "Enabled chaos mode");
                    }
                    chaos_mode
                },
                num_cores,
                wait_for_all: wait,
                ignore_nested: ignore_error,
                scarce_fds,
                setuid_sudo,
                trace_id: Box::new(trace_id.unwrap_or(TraceUuid::generate_new())),
                copy_preload_src,
                syscallbuf_desched_sig: syscall_buffer_sig,
                args: {
                    let mut args = Vec::new();
                    args.push(exe);
                    args.extend(exe_args);
                    args
                },
            },
            _ => panic!("Unexpected RdSubCommand variant. Not a Record variant!"),
        }
    }

    fn exec_child(&self) {
        unimplemented!()
    }

    fn record(&self) -> WaitStatus {
        log!(LogInfo, "Start recording...");

        let session = RecordSession::create(self);
        let rec_session = session.as_record_mut().unwrap();

        match self.print_trace_dir_fd {
            Some(fd) => {
                let dir = rec_session.trace_writer().dir().as_bytes();
                write_all(fd, dir);
                write_all(fd, b"\n");
            }
            None => (),
        }

        if self.copy_preload_src {
            let dir = rec_session.trace_writer().dir();
            copy_preload_sources_to_trace(dir);
            save_rd_git_revision(dir);
        }

        // Install signal handlers after creating the session, to ensure they're not
        // inherited by the tracee.
        install_signal_handlers();

        let mut step_result: RecordResult;
        loop {
            let done_initial_exec = rec_session.done_initial_exec();
            step_result = rec_session.record_step();
            if !done_initial_exec && rec_session.done_initial_exec() {
                rec_session.trace_writer().make_latest_trace();
            }
            if step_result != RecordResult::StepContinue || TERM_REQUEST.load(Ordering::SeqCst) {
                break;
            }
        }

        rec_session.terminate_recording();

        match step_result {
            RecordResult::StepContinue => {
                // SIGTERM interrupted us.
                return WaitStatus::for_fatal_sig(SIGTERM);
            }
            RecordResult::StepExited(wait_status) => {
                return wait_status;
            }

            RecordResult::StepSpawnFailed(message) => {
                eprintln!("\n{:?}", message);
                return WaitStatus::for_exit_code(EX_UNAVAILABLE as i32);
            }
        }
    }
}

fn install_signal_handlers() {
    unimplemented!()
}

fn save_rd_git_revision<T: AsRef<OsStr>>(dir: T) {
    let dir_os: &OsStr = dir.as_ref();
    unimplemented!()
}

fn copy_preload_sources_to_trace<T: AsRef<OsStr>>(dir: T) {
    let dir_os: &OsStr = dir.as_ref();
    unimplemented!()
}

impl RdCommand for RecordCommand {
    fn run(&mut self) -> ExitResult<()> {
        if running_under_rd() {
            if self.ignore_nested {
                // Does not return!
                self.exec_child();
            }
            return ExitResult::err_from(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "rd: cannot run rd recording under rd. Exiting.\n\
                       Use `rd record --ignore-nested` to start the child\n\
                       process directly.",
                ),
                1,
            );
        }

        assert_prerequisites(Some(match self.use_syscall_buffer {
            SyscallBuffering::EnableSycallBuf => true,
            SyscallBuffering::DisableSyscallBuf => false,
        }));

        if self.setuid_sudo {
            if geteuid() != Uid::from_raw(0) || var_os("SUDO_UID").is_none() {
                return ExitResult::err_from(
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "rd: --setuid-sudo option may only be used under sudo.\n\
                            Re-run as `sudo -EP rr record --setuid-sudo` to\n\
                            record privileged executables.",
                    ),
                    1,
                );
            }

            reset_uid_sudo();
        }

        if self.chaos {
            // Add up to one page worth of random padding to the environment to induce
            // a variety of possible stack pointer offsets
            let mut chars = Vec::<u8>::new();
            chars.resize(random::<usize>() % page_size(), 0);
            // chars should contain at least 1 u8.
            chars.push(0);
            self.extra_env.push((
                OsString::from("RD_CHAOS_PADDING"),
                OsString::from_vec(chars),
            ));
        }

        let status: WaitStatus = self.record();

        // Everything should have been cleaned up by now.
        check_for_leaks();

        match status.wait_type() {
            WaitType::Exit => {
                let exit_code = status.exit_code().unwrap();
                if exit_code == 0 {
                    ExitResult::Ok(())
                } else {
                    ExitResult::err_from(
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("Tracee exited with non-zero exit code: {}", exit_code),
                        ),
                        exit_code,
                    )
                }
            }
            WaitType::FatalSignal => {
                let sig = status.fatal_sig().unwrap();
                unsafe {
                    signal(Signal::try_from(sig).unwrap(), SigHandler::SigDfl).unwrap();
                    prctl(PR_SET_DUMPABLE, 0);
                }
                kill(getpid(), Some(Signal::try_from(sig).unwrap())).unwrap_or(());
                ExitResult::err_from(
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("tracee exited due to fatal signal {}", signal_name(sig)),
                    ),
                    1,
                )
            }
            _ => {
                fatal!("Don't know why we exited: WaitStatus is `{}`", status);
                unreachable!();
            }
        }
    }
}

fn reset_uid_sudo() {
    unimplemented!()
}

/// A terminating signal was received.  Set the `TERM_REQUEST` bit to
/// terminate the trace at the next convenient point.
///
/// If there's already a term request pending, then assume rd is wedged
/// and abort.
///
/// Note that this is not only called in a signal handler but it could
/// be called off the main thread.
///
/// @TODO Is this method signal handler safe?
/// @TODO Is it necessary to have extern "C" here?
extern "C" fn handle_SIGTERM(_sig: i32) {
    if TERM_REQUEST.load(Ordering::SeqCst) {
        // Don't use log!() here because we're in a signal handler. If we do anything
        // that could allocate, we could deadlock.
        let msg = b"Received SIGTERM while an earlier one was pending.  We're probably wedged.\n";
        write_all(STDERR_FILENO, msg);
        notifying_abort(backtrace::Backtrace::new());
    }
    TERM_REQUEST.store(true, Ordering::SeqCst);
}
