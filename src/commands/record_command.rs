use super::exit_result::ExitResult;
use crate::{
    assert_prerequisites,
    commands::{
        rd_options::{RdOptions, RdSubCommand},
        RdCommand,
    },
    kernel_metadata::signal_name,
    scheduler::TicksHowMany,
    session::record_session::{DisableCPUIDFeatures, SyscallBuffering, TraceUuid},
    ticks::Ticks,
    util::{check_for_leaks, page_size, running_under_rd, BindCPU},
    wait_status::{WaitStatus, WaitType},
};
use libc::{prctl, PR_SET_DUMPABLE};
use nix::{
    sys::signal::{kill, signal, SigHandler, Signal},
    unistd::{geteuid, getpid, Uid},
};
use rand::random;
use std::{convert::TryFrom, env::var_os, ffi::OsString, io, os::unix::ffi::OsStringExt};

/// DIFF NOTE: Many struct members are Option<> when compared to rr equivalents.
struct RecordCommand {
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

    /// If nonzero, the desired syscall buffer size. Must be a multiple of the page size.
    syscall_buffer_size: usize,

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
}

impl RecordCommand {
    pub fn new(options: &RdOptions) -> RecordCommand {
        match options.cmd.clone() {
            RdSubCommand::Record {
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
                // @TODO Generally speaking the `force_syscall_buffer` and the `no_syscall_buffer`
                // options are contradictory and and error should result if both options were
                // used on the commandline. For now give priority for `force_syscall_buffer`.
                use_syscall_buffer: if force_syscall_buffer {
                    SyscallBuffering::EnableSycallBuf
                } else {
                    if no_syscall_buffer {
                        SyscallBuffering::DisableSyscallBuf
                    } else {
                        SyscallBuffering::EnableSycallBuf
                    }
                },
                // @TODO
                syscall_buffer_size: syscall_buffer_size.unwrap(),
                disable_cpuid_features: DisableCPUIDFeatures::from(
                    disable_cpuid_features.unwrap_or((0, 0)),
                    disable_cpuid_features_ext.unwrap_or((0, 0, 0)),
                    disable_cpuid_features_xsave.unwrap_or(0),
                ),
                print_trace_dir_fd,
                output_trace_dir,
                use_file_cloning: !no_file_cloning,
                use_read_cloning: !no_read_cloning,
                // @TODO Generally speaking the `cpu_unbound` and `bind_to_cpu` options
                // are contradictory and an error should result if both options were
                // used on the commandline. For now we give priority to `bind_to_cpu`.
                bind_cpu: match bind_to_cpu {
                    Some(n) => BindCPU::BindToCPU(n),
                    None => {
                        if cpu_unbound {
                            BindCPU::UnboundCPU
                        } else {
                            BindCPU::RandomCPU
                        }
                    }
                },
                always_switch,
                chaos: chaos_mode,
                num_cores,
                wait_for_all: wait,
                ignore_nested: ignore_error,
                scarce_fds,
                setuid_sudo,
                trace_id: Box::new(trace_id.unwrap_or(TraceUuid::generate_new())),
                copy_preload_src,
                syscallbuf_desched_sig: syscall_buffer_sig,
            },
            _ => panic!("Unexpected RdSubCommand variant. Not a Record variant!"),
        }
    }

    fn exec_child(&self) {
        unimplemented!()
    }

    fn record(&self) -> WaitStatus {
        unimplemented!()
    }
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
