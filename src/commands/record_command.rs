use crate::{
    commands::{
        rd_options::{RdOptions, RdSubCommand},
        RdCommand,
    },
    scheduler::TicksHowMany,
    session::record_session::{DisableCPUIDFeatures, SyscallBuffering, TraceUuid},
    ticks::Ticks,
    util::BindCPU,
};
use std::{ffi::OsString, io};

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
                // @TODO
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
                // @TODO
                use_syscall_buffer: if no_syscall_buffer {
                    SyscallBuffering::DisableSyscallBuf
                } else {
                    SyscallBuffering::EnableSycallBuf
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
                bind_cpu: match bind_to_cpu {
                    Some(n) => BindCPU::BindToCPU(n),
                    None => {
                        // @TODO Check this
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

    // DIFF NOTE: In rr a result code e.g. 0 is return. We simply return Ok(()) if there is no error.
    fn record(&self) -> io::Result<()> {
        unimplemented!()
    }
}

impl RdCommand for RecordCommand {
    /// DIFF NOTE: In rr a result code e.g. 3 is returned. We simply return `Ok(())` in case there is
    /// no error or a `Err(_)` if there is.
    fn run(&mut self) -> io::Result<()> {
        self.record()
    }
}
