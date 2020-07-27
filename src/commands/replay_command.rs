use super::rd_options::RdOptions;
use crate::{commands::RdCommand, trace::trace_frame::FrameTime};
use libc::pid_t;
use std::io;

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
    target_process: pid_t,
    target_command: String,

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
    dbg_port: u16,

    /// IP host to listen on for debug connections.
    dbg_host: String,

    /// Whether to keep listening with a new server after the existing server
    /// detaches
    keep_listening: bool,

    /// Pass these options to gdb
    gdb_options: Vec<String>,

    /// Specify a custom gdb binary with -d
    gdb_binary_file_path: String,

    /// When true, echo tracee stdout/stderr writes to console.
    redirect: bool,

    /// When true, do not bind to the CPU stored in the trace file.
    cpu_unbound: bool,

    /// When true make all private mappings shared with the tracee by default
    /// to test the corresponding code.
    share_private_mappings: bool,

    /// When Some() display statistics every N steps.
    dump_interval: Option<u32>,
}

impl ReplayCommand {
    pub fn new(options: &RdOptions) -> ReplayCommand {
        unimplemented!()
    }
}

impl RdCommand for ReplayCommand {
    fn run(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}
