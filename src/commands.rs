use exit_result::ExitResult;

pub mod build_id_command;
pub mod dump_command;
pub mod env_command;
pub mod exit_result;
pub mod gdb_command;
pub mod gdb_command_handler;
pub mod gdb_server;
pub mod ps_command;
pub mod rd_options;
pub mod record_command;
pub mod replay_command;
pub mod rerun_command;
pub mod trace_info_command;

pub trait RdCommand {
    fn run(&mut self) -> ExitResult<()>;
}
