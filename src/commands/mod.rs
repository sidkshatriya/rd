use std::io;

pub mod build_id_command;
pub mod dump_command;
pub mod ps_command;
pub mod rd_options;
pub mod rerun_command;
pub mod trace_info_command;

pub trait RdCommand {
    fn run(&mut self) -> io::Result<()>;
}
