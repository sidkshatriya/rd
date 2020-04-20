use std::io;

pub mod build_id_command;
pub mod dump_command;
pub mod rd_options;
pub mod rerun_command;

pub trait RdCommand {
    fn run(&mut self) -> io::Result<()>;
}
