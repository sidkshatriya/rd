use std::io;

pub mod build_id_command;

pub trait RdCommand {
    fn run(&mut self) -> io::Result<()>;
}
