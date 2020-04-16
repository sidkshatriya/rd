use crate::commands::RdCommand;
use std::io;

pub struct DumpCommand;

impl DumpCommand {
    pub fn new() -> DumpCommand {
        DumpCommand
    }
}

impl RdCommand for DumpCommand {
    fn run(&mut self) -> io::Result<()> {
        Ok(())
    }
}
