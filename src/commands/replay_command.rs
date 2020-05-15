use crate::commands::RdCommand;
use std::io;

pub struct ReplayCommand {}

impl RdCommand for ReplayCommand {
    fn run(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}
