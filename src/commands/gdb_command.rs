use super::{exit_result::ExitResult, RdCommand};

pub struct GdbCommand;

impl RdCommand for GdbCommand {
    fn run(&mut self) -> ExitResult<()> {
        unimplemented!()
    }
}
