pub mod build_id_command;

pub trait RdCommand {
    /// @TODO some sort of exit code??
    fn run(&mut self);
}
