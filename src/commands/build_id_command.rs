use crate::commands::RdCommand;
use std::path::PathBuf;

pub struct BuildIdCommand {
    elf_files: Vec<PathBuf>,
}

impl BuildIdCommand {
    pub(crate) fn new(elf_files: &[PathBuf]) -> BuildIdCommand {
        BuildIdCommand {
            elf_files: elf_files.to_owned(),
        }
    }
}

impl RdCommand for BuildIdCommand {
    fn run(&mut self) {
        unimplemented!()
    }
}
