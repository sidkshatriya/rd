use crate::commands::RdCommand;
use goblin::elf::{note, Elf};
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};

pub struct BuildIdCommand {
    elf_files: Vec<PathBuf>,
}

impl BuildIdCommand {
    pub fn new(elf_files: &[PathBuf]) -> BuildIdCommand {
        BuildIdCommand {
            elf_files: elf_files.to_owned(),
        }
    }

    fn file_data(elf_file: &Path) -> Vec<u8> {
        let result = fs::read(elf_file);
        match result {
            Ok(file_data) => file_data,
            e => {
                fatal!("Err in reading {:?}: {:?}", elf_file, e);
                unimplemented!()
            }
        }
    }

    pub fn build_id(elf_file: &Path) -> Vec<u8> {
        let data = Self::file_data(elf_file);
        match Elf::parse(&data) {
            Ok(elf_data) => {
                let maybe_sections = elf_data.iter_note_sections(&data, None);
                if maybe_sections.is_some() {
                    for maybe_note in maybe_sections.unwrap() {
                        match maybe_note {
                            Ok(note)
                                if note.n_type == note::NT_GNU_BUILD_ID && note.name == "GNU" =>
                            {
                                return note.desc.to_vec();
                            }
                            _ => continue,
                        }
                    }
                }
                fatal!("Could not find build id in {:?}", elf_file);
                unreachable!();
            }
            e => {
                fatal!("Error in elf parsing {:?}: {:?}", elf_file, e);
                unimplemented!();
            }
        }
    }
}

impl RdCommand for BuildIdCommand {
    fn run(&mut self) {
        for elf_file in &self.elf_files {
            let build_id = Self::build_id(elf_file);
            let mut build_id_string = String::new();
            for u in build_id {
                write!(build_id_string, "{:02x}", u).unwrap();
            }
            println!("{}", build_id_string);
        }
    }
}
