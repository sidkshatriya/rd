use crate::commands::RdCommand;
use crate::log::LogLevel::LogError;
use goblin::elf::{note, Elf};
use std::ffi::OsStr;
use std::fmt::Write;
use std::io::{stdin, BufRead, BufReader};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::{fs, io};

pub struct BuildIdCommand;

impl BuildIdCommand {
    pub fn new() -> BuildIdCommand {
        BuildIdCommand
    }

    pub fn build_id(elf_file: &Path) -> io::Result<Vec<u8>> {
        let data = fs::read(elf_file)?;
        match Elf::parse(&data) {
            Ok(elf_data) => {
                let maybe_sections = elf_data.iter_note_sections(&data, None);
                if maybe_sections.is_some() {
                    for maybe_note in maybe_sections.unwrap() {
                        match maybe_note {
                            Ok(note)
                                if note.n_type == note::NT_GNU_BUILD_ID && note.name == "GNU" =>
                            {
                                return Ok(note.desc.to_vec());
                            }
                            _ => continue,
                        }
                    }
                }
                // Even though there a build id could not be found, we return an empty
                // Vec i.e. an empty build id -- this mimics the behavior in rr.
                return Ok(Vec::new());
            }
            Err(_) => {
                // Even though there was an error is parsing the elf file, we return an empty
                // Vec -- this mimics the behavior in rr.
                return Ok(Vec::new());
            }
        }
    }
}

impl RdCommand for BuildIdCommand {
    fn run(&mut self) -> io::Result<()> {
        let mut fd = BufReader::new(stdin());
        let mut elf_file_vec = Vec::new();
        loop {
            match fd.read_until(b'\n', &mut elf_file_vec) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    if elf_file_vec.ends_with(b"\n") {
                        elf_file_vec.pop();
                    }
                    let elf_file = Path::new(OsStr::from_bytes(&elf_file_vec));
                    let maybe_build_id = Self::build_id(elf_file);
                    match maybe_build_id {
                        Ok(build_id) => {
                            let mut build_id_string = String::new();
                            for u in build_id {
                                write!(build_id_string, "{:02x}", u).unwrap();
                            }
                            println!("{}", build_id_string);
                        }
                        Err(e) => {
                            log!(
                                LogError,
                                "Error while trying to read from {:?}: {:?}",
                                elf_file,
                                e
                            );
                            return Err(e);
                        }
                    }
                    elf_file_vec.clear();
                }
                Err(e) => {
                    log!(LogError, "Error while trying to read from stdin: {:?}", e);
                    return Err(e);
                }
            }
        }
    }
}
