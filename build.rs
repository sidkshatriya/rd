use bindgen::Builder;
use bindgen::CargoCallbacks;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let path = PathBuf::from(out_dir);

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_consts_x64_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_consts_x86_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_name_arch_x64_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_name_arch_x86_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_helper_functions_generated.rs"))
        .status()
        .unwrap();

    println!("cargo:rerun-if-changed=bindgen/wrapper.h");

    let bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .header("bindgen/wrapper.h")
        .generate()
        .unwrap();

    bindings
        .write_to_file(path.join("signal_bindings_generated.rs"))
        .unwrap();
}
