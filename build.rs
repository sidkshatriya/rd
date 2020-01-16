use bindgen::Builder;
use bindgen::CargoCallbacks;
use std::process::Command;

fn main() {
    Command::new("scripts/generate_syscalls.py")
        .arg("src/x64_arch/syscall_consts_x64_generated.rs")
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg("src/x86_arch/syscall_consts_x86_generated.rs")
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg("src/x64_arch/syscall_name_arch_x64_generated.rs")
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg("src/x86_arch/syscall_name_arch_x86_generated.rs")
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg("src/kernel_abi/syscall_helper_functions_generated.rs")
        .status()
        .unwrap();

    println!("cargo:rerun-if-changed=bindgen/wrapper.h");

    let bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .header("bindgen/wrapper.h")
        .generate()
        .unwrap();

    bindings
        .write_to_file("src/signal/signal_bindings_generated.rs")
        .unwrap();
}
