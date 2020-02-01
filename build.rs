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

    println!("cargo:rerun-if-changed=bindgen/signal_wrapper.h");

    let signal_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .header("bindgen/signal_wrapper.h")
        .generate()
        .unwrap();

    signal_bindings
        .write_to_file(path.join("signal_bindings_generated.rs"))
        .unwrap();

    let ptrace_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/ptrace_wrapper.h")
        .generate()
        .unwrap();

    ptrace_bindings
        .write_to_file(path.join("ptrace_bindings_generated.rs"))
        .unwrap();

    let perf_event_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/perf_event_wrapper.h")
        .generate()
        .unwrap();

    perf_event_bindings
        .write_to_file(path.join("perf_event_bindings_generated.rs"))
        .unwrap();

    let fcntl_event_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/fcntl_wrapper.h")
        .generate()
        .unwrap();

    fcntl_event_bindings
        .write_to_file(path.join("fcntl_bindings_generated.rs"))
        .unwrap();

    let kernel_abi_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .blacklist_type("timex")
        .prepend_enum_name(false)
        .header("bindgen/kernel_wrapper.h")
        .generate()
        .unwrap();

    kernel_abi_bindings
        .write_to_file(path.join("kernel_bindings_generated.rs"))
        .unwrap();

    capnpc::CompilerCommand::new()
        .file("schema/trace.capnp")
        .run()
        .unwrap();
}
