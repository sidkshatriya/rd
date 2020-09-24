use bindgen::{
    callbacks::{EnumVariantValue, ParseCallbacks},
    Builder,
    CargoCallbacks,
};
use std::{env, path::PathBuf, process::Command};

#[derive(Debug)]
struct CustomPrefixCallbacks;

impl ParseCallbacks for CustomPrefixCallbacks {
    fn enum_variant_name(
        &self,
        _enum_name: Option<&str>,
        original_variant_name: &str,
        _variant_value: EnumVariantValue,
    ) -> Option<String> {
        Some(String::from("__") + original_variant_name)
    }

    fn include_file(&self, filename: &str) {
        CargoCallbacks::include_file(&CargoCallbacks, filename)
    }
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let path = PathBuf::from(out_dir);

    cc::Build::new()
        .file("src/cpuid_loop.S")
        .compile("cpuid_loop");

    cc::Build::new().file("src/rdtsc.c").compile("rdtsc");

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_consts_x64_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_consts_x86_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_const_asserts_x86_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_const_asserts_x64_generated.rs"))
        .status()
        .unwrap();

    // These are typically not needed. Uncomment and use when necessary e.g. there are new syscalls
    /*
    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_consts_trait_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_consts_trait_impl_x86_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_consts_trait_impl_x64_generated.rs"))
        .status()
        .unwrap();
    */

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

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("check_syscall_numbers_generated.rs"))
        .status()
        .unwrap();

    println!("cargo:rerun-if-changed=scripts/generate_syscalls.py");
    println!("cargo:rerun-if-changed=scripts/syscalls.py");

    let signal_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .header("bindgen/signal_wrapper.h")
        .derive_default(true)
        .generate()
        .unwrap();

    signal_bindings
        .write_to_file(path.join("signal_bindings_generated.rs"))
        .unwrap();

    let audit_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .header("bindgen/audit_wrapper.h")
        .derive_default(true)
        .generate()
        .unwrap();

    audit_bindings
        .write_to_file(path.join("audit_bindings_generated.rs"))
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
        .derive_default(true)
        .prepend_enum_name(false)
        // Workaround for "error[E0587]: type has conflicting packed and align representation hints"
        // We don't need these types so just omit them.
        .blacklist_type("perf_event_mmap_page")
        .blacklist_type("perf_event_mmap_page__bindgen_ty_1__bindgen_ty_1")
        .blacklist_type("perf_event_mmap_page__bindgen_ty_1")
        .header("bindgen/perf_event_wrapper.h")
        .generate()
        .unwrap();

    perf_event_bindings
        .write_to_file(path.join("perf_event_bindings_generated.rs"))
        .unwrap();

    let fcntl_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/fcntl_wrapper.h")
        .generate()
        .unwrap();

    fcntl_bindings
        .write_to_file(path.join("fcntl_bindings_generated.rs"))
        .unwrap();

    let sysexits_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/sysexits_wrapper.h")
        .generate()
        .unwrap();

    sysexits_bindings
        .write_to_file(path.join("sysexits_bindings_generated.rs"))
        .unwrap();

    let prctl_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/prctl_wrapper.h")
        .generate()
        .unwrap();

    prctl_bindings
        .write_to_file(path.join("prctl_bindings_generated.rs"))
        .unwrap();

    let kernel_abi_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .derive_default(true)
        .prepend_enum_name(false)
        .header("bindgen/kernel_wrapper.h")
        .generate()
        .unwrap();

    kernel_abi_bindings
        .write_to_file(path.join("kernel_bindings_generated.rs"))
        .unwrap();

    let gdb_register_bindings = Builder::default()
        .parse_callbacks(Box::new(CustomPrefixCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/gdb_register_wrapper.h")
        .generate()
        .unwrap();

    gdb_register_bindings
        .write_to_file(path.join("gdb_register_bindings_generated.rs"))
        .unwrap();

    let gdb_request_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/gdb_request_wrapper.h")
        .generate()
        .unwrap();

    gdb_request_bindings
        .write_to_file(path.join("gdb_request_bindings_generated.rs"))
        .unwrap();

    let kernel_supplement_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .derive_default(true)
        .prepend_enum_name(false)
        .header("bindgen/kernel_supplement_wrapper.h")
        .generate()
        .unwrap();

    kernel_supplement_bindings
        .write_to_file(path.join("kernel_supplement_bindings_generated.rs"))
        .unwrap();

    capnpc::CompilerCommand::new()
        .file("schema/trace.capnp")
        .run()
        .unwrap();
}
