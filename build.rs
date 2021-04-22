use bindgen::{
    callbacks::{EnumVariantValue, ParseCallbacks},
    Builder, CargoCallbacks,
};
use cmake::Config;
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
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let mut target_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    // @TODO What about cases where there is a custom target dir?
    target_dir.push("target");
    let path = PathBuf::from(out_dir);
    println!("cargo:rustc-link-arg-bins=-Wl,--dynamic-list=scripts/dynamic_list_for_ld.txt");

    Config::new(".")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("CMAKE_INSTALL_PREFIX", target_dir)
        .build();

    cc::Build::new()
        .file("src/cpuid_loop.S")
        .compile("cpuid_loop");
    println!("cargo:rerun-if-changed=src/cpuid_loop.S");

    cc::Build::new().file("src/rdtsc.c").compile("rdtsc");
    println!("cargo:rerun-if-changed=src/rdtsc.c");

    cc::Build::new().file("src/ioctl.c").compile("ioctl");
    println!("cargo:rerun-if-changed=src/ioctl.c");

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

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("syscall_record_case_generated.rs"))
        .status()
        .unwrap();

    Command::new("scripts/generate_syscalls.py")
        .arg(path.join("assembly_templates_generated.rs"))
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
    println!("cargo:rerun-if-changed=scripts/assembly_templates.py");
    println!("cargo:rerun-if-changed=scripts/syscalls.py");

    let perf_event_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .derive_default(true)
        .prepend_enum_name(false)
        .header("bindgen/perf_event_wrapper.h")
        .generate()
        .unwrap();
    println!("cargo:rerun-if-changed=bindgen/perf_event_wrapper.h");

    perf_event_bindings
        .write_to_file(path.join("perf_event_bindings_generated.rs"))
        .unwrap();

    let kernel_abi_bindings = Builder::default()
        .parse_callbacks(Box::new(CargoCallbacks))
        .derive_default(true)
        .prepend_enum_name(false)
        .header("bindgen/kernel_wrapper.h")
        .generate()
        .unwrap();
    println!("cargo:rerun-if-changed=bindgen/kernel_wrapper.h");

    kernel_abi_bindings
        .write_to_file(path.join("kernel_bindings_generated.rs"))
        .unwrap();

    let gdb_register_bindings = Builder::default()
        .parse_callbacks(Box::new(CustomPrefixCallbacks))
        .prepend_enum_name(false)
        .header("bindgen/gdb_register_wrapper.h")
        .generate()
        .unwrap();
    println!("cargo:rerun-if-changed=bindgen/gdb_register_wrapper.h");

    gdb_register_bindings
        .write_to_file(path.join("gdb_register_bindings_generated.rs"))
        .unwrap();

    let names = [
        "signal",
        "audit",
        "fcntl",
        "ptrace",
        "sysexits",
        "prctl",
        "gdb_request",
        "kernel_supplement",
        "packet",
        "personality",
        "thread_db",
        "misc_for_ioctl",
    ];

    for &name in &names {
        let bindings = Builder::default()
            .parse_callbacks(Box::new(CargoCallbacks))
            .header(format!("bindgen/{}_wrapper.h", name))
            .prepend_enum_name(false)
            .derive_default(true)
            .generate()
            .unwrap();
        println!("cargo:rerun-if-changed=bindgen/{}_wrapper.h", name);

        bindings
            .write_to_file(path.join(format!("{}_bindings_generated.rs", name)))
            .unwrap();
    }

    capnpc::CompilerCommand::new()
        .file("schema/trace.capnp")
        .run()
        .unwrap();
    println!("cargo:rerun-if-changed=schema/trace.capnp");
}
