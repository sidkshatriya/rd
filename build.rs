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
}
