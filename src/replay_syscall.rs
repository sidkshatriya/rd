#[cfg(feature = "verify_syscall_numbers")]
include!(concat!(
    env!("OUT_DIR"),
    "/check_syscall_numbers_generated.rs"
));
