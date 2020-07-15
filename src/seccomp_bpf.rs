use crate::{
    bindings::kernel::{sock_filter, BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W},
    kernel_supplement::{seccomp_data, SECCOMP_RET_ALLOW, SECCOMP_RET_DATA, SECCOMP_RET_TRACE},
    remote_code_ptr::RemoteCodePtr,
};
use std::convert::TryInto;

// Copyright notice as in rr's `src/seccomp-bpf.h` (see https://github.com/mozilla/rr)
/*
 * seccomp example for x86 (32-bit and 64-bit) with BPF macros
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Will Drewry <wad@chromium.org>
 *  Kees Cook <keescook@chromium.org>
 *
 * The code may be used by anyone for any purpose, and can serve as a
 * starting point for developing applications using mode 2 seccomp.
 */

fn bpf_stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

#[derive(Clone)]
pub struct SeccompFilter {
    pub filters: Vec<sock_filter>,
}

impl Default for SeccompFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SeccompFilter {
    pub fn new() -> SeccompFilter {
        SeccompFilter {
            filters: Vec::new(),
        }
    }

    pub fn allow(&mut self) {
        self.filters
            .push(bpf_stmt((BPF_RET + BPF_K) as u16, SECCOMP_RET_ALLOW));
    }

    pub fn trace(&mut self) {
        self.filters.push(bpf_stmt(
            (BPF_RET + BPF_K) as u16,
            SECCOMP_RET_TRACE | SECCOMP_RET_DATA,
        ));
    }

    pub fn allow_syscalls_from_callsite(&mut self, ip: RemoteCodePtr) {
        let inst_ptr: u32 = offset_of!(seccomp_data, instruction_pointer) as u32;
        let v: u32 = ip.register_value().try_into().unwrap();
        self.filters
            .push(bpf_stmt((BPF_LD + BPF_W + BPF_ABS) as u16, inst_ptr));
        self.filters
            .push(bpf_jump((BPF_JMP + BPF_JEQ + BPF_K) as u16, v, 0, 1));
        self.allow()
    }
}
