use crate::kernel_metadata::ptrace_event_name;
use crate::kernel_metadata::signal_name;
use crate::ptrace::PTRACE_EVENT_STOP as _PTRACE_EVENT_STOP;
use crate::record_task::RecordTask;
use libc::PTRACE_O_TRACESYSGOOD;
use libc::{SIGSTOP, SIGTRAP};
use libc::{WEXITSTATUS, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WSTOPSIG, WTERMSIG};
use std::fmt;

pub const PTRACE_EVENT_STOP: i32 = _PTRACE_EVENT_STOP as i32;

enum Type {
    // Task exited normally.
    Exit,
    // Task exited due to fatal signal.
    FatalSignal,
    // Task is in a signal-delivery-stop.
    SignalStop,
    // Task is in a group-stop. (See ptrace man page.)
    // You must use PTRACE_SEIZE to generate PTRACE_EVENT_STOPs, or these
    // will be treated as STOP_SIGNAL.
    GroupStop,
    // Task is in a syscall-stop triggered by PTRACE_SYSCALL
    // and PTRACE_O_TRACESYSGOOD.
    SyscallStop,
    // Task is in a PTRACE_EVENT stop, except for PTRACE_EVENT_STOP
    // which is treated as GROUP_STOP.
    PtraceEvent,
}

use Type::*;

pub struct WaitStatus {
    status: i32,
}

impl WaitStatus {
    // method is called type() in rr.
    fn wait_type(&self) -> Type {
        if let Some(_exit_code) = self.exit_code() {
            return Exit;
        }

        if let Some(_fatal_sig) = self.fatal_sig() {
            return FatalSignal;
        }

        if let Some(_stop_sig) = self.stop_sig() {
            return SignalStop;
        }

        if let Some(_group_stop_sig) = self.group_stop_sig() {
            return GroupStop;
        }

        if self.is_syscall() {
            return SyscallStop;
        }

        if let Some(_ptrace_event) = self.ptrace_event() {
            return PtraceEvent;
        }

        fatal!("Status {:x} not understood", self.status);

        return Exit;
    }

    /// What was the exit code of the process?
    fn exit_code(&self) -> Option<i32> {
        unsafe {
            if WIFEXITED(self.status) {
                Some(WEXITSTATUS(self.status))
            } else {
                None
            }
        }
    }

    /// Did we receive a fatal signal?
    fn fatal_sig(&self) -> Option<i32> {
        unsafe {
            if WIFSIGNALED(self.status) {
                Some(WTERMSIG(self.status))
            } else {
                None
            }
        }
    }

    /// What was the stopping signal?
    fn stop_sig(&self) -> Option<i32> {
        unsafe {
            if !WIFSTOPPED(self.status) || ((self.status >> 16) & 0xff != 0) {
                return None;
            }
        }

        let mut sig: i32 = unsafe { WSTOPSIG(self.status) };

        if sig == (SIGTRAP | 0x80) {
            return None;
        }

        sig &= !0x80;
        if sig != 0 {
            Some(sig)
        } else {
            // @TODO. Assume SIGSTOP. Is this OK?
            Some(SIGSTOP)
        }
    }

    // This method is called group_stop() in the rr codebase.
    fn group_stop_sig(&self) -> Option<i32> {
        unsafe {
            if !WIFSTOPPED(self.status) || ((self.status >> 16) & 0xff != PTRACE_EVENT_STOP) {
                return None;
            }
        }

        let mut sig: i32 = unsafe { WSTOPSIG(self.status) };
        sig &= !0x80;
        if sig != 0 {
            Some(sig)
        } else {
            // @TODO. Assume SIGSTOP. Is this OK?
            Some(SIGSTOP)
        }
    }

    fn is_syscall(&self) -> bool {
        unsafe {
            if self.ptrace_event().is_some() || !WIFSTOPPED(self.status) {
                return false;
            }

            return WSTOPSIG(self.status) == (SIGTRAP | 0x80);
        }
    }

    fn ptrace_event(&self) -> Option<i32> {
        let event: i32 = (self.status >> 16) & 0xff;
        if event == PTRACE_EVENT_STOP {
            None
        } else {
            Some(event)
        }
    }

    // Return a WaitStatus for a process exit.
    fn for_exit_code(code: i32) -> WaitStatus {
        debug_assert!(code >= 0 && code < 0x100);
        WaitStatus { status: code << 8 }
    }

    // Return a WaitStatus for a fatal signal
    fn for_fatal_sig(sig: i32) -> WaitStatus {
        debug_assert!(sig >= 1 && sig < 0x80);
        WaitStatus { status: sig }
    }

    // Return a WaitStatus for a stop signal
    fn for_stop_sig(sig: i32) -> WaitStatus {
        debug_assert!(sig >= 1 && sig < 0x80);
        WaitStatus {
            status: (sig << 8) | 0x7f,
        }
    }

    fn for_group_sig(sig: i32, t: &RecordTask) -> WaitStatus {
        debug_assert!(sig >= 1 && sig < 0x80);
        let mut code: i32 = (sig << 8) | 0x7f;
        if t.emulated_ptrace_seized {
            code |= PTRACE_EVENT_STOP << 16;
        }

        WaitStatus { status: code }
    }

    fn for_syscall(t: &RecordTask) -> WaitStatus {
        let mut code: i32 = (SIGTRAP << 8) | 0x7f;
        if t.emulated_ptrace_options & PTRACE_O_TRACESYSGOOD != 0 {
            code |= 0x80 << 8;
        }

        WaitStatus { status: code }
    }

    fn for_ptrace_event(ptrace_event: i32) -> WaitStatus {
        debug_assert!(ptrace_event >= 1 && ptrace_event < 0x100);
        WaitStatus {
            status: (ptrace_event << 16) | (SIGTRAP << 8) | 0x7f,
        }
    }
}

impl fmt::Display for WaitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.status)?;
        match self.wait_type() {
            Exit => write!(f, " (EXIT-{})", self.exit_code().unwrap()),
            FatalSignal => write!(f, " (FATAL-{})", signal_name(self.fatal_sig().unwrap())),
            SignalStop => write!(f, " (STOP-{})", signal_name(self.stop_sig().unwrap())),
            GroupStop => write!(
                f,
                " (GROUP-STOP-{})",
                signal_name(self.group_stop_sig().unwrap())
            ),
            SyscallStop => write!(f, " (SYSCALL)"),
            PtraceEvent => write!(f, " ({})", ptrace_event_name(self.ptrace_event().unwrap())),
        }
    }
}
