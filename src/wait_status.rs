use crate::bindings::ptrace::{PTRACE_EVENT_STOP, PTRACE_O_TRACESYSGOOD};
use crate::kernel_metadata::ptrace_event_name;
use crate::kernel_metadata::signal_name;
use crate::task::record_task::record_task::RecordTask;
use libc::{SIGSTOP, SIGTRAP};
use libc::{WEXITSTATUS, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WSTOPSIG, WTERMSIG};
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
/// Called simply `Type` in rr.
pub enum WaitType {
    /// Task exited normally.
    Exit,
    /// Task exited due to fatal signal.
    FatalSignal,
    /// Task is in a signal-delivery-stop.
    SignalStop,
    /// Task is in a group-stop. (See ptrace man page.)
    /// You must use PTRACE_SEIZE to generate PTRACE_EVENT_STOPs, or these
    /// will be treated as STOP_SIGNAL.
    GroupStop,
    /// Task is in a syscall-stop triggered by PTRACE_SYSCALL
    /// and PTRACE_O_TRACESYSGOOD.
    SyscallStop,
    /// Task is in a PTRACE_EVENT stop, except for PTRACE_EVENT_STOP
    /// which is treated as GroupStop.
    PtraceEvent,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct WaitStatus {
    status: i32,
}

impl Default for WaitStatus {
    fn default() -> Self {
        Self::new(0)
    }
}

impl WaitStatus {
    pub fn new(status: i32) -> WaitStatus {
        WaitStatus { status }
    }

    /// method is called type() in rr.
    pub fn wait_type(&self) -> WaitType {
        if let Some(_exit_code) = self.exit_code() {
            return WaitType::Exit;
        }

        if let Some(_fatal_sig) = self.fatal_sig() {
            return WaitType::FatalSignal;
        }

        if let Some(_stop_sig) = self.stop_sig() {
            return WaitType::SignalStop;
        }

        if let Some(_group_stop_sig) = self.group_stop_sig() {
            return WaitType::GroupStop;
        }

        if self.is_syscall() {
            return WaitType::SyscallStop;
        }

        if let Some(_ptrace_event) = self.ptrace_event() {
            return WaitType::PtraceEvent;
        }

        fatal!("Status {:#x} not understood", self.status);

        return WaitType::Exit;
    }

    /// What was the exit code of the process?
    /// Exit code if wait_type() == EXIT, otherwise None.
    pub fn exit_code(&self) -> Option<i32> {
        unsafe {
            if WIFEXITED(self.status) {
                Some(WEXITSTATUS(self.status))
            } else {
                None
            }
        }
    }

    /// Did we receive a fatal signal?
    /// Fatal signal if wait_type() == FATAL_SIGNAL, otherwise None.
    pub fn fatal_sig(&self) -> Option<i32> {
        unsafe {
            let termsig = WTERMSIG(self.status);
            // Subtle. Makes sure Option<> is what we mean.
            if WIFSIGNALED(self.status) && termsig > 0 {
                Some(termsig)
            } else {
                None
            }
        }
    }

    /// What was the stopping signal?
    /// Stop signal if wait_type() == STOP_SIGNAL, otherwise None. A zero signal
    /// (rare but observed via PTRACE_INTERRUPT) is converted to SIGSTOP.
    pub fn stop_sig(&self) -> Option<i32> {
        unsafe {
            // Here the ((self.status >> 16) & 0xff != 0) is checking if its not some ptrace event
            // or a group stop (which is nothing but a ptrace event where
            // ((self.status >> 16) & 0xff == PTRACE_EVENT_STOP if PTRACE_SIEZE is used)
            if !WIFSTOPPED(self.status) || ((self.status >> 16) & 0xff != 0) {
                return None;
            }
        }

        let mut sig: i32 = unsafe { WSTOPSIG(self.status) };

        if sig == (SIGTRAP | 0x80) {
            // Its a syscall-enter or syscall-exit stop as we're using PTRACE_O_TRACESYSGOOD
            return None;
        }

        sig &= !0x80;
        if sig != 0 {
            Some(sig)
        } else {
            Some(SIGSTOP)
        }
    }

    /// Group stop signal if wait_type() == GROUP_STOP, otherwise None. A zero signal
    /// (rare but observed via PTRACE_INTERRUPT) is converted to SIGSTOP.
    /// This method is called group_stop() in the rr codebase.
    pub fn group_stop_sig(&self) -> Option<i32> {
        unsafe {
            // (self.status >> 16) & 0xff == PTRACE_EVENT_STOP is the classic signature of a group
            // stop when PTRACE_SIEZE is used
            if !WIFSTOPPED(self.status) || ((self.status >> 16) & 0xff != PTRACE_EVENT_STOP as i32)
            {
                return None;
            }
        }

        let mut sig: i32 = unsafe { WSTOPSIG(self.status) };

        sig &= !0x80;
        if sig != 0 {
            Some(sig)
        } else {
            Some(SIGSTOP)
        }
    }

    pub fn is_syscall(&self) -> bool {
        unsafe {
            // Eliminate some obvious im-possibilities.
            if self.ptrace_event().is_some() || !WIFSTOPPED(self.status) {
                return false;
            }

            // We're using PTRACE_O_TRACESYSGOOD.
            return WSTOPSIG(self.status) == (SIGTRAP | 0x80);
        }
    }

    /// ptrace event if wait_type() == PTRACE_EVENT, None otherwise.
    pub fn ptrace_event(&self) -> Option<u32> {
        let event: u32 = ((self.status >> 16) & 0xff) as u32;
        // Subtle. Makes sure Option<> is what we mean.
        if event == PTRACE_EVENT_STOP || event == 0 {
            None
        } else {
            Some(event)
        }
    }

    /// For exit_code() and fatal_sig(), returns None. For all other types
    /// returns the signal involved.
    pub fn ptrace_signal(&self) -> Option<i32> {
        unsafe {
            if WIFSTOPPED(self.status) {
                Some(WSTOPSIG(self.status) & 0x7f)
            } else {
                None
            }
        }
    }

    /// Return a WaitStatus for a process exit.
    pub fn for_exit_code(code: i32) -> WaitStatus {
        debug_assert!(code >= 0 && code < 0x100);
        WaitStatus { status: code << 8 }
    }

    /// Return a WaitStatus for a fatal signal
    pub fn for_fatal_sig(sig: i32) -> WaitStatus {
        debug_assert!(sig >= 1 && sig < 0x80);
        WaitStatus { status: sig }
    }

    /// Return a WaitStatus for a stop signal
    pub fn for_stop_sig(sig: i32) -> WaitStatus {
        debug_assert!(sig >= 1 && sig < 0x80);
        WaitStatus {
            status: (sig << 8) | 0x7f,
        }
    }

    pub fn for_group_sig(sig: i32, t: &RecordTask) -> WaitStatus {
        debug_assert!(sig >= 1 && sig < 0x80);
        let mut code: i32 = (sig << 8) | 0x7f;
        if t.emulated_ptrace_seized {
            code |= (PTRACE_EVENT_STOP as i32) << 16;
        }

        WaitStatus { status: code }
    }

    pub fn for_syscall(t: &RecordTask) -> WaitStatus {
        let mut code: i32 = (SIGTRAP << 8) | 0x7f;
        if t.emulated_ptrace_options.is_some()
            && (t.emulated_ptrace_options.unwrap() & PTRACE_O_TRACESYSGOOD != 0)
        {
            code |= 0x80 << 8;
        }

        WaitStatus { status: code }
    }

    pub fn for_ptrace_event(ptrace_event: i32) -> WaitStatus {
        debug_assert!(ptrace_event >= 1 && ptrace_event < 0x100);
        WaitStatus {
            status: (ptrace_event << 16) | (SIGTRAP << 8) | 0x7f,
        }
    }

    pub fn get(&self) -> i32 {
        self.status
    }
}

impl Display for WaitStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{:#x}", self.status)?;
        match self.wait_type() {
            WaitType::Exit => write!(f, " (EXIT-{})", self.exit_code().unwrap()),
            WaitType::FatalSignal => {
                write!(f, " (FATAL-{})", signal_name(self.fatal_sig().unwrap()))
            }
            WaitType::SignalStop => write!(f, " (STOP-{})", signal_name(self.stop_sig().unwrap())),
            WaitType::GroupStop => write!(
                f,
                " (GROUP-STOP-{})",
                signal_name(self.group_stop_sig().unwrap())
            ),
            WaitType::SyscallStop => write!(f, " (SYSCALL)"),
            WaitType::PtraceEvent => {
                write!(f, " ({})", ptrace_event_name(self.ptrace_event().unwrap()))
            }
        }
    }
}
