use crate::{
    bindings::ptrace::{PTRACE_EVENT_STOP, PTRACE_O_TRACESYSGOOD},
    kernel_metadata::{ptrace_event_name, signal_name},
    session::task::record_task::record_task::RecordTask,
};
use libc::{SIGSTOP, SIGTRAP, WEXITSTATUS, WIFEXITED, WIFSIGNALED, WIFSTOPPED, WSTOPSIG, WTERMSIG};
use std::{
    fmt,
    fmt::{Display, Formatter, Result},
    num::NonZeroU8,
};

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

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
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

        if self.maybe_stop_sig().is_sig() {
            return WaitType::SignalStop;
        }

        if self.maybe_group_stop_sig().is_sig() {
            return WaitType::GroupStop;
        }

        if self.is_syscall() {
            return WaitType::SyscallStop;
        }

        if self.maybe_ptrace_event().is_ptrace_event() {
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
    pub fn maybe_stop_sig(&self) -> MaybeStopSignal {
        unsafe {
            // Here the ((self.status >> 16) & 0xff != 0) is checking if its not some ptrace event
            // or a group stop (which is nothing but a ptrace event where
            // ((self.status >> 16) & 0xff == PTRACE_EVENT_STOP if PTRACE_SIEZE is used)
            if !WIFSTOPPED(self.status) || ((self.status >> 16) & 0xff != 0) {
                return MaybeStopSignal::new_none();
            }
        }

        let mut sig: i32 = unsafe { WSTOPSIG(self.status) };

        if sig == (SIGTRAP | 0x80) {
            // Its a syscall-enter or syscall-exit stop as we're using PTRACE_O_TRACESYSGOOD
            return MaybeStopSignal::new_none();
        }

        sig &= !0x80;
        if sig != 0 {
            MaybeStopSignal::new_sig(sig)
        } else {
            MaybeStopSignal::new_sig(SIGSTOP)
        }
    }

    /// Group stop signal if wait_type() == GROUP_STOP, otherwise None. A zero signal
    /// (rare but observed via PTRACE_INTERRUPT) is converted to SIGSTOP.
    /// DIFF NOTE: This method is called group_stop() in the rr codebase.
    pub fn maybe_group_stop_sig(&self) -> MaybeStopSignal {
        unsafe {
            // (self.status >> 16) & 0xff == PTRACE_EVENT_STOP is the classic signature of a group
            // stop when PTRACE_SIEZE is used
            if !WIFSTOPPED(self.status) || ((self.status >> 16) & 0xff != PTRACE_EVENT_STOP as i32)
            {
                return MaybeStopSignal::new_none();
            }
        }

        let mut sig: i32 = unsafe { WSTOPSIG(self.status) };

        sig &= !0x80;
        if sig != 0 {
            MaybeStopSignal::new_sig(sig)
        } else {
            MaybeStopSignal::new_sig(SIGSTOP)
        }
    }

    pub fn is_syscall(&self) -> bool {
        unsafe {
            // Eliminate some obvious im-possibilities.
            if self.maybe_ptrace_event().is_ptrace_event() || !WIFSTOPPED(self.status) {
                return false;
            }

            // We're using PTRACE_O_TRACESYSGOOD.
            WSTOPSIG(self.status) == (SIGTRAP | 0x80)
        }
    }

    /// ptrace event if wait_type() == PTRACE_EVENT, None otherwise.
    pub fn maybe_ptrace_event(&self) -> MaybePtraceEvent {
        let event: u32 = ((self.status >> 16) & 0xff) as u32;
        if event == PTRACE_EVENT_STOP || event == 0 {
            MaybePtraceEvent::new_none()
        } else {
            MaybePtraceEvent::new_event(event)
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
        match t.emulated_ptrace_options {
            Some(options) if options & PTRACE_O_TRACESYSGOOD != 0 => {
                code |= 0x80 << 8;
            }
            _ => (),
        }

        WaitStatus { status: code }
    }

    pub fn for_ptrace_event(ptrace_event: u32) -> WaitStatus {
        debug_assert!(ptrace_event >= 1 && ptrace_event < 0x100);
        WaitStatus {
            status: ((ptrace_event as i32) << 16) | (SIGTRAP << 8) | 0x7f,
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
            WaitType::SignalStop => write!(
                f,
                " (STOP-{})",
                signal_name(self.maybe_stop_sig().unwrap_sig())
            ),
            WaitType::GroupStop => write!(
                f,
                " (GROUP-STOP-{})",
                signal_name(self.maybe_group_stop_sig().unwrap_sig())
            ),
            WaitType::SyscallStop => write!(f, " (SYSCALL)"),
            WaitType::PtraceEvent => write!(
                f,
                " ({})",
                ptrace_event_name(self.maybe_ptrace_event().unwrap_event())
            ),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct MaybePtraceEvent(Option<NonZeroU8>);

impl MaybePtraceEvent {
    pub fn unwrap_event(&self) -> u32 {
        match self.0 {
            None => panic!("Cannot unwrap"),
            Some(non_zero) => non_zero.get() as u32,
        }
    }

    pub fn get_raw_repr(&self) -> u32 {
        match self.0 {
            None => 0,
            Some(non_zero) => non_zero.get() as u32,
        }
    }

    pub fn is_ptrace_event(&self) -> bool {
        self.0.is_some()
    }

    pub fn new_none() -> MaybePtraceEvent {
        MaybePtraceEvent(None)
    }

    /// Ensure that val != 0 and val <= 0xff otherwise you will get `MaybePtraceEvent(None)`
    pub fn new_event(val: u32) -> MaybePtraceEvent {
        if val == 0 || val > 0xff {
            MaybePtraceEvent(None)
        } else {
            // We've already checked so no point checking again.
            MaybePtraceEvent(Some(unsafe { NonZeroU8::new_unchecked(val as u8) }))
        }
    }
}

impl PartialEq<u32> for MaybePtraceEvent {
    fn eq(&self, other: &u32) -> bool {
        self.0.map_or(false, |op| op.get() as u32 == *other)
    }
}

impl Display for MaybePtraceEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !self.is_ptrace_event() {
            f.write_str("- Not a ptrace event -")
        } else {
            f.write_str(&ptrace_event_name(self.unwrap_event()))
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct MaybeStopSignal(Option<NonZeroU8>);

impl MaybeStopSignal {
    pub fn unwrap_sig(&self) -> i32 {
        match self.0 {
            None => panic!("Cannot unwrap"),
            Some(non_zero) => non_zero.get() as i32,
        }
    }

    // Avoid using this method. Use `unwrap_sig()`
    pub fn get_raw_repr(&self) -> i32 {
        match self.0 {
            None => 0,
            Some(non_zero) => non_zero.get() as i32,
        }
    }

    pub fn is_sig(&self) -> bool {
        self.0.is_some()
    }
    pub fn is_not_sig(&self) -> bool {
        self.0.is_none()
    }

    pub fn new_none() -> MaybeStopSignal {
        MaybeStopSignal(None)
    }

    /// Ensure that sig >= 1 and sig < 0x80 otherwise you will get `MaybeStopSignal(None)`
    pub fn new_sig(sig: i32) -> MaybeStopSignal {
        if sig < 1 || sig >= 0x80 {
            MaybeStopSignal(None)
        } else {
            // We've already checked so no point checking again.
            MaybeStopSignal(Some(unsafe { NonZeroU8::new_unchecked(sig as u8) }))
        }
    }
}

impl PartialEq<i32> for MaybeStopSignal {
    fn eq(&self, other: &i32) -> bool {
        self.0.map_or(false, |op| op.get() as i32 == *other)
    }
}

impl PartialEq<u8> for MaybeStopSignal {
    fn eq(&self, other: &u8) -> bool {
        self.0.map_or(false, |op| op.get() == *other)
    }
}

impl Display for MaybeStopSignal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !self.is_sig() {
            f.write_str("- Not a signal -")
        } else {
            f.write_str(&signal_name(self.unwrap_sig()))
        }
    }
}
